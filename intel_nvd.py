# intel_nvd.py
import math
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

import ratelimit
import store

# cache en memoria (producto, versión)
_CACHE: dict[tuple[str, str], list[dict]] = {}

# Config API NVD
NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
API_KEY = os.getenv("NVD_API_KEY", "").strip() or None

#ritmo por defecto, teniendo api_key mas rapido, que en este proyecto se tiene.
BASE_DELAY = 0.35 if API_KEY else 0.8
MAX_RETRIES = 3
TIMEOUT = (6, 20)  # (connect, read)

HEADERS = {"User-Agent": "tfm-vulnscan/1.0"}
if API_KEY:
    HEADERS["apiKey"] = API_KEY

# límites oficiales de la API NVD: 5 req/30s sin clave, 50 req/30s con clave (NUC-001).
# _BUCKET es el presupuesto global compartido por todos los hilos del proceso.
_WINDOW_S = 30.0
_BUCKET = ratelimit.TokenBucket(50 if API_KEY else 5, _WINDOW_S)


def _product_synonyms(product: str, banner: str = "") -> list[str]:

    p = (product or "").lower().strip()
    b = (banner or "").lower()

    if p in ("httpd", "apache", "apache2") or ("apache" in b and "http" in b):
        return ["httpd", "apache http server", "apache httpd", "apache2", "apache"]
    if p in ("postgresql", "postgres") or ("postgres" in b):
        return ["postgresql", "postgres"]
    if p in ("nginx",):
        return ["nginx"]
    if p in ("openssh",):
        return ["openssh"]
    if p in ("samba", "smbd"):
        return ["samba", "smbd"]
    if p in ("mysql",):
        return ["mysql"]
    if p in ("mariadb",):
        return ["mariadb"]

    base = (product or "").strip()
    if base and base.lower() != base:
        return [base, base.lower()]
    return [base] if base else []


def search_cves_smart(product: str, version: str, banner: str = "", max_cves: int = 120) -> list[dict]:
    # busqueda robusta nvd, prueba sinonimos, variantes de version y deduplica

    products = _product_synonyms(product, banner=banner)
    versions = _version_candidates(version)

    results_map: dict[str, dict] = {}
    for prod in products:
        for ver in versions:
            partial = search_cves_by_product_version(prod, ver, max_cves=max_cves)
            for c in partial:
                cid = c.get("cve_id")
                if cid:
                    results_map[cid] = c  # dedup

    return list(results_map.values())


def _sleep_backoff(attempt: int):
    wait = BASE_DELAY * math.pow(2, attempt - 1)
    time.sleep(wait)


def _safe_get(url: str, params: dict) -> dict:
    for attempt in range(1, MAX_RETRIES + 1):
        _BUCKET.acquire()
        try:
            r = requests.get(url, params=params, headers=HEADERS, timeout=TIMEOUT)
            # rate-limit / errores temporales
            # para cuando tiene que hacer muchas llamadas a nvd porque hay muchos servicios
            if r.status_code in (429, 502, 503, 504):
                _sleep_backoff(attempt)
                continue
            r.raise_for_status()
            return r.json()
        except requests.Timeout:
            _sleep_backoff(attempt)
        except requests.RequestException:
            _sleep_backoff(attempt)
    return {}


def _parse_cvss(cve: dict) -> tuple[float, str]:

    # devuelve cvss severity en v3.1, y sino se puede probamos 3 y 2
    metrics = (cve.get("metrics") or {})
    # v3.1
    m31 = metrics.get("cvssMetricV31") or []
    if m31:
        score = m31[0].get("cvssData", {}).get("baseScore")
        sev = m31[0].get("cvssData", {}).get("baseSeverity")
        if isinstance(score, (int, float)):
            return float(score), (sev or "")
    # v3.0
    m30 = metrics.get("cvssMetricV30") or []
    if m30:
        score = m30[0].get("cvssData", {}).get("baseScore")
        sev = m30[0].get("cvssData", {}).get("baseSeverity")
        if isinstance(score, (int, float)):
            return float(score), (sev or "")
    # v2
    m2 = metrics.get("cvssMetricV2") or []
    if m2:
        score = m2[0].get("cvssData", {}).get("baseScore")
        sev = m2[0].get("baseSeverity") or ""
        if isinstance(score, (int, float)):
            return float(score), sev
    return 0.0, ""


def _first_cpe(cve: dict) -> str:

    configs = cve.get("configurations") or []
    if isinstance(configs, dict):
        configs = [configs]
    for cfg in configs:
        nodes = cfg.get("nodes") or []
        for node in nodes:
            matches = node.get("cpeMatch") or []
            for m in matches:
                crit = m.get("criteria")
                if crit and crit.startswith("cpe:2.3:"):
                    return crit
    return ""


def _desc(cve: dict) -> str:
    descs = cve.get("descriptions") or []
    if descs:
        for d in descs:
            if (d.get("lang") or "").lower() == "es":
                return d.get("value") or ""
        return descs[0].get("value") or ""
    return ""


def _search_raw(keyword: str, start_index: int = 0, results_per_page: int = 200) -> dict:
    params = {
        "keywordSearch": keyword,
        "startIndex": start_index,
        "resultsPerPage": results_per_page,
    }
    data = _safe_get(NVD_BASE, params)
    return data


def search_cves_by_product_version(product: str, version: str, max_cves: int = 50) -> list[dict]:

    # busca por keyword con servicio:version
    key = (product.lower().strip(), version.lower().strip())
    if key in _CACHE:
        return _CACHE[key]

    disk_key = f"kw:{key[0]}:{key[1]}"
    cached = store.get_fresh(disk_key, store.CVE_TTL_S)
    if cached is not None:
        _CACHE[key] = cached
        return cached

    keyword = f"{product} {version}".strip()
    results: list[dict] = []

    # paginacion si hay muchos resultados
    start = 0
    while len(results) < max_cves:
        data = _search_raw(keyword, start_index=start)
        vulns = data.get("vulnerabilities") or []
        if not vulns:
            break
        for item in vulns:
            cve = item.get("cve") or {}
            cve_id = cve.get("id") or ""
            if not cve_id:
                continue
            cvss, sev = _parse_cvss(cve)
            results.append({
                "cve_id": cve_id,
                "severity": sev,
                "cvss": float(cvss) if cvss else 0.0,
                "cpe": _first_cpe(cve),
                "description": _desc(cve),
            })
            if len(results) >= max_cves:
                break
        # si hay mas paginas
        total = data.get("totalResults")
        if total is None or (start + len(vulns)) >= total:
            break
        start += len(vulns)

    _CACHE[key] = results
    store.put(disk_key, results)
    return results


def _version_candidates(version: str) -> list[str]:

    if not version:
        return []
    import re
    nums = re.findall(r"\d+", version)
    out = [version.strip()]
    if len(nums) >= 2:
        out.append(".".join(nums[:2]))
    if len(nums) >= 1:
        out.append(nums[0])
    # quitar duplicados preservando orden
    seen, res = set(), []
    for x in out:
        if x not in seen:
            seen.add(x)
            res.append(x)
    return res


def _build_cpe23(cpe_base: str, version: str | None) -> str:

    # CPE 2.3 tiene 13 componentes empezando por 'cpe:2.3'
    parts = cpe_base.split(":")
    if len(parts) < 5:
        raise ValueError(f"CPE base no válido: {cpe_base}")
    #cpe:2.3:a:vendor:product:<version>:*:*:*:*:*:*:*:*
    filled = parts[:5]  # cpe, 2.3, a, vendor, product
    filled.append(version or "*")
    # rellenar hasta 13 con '*'
    while len(filled) < 13:
        filled.append("*")
    return ":".join(filled)


_last_call_ts = 0.0  # (obsoleto: el ritmo lo fija _BUCKET; se conserva por compatibilidad de contexto)


def _nvd_request(params: dict) -> dict:

    for attempt in range(1, MAX_RETRIES + 1):
        _BUCKET.acquire()
        try:
            r = requests.get(NVD_BASE, params=params, headers=HEADERS, timeout=TIMEOUT)

            # codigo que sale de rate-limit cuando saturamos la api nvd
            if r.status_code == 429:
                retry_after = r.headers.get("Retry-After")
                if retry_after and retry_after.isdigit():
                    time.sleep(float(retry_after))
                else:
                    time.sleep(BASE_DELAY * (2 ** (attempt - 1)))
                continue

            # Errores temporales
            if r.status_code in (502, 503, 504):
                time.sleep(BASE_DELAY * (2 ** (attempt - 1)))
                continue

            r.raise_for_status()
            return r.json()

        except requests.Timeout:
            time.sleep(BASE_DELAY * (2 ** (attempt - 1)))
        except requests.RequestException:
            time.sleep(BASE_DELAY * (2 ** (attempt - 1)))
    return {}



def _extract_cvss(metrics: dict) -> float | None:
    # intenta CVSS v3.1, v3.0 y v2
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        arr = metrics.get(key)
        if arr:
            try:
                return float(arr[0]["cvssData"]["baseScore"])
            except Exception:
                pass
    return None


def _parse_nvd_response(js: dict) -> list[dict]:
    items: list[dict] = []
    for vuln in js.get("vulnerabilities", []):
        cve = vuln.get("cve", {})
        cve_id = cve.get("id")
        desc = ""
        descs = cve.get("descriptions") or []
        if descs:
            desc = descs[0].get("value", "")
        metrics = cve.get("metrics") or {}
        score = _extract_cvss(metrics)
        pub = cve.get("published")
        items.append({
            "cve_id": cve_id,
            "description": desc,
            "cvss": score,
            "published": pub,
            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}" if cve_id else "",
        })
    return items


def search_cves_by_cpe(cpe_base: str, version: str, max_cves: int = 200) -> list[dict]:
    # consulta nvd por cpe, mas preciso que keyword search
    results: dict[str, dict] = {}
    versions = _version_candidates(version) or ["*"]

    for ver in versions:
        cache_key = f"cpe:{cpe_base}:{ver}"
        cached = store.get_fresh(cache_key, store.CVE_TTL_S)
        if cached is not None:
            batch = cached
        else:
            cpe = _build_cpe23(cpe_base, ver)
            batch = []
            start = 0
            while True:
                params = {
                    "cpeName": cpe,
                    "startIndex": start,
                    "resultsPerPage": 200,
                }
                js = _nvd_request(params)
                batch.extend(_parse_nvd_response(js))
                total = js.get("totalResults", 0)
                start += 200
                if not js or len(batch) >= max_cves or start >= total:
                    break
            # no se cachean respuestas vacías por fallo transitorio: fijaría "sin CVEs" durante 72h
            if batch:
                store.put(cache_key, batch)
        for it in batch:
            cid = it.get("cve_id")
            if cid:
                results[cid] = it
            if len(results) >= max_cves:
                break
    return list(results.values())


# funcion principal, intenta primero mapear CVE por CPE y si no hay resultados busca por keywords.
def search_cves_cpe_first(product: str, version: str, banner: str = "", max_cves: int = 200) -> list[dict]:
    try:
        from cpe_map import resolve_cpe_bases
    except Exception:
        resolve_cpe_bases = None  

    # 1) CPE
    if resolve_cpe_bases:
        bases = resolve_cpe_bases(product, banner=banner) or []
        for base in bases:
            items = search_cves_by_cpe(base, version, max_cves=max_cves)
            if items:
                return items

    # 2) si no hay resultados cpe usamos plan b
    try:
        return search_cves_smart(product, version, banner=banner, max_cves=max_cves)
    except Exception:
        return search_cves_by_product_version(product, version, max_cves=max_cves)


def get_cve(cve_id: str):
    """Ficha de un CVE concreto por ID (para PSIRT/INT-003 y la tool advisories).

    {"id", "published", "cvss", "description"} o None si NVD no lo tiene. Va por el
    token bucket global y se cachea con el TTL de CVEs.
    """
    clave = f"nvdid:{cve_id}"
    fresco = store.get_fresh(clave, store.CVE_TTL_S)
    if fresco is not None:
        return fresco
    js = _nvd_request({"cveId": cve_id})
    vulns = js.get("vulnerabilities") or []
    if not vulns:
        return None
    cve = vulns[0].get("cve") or {}
    descs = cve.get("descriptions") or []
    out = {
        "id": cve.get("id", cve_id),
        "published": (cve.get("published") or "")[:10],
        "cvss": _extract_cvss(cve.get("metrics") or {}),
        "description": (descs[0].get("value", "") if descs else "")[:200],
    }
    store.put(clave, out)
    return out


def search_cves_for_services(services: list[dict], max_workers: int = 4) -> dict[tuple, list[dict]]:
    """Busca CVEs para varios servicios en paralelo (NUC-001).

    services: dicts con al menos "port" y "banner" (y "proto" si existe). Añade
    "software"/"version" parseados a cada dict y devuelve {(port, proto): [cve, ...]}.
    El ritmo real hacia NVD lo impone _BUCKET (compartido entre hilos) y la caché de
    store elimina las consultas repetidas.
    """
    from utils import (
        parse_software_version_from_banner,  # tardío: utils no depende de intel
    )

    out: dict[tuple, list[dict]] = {}
    jobs = []
    for p in services:
        key = (p.get("port"), p.get("proto", "tcp"))
        software, version = parse_software_version_from_banner(p.get("banner", ""))
        p["software"] = software or ""
        p["version"] = version or ""
        out[key] = []
        if software and version:
            jobs.append((key, software, version, p.get("banner", "")))
    if not jobs:
        return out

    with ThreadPoolExecutor(max_workers=max(1, max_workers)) as ex:
        futs = {ex.submit(search_cves_cpe_first, sw, ver, banner): key
                for key, sw, ver, banner in jobs}
        for fut in as_completed(futs):
            key = futs[fut]
            try:
                out[key] = fut.result()
            except Exception as e:
                print(f"    [NVD] error buscando CVEs para {key}: {e}")
                out[key] = []
    return out
