# intel_psirt.py — PSIRT multi-vendor: advisories más rápidos que NVD (INT-003).
# Vendors v1 (verificados en vivo, F0 2026-10-24, ambos gratuitos y sin key):
#   - Red Hat Security Data API: GET /hydra/rest/securitydata/cve/{CVE}.json
#   - Ubuntu Security CVE API:   GET /security/cves.json?q={CVE} (filtrar id exacto)
# TTL 6 h (el valor de esta fuente ES la velocidad); degradación elegante (ley 11):
# fallo de red → última copia buena avisando; el fallo NUNCA se cachea como "sin advisory".
import requests

import store

RH_URL = "https://access.redhat.com/hydra/rest/securitydata/cve/{cve}.json"
UB_URL = "https://ubuntu.com/security/cves.json?q={cve}"
TTL_S = 6 * 3600


def _redhat(cve: str, timeout=15):
    clave = f"psirt:rh:{cve}"
    fresco = store.get_fresh(clave, TTL_S)
    if fresco is not None:
        return fresco
    try:
        r = requests.get(RH_URL.format(cve=cve), timeout=timeout)
        if r.status_code == 404:
            out = None  # respuesta válida: Red Hat no cubre este CVE
            store.put(clave, out)
            return out
        r.raise_for_status()
        data = r.json()
        cvss3 = data.get("cvss3") or {}
        out = {
            "vendor": "RedHat",
            "severidad": data.get("threat_severity") or "",
            "fecha": (data.get("public_date") or "")[:10],
            "cvss": cvss3.get("cvss3_base_score") or "",
            "url": f"https://access.redhat.com/security/cve/{cve}",
        }
        store.put(clave, out)
        return out
    except Exception:
        viejo = store.get_any(clave)
        if viejo is not None:
            print(f"[!] PSIRT RedHat: fallo para {cve}; usando última copia local.")
            return viejo[0]
        return None


def _ubuntu(cve: str, timeout=20):
    clave = f"psirt:ub:{cve}"
    fresco = store.get_fresh(clave, TTL_S)
    if fresco is not None:
        return fresco
    try:
        r = requests.get(UB_URL.format(cve=cve), timeout=timeout)
        r.raise_for_status()
        registro = None
        for c in r.json().get("cves") or []:
            if c.get("id") == cve:  # la búsqueda q= devuelve coincidencias parciales
                registro = c
                break
        if registro is None:
            out = None  # respuesta válida: Ubuntu no lo lista
            store.put(clave, out)
            return out
        out = {
            "vendor": "Ubuntu",
            "severidad": (registro.get("priority") or "").capitalize(),
            "fecha": (registro.get("published") or "")[:10],
            "cvss": (registro.get("cvss3") or "").get("base_score", "") or "",
            "notas": (registro.get("notices_ids") or [])[:3],  # USN oficiales
            "url": f"https://ubuntu.com/security/{cve}",
        }
        store.put(clave, out)
        return out
    except Exception:
        viejo = store.get_any(clave)
        if viejo is not None:
            print(f"[!] PSIRT Ubuntu: fallo para {cve}; usando última copia local.")
            return viejo[0]
        return None


def para_cve(cve: str):
    """Advisories de ambos vendors para un CVE: {"redhat": ...|None, "ubuntu": ...|None}."""
    return {"redhat": _redhat(cve), "ubuntu": _ubuntu(cve)}


def para_cves(cve_ids):
    """Mapa {cve: para_cve(...)} para enriquecer el pipeline en lote."""
    return {c: para_cve(c) for c in {str(x).upper() for x in (cve_ids or [])}}


def resumen_hallazgo(advisories: dict) -> str:
    """Texto para el informe: 'RedHat=Important (anticipa NVD 2d); Ubuntu=High; USN-...'.
    La anticipación se calcula fuera (requiere la fecha publicada de NVD)."""
    partes = []
    for vendor in ("redhat", "ubuntu"):
        info = advisories.get(vendor) if isinstance(advisories, dict) else None
        if info:
            texto = f"{info.get('vendor')}={info.get('severidad') or '?'}"
            notas = info.get("notas") or []
            if notas:
                texto += f" ({notas[0]})"
            partes.append(texto)
    return "; ".join(partes)


def dias_anticipa(fecha_vendor: str, fecha_nvd: str):
    """Días que el vendor se adelantó a NVD (>0 anticipa; None si falta alguna fecha)."""
    if not fecha_vendor or not fecha_nvd:
        return None
    try:
        from datetime import date

        def _d(s):
            a, m, d = s[:10].split("-")
            return date(int(a), int(m), int(d))

        return (_d(fecha_nvd) - _d(fecha_vendor)).days
    except Exception:
        return None


def resumen_con_gap(advisories: dict, fecha_nvd: str) -> str:
    """Resumen para el informe (INT-003): severidades vendor + anticipación a NVD si consta."""
    texto = resumen_hallazgo(advisories)
    if not texto or not fecha_nvd:
        return texto
    gaps = [g for g in (dias_anticipa((a or {}).get("fecha"), fecha_nvd)
                        for a in (advisories or {}).values()) if g is not None]
    maximo = max(gaps, default=None)
    if maximo is not None and maximo > 0:
        texto += f" [anticipa NVD {maximo}d]"
    return texto
