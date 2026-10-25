# intel_epss.py — EPSS de FIRST con caché local por CVE (DAT-001).
# Solo consulta la API de los CVEs sin copia vigente; el resto sale de la caché (ley 11).
import requests

import store

EPSS_URL = "https://api.first.org/data/v1/epss"


def _chunk(lst, n):
    for i in range(0, len(lst), n):
        yield lst[i:i + n]


def get_epss_for_cves(cve_list, timeout=8):

    result = {}
    if not cve_list:
        return result

    unicos = list(dict.fromkeys(cve_list))
    missing = []
    for cve in unicos:
        cached = store.get_fresh(f"epss:{cve}", store.EPSS_TTL_S)
        if cached is not None:
            result[cve] = cached
        else:
            missing.append(cve)

    for chunk in _chunk(missing, 200):
        params = {"cve": ",".join(chunk)}
        try:
            r = requests.get(EPSS_URL, params=params, timeout=timeout)
            r.raise_for_status()
            data = r.json()
        except Exception:
            continue
        for row in data.get("data", []):
            cve = row.get("cve")
            if not cve:
                continue
            try:
                epss = float(row.get("epss", 0.0) or 0.0)
            except Exception:
                epss = 0.0
            try:
                pct = float(row.get("percentile", 0.0) or 0.0)
            except Exception:
                pct = 0.0
            entry = {"epss": epss, "percentile": pct}
            result[cve] = entry
            store.put(f"epss:{cve}", entry)

    sin_datos = [c for c in missing if c not in result]
    if sin_datos:
        print(f"[!] EPSS: {len(sin_datos)} CVE(s) sin dato y sin copia local; se puntúan como EPSS 0.")

    return result
