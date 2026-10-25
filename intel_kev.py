# intel_kev.py — catálogo KEV de CISA con caché local y fallback (DAT-001).
# Nunca devuelve vacío en silencio: si la red falla, sirve la última copia buena avisando (ley 11).
import datetime

import requests

import store

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_SNAP_KEY = "kev"


def load_kev_set(timeout=8):
    try:
        r = requests.get(KEV_URL, timeout=timeout)
        r.raise_for_status()
        data = r.json()
    except Exception as e:
        snap = store.get_any(_SNAP_KEY)
        if snap is not None:
            payload, age_s = snap
            edad = datetime.timedelta(seconds=int(age_s))
            print(f"[!] KEV: descarga fallida ({e}); usando la última copia local (edad: {edad}).")
            return set(payload)
        print("[!] KEV: descarga fallida y sin copia local; los flags KEV saldrán en 'No' por falta de datos.")
        return set()

    out = set()
    for v in (data.get("vulnerabilities") or []):
        cve = v.get("cveID")
        if cve:
            out.add(cve)
    store.put(_SNAP_KEY, sorted(out))
    return out
