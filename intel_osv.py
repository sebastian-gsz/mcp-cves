# intel_osv.py — OSV (Google): vulnerabilidades por dependencia de código (INT-002).
# Consulta api.osv.dev (sin key) por (ecosistema, paquete, versión); parsers de manifiestos
# puros (disco sí, red no) y caché TTL 24 h con degradación elegante (ley 11).
import json
import os
import re
import tomllib
import xml.etree.ElementTree as ET

import requests

import store

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
OSV_QUERYBATCH_URL = "https://api.osv.dev/v1/querybatch"
EXCLUIR_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__", ".tox", "dist", "build"}
PROFUNDIDAD_MAX = 4

# manifiesto -> (ecosistema OSV, parser)
_MANIFIESTOS = {
    "requirements.txt": ("PyPI", "_parse_requirements"),
    "package.json": ("npm", "_parse_package_json"),
    "go.mod": ("Go", "_parse_go_mod"),
    "Cargo.toml": ("crates.io", "_parse_cargo"),
    "pom.xml": ("Maven", "_parse_pom"),
    "Gemfile": ("RubyGems", "_parse_gemfile"),
}

# lockfiles (INT-004): el árbol RESUELTO real — transitivos incluidos — con versiones exactas
_LOCKFILES = {
    "pnpm-lock.yaml": ("npm", "_parse_pnpm_lock"),
    "package-lock.json": ("npm", "_parse_package_lock"),
    "yarn.lock": ("npm", "_parse_yarn_lock"),
    "poetry.lock": ("PyPI", "_parse_poetry_lock"),
    "uv.lock": ("PyPI", "_parse_uv_lock"),
}
_CONOCIDOS = {**_MANIFIESTOS, **_LOCKFILES}

_SEVERIDAD_PROXY = {"LOW": 2.0, "MODERATE": 4.0, "MEDIUM": 5.0, "HIGH": 7.5, "CRITICAL": 9.5}


def detectar_manifiestos(directorio: str):
    """Lista [(nombre_manifiesto, ruta)] hasta PROFUNDIDAD_MAX, sin bajar en dirs excluidos."""
    base = os.path.abspath(directorio)
    out = []
    for actual, dirs, ficheros in os.walk(base):
        rel = os.path.relpath(actual, base)
        prof = 0 if rel == "." else rel.count(os.sep) + 1
        if prof >= PROFUNDIDAD_MAX:
            dirs[:] = []
        dirs[:] = [d for d in dirs if d not in EXCLUIR_DIRS]
        for f in ficheros:
            if f in _CONOCIDOS:
                out.append((f, os.path.join(actual, f)))
    return out


def _parse_requirements(texto: str):
    # pares (paquete, versión exacta) de líneas "paquete==1.2.3"; sin pin exacto se omite
    out = []
    for linea in texto.splitlines():
        linea = linea.split("#", 1)[0].strip()
        m = re.match(r"^([A-Za-z0-9_.\-]+)==([^\s;]+)", linea)
        if m:
            out.append((m.group(1), m.group(2)))
    return out


def _parse_package_json(texto: str):
    try:
        data = json.loads(texto)
    except Exception:
        return []
    out = []
    for seccion in ("dependencies", "devDependencies"):
        for nombre, version in (data.get(seccion) or {}).items():
            if isinstance(version, str) and re.fullmatch(r"\d+(\.\d+)*([\w.\-+]*)?", version):
                out.append((nombre, version))
    return out


def _parse_go_mod(texto: str):
    out = []
    for linea in texto.splitlines():
        m = re.match(r"^\s+([\w./\-]+)\s+v(\d+\.\d+\.\d+[^\s]*)", linea)
        if m:
            out.append((m.group(1), "v" + m.group(2)))
    return out


def _parse_cargo(texto: str):
    try:
        data = tomllib.loads(texto)
    except Exception:
        return []
    out = []
    for nombre, valor in (data.get("dependencies") or {}).items():
        version = valor if isinstance(valor, str) else (valor or {}).get("version", "")
        if version:
            out.append((nombre, version))
    return out


def _parse_pom(texto: str):
    out = []
    try:
        raiz = ET.fromstring(texto)
    except Exception:
        return out
    ns = "{http://maven.apache.org/POM/4.0.0}"
    for dep in raiz.iter(f"{ns}dependency"):
        gid = dep.findtext(f"{ns}groupId") or ""
        aid = dep.findtext(f"{ns}artifactId") or ""
        ver = dep.findtext(f"{ns}version") or ""
        if gid and aid and ver and not ver.startswith("${"):
            out.append((f"{gid}:{aid}", ver))
    return out


def _parse_gemfile(texto: str):
    out = []
    for linea in texto.splitlines():
        m = re.match(r"^\s*gem\s+['\"]([\w.\-]+)['\"]\s*,\s*['\"]([\d.]+[\w.]*)['\"]", linea)
        if m:
            out.append((m.group(1), m.group(2)))
    return out


# --- lockfiles (INT-004): parsers del árbol resuelto ---


def _parse_pnpm_lock(texto: str):
    """pnpm-lock.yaml (v6-v9) SIN yaml-lib: claves `name@version:` de la sección `packages:`.

    Los nombres con scope (@org/pkg) se resuelven partiendo del ÚLTIMO '@'; los sufijos de
    peer `(...)` de la sección snapshots: se excluyen porque viven en otra sección.
    """
    out, en_packages = [], False
    for linea in texto.splitlines():
        if not linea.strip() or linea.lstrip().startswith("#"):
            continue
        if not linea.startswith(" "):  # clave de nivel 0: cambia de sección
            en_packages = linea.strip() == "packages:"
            continue
        m = re.match(r"^ {2}'?([^:']+)'?:\s*$", linea)
        if not m or not en_packages:
            continue
        km = re.match(r"^(?P<name>.+)@(?P<ver>v?\d[^\s()]*)$", m.group(1))
        if km:
            par = (km.group("name"), km.group("ver"))
            if par not in out:
                out.append(par)
    return out


def _parse_package_lock(texto: str):
    """package-lock.json: v2/v3 (sección packages con rutas node_modules/...) y legacy v1
    (dependencies anidados)."""
    try:
        data = json.loads(texto)
    except Exception:
        return []
    out = []
    for ruta, info in (data.get("packages") or {}).items():
        version = (info or {}).get("version")
        if ruta and ruta != "" and isinstance(version, str) and "node_modules/" in ruta:
            out.append((ruta.rsplit("node_modules/", 1)[-1], version))
    seen = {p for p, _ in out}

    def _legacy(deps):
        for nombre, info in (deps or {}).items():
            version = (info or {}).get("version")
            if isinstance(version, str) and (nombre, version) not in seen:
                out.append((nombre, version))
                seen.add((nombre, version))
            _legacy((info or {}).get("dependencies") if isinstance(info, dict) else None)

    _legacy(data.get("dependencies"))
    return out


def _parse_yarn_lock(texto: str):
    """yarn.lock v1 por bloques: cabeceras `name@rango, name@rango2:` → `version "X"`."""
    out, claves = [], []
    for linea in texto.splitlines():
        if linea and not linea.startswith((" ", "#")):
            claves = []
            if linea.rstrip().endswith(":"):
                for token in linea.rstrip()[:-1].split(", "):
                    km = re.match(r"^(.+)@(v?\d[^\s]*)$|^(.+)@(\^[^\s]+|~[^\s]+)$", token.strip().strip('"'))
                    if km:
                        nombre = km.group(1) or km.group(3)
                        claves.append(nombre)
        elif claves:
            m = re.match(r"^\s+version\s+[\"']([^\"']+)[\"']\s*$", linea)
            if m:
                for nombre in claves:
                    par = (nombre, m.group(1))
                    if par not in out:
                        out.append(par)
                claves = []
    return out


def _parse_poetry_lock(texto: str):
    try:
        data = tomllib.loads(texto)
    except Exception:
        return []
    out, seen = [], set()
    for paquete in data.get("package") or []:
        par = (paquete.get("name"), paquete.get("version"))
        if par[0] and par[1] and par not in seen:
            out.append(par)
            seen.add(par)
    return out


def _parse_uv_lock(texto: str):
    try:
        data = tomllib.loads(texto)
    except Exception:
        return []
    out, seen = [], set()
    for paquete in data.get("package") or []:
        fuente = paquete.get("source") or {}
        if fuente.get("virtual") or fuente.get("editable"):
            continue  # el propio proyecto, no una dependencia resuelta
        par = (paquete.get("name"), paquete.get("version"))
        if par[0] and par[1] and par not in seen:
            out.append(par)
            seen.add(par)
    return out


def parse_manifiesto(nombre: str, ruta: str):
    """Devuelve [(ecosistema, paquete, versión)] de un manifiesto o lockfile (sin red)."""
    ecosistema, parser = _CONOCIDOS.get(nombre, (None, None))
    if not parser:
        return []
    try:
        with open(ruta, encoding="utf-8", errors="ignore") as f:
            texto = f.read()
    except OSError:
        return []
    return [(ecosistema, p, v) for p, v in globals()[parser](texto)]


def _parse_vulns(vulns) -> list:
    """Normaliza la lista de vulns OSV (igual en /query y en /querybatch)."""
    out = []
    for vuln in vulns or []:
        aliases = [a for a in vuln.get("aliases") or [] if a.startswith("CVE-")]
        db_specific = vuln.get("database_specific") or {}
        sev = str(db_specific.get("severity") or "").upper()
        out.append({
            "cve_id": aliases[0] if aliases else vuln.get("id", ""),
            "osv_id": vuln.get("id", ""),
            "resumen": (vuln.get("summary") or "")[:200],
            "cvss": _SEVERIDAD_PROXY.get(sev, 0.0),
            "url": f"https://osv.dev/vulnerability/{vuln.get('id', '')}",
        })
    return out


def consultar_osv(ecosistema: str, paquete: str, version: str, timeout=15):
    """Vulnerabilidades OSV de (ecosistema, paquete, versión); caché TTL 24 h.

    Cada hallazgo: {"cve_id", "osv_id", "resumen", "cvss", "url"}. cvss es un PROXY por
    severidad declarada (LOW..CRITICAL → 2..9.5) cuando OSV no da puntuación numérica.
    Fallo de red: lista vacía SIN cachear (ley 11).
    """
    clave = f"osv:{ecosistema}:{paquete}:{version}"
    fresco = store.get_fresh(clave, 24 * 3600)
    if fresco is not None:
        return fresco
    out = []
    try:
        r = requests.post(OSV_QUERY_URL, json={"package": {"name": paquete, "ecosystem": ecosistema},
                                               "version": version}, timeout=timeout)
        r.raise_for_status()
        out = _parse_vulns(r.json().get("vulns"))
        store.put(clave, out)
    except Exception:
        pass  # sin red: nada, y no se cachea el vacío
    return out


def consultar_osv_batch(pares, chunk=100, timeout=20):
    """Consulta OSV en LOTES (INT-004): /v1/querybatch para árboles grandes.

    pares: [(ecosistema, paquete, versión), ...]. Devuelve {(eco, pkg, ver): [hallazgo, ...]}
    sirviendo primero de caché; los fallos del lote caen a la consulta individual
    (que cachea lo válido y no cachea los fallos, ley 11).
    """
    resultados = {}
    pendientes = []
    for par in dict.fromkeys(tuple(p) for p in (pares or [])):  # dedup preservando orden
        fresco = store.get_fresh(f"osv:{par[0]}:{par[1]}:{par[2]}", 24 * 3600)
        if fresco is not None:
            resultados[par] = fresco
        else:
            pendientes.append(tuple(par))

    for i in range(0, len(pendientes), chunk):
        bloque = pendientes[i:i + chunk]
        try:
            r = requests.post(OSV_QUERYBATCH_URL, json={"queries": [
                {"package": {"name": pkg, "ecosystem": eco}, "version": ver}
                for eco, pkg, ver in bloque
            ]}, timeout=timeout)
            r.raise_for_status()
            resultados_batch = r.json().get("results") or []
            for (eco, pkg, ver), res in zip(bloque, resultados_batch):
                out = _parse_vulns(res.get("vulns"))
                resultados[(eco, pkg, ver)] = out
                store.put(f"osv:{eco}:{pkg}:{ver}", out)
        except Exception:
            for eco, pkg, ver in bloque:  # fallback: consulta individual
                resultados[(eco, pkg, ver)] = consultar_osv(eco, pkg, ver, timeout=timeout)
    return resultados
