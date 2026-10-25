# nucleo.py — núcleo importable del escáner: pipeline completo sin interacción (NUC-003).
# La CLI (cve_scanner.py) es una capa fina sobre estas funciones; el futuro servidor MCP
# las usará como fachadas. Los módulos que dependen de binarios del sistema (nmap/scapy)
# se importan de forma perezosa para que el núcleo sea importable sin ellos.
import os
from concurrent.futures import ThreadPoolExecutor, as_completed

import config
import diferencial
import export_csv_pdf
import intel_epss
import intel_exploit
import intel_kev
import intel_nvd
import intel_osv
import intel_psirt
import scoring
import store
import targets


def descubrir_hosts(cidr: str, debug: bool = False):
    """Hosts vivos en el CIDR: ARP primero, fallback a nmap -sn."""
    if not targets.es_cidr(cidr):
        print(f"[!] CIDR no válido: '{cidr}' (se esperaba p. ej. 192.168.1.0/24).")
        return []

    import discovery_arp  # perezoso: scapy
    import scanner  # perezoso: python-nmap

    hosts = discovery_arp.discover_hosts_arp(cidr)
    if not hosts:
        print("[!] ARP no encontró hosts o faltan privilegios. Probando Nmap -sn.")
        hosts = scanner.nmap_discover_hosts(cidr, debug=debug)
    return hosts


def _count_ports(pstr: str) -> int:
    """Cuenta el total de puertos de una cadena en formato nmap ('22,80' o '1-1000')."""
    total = 0
    for tok in (pstr or "").split(","):
        tok = tok.strip()
        if not tok:
            continue
        if "-" in tok:
            try:
                a, b = tok.split("-", 1)
                a, b = int(a), int(b)
                if 1 <= a <= b <= 65535:
                    total += (b - a + 1)
            except Exception:
                pass
        elif tok.isdigit():
            v = int(tok)
            if 1 <= v <= 65535:
                total += 1
    return total


def _host_timeout_for_ports(n_ports: int) -> int:
    if n_ports <= 30:
        return 60000          # 60s
    if n_ports <= 200:
        return 180000         # 180s
    return 300000             # 300s para listas grandes


def _escanear_host(host, puertos, kev_set, debug):
    """Escanea un host completo y devuelve (os, ports, hallazgos) o None si no hay puertos.

    Corre en un hilo del pool de hosts; las búsquedas CVE de sus servicios corren a su vez
    en paralelo (search_cves_for_services) bajo el token bucket global de NVD.
    """
    import scanner  # perezoso: python-nmap

    os_name = scanner.nmap_scan_os(host, debug=debug, host_timeout_ms=45000)
    scan = scanner.nmap_scan_host(host, puertos, debug=debug,
                                  host_timeout_ms=_host_timeout_for_ports(_count_ports(puertos)))
    if not scan or not scan.get("ports"):
        return None
    cves_por_servicio = intel_nvd.search_cves_for_services(scan["ports"], max_workers=4)
    cve_ids = sorted({c["cve_id"] for cves in cves_por_servicio.values() for c in cves})
    epss_map = intel_epss.get_epss_for_cves(cve_ids) if cve_ids else {}
    armas_map = intel_exploit.armas_para_cves(cve_ids) if cve_ids else {}  # INT-001
    psirt_map = intel_psirt.para_cves(cve_ids) if cve_ids else {}  # INT-003
    hallazgos = []
    for p in scan["ports"]:
        for c in cves_por_servicio.get((p["port"], p["proto"]), []):
            cve_id = c["cve_id"]
            cvss = c.get("cvss", 0.0) or 0.0
            kev = cve_id in kev_set
            epss_val = epss_map.get(cve_id, {}).get("epss", 0.0)
            arma = armas_map.get(cve_id, {}).get("tiene_arma", False)
            psirt = intel_psirt.resumen_con_gap(psirt_map.get(cve_id, {}), c.get("published", ""))
            hallazgos.append({
                "host": host, "os": os_name, "port": p["port"], "proto": p["proto"],
                "banner": p["banner"], "software": p.get("software", ""), "version": p.get("version", ""),
                "cve_id": cve_id, "severity": c.get("severity", "") or "", "cvss": cvss, "kev": kev,
                "epss": epss_val,
                "score": scoring.compute_score(cvss=cvss, kev=kev, epss=epss_val, arma=arma),
                "arma_publica": arma,
                "arma_detalle": armas_map.get(cve_id, {}).get("resumen", ""),
                "psirt": psirt,
                "description": c.get("description", "")[:220],
            })
    return os_name, scan["ports"], hallazgos


def escanear(objetivos, puertos, debug=None, max_workers=None):
    """Pipeline completo: escaneo en paralelo, correlación CVE y diferencial.

    Devuelve (resumen_hosts, hallazgos, filas_diferencial): cada puerto del resumen y cada
    hallazgo llevan 'estado_diferencial' (NUEVO/CERRADO/PERSISTENTE) respecto al escaneo
    anterior del mismo host. Las filas del diferencial incluyen también los servicios CERRADOS.
    max_workers: tamaño del pool de hosts (por defecto config.host_workers(), env NUC_HOST_WORKERS).
    """
    if debug is None:
        debug = config.debug_enabled()
    if max_workers is None:
        max_workers = config.host_workers()

    # Frontera de validación (SEG-002/H3): solo IPs explícitas llegan a nmap.
    objetivos_validos, rechazados = targets.filtrar_objetivos(objetivos)
    for r in rechazados:
        print(f"[!] Objetivo rechazado (no es una IP válida): '{r}'")
    if not objetivos_validos:
        print("[!] Ningún objetivo válido: se requiere IP explícita (los nombres de host no se aceptan).")
        return [], [], []

    objetivos = objetivos_validos
    print("\n[*] Iniciando escaneo de hosts en paralelo...\n")
    hallazgos = []
    kev_set = intel_kev.load_kev_set()  # cache KEV para toda la ejecución
    resumen_hosts = []

    with ThreadPoolExecutor(max_workers=min(max_workers, max(1, len(objetivos)))) as pool:
        futs = {pool.submit(_escanear_host, host, puertos, kev_set, debug): host for host in objetivos}
        for fut in as_completed(futs):
            host = futs[fut]
            try:
                res = fut.result()
            except Exception as e:
                print(f"[!] Error escaneando {host}: {e}")
                continue
            if res is None:
                print(f"[!] Sin resultados de puertos para {host}")
                continue
            os_name, ports_salida, hallazgos_host = res
            print(f"[*] {host} listo: {len(ports_salida)} puerto(s) abierto(s), "
                  f"{len(hallazgos_host)} CVE(s) correlacionados")
            resumen_hosts.append({"host": host, "os": os_name, "ports": ports_salida})
            hallazgos.extend(hallazgos_host)

    # Diferencial de inventario por host (DAT-002): se compara con el escaneo anterior
    # y DESPUÉS se persiste el inventario actual como lote nuevo.
    filas_diff = []
    estados_por_host = {}
    for r in resumen_hosts:
        host = r["host"]
        actual = [
            {"port": p["port"], "proto": p["proto"], "banner": p.get("banner", ""),
             "software": p.get("software", ""), "version": p.get("version", "")}
            for p in r["ports"]
        ]
        anterior = store.load_last_inventory(host)
        diff = diferencial.comparar_inventarios(anterior, actual)
        estados_por_host[host] = {k: v["estado"] for k, v in diff.items()}
        for p in r["ports"]:
            p["estado_diferencial"] = estados_por_host[host].get((p["port"], p["proto"]), "")
        for (port, proto), v in sorted(diff.items()):
            servicio = v["ahora"] or v["antes"] or {}
            filas_diff.append([host, v["estado"], f"{port}/{proto}", servicio.get("banner", "")])
        store.save_inventory(host, actual)
    for h in hallazgos:
        h["estado_diferencial"] = estados_por_host.get(h["host"], {}).get((h["port"], h["proto"]), "")

    return resumen_hosts, hallazgos, filas_diff


def escanear_dependencias(directorio: str):
    """Vector SCA (INT-002/INT-004): manifiestos Y LOCKFILES del directorio → OSV → hallazgos.

    Audita el árbol RESUELTO (transitivos incluidos) vía querybatch; reutiliza KEV y arma
    pública para puntuar (4 factores); los hallazgos llevan vector implícito (host='',
    banner=manifiesto, software=paquete) y exportan con generar_informes().
    """
    manifiestos = intel_osv.detectar_manifiestos(directorio)
    if not manifiestos:
        print(f"[!] Sin manifiestos ni lockfiles conocidos en {directorio} "
              f"(requirements.txt, package.json, go.mod, Cargo.toml, pom.xml, Gemfile, "
              f"pnpm-lock.yaml, package-lock.json, yarn.lock, poetry.lock, uv.lock).")
        return []

    # 1) recolectar pares (ecosistema, paquete, versión) deduplicados del árbol resuelto
    pares = []
    origen = {}  # par -> nombre del primer fichero que lo trajo (para el hallazgo)
    for nombre, ruta in manifiestos:
        for ecosistema, paquete, version in intel_osv.parse_manifiesto(nombre, ruta):
            par = (ecosistema, paquete, version)
            if par not in origen:
                origen[par] = nombre
                pares.append(par)

    # 2) consultar OSV en lotes (querybatch, INT-004)
    resultados = intel_osv.consultar_osv_batch(pares)

    # 3) construir hallazgos con el mismo pipeline de puntuación
    kev_set = intel_kev.load_kev_set()
    cve_ids_pendientes = [v.get("cve_id") for res in resultados.values() for v in res if v.get("cve_id")]
    armas_map = intel_exploit.armas_para_cves(cve_ids_pendientes) if cve_ids_pendientes else {}
    hallazgos = []
    for par, vulns in resultados.items():
        ecosistema, paquete, version = par
        nombre = origen.get(par, "")
        for vuln in vulns:
            cve_id = vuln.get("cve_id", "")
            arma = armas_map.get(cve_id, {}).get("tiene_arma", False)
            kev = cve_id in kev_set
            cvss = vuln.get("cvss", 0.0)
            hallazgos.append({
                "host": "", "os": ecosistema, "port": "", "proto": "",
                "banner": nombre, "software": paquete, "version": version,
                "cve_id": cve_id or vuln.get("osv_id", ""), "severity": "", "cvss": cvss,
                "kev": kev, "epss": 0.0,
                "score": scoring.compute_score(cvss=cvss, kev=kev, epss=0.0, arma=arma),
                "arma_publica": arma, "arma_detalle": armas_map.get(cve_id, {}).get("resumen", ""),
                "estado_diferencial": "",
                "description": f"[{ecosistema}] {vuln.get('resumen', '')} {vuln.get('url', '')}"[:220],
            })
    return hallazgos


def generar_informes(hallazgos, csv_path=None, pdf_path=None):
    """Exporta CSV (siempre) y PDF (si reportlab está disponible). Devuelve (csv_path, pdf_ok)."""
    os.makedirs("outputs", exist_ok=True)
    csv_path = csv_path or os.path.join("outputs", "reporte_vulnerabilidades.csv")
    pdf_path = pdf_path or os.path.join("outputs", "informe_escaneo.pdf")
    export_csv_pdf.export_csv(hallazgos, csv_path)
    pdf_ok = True
    try:
        export_csv_pdf.export_pdf(hallazgos, pdf_path)
    except Exception as e:
        print(f"[!] Error exportando PDF: {e}")
        pdf_ok = False
    return csv_path, pdf_ok
