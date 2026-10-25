# scanner.py
from __future__ import annotations

import nmap


def nmap_discover_hosts(cidr: str, debug: bool = False, host_timeout_ms: int = 25000) -> list[str]:
    nm = nmap.PortScanner()
    args = f"-sn -T4 --max-retries 1 --host-timeout {host_timeout_ms}ms"
    if debug:
        print(f"    [nmap-discover] nmap {cidr} {args}")
    try:
        nm.scan(hosts=cidr, arguments=args)
    except nmap.PortScannerError as e:
        print(f"    [discover][error] {e}")
        return []
    hosts_up = []
    for host in nm.all_hosts():
        try:
            state = nm[host]["status"]["state"]
        except Exception:
            state = "unknown"
        if state == "up":
            hosts_up.append(host)
    if debug:
        print(f"    [nmap-discover] {len(hosts_up)} host(s) up")
    return hosts_up


def _banner_from_service(svc: dict) -> str:
    product = svc.get("product") or ""
    version = svc.get("version") or ""
    extrainfo = svc.get("extrainfo") or ""
    name = svc.get("name") or ""
    parts = []
    if product:
        parts.append(product)
    if version:
        parts.append(version)
    if extrainfo:
        parts.append(extrainfo)
    if parts:
        return " ".join(parts).strip()
    hint = extrainfo or svc.get("servicefp") or ""
    if name and hint:
        return f"{name} (unknown banner: {hint})"
    return name or "unknown"


def nmap_scan_host(
    host: str,
    ports: str,
    debug: bool = False,
    host_timeout_ms: int = 60000,
) -> dict:
    """ 
        {  
        "os": <str>,
        "ports": [ { "port": <int>, "proto": "tcp|udp", "service": <str>, "banner": <str> } ]  
        }
    """
    nm = nmap.PortScanner()
    args = f"-Pn -sT -sV -T4 --max-retries 1 --host-timeout {host_timeout_ms}ms -p {ports}"
    # La opción -sU, para escanear UDP, se ha quitado por limitaciones de tiempo y fiabilidad. Se puede añadir y optimizar en un futuro
    if debug:
        print(f"    [nmap-scan] nmap {host} {args}")
    try:
        nm.scan(hosts=host, arguments=args)
    except nmap.PortScannerError as e:
        print(f"    [scan][error] {e}")
        return {}

    if host not in nm.all_hosts():
        if debug:
            print(f"    [nmap-scan] host {host} no presente en resultados")
        return {}
    ports_out: list[dict] = []
    for proto in ("tcp", "udp"):
        if proto not in nm[host]:
            continue
        try:
            port_dict = nm[host][proto]  # dict: {port_int: {...}}
            for p, data in port_dict.items():
                state = data.get("state") or ""
                if state != "open":
                    continue
                service_name = data.get("name") or ""
                banner = _banner_from_service({
                    "name": data.get("name"),
                    "product": data.get("product"),
                    "version": data.get("version"),
                    "extrainfo": data.get("extrainfo"),
                    "servicefp": data.get("servicefp"),
                })
                ports_out.append({
                    "port": int(p),"proto": proto,"service": service_name,"banner": banner,
                })
        except Exception as e:
            if debug:
                print(f"    [nmap-scan][warn] error procesando {host}/{proto}: {e}")

    if debug:
        print(f"    [nmap-scan] {host}: {len(ports_out)} puerto(s) abiertos")
    return {"ports": ports_out}


def nmap_scan_os(
    host: str,
    debug: bool = False,
    host_timeout_ms: int = 60000,
) -> str:
    nm = nmap.PortScanner()
    args = f"-Pn -O --osscan-limit -T4 --max-retries 1 --host-timeout {host_timeout_ms}ms"
    if debug:
        print(f"    [nmap-os] nmap {host} {args}")
    try:
        nm.scan(hosts=host, arguments=args)
    except nmap.PortScannerError as e:
        if debug:
            print(f"    [nmap-os][error] {e}")
        return "No detectado"
    except Exception as e:
        if debug:
            print(f"    [nmap-os][error] {e}")
        return "No detectado"

    if host not in nm.all_hosts():
        if debug:
            print(f"    [nmap-os] host {host} no presente en resultados")
        return "No detectado"

    # OS (si está disponible)
    try:
        osmatches = nm[host].get("osmatch") or []
        if osmatches:
            return osmatches[0].get("name") or "No detectado"
    except Exception:
        pass
    return "No detectado"
