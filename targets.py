# targets.py — validación de objetivos de escaneo (SEG-002, hallazgo H3 de la auditoría).
# Frontera de seguridad: nada que no sea IP/CIDR explícito llega a nmap ni a scapy.
# Los nombres de host NO se aceptan (para escanear "localhost", usa 127.0.0.1): una cadena
# cualquiera en la línea de comandos de nmap podría interpretarse como flag.
import ipaddress


def es_ip(texto: str) -> bool:
    try:
        ipaddress.ip_address((texto or "").strip())
        return True
    except ValueError:
        return False


def es_cidr(texto: str) -> bool:
    try:
        ipaddress.ip_network((texto or "").strip(), strict=False)
        return True
    except ValueError:
        return False


def filtrar_objetivos(objetivos):
    """Devuelve (validos, rechazados) como listas de strings.

    Solo IPs explícitas (IPv4/IPv6); la validación de CIDRs es aparte (es_cidr),
    porque un CIDR no es un host escaneable directo.
    """
    validos, rechazados = [], []
    for o in objetivos or []:
        t = (o or "").strip()
        if t and es_ip(t):
            validos.append(t)
        else:
            rechazados.append(t)
    return validos, rechazados


def ip_en_whitelist(ip: str, cidrs) -> bool:
    """¿La IP cae dentro de alguna de las redes de la whitelist? (SEG-002/MCP-001)"""
    try:
        addr = ipaddress.ip_address((ip or "").strip())
    except ValueError:
        return False
    for c in cidrs or []:
        try:
            net = ipaddress.ip_network(c.strip(), strict=False)
        except (ValueError, AttributeError):
            continue
        if addr.version == net.version and addr in net:
            return True
    return False


def cidr_en_whitelist(cidr: str, cidrs) -> bool:
    """¿El CIDR pedido es subred de alguna red autorizada? (para discovery MCP-001)"""
    try:
        req = ipaddress.ip_network((cidr or "").strip(), strict=False)
    except ValueError:
        return False
    for c in cidrs or []:
        try:
            net = ipaddress.ip_network(c.strip(), strict=False)
        except (ValueError, AttributeError):
            continue
        if req.version == net.version and req.subnet_of(net):
            return True
    return False
