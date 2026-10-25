# discovery_arp.py Descubrimiento L2 con ARP usando Scapy

from scapy.all import ARP, Ether, conf, srp


def discover_hosts_arp(cidr: str, iface: str | None = None, timeout: int = 2, retry: int = 1) -> list[str]:
    conf.verb = 0
    # Trama Ethernet broadcast + ARP who-has pdst=cidr
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=cidr)
    try:
        ans, _ = srp(pkt, timeout=timeout, retry=retry, iface=iface)
    except PermissionError:
        print("[!] Permiso denegado enviando ARP. Use sudo o setcap.")
        return []
    except Exception as e:
        print(f"[!] Error en ARP discovery: {e}")
        return []
    vivos: list[str] = []
    for _, rcv in ans:
        ip = rcv.psrc
        if ip and ip not in vivos:
            vivos.append(ip)
    return vivos

