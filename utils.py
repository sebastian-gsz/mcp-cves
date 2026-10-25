import re

from tabulate import tabulate

# extrae software/versión de banners tipo: "Apache httpd/2.4.41", "nginx/1.18.0", "OpenSSH/8.2p1"
BANNER_REGEX = re.compile(r"([\w\-\.\+]+)[/ ](\d+(?:\.\d+)*(?:[a-z]\d+)?)", re.IGNORECASE)
# palabras muy genericas que no se quieren usar como "producto"
_GENERIC_TOKENS = {"db", "server", "service", "daemon", "http", "https"}
# pistas para normalizar si el token hallado es generico (o si conviene priorizar)
_HINTS = [
    (re.compile(r"\bpostgresql\b|\bpostgres\b", re.IGNORECASE), "PostgreSQL"),(re.compile(r"\bapache\b.*\bhttpd?\b|\bhttpd\b", re.IGNORECASE), "httpd"),
    (re.compile(r"\bnginx\b", re.IGNORECASE), "nginx"),(re.compile(r"\bopenssh\b", re.IGNORECASE), "OpenSSH"),
    (re.compile(r"\bsamba\b|\bsmbd\b", re.IGNORECASE), "samba"),(re.compile(r"\bmysql\b", re.IGNORECASE), "mysql"),
    (re.compile(r"\bmariadb\b", re.IGNORECASE), "mariadb"),(re.compile(r"\bopenvpn\b", re.IGNORECASE), "OpenVPN"),
    (re.compile(r"\bvsftpd\b", re.IGNORECASE), "vsftpd"),(re.compile(r"\bproftpd\b", re.IGNORECASE), "ProFTPD"),
]

# límite defensivo ante banners hostiles antes de aplicar regex (SEG-001, ley 12 del mapa maestro)
BANNER_MAX_LEN = 500


def parse_software_version_from_banner(banner: str):
    if not banner:
        return None, None
    banner = banner[:BANNER_MAX_LEN]
    # Candidatos (token, versión) en todo el banner
    candidates = list(BANNER_REGEX.finditer(banner))
    if not candidates:
        return None, None
    # 1) si hay pistas fuertes en el banner, se usan
    picked_name = None
    for rx, canonical in _HINTS:
        if rx.search(banner or ""):
            picked_name = canonical
            break
    # 2) elige el primer candidato cuyo token no sea genérico
    for m in candidates:
        sw = m.group(1)
        ver = m.group(2)
        if sw and sw.lower() not in _GENERIC_TOKENS:
            # si habia pista fuerte (p.ej. PostgreSQL) y diffiere, usa la pista
            if picked_name:
                return picked_name, ver
            return sw, ver
    # 3) si todos eran genericos, usa el primero pero intenta mejorar con pista
    sw = candidates[0].group(1)
    ver = candidates[0].group(2)
    if picked_name:
        return picked_name, ver
    return sw, ver


def nice_print_table(rows, headers):
    if not rows:
        print("(sin datos)")
        return
    print(tabulate(rows, headers=headers, tablefmt="github"))