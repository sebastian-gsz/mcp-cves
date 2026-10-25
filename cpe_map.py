# cpe_map.py — resolución sencilla de CPE base por producto/banner

import re

# Mapa de productos habituales -> CPE base (sin versión)
# Formato base: cpe:2.3:a:<vendor>:<product>
CPE_BASES = {
    # Web servers / proxies
    "httpd": ["cpe:2.3:a:apache:http_server"],
    "apache http server": ["cpe:2.3:a:apache:http_server"],
    "apache2": ["cpe:2.3:a:apache:http_server"],
    "nginx": ["cpe:2.3:a:f5:nginx"],
    "lighttpd": ["cpe:2.3:a:lighttpd:lighttpd"],
    "iis": ["cpe:2.3:a:microsoft:internet_information_services"],
    "haproxy": ["cpe:2.3:a:haproxy:haproxy"],
    "squid": ["cpe:2.3:a:squid-cache:squid"],
    "varnish": ["cpe:2.3:a:varnish-cache:varnish_cache"],
    "traefik": ["cpe:2.3:a:traefik:traefik"],

    # App servers
    "tomcat": ["cpe:2.3:a:apache:tomcat"],
    "jetty": ["cpe:2.3:a:eclipse:jetty"],

    # Bases de datos
    "postgresql": ["cpe:2.3:a:postgresql:postgresql"],
    "postgres": ["cpe:2.3:a:postgresql:postgresql"],
    "mysql": ["cpe:2.3:a:oracle:mysql"],
    "mariadb": ["cpe:2.3:a:mariadb:mariadb"],
    "mssql": ["cpe:2.3:a:microsoft:sql_server"],
    "sql server": ["cpe:2.3:a:microsoft:sql_server"],
    "oracle database": ["cpe:2.3:a:oracle:database"],
    "sqlite": ["cpe:2.3:a:sqlite:sqlite"],
    "mongodb": ["cpe:2.3:a:mongodb:mongodb"],
    "redis": ["cpe:2.3:a:redislabs:redis"],
    "couchdb": ["cpe:2.3:a:apache:couchdb"],
    "elasticsearch": ["cpe:2.3:a:elastic:elasticsearch"],
    "kibana": ["cpe:2.3:a:elastic:kibana"],
    "logstash": ["cpe:2.3:a:elastic:logstash"],

    # Lenguajes / runtimes / libs
    "php": ["cpe:2.3:a:php:php"],
    "openssl": ["cpe:2.3:a:openssl:openssl"],
    "gnutls": ["cpe:2.3:a:gnutls:gnutls"],
    "libssh": ["cpe:2.3:a:libssh:libssh"],
    "libxml2": ["cpe:2.3:a:xmlsoft:libxml2"],
    "openjdk": ["cpe:2.3:a:openjdk:openjdk"],
    "oracle jre": ["cpe:2.3:a:oracle:jre"],
    "oracle jdk": ["cpe:2.3:a:oracle:jdk"],

    # SSH / SMB / VPN
    "openssh": ["cpe:2.3:a:openbsd:openssh"],
    "dropbear": ["cpe:2.3:a:matt_johnston:dropbear_ssh"],
    "samba": ["cpe:2.3:a:samba:samba"],
    "smbd": ["cpe:2.3:a:samba:samba"],
    "openvpn": ["cpe:2.3:a:openvpn:openvpn"],

    # FTP servers
    "vsftpd": ["cpe:2.3:a:vsftpd:vsftpd"],
    "proftpd": ["cpe:2.3:a:proftpd:proftpd"],
    "pure-ftpd": ["cpe:2.3:a:pureftpd:pure-ftpd"],
    "filezilla server": ["cpe:2.3:a:filezilla_project:filezilla_server"],

    # Mail
    "postfix": ["cpe:2.3:a:postfix:postfix"],
    "exim": ["cpe:2.3:a:exim:exim"],
    "dovecot": ["cpe:2.3:a:dovecot:dovecot"],
    "sendmail": ["cpe:2.3:a:sendmail:sendmail"],

    # Mensajería / colas
    "rabbitmq": ["cpe:2.3:a:pivotal_software:rabbitmq"],
    "activemq": ["cpe:2.3:a:apache:activemq"],

    # Monitoring / devops
    "grafana": ["cpe:2.3:a:grafana_labs:grafana"],
    "prometheus": ["cpe:2.3:a:prometheus:prometheus"],
    "docker": ["cpe:2.3:a:docker:docker"],
    "containerd": ["cpe:2.3:a:containerd:containerd"],
}

def _norm(s: str) -> str:
    return (s or "").strip().lower()

_HINTS = [
    # Web
    (re.compile(r"\bapache\b.*\bhttpd?\b|\bhttpd\b", re.IGNORECASE), "httpd"),
    (re.compile(r"\bnginx\b", re.IGNORECASE), "nginx"),
    (re.compile(r"\blighttpd\b", re.IGNORECASE), "lighttpd"),
    (re.compile(r"\biis\b|\binternet information services\b", re.IGNORECASE), "iis"),
    (re.compile(r"\bhaproxy\b", re.IGNORECASE), "haproxy"),
    (re.compile(r"\bsquid\b", re.IGNORECASE), "squid"),
    (re.compile(r"\bvarnish\b", re.IGNORECASE), "varnish"),
    (re.compile(r"\btraefik\b", re.IGNORECASE), "traefik"),
    (re.compile(r"\btomcat\b", re.IGNORECASE), "tomcat"),
    (re.compile(r"\bjetty\b", re.IGNORECASE), "jetty"),

    # DB
    (re.compile(r"\bpostgresql\b|\bpostgres\b", re.IGNORECASE), "postgresql"),
    (re.compile(r"\bmariadb\b", re.IGNORECASE), "mariadb"),
    (re.compile(r"\bmysql\b", re.IGNORECASE), "mysql"),
    (re.compile(r"\bmssql\b|\bsql server\b", re.IGNORECASE), "sql server"),
    (re.compile(r"\boracle\b.*\bdatabase\b", re.IGNORECASE), "oracle database"),
    (re.compile(r"\bsqlite\b", re.IGNORECASE), "sqlite"),
    (re.compile(r"\bmongodb\b", re.IGNORECASE), "mongodb"),
    (re.compile(r"\bredis\b", re.IGNORECASE), "redis"),
    (re.compile(r"\bcouchdb\b", re.IGNORECASE), "couchdb"),
    (re.compile(r"\belasticsearch\b", re.IGNORECASE), "elasticsearch"),
    (re.compile(r"\bkibana\b", re.IGNORECASE), "kibana"),
    (re.compile(r"\blogstash\b", re.IGNORECASE), "logstash"),

    # Runtimes / libs
    (re.compile(r"\bphp\b", re.IGNORECASE), "php"),
    (re.compile(r"\bopenssl\b", re.IGNORECASE), "openssl"),
    (re.compile(r"\bgnutls\b", re.IGNORECASE), "gnutls"),
    (re.compile(r"\blibssh\b", re.IGNORECASE), "libssh"),
    (re.compile(r"\blibxml2\b", re.IGNORECASE), "libxml2"),
    (re.compile(r"\bopenjdk\b", re.IGNORECASE), "openjdk"),
    (re.compile(r"\boracle\b.*\bjre\b", re.IGNORECASE), "oracle jre"),
    (re.compile(r"\boracle\b.*\bjdk\b", re.IGNORECASE), "oracle jdk"),

    # SSH / SMB / VPN
    (re.compile(r"\bopenssh\b", re.IGNORECASE), "openssh"),
    (re.compile(r"\bdropbear\b", re.IGNORECASE), "dropbear"),
    (re.compile(r"\bsamba\b|\bsmbd\b", re.IGNORECASE), "samba"),
    (re.compile(r"\bopenvpn\b", re.IGNORECASE), "openvpn"),

    # FTP
    (re.compile(r"\bvsftpd\b", re.IGNORECASE), "vsftpd"),
    (re.compile(r"\bproftpd\b", re.IGNORECASE), "proftpd"),
    (re.compile(r"\bpure[-_ ]?ftpd\b", re.IGNORECASE), "pure-ftpd"),
    (re.compile(r"\bfilezilla\b.*\bserver\b", re.IGNORECASE), "filezilla server"),

    # Mail
    (re.compile(r"\bpostfix\b", re.IGNORECASE), "postfix"),
    (re.compile(r"\bexim\b", re.IGNORECASE), "exim"),
    (re.compile(r"\bdovecot\b", re.IGNORECASE), "dovecot"),
    (re.compile(r"\bsendmail\b", re.IGNORECASE), "sendmail"),

    # Mensajería / devops
    (re.compile(r"\brabbitmq\b", re.IGNORECASE), "rabbitmq"),
    (re.compile(r"\bactivemq\b", re.IGNORECASE), "activemq"),
    (re.compile(r"\bgrafana\b", re.IGNORECASE), "grafana"),
    (re.compile(r"\bprometheus\b", re.IGNORECASE), "prometheus"),
    (re.compile(r"\bdocker\b", re.IGNORECASE), "docker"),
    (re.compile(r"\bcontainerd\b", re.IGNORECASE), "containerd"),
]

def resolve_cpe_bases(software: str, banner: str = "") -> list[str]:
    #devuelve una lista de CPE base candidatos (sin version) para un software.
    #primero usa pistas del banner, luego el nombre normalizado.
    #los dos campos provienen de la red y se truncan antes de regex (SEG-001, ley 12)
    sw = _norm(software)[:500]
    b = (banner or "")[:500]

    for rx, canonical in _HINTS:
        if rx.search(b) or rx.search(software or ""):
            bases = CPE_BASES.get(canonical)
            if bases:
                return bases
    bases = CPE_BASES.get(sw)
    if bases:
        return bases
    if sw in ("apache", "apache2"):
        return CPE_BASES["httpd"]

    return []
