# cve_scanner.py: CAPA CLI del escáner. El pipeline completo vive en nucleo.py (NUC-003):
# esta capa solo pregunta objetivos/puertos, orquesta el núcleo y presenta/exporta resultados.
import os
import sys

from dotenv import load_dotenv

import nucleo
import ports
import targets
from utils import nice_print_table


def _pedir_objetivos():
    print("=== Definición de objetivos ===")
    modo = input("¿Qué quieres escanear? 1) Rango CIDR  2) IP única  3) Lista separada por comas [Enter=1]: ").strip() or "1"

    if modo == "1":
        cidr = input("Rango CIDR (p.ej. 192.168.1.0/24): ").strip()
        print(f"\n[*] Descubriendo hosts por ARP en {cidr}...")
        objetivos = nucleo.descubrir_hosts(cidr)
        if not objetivos:
            print("[!] No se detectaron hosts activos.")
        else:
            print(f"[*] Descubiertos {len(objetivos)} host(s): {', '.join(objetivos)}")
        return objetivos

    if modo == "2":
        ip = input("IP: ").strip()
        if not ip or not targets.es_ip(ip):
            print("[!] IP no válida.")
            return []
        return [ip]

    if modo == "3":
        lista = input("IPs separadas por comas: ").strip()
        candidatos = [ip.strip() for ip in lista.split(",") if ip.strip()]
        validos, rechazados = targets.filtrar_objetivos(candidatos)
        for r in rechazados:
            print(f"[!] Objetivo rechazado (no es una IP válida): '{r}'")
        if not validos:
            print("[!] Lista vacía o sin IPs válidas.")
        return validos

    print("[!] Opción inválida.")
    return []


def _pedir_puertos():
    print()
    opcion_p = input(
        "Puertos a escanear -> 1: introducir manualmente (p.ej 1-1000 o 22,80,445) | 2: usar puertos más comunes por defecto: "
    ).strip()

    if opcion_p == "2":
        puertos = ports.load_ports_file("data/puertos_comunes.txt")
        if not puertos:
            print("[!] No se pudieron cargar puertos del fichero. Usa la opción 1 o revisa el archivo.")
        return puertos

    if opcion_p == "1":
        puertos_raw = input("Introduce puertos (formato nmap, p.ej. '1-1000' o '22,80,443'): ").strip()
        return ports.parse_ports_input(puertos_raw)

    return ports.parse_ports_input(opcion_p)


def main():
    load_dotenv()  # Carga .env

    print(r"""
    ██████╗ ██╗     ██╗███████╗      ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗ 
    ██╔═══   █║     █║ ██╔════╝      ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
    ██║      ██║   ██║ █████╗        ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
    ██║       █║  █║   ██╔══╝        ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
    ╚██████╔╝╚  ██ ╔╝  ███████╗      ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
    ╚═════╝    ╚══╝    ╚══════╝      ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
    """)

    print(" | Vulnerability & CVE Scanner |   · Discovery  · Scan  · Enrichment  · NVD  · EPSS  · KEV Integration\n\n\n")

    # 1) Objetivos
    objetivos = _pedir_objetivos()
    if not objetivos:
        return

    # 2) Puertos
    puertos = _pedir_puertos()
    if not puertos:
        print("[!] Entrada de puertos no válida. Usando puertos más comunes por defecto.")
        puertos = ports.load_ports_file("data/puertos_comunes.txt")
        if not puertos:
            return

    # 3) Pipeline completo en el núcleo (escaneo paralelo + CVE + diferencial)
    resumen_hosts, hallazgos, filas_diff = nucleo.escanear(objetivos, puertos)

    # 4) Resultados
    print("\n=== Resumen de puertos detectados ===")
    filas = []
    for r in resumen_hosts:
        for p in r["ports"]:
            filas.append([r["host"], r["os"], f'{p["port"]}/{p["proto"]}', p.get("banner") or ""])
    nice_print_table(filas, headers=["Host", "SO (si se intentó)", "Puerto", "Banner"])

    print("\n=== Diferencial de inventario (vs. escaneo anterior) ===")
    nice_print_table(filas_diff, headers=["Host", "Estado", "Servicio", "Banner"])

    csv_path, pdf_ok = nucleo.generar_informes(hallazgos)
    print(f"[*] CSV: {csv_path}")
    if pdf_ok:
        print("[*] Exportado PDF -> outputs/informe_escaneo.pdf")

    if hallazgos:
        top = sorted(hallazgos, key=lambda x: x["score"], reverse=True)[:10]
        print("\n=== Top 10 vulnerabilidades por score ===")
        filas = []
        for h in top:
            filas.append([h["host"], f'{h["port"]}/{h["proto"]}', h["cve_id"], f'{h["cvss"]:.1f}',
                          "Sí" if h["kev"] else "No", f'{h["epss"]:.3f}', f'{h["score"]:.1f}'])
        nice_print_table(filas, headers=["Host", "Puerto", "CVE", "CVSS", "KEV", "EPSS", "Score"])

    print("\n¡Listo!\n")


if __name__ == "__main__":
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    main()
