---
title: ARCHITECTURE.md — Tronco «Escáner de vulnerabilidades» (código en la raíz)
Rol: Responsable técnico del escáner CVE
Objetivo: Regular y documentar el pipeline completo del escáner: descubrimiento, escaneo, enriquecimiento de inteligencia, priorización y exportación.
Nivel: Tronco
Estado: implemented
Padre: docs/ARCHITECTURE.md
Lectura obligatoria: SÍ — antes de inspeccionar o modificar cualquier módulo del escáner.
---

<br>**↑ Padre**: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — mapa maestro, leyes universales y convenciones del proyecto.<br/>

## 1. Alcance y autoridad

Este contrato se aplica exclusivamente a los módulos Python que viven en la **raíz del repositorio**
(`mcp-cves/*.py`), a sus tests (`tests/`) y a sus datos de entrada (`data/`) y salida (`outputs/`). Como el
código del escáner
es plano (sin subdirectorios con lógica propia), este tronco concentra el contrato completo del producto;
los frutos lógicos se delimitan por grupos de módulos dentro del §3.

- **Entradas**: objetivos de escaneo (CIDR / IP / lista, introducidos por el operador), lista de puertos
  (`data/puertos_comunes.txt` o entrada manual), configuración de entorno (`.env`).
- **Proceso**: descubrimiento de hosts (ARP/nmap) → escaneo de OS/puertos/servicios (nmap) → parsing de
  software/versión desde banners → búsqueda de CVEs (NVD, primero por CPE) → enriquecimiento (EPSS, KEV) →
  score ponderado → exportación CSV/PDF.
- **Salidas**: tablas por consola, `outputs/reporte_vulnerabilidades.csv` y `outputs/informe_escaneo.pdf`.

Quedan fuera: la gestión documental (`docs/`), las decisiones de trabajo (Workboard) y las ejecuciones
históricas (bitácoras de `docs/runbooks/`). La infraestructura Docker (INF-001) empaqueta este tronco;
su contrato de despliegue vive en la propia `Dockerfile`/`docker-compose.yml`.

## 2. Cláusulas de comportamiento e implementación

1. Lee este contrato y la cadena superior antes de modificar cualquier módulo.
2. Antes de trabajo operativo, consulta [docs/workboard](docs/workboard/README.md) y cumple su
   protocolo de claim, bloqueo y cierre.
3. Los objetivos de escaneo SIEMPRE provienen del operador (ley 10 del mapa maestro); ninguna función
   amplía por sí misma el alcance de objetivos. Desde SEG-002, además, solo IPs/CIDRs explícitos
   pasan la validación de `targets.py` en la frontera del núcleo (nada que no valide llega a nmap).
4. Las respuestas de NVD/EPSS/KEV y los banners de la red son **entrada no confiable**: se truncan y
   normalizan antes de parsear o renderizar (ley 12).
5. Si una fuente externa falla, el resultado se declara con su antigüedad o su ausencia explícita
   (ley 11); prohibido sustituir fallo por vacío silencioso.
6. Los cambios de comportamiento, símbolos públicos o dependencias requieren actualizar este contrato
   en la misma entrega.
7. No alteres ni relajes contratos superiores; ante conflicto, detén la ejecución y solicita resolución.

## 3. Mapa real de archivos y símbolos (contrastado 2026-10-22)

| Archivo | Responsabilidad comprobada | Símbolos principales |
|---|---|---|
| `cve_scanner.py` | CLI interactiva fina (NUC-003): prompts de objetivos/puertos, presentación de resultados; todo el pipeline delega en `nucleo` | `main()`, `_pedir_objetivos()`, `_pedir_puertos()` |
| `nucleo.py` | Núcleo importable del escáner (NUC-003, base del futuro servidor MCP): descubrimiento, escaneo paralelo, correlación CVE y diferencial, informes, SCA de dependencias con árbol resuelto vía lockfiles y querybatch (INT-002/INT-004). Sin interacción; valida objetivos (SEG-002) antes de tocar nmap; imports perezosos de nmap/scapy | `descubrir_hosts()`, `escanear()`, `_escanear_host()`, `escanear_dependencias()`, `generar_informes()` |
| `mcp_server.py` | Servidor MCP mínimo sobre stdio (MCP-001): JSON-RPC 2.0 puro stdlib, una línea JSON por mensaje. Tools `puntuar`/`buscar_cves`/`armas_publicas`/`advisories` (sin red local), `escanear_dependencias` (fail-closed con whitelist `MCP_DEPS_ROOTS`) y `descubrir_hosts`/`escanear` (fail-closed con `MCP_ALLOWED_CIDRS`); stdout del núcleo redirigido a stderr | `serve()`, `handle()`, `_run_tool()` |
| `config.py` | Helpers de configuración centralizada sin dependencias (ley 5 del mapa maestro) | `debug_enabled()`, `db_path()` |
| `store.py` | Caché local SQLite (tablas `kv` con TTL y `inventario` por lotes): CVEs 72h, EPSS 24h, snapshot KEV con fallback, historial de inventario por host (DAT-001/DAT-002) | `put()`, `get_fresh()`, `get_any()`, `save_inventory()`, `load_last_inventory()` |
| `ratelimit.py` | Token bucket por ventana fija, thread-safe: presupuesto global de peticiones a NVD (NUC-001) | `TokenBucket.acquire()` |
| `diferencial.py` | Comparador puro de inventarios de servicios: NUEVO/CERRADO/PERSISTENTE (DAT-002) | `comparar_inventarios()` |
| `targets.py` | Validación pura de objetivos: solo IPs/CIDRs explícitos (IPv4/IPv6) llegan a nmap/scapy; hostnames rechazados; whitelist para el servidor MCP (SEG-002/MCP-001) | `es_ip()`, `es_cidr()`, `filtrar_objetivos()`, `ip_en_whitelist()`, `cidr_en_whitelist()` |
| `scanner.py` | Escaneo con nmap: descubrimiento (`-sn`), puertos/servicios/banners (`-Pn -sT -sV`), detección de OS (`-O`) | `nmap_discover_hosts()`, `nmap_scan_host()`, `nmap_scan_os()`, `_banner_from_service()` |
| `discovery_arp.py` | Descubrimiento L2 por ARP broadcast con scapy | `discover_hosts_arp()` |
| `ports.py` | Parseo de listas/rangos de puertos y carga de `data/puertos_comunes.txt` | `parse_ports_input()`, `load_ports_file()` |
| `utils.py` | Parsing de software/versión desde banners (regex + pistas; banners truncados a 500 chars, SEG-001) y tablas de consola | `parse_software_version_from_banner()`, `nice_print_table()`, `BANNER_REGEX`, `BANNER_MAX_LEN` |
| `intel_nvd.py` | Cliente de la API NVD 2.0: búsqueda por CPE primero, por keyword como plan B, ficha por ID (`get_cve` para PSIRT/advisories); caché en memoria + disco; ritmo impuesto por token bucket compartido; reintentos con backoff; búsqueda concurrente por servicio (≤4 hilos) | `search_cves_cpe_first()`, `search_cves_for_services()`, `search_cves_by_cpe()`, `search_cves_smart()`, `search_cves_by_product_version()`, `get_cve()`, `_nvd_request()`, `_safe_get()`, `_BUCKET` |
| `cpe_map.py` | Resolución producto/banner → CPE 2.3 base (mapa + pistas regex sobre entradas truncadas, SEG-001) | `resolve_cpe_bases()`, `CPE_BASES`, `_HINTS` |
| `intel_epss.py` | Puntuación EPSS de FIRST, en lotes de 200 CVEs, con caché local 24 h | `get_epss_for_cves()` |
| `intel_exploit.py` | ¿Existe arma pública? (INT-001): snapshot Exploit-DB (GitLab, columna `codes`, marcado Metasploit, TTL 24 h) + índice PoC-in-GitHub por CVE (404=sin PoC, TTL 24 h); degradación elegante | `armas_para_cves()`, `parse_edb_csv()`, `_edb_snapshot()`, `_poc_github()` |
| `intel_osv.py` | Vector SCA (INT-002/INT-004): detección de manifiestos y LOCKFILES (requirements/package.json/go.mod/Cargo/pom/Gemfile + pnpm-lock.yaml, package-lock.json v3/v1, yarn.lock, poetry.lock, uv.lock), parsers puros, consulta OSV individual y en LOTE (/v1/querybatch con chunks y fallback) con TTL 24 h; cvss proxy por severidad declarada | `detectar_manifiestos()`, `parse_manifiesto()`, `consultar_osv()`, `consultar_osv_batch()` |
| `intel_psirt.py` | Advisories de vendor día 0 (INT-003): Red Hat Security Data API y Ubuntu CVE API (ambas sin key, verificadas en vivo), TTL 6 h (su valor es la velocidad); calcula los días que el vendor anticipa a NVD; degradación elegante | `para_cve()`, `para_cves()`, `dias_anticipa()`, `resumen_con_gap()` |
| `intel_kev.py` | Descarga del catálogo KEV de CISA a un conjunto en memoria | `load_kev_set()` |
| `scoring.py` | Score ponderado (INT-001, 4 factores): CVSS 45% + KEV 15% + EPSS 20% + ARMA pública 20% | `compute_score()` |
| `export_csv_pdf.py` | Exportación CSV (neutraliza fórmulas de hoja de cálculo) y PDF (reportlab perezoso, texto escapado XML/latin-1, semáforo de score, columna Estado diferencial) | `export_csv()`, `export_pdf()`, `_clean_text()`, `_csv_safe()`, `_score_color()` |
| `tests/` | Tests unitarios sin red ni disco (unittest stdlib, compatibles con pytest; fixtures NVD/EDB en `tests/fixtures/`) | `test_nuc001.py` … `test_int004.py` (13 ficheros) |
| Infra (`Dockerfile`, `docker-compose.yml`, `.dockerignore`, `requirements.txt` pineado) | Imagen reproducible: usuario no root `scanner`, nmap del sistema, capabilities NET_RAW/NET_ADMIN concedidas al contenedor en ejecución, volúmenes `data/` y `outputs/`, red del host para escanear la LAN (INF-001) | — |

## 4. Grafo funcional aprobado

```text
mcp_server.serve()  (transporte stdio MCP: JSON-RPC línea a línea; MCP-001)
    ↓  handle() → _run_tool()   [escanear/descubrir: fail-closed con whitelist MCP_ALLOWED_CIDRS]
cve_scanner.main()  (CLI fina: prompts + presentación; load_dotenv)
    ↓
nucleo.escanear(objetivos, puertos)   ·   nucleo.descubrir_hosts(cidr)   [NUC-003]
targets.filtrar_objetivos / ip_en_whitelist   [frontera de validación SEG-002/MCP-001]
descubrimiento: discovery_arp.discover_hosts_arp(cidr) ──(fallback)──→ scanner.nmap_discover_hosts(cidr)
    ↓
selección de puertos: ports.load_ports_file("data/puertos_comunes.txt") | ports.parse_ports_input()
    ↓  (por host, pool de ≤8 hilos)
nucleo._escanear_host(host, puertos, kev_set, debug)
scanner.nmap_scan_os(host)  +  scanner.nmap_scan_host(host, puertos)
    ↓  (por servicio, pool de ≤4 hilos bajo token bucket NVD)
intel_nvd.search_cves_for_services(ports)
    ·   utils.parse_software_version_from_banner(banner) → software, version
    ↓   (por servicio)
intel_nvd.search_cves_cpe_first(software, version, banner)
    ├── cpe_map.resolve_cpe_bases()  →  intel_nvd.search_cves_by_cpe()      [plan A: CPE]
    └── intel_nvd.search_cves_smart() → …_by_product_version()             [plan B: keyword]
    ↓
intel_epss.get_epss_for_cves(cve_ids)   ·   intel_kev.load_kev_set()
intel_exploit.armas_para_cves(cve_ids)  [INT-001: arma pública → 4º factor del score]
    ⇅  store.py — caché SQLite local (CVEs TTL 72h, EPSS 24h, KEV/EDB/PoC con fallback; ley 11)
    ↓
scoring.compute_score(cvss, kev, epss)
    ↓
diferencial.comparar_inventarios(anterior, actual)  ·  store.save_inventory(host, actual)   [DAT-002]
    ↓
export_csv_pdf.export_csv(hallazgos, "outputs/reporte_vulnerabilidades.csv")
export_csv_pdf.export_pdf(hallazgos, "outputs/informe_escaneo.pdf")
    ↑  nucleo.generar_informes() los invoca (PDF protegido si falta reportlab)
```

Dependencias aprobadas: los módulos `intel_*` consumen las APIs externas (NVD, FIRST, CISA) y la
caché local `store.py`; el ritmo hacia NVD lo impone `ratelimit.TokenBucket`, compartido por todos
los hilos del proceso;
`cpe_map`, `ports`, `utils` y `scoring` son puros (sin red ni disco); `scanner`/`discovery_arp` son los
únicos que tocan la red local vía nmap/scapy.

## 5. Configuración, datos y resultados

| Parámetro / dato | Fuente | Efecto |
|---|---|---|
| `NVD_API_KEY` | `.env` / entorno | Añade cabecera `apiKey` a NVD y fija el token bucket en 50 req/30 s (sin clave: 5 req/30 s); `BASE_DELAY` (0,35/0,8 s) queda solo para backoffs de reintento |
| `DEBUG` | `.env` / entorno | Opt-in desde NUC-002 (vía `config.debug_enabled()`): solo `1/true/yes/on` (insensible a mayúsculas) activa el modo debug; sin definir o con cualquier otro valor queda **desactivado** |
| `CVESCANNER_DB` | `.env` / entorno | Ruta de la caché SQLite de `store.py` (por defecto `data/cache.sqlite3`); el fichero se crea solo |
| `MCP_ALLOWED_CIDRS` | `.env` / entorno | Whitelist de redes para las tools de escaneo del servidor MCP: lista de CIDRs separada por comas. **Vacía por defecto = fail-closed** (escanear/descubrir_hosts se niegan) |
| `NUC_HOST_WORKERS` | `.env` / entorno | Tamaño del pool de hosts de `nucleo.escanear` (default 8, rango 1-64); `1` = secuencial, para la medición A/B de NUC-001 |
| `MCP_DEPS_ROOTS` | `.env` / entorno | Whitelist de directorios para la tool `escanear_dependencias` del servidor MCP (INT-002). **Vacía por defecto = fail-closed**; rutas resueltas con realpath contra traversal `..` |
| `data/puertos_comunes.txt` | Archivo | 302 puertos para la opción de escaneo por defecto |
| `outputs/` | Generado | `reporte_vulnerabilidades.csv` e `informe_escaneo.pdf` por cada ejecución |

## 6. Validación reproducible

- **Prueba o comando**: `python cve_scanner.py` (CLI interactivo; requiere `nmap` instalado y, para ARP,
  privilegios de red). Módulos puros verificables en aislamiento: `python -c "from scoring import compute_score"`.
- **Superficie cubierta**: flujo completo descrito en §4, contrastado por lectura de los 11 módulos.
- **Límites**: no se ejecutó un escaneo contra red real ni contra las APIs externas durante el
  contraste; la validación es de código, no de ejecución.

## 7. Convenciones y antipatrones locales

- Comportamiento factual conocido (no es backlog; los trabajos correspondientes viven en el Workboard):
  escaneo TCP connect (`-sT`) sin UDP. Desde NUC-001, el ritmo hacia NVD lo impone un token bucket de
  5/30 s sin clave y 50/30 s con clave, compartido por todos los hilos del proceso. Desde DAT-001, la
  caché SQLite sirve copias de NVD/EPSS/KEV y los fallos de red se degradan a la última copia buena
  avisando por consola.
  Desde SEG-001, todo dato proveniente de la red se trunca a 500 caracteres antes de regex, se escapa
  para XML antes del PDF y el CSV neutraliza prefijos de fórmula (`=`, `+`, `-`, `@`). Desde DAT-002,
  cada escaneo persiste el inventario por host (tabla `inventario`, por lotes) y el informe marca cada
  servicio/hallazgo como NUEVO, CERRADO o PERSISTENTE respecto al escaneo anterior. Desde INT-001,
  el score pondera 4 factores (CVSS 45/KEV 15/EPSS 20/arma pública 20) y el informe añade la columna
  Arma (exploit-db/metasploit/PoC GitHub fusionados por CVE). Desde INT-002 existe el vector SCA
  (`nucleo.escanear_dependencias`): manifiestos → OSV con cvss proxy por severidad, puntuado con el
  mismo pipeline y fail-closed por `MCP_DEPS_ROOTS` en el servidor MCP. Desde INT-003, cada hallazgo
  de red lleva la columna `psirt` (severidad Red Hat/Ubuntu + USN + días que el vendor anticipó a NVD)
  y la tool MCP `advisories` expone la ficha completa por CVE. Desde INT-004, el SCA audita el árbol
  RESUELTO leyendo lockfiles (pnpm-lock.yaml, package-lock.json, yarn.lock, poetry.lock, uv.lock —
  transitivos incluidos) y consulta OSV en lotes (/v1/querybatch) con fallback individual.
- Prohibido añadir nuevas llamadas de red fuera de los módulos `intel_*`.
- Prohibido introducir secretos en código, banners exportados o informes.

## 8. Términos y condiciones

1. **Autoridad**: subordinado a `docs/ARCHITECTURE.md` y a la cadena superior.
2. **Estado `implemented`**: el mapa (§3) y el grafo (§4) describen comportamiento existente contrastado
   con la implementación el 2026-10-22, no trabajo futuro.
3. **Propiedad**: el conocimiento específico del escáner permanece aquí; las reglas compartidas, en el
   mapa maestro.
4. **Workboard**: fuente exclusiva del ciclo de trabajo, claims, autorizaciones y evidencia.
5. **Finalización y fallo**: se comunican límites, errores y validaciones fallidas; no se declara éxito
   completo con condiciones de aceptación sin verificar.

---
*Fin del contrato del tronco de código. Sube a [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) para las normas superiores.*
