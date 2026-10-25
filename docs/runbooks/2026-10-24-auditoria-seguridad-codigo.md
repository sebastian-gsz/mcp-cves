---
title: "Auditoría de seguridad del propio código del escáner — mcp-cves"
type: execution-log
document_status: draft
outcome: "SIN código malicioso detectado: 3 destinos de red oficiales (NIST/FIRST/CISA) + escaneo local autorizado; cero ejecución dinámica, cero acceso a rutas sensibles, escrituras confinadas al proyecto. 5 riesgos no maliciosos documentados."
system: "mcp-cves (escáner de vulnerabilidades y CVEs)"
environment: "local (WSL2, análisis estático)"
execution_date: "2026-10-24"
recorded_date: 2026-10-24
version: "post NUC-003 (nucleo.py + CLI fina); 66 tests en verde"
source: "análisis: barridos estáticos sistemáticos + lectura completa de los 16 módulos"
confidence: "directly-verified"
---

# Auditoría de seguridad del propio código — mcp-cves

## Objetivo y alcance

Responder a la pregunta del operador: **¿puede este proyecto (que corre con privilegios y toca la
red) robar datos o dañar el equipo que lo ejecuta?** Se audita TODO el código del repositorio —
los 10 módulos originales (abril 2026) y los 6 añadidos durante la orquestación (config, store,
ratelimit, diferencial, nucleo, tests), con el mismo criterio.

## Fuente y límites de evidencia

- **Verificado directamente**: 5 barridos estáticos sistemáticos (greps con recibo incluido abajo),
  lectura íntegra de los 16 módulos esta semana, análisis de flujo de datos y de la cadena de
  llamadas de red.
- **NO verificado (límites)**: análisis dinámico en ejecución contra red real (no hay nmap/scapy
  aquí); auditoría del bytecode de las dependencias (transitivas) — cubierta en el futuro por
  `pip-audit` en CI (NUC-004) y pineado (INF-001); comportamiento de las libs (requests/scapy/
  python-nmap se dan por confiables en sus versiones oficiales de PyPI).

## Entorno observado

- 16 módulos Python + tests + 1 fichero de datos; ~2.900 líneas totales; sin ficheros ocultos
  ejecutables (solo `.github/workflows/ci.yml`, revisado: instala nmap, corre ruff y pytest).

## Verificación

| Comprobación | Resultado observado | Fuente |
|---|---|---|
| Ejecución dinámica (`eval`, `exec`, `os.system`, `subprocess` directo, `shell=True`, `__import__`, `pickle`, `marshal`, `base64`) | **CERO coincidencias** en todo el repo | grep exacto (sweep 4) |
| Destinos de red saliente | Solo 3: `services.nvd.nist.gov` (NIST), `api.first.org` (FIRST), `www.cisa.gov` (CISA) — dominios oficiales; 4 llamadas `requests.get` en total | sweep 2+8 |
| ¿La API key de NVD viaja a otros hosts? | No: `HEADERS` (con `apiKey`) solo se pasa en `intel_nvd.py:84/255`; la línea 84 es `_safe_get`, cuyo único caller usa `NVD_BASE` (línea 159). EPSS y KEV llaman **sin** headers | sweep 7+11 |
| Lectura de rutas sensibles (`~/.ssh`, `.aws`, navegadores, `/etc/passwd`, historiales) | **CERO coincidencias** | sweep 9 |
| Operaciones de fichero | Lectura: `.env` y `data/puertos_comunes.txt`. Escritura: `outputs/*.csv/pdf` y `data/cache.sqlite3` (vía `CVESCANNER_DB`). **Sin borrados, renombrados ni rmtree** | sweep 5 |
| Variables de entorno leídas | Solo `NVD_API_KEY`, `DEBUG`, `CVESCANNER_DB` (las tres documentadas en el contrato §5) | sweep 6 |
| Secreto comprometido en el repo | Ninguno: no existe `.env` ni claves/PEM | sweep 13 |
| Ofuscación / cadenas codificadas | Ninguna: código legible con comentarios; los únicos `compile(` son `re.compile` (regex de banners) | sweeps 3+4 |
| scapy | Solo `srp()` (enviar/recibir ARP hacia el CIDR indicado); sin `sniff()`, sin envío a hosts arbitrarios | sweep 12 |
| `data/puertos_comunes.txt` | Solo números de puerto y comentarios (0 líneas no numéricas) | sweep 10 |
| Dependencias (typosquatting) | 6 nombres canónicos de PyPI (python-nmap, requests, python-dotenv, tabulate, scapy, reportlab); sin versiones fijadas | sweep 14 |

## Flujo de datos (qué sale de tu máquina)

1. **A NIST/NVD**: consultas CPE y keywords tipo `"nginx 1.18.0"` — revelan el inventario de
   software de tu red a un tercero (ver hallazgo H1). La API key solo viaja aquí (correcto).
2. **A FIRST (EPSS)**: listas de CVEs (ids públicos, sin datos tuyos).
3. **De CISA (KEV)**: solo descarga; no envía nada.
4. **A tu red local**: ARP broadcast al CIDR que TÚ introduces + sondas nmap a los puertos que TÚ
   eliges. No hay objetivos hardcodeados ni generados por el código.
5. **A disco**: inventario de tu red + hallazgos en `data/cache.sqlite3` y `outputs/` (hallazgo H4).

## Hallazgos (riesgos NO maliciosos, con severidad)

| # | Severidad | Hallazgo | Recomendación |
|---|---|---|---|
| H1 | MEDIA (privacidad) | Las búsquedas keyword a NVD revelan tu inventario de software a un servicio externo; es inherente al diseño | Modo "solo CPE" (envía menos contexto) o réplica local de NVD como mejora futura; hoy lo asume el operador |
| H2 | BAJA (supply chain) | 6 dependencias sin versión fijada: un `pip install` futuro podría traer una versión comprometida | Pinear con hashes + `pip-audit` (ya planificado: INF-001 + CI de NUC-004) |
| H3 | BAJA (inyección de flags nmap) | `scanner.py` construye argumentos nmap con el host introducido por el operador; sin shell intermedio (python-nmap usa lista de args), pero un host tipo `-foo` podría interpretarse como flag de nmap | Validar objetivos con `ipaddress`/regex antes de escanear (encaja con la whitelist de la ley 10 para el futuro MCP) |
| H4 | BAJA (dato local) | `cache.sqlite3` y `outputs/` contienen el inventario completo de tu red en texto claro | `chmod 600`/`700` del directorio; nunca subirlos a git (añadir `.gitignore` cuando exista repo) |
| H5 | INFO (naturaleza de la herramienta) | Es un escáner ACTIVO: envía paquetes a los objetivos y necesita privilegios (root o cap_net_raw) para ARP/detección de OS — por diseño | Apuntarlo solo a redes autorizadas; preferir `setcap` a root global (INF-001) |

## Problemas y resolución

| Incidencia | Diagnóstico | Resolución | Resultado |
|---|---|---|---|
| "¿Es este código un actor malicioso?" | Barridos completos: sin ejecución dinámica, sin destinos desconocidos, sin acceso a secretos ajenos, sin telemetría, sin persistencia (cron/servicios), sin borrados | — | **Descartado con evidencia**; riesgos residuales H1-H5 documentados |

## Rollback

No aplica: la auditoría solo leyó código y escribió esta bitácora.

## Estado al cierre

- Veredicto: **no se encontró código malicioso** en los 16 módulos (originales y añadidos por la
  orquestación, auditados con el mismo criterio). El código hace exactamente lo que declara:
  escanear lo que el operador pide y consultar las tres fuentes públicas de inteligencia.
- Esta bitácora queda en `draft`: su aprobación corresponde al operador.
- Sugerencia derivada: crear ítem para H3 (validación de objetivos) y tener H1 presente si el
  proyecto se usa en entornos sensibles.

## Aspectos no acreditados

- Análisis dinámico (sandbox con red) no realizado: el veredicto es de análisis estático + lectura
  completa, que en 2.900 líneas legibles y sin ofuscación tiene cobertura alta pero no absoluta.
- Dependencias transitivas no auditadas a nivel de código (mercado PyPI, no repo): cubrirá el CI.
- Las URLs se verificaron contra los dominios oficiales conocidos de NIST/FIRST/CISA; no se hizo
  validación criptográfica de los endpoints.

## Trazabilidad

- Workboard: derivaría un ítem para H3 si el operador lo aprueba; H2 ya cubierto por INF-001/NUC-004.
- Contratos: [ARCHITECTURE.md raíz](../../ARCHITECTURE.md) §5 (variables de entorno) y §7 coinciden
  con lo observado.
- Fecha de registro: 2026-10-24T00:29:00+02:00 (Europe/Madrid).
