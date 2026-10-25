---
title: "Auditoría cuantitativa y plan de mejoras del escáner — mcp-cves"
type: execution-log
document_status: draft
outcome: "Auditoría del código completada con métricas contrastadas; plan de mejoras priorizado en 8 ítems creados en el Workboard"
system: "mcp-cves (escáner de vulnerabilidades y CVEs)"
environment: "local (WSL2, no productivo)"
execution_date: "2026-10-22"
recorded_date: 2026-10-22
version: "1.0 — estado del código contrastado el 2026-10-22"
source: "análisis sobre los 11 módulos Python del repositorio"
confidence: "directly-verified"
---

# Auditoría cuantitativa y plan de mejoras del escáner — mcp-cves

## Objetivo y alcance

Auditar cuantitativamente el escáner (cifras de código, tiempos de ejecución configurados, cuellos de
botella y números desfavorables) y derivar de ahí un plan de mejoras dividido por frontera de control
(lo que el proyecto controla frente a lo que no) y por dominio (datos/infra, código/lenguaje, red,
seguridad de la propia aplicación). Este registro cubre el análisis y el plan; **la implementación de
ninguna mejora se ejecutó en esta sesión**.

## Fuente y límites de evidencia

- **Hechos verificados directamente** por el agente: lectura completa de los 11 módulos Python,
  conteos con `wc -l`/`grep`, valores de timeout/delay extraídos del código, simetría del scoring.
- **Datos informados por terceros** (no verificados en esta sesión): los límites oficiales de la API
  NVD (5 req/30 s sin clave, 50 req/30 s con clave) provienen de su documentación pública.
- **Simulaciones**: los escenarios de duración son estimaciones derivadas de los timeouts configurados,
  no ejecuciones cronometradas contra una red real.

## Entorno observado

- Sistema/versión: Python 3 (usa sintaxis `str | None`, requiere ≥3.10); 1.280 líneas en 11 módulos.
- Host/entorno: WSL2 local; sin repositorio git en el proyecto.
- Configuración relevante: `.env` opcional con `NVD_API_KEY` y `DEBUG`; `data/puertos_comunes.txt`
  (302 puertos); dependencias: python-nmap, requests, python-dotenv, tabulate, scapy, reportlab.

## Pasos ejecutados (auditoría: los números del código)

**Inventario del proyecto:**

| Métrica | Valor | Lectura |
|---|---|---|
| Líneas de Python | 1.280 en 11 archivos | Proyecto pequeño-mediano |
| Archivo más grande | `intel_nvd.py` 359 líneas (28%) | Concentra la lógica más compleja |
| Funciones | 36 | Media de ~35 líneas/función |
| Manejadores `except` | 25 | Muchos tragan errores en silencio |
| Tests | 0 | Cobertura 0% |
| Dependencias | 6, todas sin versión fijada | No reproducible |
| Puertos en lista común | 302 | Con >200 puertos cae en el timeout máximo (300 s/host) |
| APIs externas | 3 (NVD, EPSS, KEV) | Ninguna con caché en disco |
| Concurrencia | 1 hilo, 100% secuencial | Principal cuello de botella |
| Persistencia entre ejecuciones | 0 | Cada scan vuelve a pagar todas las consultas a NVD |

**Tiempos (techos configurados en el código, no tiempos reales):**

```text
Descubrimiento ARP                 █                2 s
Descubrimiento nmap -sn     ██████          25 s
Escaneo de OS                          ███████████     45 s
Puertos (≤30)                             ███████████████ 60 s
Puertos (≤200)                           ████████████████████████████████████████████ 180 s
Puertos (>200)  ← lista             ██████████████████████████████████████████████████████████████████████ 300 s
```

**Simulación de un /24 (20 hosts vivos, ~60 servicios con versión):** optimista ~15 min; techo
~2,5 h. El salto se debe a la secuencialidad total: un host debe terminar para empezar el siguiente.

**Hallazgos negativos contrastados:**

1. **Rate limit de NVD ignorado matemáticamente**: el código envía 1 petición cada 0,8 s (~37/30 s),
   7× el límite no autenticado (5/30 s); con clave va justo por encima (≈1,8 req/s frente a 1,67).
2. **Scoring con prioridad invertida**: con 95/2,5/2,5, un CVE en KEV (explotado activamente) con
   CVSS 7,5 puntúa 76,0 y queda 17 puntos por debajo de un CVE teórico CVSS 9,8 (93,1).
3. **Fallos silenciosos**: si la descarga de KEV falla (timeout 8 s) devuelve conjunto vacío y el
   informe sale subestimado sin aviso; EPSS igual → 0,0.
4. **Bug de DEBUG invertido** (`cve_scanner.py`): sin `.env`, `os.getenv("DEBUG")` es `None`,
   `None == 'False'` es falso → modo debug activado por defecto.
5. **Cobertura de escaneo**: 0 puertos UDP (retirado); `-sT` (connect scan) en vez de SYN scan:
   más lento y deja conexión registrada en los logs del objetivo.

## Resultados: plan de mejoras (frontera de control)

Principio rector: **de fuera solo controlamos cuánto lo necesitamos; de dentro lo controlamos todo.**

### A. Lo que NO controlamos (servicios externos)

No controlamos límites, latencia ni disponibilidad de estas APIs — pero sí cuántas veces las llamamos
y qué pasa cuando fallan:

| Servicio externo | Qué no controlamos | Acciones para defenderse de ello |
|---|---|---|
| **NVD** (CVEs) | Rate limit 5 req/30s sin clave, 50 con clave; latencia variable; a veces cae días | Caché persistente (reduce llamadas ~90%), token bucket real que respete el límite, cachear la respuesta 429 |
| **EPSS** (FIRST) | Se actualiza 1×/día, sin SLA, sin clave | Snapshot diario local: 1 llamada al día en vez de 1 por scan; ya agrupa 200 CVEs/petición |
| **KEV** (CISA) | Feed JSON de ~2-3 MB, se publica cuando CISA quiere | Caché con TTL 24h y **fallback a la última copia buena**; hoy un fallo devuelve vacío y subestima el informe — el bug más grave de los "no controlados" |
| **nmap instalado en el SO** | Versión, permisos, presencia | Validar versión al arranque; fallar con mensaje claro, no con traceback |

Patrón común de la columna A: **degradación elegante** — si la API falla, usar la última copia local y
avisar en el informe ("KEV: datos de hace 3 días"), nunca inventar un cero.

### B. Lo que SÍ controlamos

**B1. Datos y persistencia → optimizaciones de infraestructura** (hoy: 0 persistencia)

1. **SQLite como capa de datos**: `cves` (por CPE+versión, TTL 72h), `intel_snapshots` (EPSS/KEV
   diarios), `scan_history` (host, puerto, banner, fecha).
2. **Escaneos diferenciales** contra `scan_history`: solo lo nuevo/cerrado; convierte el escáner
   puntual en monitoreo — la mejora de producto más valiosa.
3. Configuración validada con `pydantic-settings` (muere el bug de DEBUG de raíz), `.env` con
   permisos 600.

**B2. Código y lenguaje (Python explotado al máximo)**

1. **Async con `asyncio` + `httpx`**: consultas NVD concurrentes (límite 4-8) con rate limiter
   compartido; baja el escenario de 2,5 h a minutos.
2. **nmap bloqueante** → pool de procesos (uno por host) o `ProcessPoolExecutor`.
3. **`orjson`** para feed KEV y páginas NVD de 200 resultados.
4. **Separar CLI de núcleo**: `main()` (192 líneas con `input()`) → librería importable; requisito
   previo para el servidor MCP que el nombre del proyecto declara.
5. **Tests pytest** con respuestas NVD grabadas (con 0 tests, todo refactor es a ciegas).
6. Corregir los 3 bugs medidos: DEBUG invertido, rate limit 7×, reponderar score a 60/20/20.

**B3. Red (la parte escaneo)**

1. `-sS` (SYN scan) en vez de `-sT`: más rápido y no deja conexión completa en los logs del objetivo.
2. Reintroducir UDP top-100.
3. Escaneo por fases: discovery → top-100 rápido → deep scan selectivo.
4. `--min-rate` y `--max-rtt-timeout` afinados en vez de timeouts fijos de 300 s.

**B4. Seguridad de la propia aplicación (cómo reacciona ante entornos hostiles)**

| Vector | Cómo reacciona hoy | Acción |
|---|---|---|
| **Banner malicioso** (host comprometido devuelve banner trampa) | Se parsea con regex y se inyecta en CSV y PDF | Validar/limitar longitud, escapar en PDF (PDF injection), tests con banners hostiles |
| **ReDoS** | Las regex de `cpe_map.py` y `utils.py` corren sobre input de la red sin límite | Límite de longitud de banner antes de parsear (p. ej. 500 chars) |
| **Respuestas NVD envenenadas** | JSON → dicts → informe sin límites | Limitar tamaño de respuesta, validar tipos |
| **Corre como root** (necesario para ARP/SYN) | Todo el proceso con máximo privilegio | `setcap cap_net_raw+ep` solo a lo necesario o usuario dedicado + capabilities mínimas |
| **API key NVD en `.env`** | Sin control visible | No loggearla nunca, `.gitignore`, rotación |
| **Supply chain propia** | 6 dependencias sin pin | `pip-audit` sobre sí mismo + versiones fijadas con hash |
| **Cuando sea MCP** (futuro) | — | El servidor MCP expondrá "escanea esta red" a un agente: validar CIDRs contra whitelist de rangos autorizados |

### Prioridad sugerida (impacto × esfuerzo)

| # | Acción | Dominio | Impacto | Esfuerzo |
|---|---|---|---|---|
| 1 | Caché SQLite de CVEs + fallback KEV | Datos/externos | Muy alto | Bajo |
| 2 | Async NVD + pool nmap | Código | Muy alto | Medio |
| 3 | Reponderar score 60/20/20 + fix DEBUG | Código | Alto | Muy bajo |
| 4 | Separar núcleo de CLI (base del MCP) | Código | Alto | Medio |
| 5 | Docker + capabilities en vez de root | Infra/seguridad | Medio | Bajo |
| 6 | Escaneo diferencial | Datos | Alto | Medio |
| 7 | Banner límites + escaping PDF | Seguridad | Medio | Bajo |
| 8 | Tests + CI | Código | Alto | Medio |

## Verificación

| Comprobación | Resultado observado | Fuente |
|---|---|---|
| Líneas por módulo (1.280 total) | Confirmado con `wc -l` | Contraste directo |
| 302 puertos en `data/puertos_comunes.txt` | Confirmado con `wc -l` | Contraste directo |
| Timeouts 2/25/45/60/180/300 s y delays 0,35/0,8 s | Confirmados leyendo `scanner.py`, `cve_scanner.py`, `intel_nvd.py`, `discovery_arp.py` | Contraste directo |
| Pesos 95/2,5/2,5 en `scoring.py` | Confirmado leyendo el módulo | Contraste directo |
| Bug DEBUG (None → activado) | Confirmado leyendo `cve_scanner.py:106-110` | Contraste directo |
| Límites oficiales NVD (5/50 req por 30 s) | Informado por documentación pública de NVD; no re-verificado en esta sesión | Terceros |

## Problemas y resolución

| Incidencia | Diagnóstico | Resolución | Resultado |
|---|---|---|---|
| Fallo de KEV → informe subestimado en silencio | `load_kev_set()` devuelve `set()` ante cualquier excepción | Plan: caché + fallback con aviso (DAT-001) | Pendiente de implementación |
| DEBUG activado por defecto | Lógica invertida en `cve_scanner.py` | Plan: corrección + test (NUC-002) | Pendiente de implementación |
| 429 de NVD por ritmo 7× superior al límite | Delay base no alineado con la ventana oficial | Plan: token bucket + caché (DAT-001 + NUC-001) | Pendiente de implementación |

## Rollback

No aplica: esta ejecución solo produjo documentación (bitácora, ítems del Workboard, contratos del
harness). No se modificó ningún módulo del escáner.

## Estado al cierre

- Auditoría completada y plan de mejoras priorizado (tabla anterior).
- Las 8 acciones del plan quedaron registradas como ítems `open` en el Workboard
  (`DAT-001`, `NUC-001`, `NUC-002`, `NUC-003`, `NUC-004`, `INF-001`, `DAT-002`, `SEG-001`),
  a la espera de autorización del operador.
- Este documento queda en `draft`: la aprobación y vigencia corresponde al operador.

## Aspectos no acreditados

- No se ejecutó ningún escaneo real ni llamada a NVD/EPSS/KEV durante la auditoría; los tiempos de
  red son estimaciones de diseño, no mediciones.
- No se ejecutaron los tests (no existen) ni se verificó la herramienta contra un objetivo vivo.
- Los límites oficiales de la API NVD provienen de documentación pública, no de una prueba de carga.
- El escenario de simulación /24 asume 20 hosts y 60 servicios; un entorno real variará.

## Trazabilidad

- Workboard/autorización: ítems `DAT-001`, `NUC-001`, `NUC-002`, `NUC-003`, `NUC-004`, `INF-001`,
  `DAT-002`, `SEG-001` (creados el 2026-10-22, pendientes de claim).
- Contratos relacionados: [ARCHITECTURE.md raíz](../../ARCHITECTURE.md) (§7 recoge los antipatrones
  observados), [docs/ARCHITECTURE.md](../../docs/ARCHITECTURE.md) (leyes 10-12 nacidas de este plan).
- Fecha de registro: 2026-10-22T02:55:00+02:00 (Europe/Madrid).
