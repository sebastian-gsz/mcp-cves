---
id: INT-002
title: "OSV (Google): escáner de dependencias (SCA) para proyectos locales"
status: done
priority: P2
node: "."
parent: null
claimed_by: agent
claimed_at: 2026-10-24T12:35:23+02:00
created_at: 2026-10-24T11:45:16+02:00
updated_at: 2026-10-24T12:49:00+02:00
closed_at: 2026-10-24T12:49:00+02:00
closed_reason: null
touches:
  - intel_osv.py
  - nucleo.py
  - mcp_server.py
  - config.py
  - tests/test_int002.py
  - tests/test_mcp001.py
  - ARCHITECTURE.md
blocks: []
blocked_by: []
acceptance:
  - "Nuevo vector de escaneo: dado un directorio de proyecto, detecta manifiestos y consulta OSV por paquete/versión con caché TTL 24 h y degradación elegante"
  - "Hallazgos de dependencias integrados en el mismo pipeline (score, CSV/PDF) con vector='dependencia' y ecosistema visible"
  - "MCP tool `escanear_dependencias(ruta)` FAIL-CLOSED: solo rutas bajo MCP_DEPS_ROOTS"
  - "Tests con fixtures OSV grabadas"
subtasks:
  - "[x] F0: manifiestos soportados (requirements.txt, package.json, go.mod, Cargo.toml, pom.xml, Gemfile) y verificación en vivo de api.osv.dev"
  - "[x] F1: intel_osv.py (parsers puros + consulta POST /v1/query con TTL 24 h; fallo de red no cachea vacío)"
  - "[x] F2: 15 tests (parsers de los 6 manifiestos, detección con exclusiones, OSV con mock, nucleo con proyecto mixto, MCP fail-closed con traversal)"
  - "[x] F3: wiring (nucleo.escanear_dependencias, config.mcp_deps_roots, informe, contrato)"
external:
  - "https://api.osv.dev"
decision_log:
  - "2026-10-24T11:45:16+02:00 (agent): CREACIÓN — plan de integraciones del operador; api.osv.dev verificado en vivo sin key."
  - "2026-10-24T12:35:23+02:00 (agent): CLAIM — continúa la autorización («Comienza a implementar…»)."
  - "2026-10-24T12:40:00+02:00 (agent): DISEÑO — solo versiones EXACTAS son consultables (==/pinned; ^~>= y ${var} fuera, anotado en tests); cvss = proxy por severidad declarada de OSV (LOW..CRITICAL → 2..9.5) porque OSV no siempre da puntuación numérica: documentado en contrato y hallazgo. EPSS queda a 0 en este vector (sin llamada extra por dependencia)."
  - "2026-10-24T12:47:00+02:00 (agent): SEGURIDAD — la ruta de la tool MCP se resuelve con realpath y commonpath contra MCP_DEPS_ROOTS: un 'proyecto/../../etc' se resuelve FUERA y se rechaza (test dedicado de traversal)."
---

## Contexto

El escáner solo veía lo que expone la RED (banners). Las dependencias del código (la librería log4j
de turno) son invisibles a nmap. OSV es la fuente canónica abierta para SCA.

## Evidencia

Ejecutado el 2026-10-24T12:48+02:00 (agente agent): `python3 tests/test_int002.py` → **15/15 OK**;
suite completa **124 tests, 0 fallos**.

1. **Parsers de los 6 manifiestos** (`TestParsers`): requirements (solo `==`), package.json
   (exactas, `^~` fuera), go.mod, Cargo.toml (string y tabla, tomllib stdlib), pom.xml (namespace
   Maven, `${var}` fuera), Gemfile.
2. **Detección** (`TestDetectarManifiestos`): profundidad máx. 4, node_modules/.git/venv excluidos.
3. **OSV** (`TestConsultarOsv`): POST /v1/query parsea aliases→CVE, severidad→cvss proxy
   (CRITICAL→9.5), URL osv.dev; segunda consulta = 0 peticiones (TTL 24 h); fallo de red → []
   SIN cachear (ley 11).
4. **Pipeline integrado** (`TestNucleoDeps`): proyecto mixto (requirements+package.json) con un
   paquete vulnerable → hallazgo con os=PyPI, banner=manifiesto, kev+arma reales vía mocks y
   score 77,5 con los 4 factores; sin manifiestos → [] con aviso.
5. **MCP fail-closed** (`TestMcpFailClosedDeps`): sin `MCP_DEPS_ROOTS` → isError con instrucción;
   ruta fuera → rechazada sin llamar al núcleo; **ruta con `..` resuelta contra la whitelist →
   rechazada** (traversal cubierto); ruta autorizada → escanea y resume.
6. **Contrato**: §3 (intel_osv, nucleo SCA, mcp tools, tests), §5 `MCP_DEPS_ROOTS`, §7 — misma entrega.

## Límites de la validación

- OSV consultado con mocks (la verificación en vivo de api.osv.dev fue del endpoint, no del flujo
  completo en este entorno); la E2E real queda para la próxima sesión con dependencias instaladas.
- Solo dependencias con versión exacta se consultan; rangos semánticos quedan fuera por diseño
  (anotado en tests y contrato).
