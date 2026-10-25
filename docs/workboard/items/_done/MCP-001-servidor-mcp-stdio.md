---
id: MCP-001
title: "Servidor MCP mínimo (stdio, JSON-RPC stdlib) exponiendo el núcleo"
status: done
priority: P1
node: "."
parent: null
claimed_by: agent
claimed_at: 2026-10-24T01:03:26+02:00
created_at: 2026-10-24T01:03:26+02:00
updated_at: 2026-10-24T01:43:28+02:00
closed_at: 2026-10-24T01:43:28+02:00
closed_reason: null
touches:
  - mcp_server.py
  - targets.py
  - config.py
  - tests/test_mcp001.py
  - .gitignore
  - ruff.toml
  - ARCHITECTURE.md
  - docs/ARCHITECTURE.md
  - docs/workboard/README.md
blocks: []
blocked_by: []
acceptance:
  - "Servidor stdio sin dependencias fuera de stdlib (una línea JSON por mensaje): initialize, notifications/initialized, tools/list, tools/call, ping y errores JSON-RPC (-32700/-32601)"
  - "Tools del núcleo expuestas con inputSchema: puntuar, buscar_cves, descubrir_hosts, escanear (esta última genera también CSV/PDF)"
  - "FAIL-CLOSED: escanear/descubrir_hosts se niegan si MCP_ALLOWED_CIDRS no está configurada o el objetivo cae fuera; el stdout del núcleo se redirige a stderr para no corromper el canal JSON-RPC"
  - "Tests del protocolo (framing incluido) y de la autorización"
  - "Integración con un cliente MCP real (Inspector/agent/Claude): diferida al sandbox"
subtasks:
  - "[x] targets.py: ip_en_whitelist/cidr_en_whitelist; config.py: mcp_allowed_cidrs()"
  - "[x] mcp_server.py: bucle stdio + handle() puro testeable"
  - "[x] tests/test_mcp001.py (19 tests)"
  - "[x] Integración real con MCP Inspector (cliente oficial de referencia) el 2026-10-24 en el WSL del operador"
external:
  - null
decision_log:
  - "2026-10-24T01:03:26+02:00 (agent): CREACIÓN+CLAIM — el proyecto se llama mcp-cves y nunca lo fue: NUC-003 dejó la base y este ítem la consume. JSON-RPC 2.0 puro stdlib (transporte stdio de MCP)."
  - "2026-10-24T01:05:00+02:00 (agent): DISEÑO — stdout del núcleo redirigido a stderr (el stdout es el canal del protocolo); fail-closed por defecto; whitelist con semántica de subred."
  - "2026-10-24T01:06:10+02:00 (agent): ESTADO — criterios 1-4 con 19/19 tests; criterio 5 pendiente de cliente real."
  - "2026-10-24T01:38:00+02:00 (agent): INTEGRACIÓN REAL — MCP Inspector oficial (npx @modelcontextprotocol/inspector --cli) contra el servidor: initialize+eco de protocolo, tools/list (4 tools con schema), puntuar(9.8,KEV,0.95)→97.8, y FAIL-CLOSED demostrado con cliente mal configurado (Inspector no propaga el entorno del padre: el servidor se negó con instrucción de configuración)."
  - "2026-10-24T01:43:28+02:00 (agent): CIERRE — con el entorno preparado (wrapper con MCP_ALLOWED_CIDRS=127.0.0.0/8 + nmap en PATH), el Inspector ejecutó un ESCANEO REAL end-to-end: 127.0.0.5:8021-8023 → nmap detecta nginx 1.18.0 → 57 hallazgos con KEV/EPSS reales (CVE-2023-44487 en KEV, EPSS 1.000, score 85.0 con los pesos 60/20/20), diferencial PERSISTENTE y CSV+PDF generados, isError=false. Criterio 5 cumplido; ítem cerrado. mcp-cves ES un MCP, verificado con el cliente oficial."
---

## Contexto

La recomendación «Cuando sea MCP (futuro)» de la bitácora de auditoría
[2026-10-24-auditoria-seguridad-codigo.md](../../../runbooks/2026-10-24-auditoria-seguridad-codigo.md)
exigía whitelist para que ningún LLM con acceso pueda lanzar escaneos fuera de permiso.

## Evidencia

1. **Protocolo (criterios 1-4)**: `tests/test_mcp001.py` 19/19 — initialize con eco de versión,
   tools/list con inputSchema, ping, -32601/-32700, framing línea a línea (notificaciones sin
   respuesta), fail-closed en sus variantes, semántica de subred, stdout del núcleo fuera del canal.
2. **Cliente oficial (criterio 5)** — MCP Inspector (`npx -y @modelcontextprotocol/inspector --cli`),
   2026-10-24T01:43+02:00:
   - `tools/list` → 4 tools.
   - `puntuar(cvss=9.8, kev=true, epss=0.95)` → `97.8`, isError false.
   - Cliente sin entorno → `FAIL-CLOSED: la whitelist MCP_ALLOWED_CIDRS no está configurada…`
     (isError true): el servidor se niega aunque el cliente sea el oficial.
   - **Escaneo real autorizado** (`hosts=["127.0.0.5"]`, `puertos=8021-8023`): resumen con 57
     hallazgos, diferencial `3 persistentes`, `Informe CSV: outputs/reporte_vulnerabilidades.csv |
     PDF: outputs/informe_escaneo.pdf`, top con CVE-2023-44487 (KEV sí, EPSS 1.000, score 85.0) —
     todo con nmap/NVD/CISA/EPSS reales.

## Límites de la validación

- Inspector CLI (transporte stdio) verificado; otros clientes (agent/Claude Desktop) usan el mismo
  protocolo y no se probaron uno a uno.
- El escaneo autorizado fue contra loopback propio; en producción la whitelist delimita los rangos.
