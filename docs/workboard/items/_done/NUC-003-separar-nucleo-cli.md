---
id: NUC-003
title: "Separar núcleo de CLI (librería importable, base del futuro servidor MCP)"
status: done
priority: P2
node: "."
parent: null
claimed_by: agent
claimed_at: 2026-10-24T00:24:40+02:00
created_at: 2026-10-22T02:50:00+02:00
updated_at: 2026-10-24T00:27:21+02:00
closed_at: 2026-10-24T00:27:21+02:00
closed_reason: null
touches:
  - nucleo.py
  - cve_scanner.py
  - tests/test_nuc003.py
  - ARCHITECTURE.md
blocks: []
blocked_by: [NUC-004]
acceptance:
  - "Existe una API de núcleo importable (descubrir, escanear, buscar CVEs, puntuar, exportar) sin ninguna llamada a input()"
  - "cve_scanner.py queda como capa CLI fina sobre el núcleo, con comportamiento observable equivalente"
  - "El contrato del tronco refleja la nueva frontera núcleo/CLI en la misma entrega"
subtasks:
  - "[x] Extraer el flujo de main() a nucleo.py (descubrir_hosts, escanear, _escanear_host, generar_informes) con imports perezosos de nmap/scapy"
  - "[x] CLI fina (cve_scanner.py): prompts idénticos + presentación; delega el pipeline"
external:
  - null
decision_log:
  - "2026-10-24T00:24:40+02:00 (agent): CLAIM — autorización del operador; NUC-004 aportó ya la red de tests que motivaba el bloqueo (66 tests verdes antes de este refactor)."
  - "2026-10-24T00:25:30+02:00 (agent): DISEÑO — scanner/discovery_arp se importan de forma perezosa dentro de las funciones del núcleo: nucleo.py es importable y testeable sin nmap/scapy instalados (requisito práctico para tests y para el futuro MCP). escanear() devuelve también filas_diferencial (incluye CERRADOS) para que la presentación quede en la CLI."
  - "2026-10-24T00:26:30+02:00 (agent): TEST BUG — el primer test de generar_informes comprobaba la existencia del CSV DESPUÉS de que TemporaryDirectory lo borrara; corregido moviendo las aserciones dentro del bloque (fallo del test, no del núcleo)."
---

## Contexto

Ítem nº4 del plan de mejoras (bitácora
[2026-10-22-auditoria-y-plan-de-mejoras.md](../../../runbooks/2026-10-22-auditoria-y-plan-de-mejoras.md)).
`main()` mezclaba prompts y negocio; el proyecto (mcp-cves) necesita un núcleo importable del que
el futuro servidor MCP exponga tools.

## Evidencia

Ejecutado el 2026-10-24T00:27+02:00 (agente agent): `python3 tests/test_nuc003.py` → **7/7 OK**;
suite completa **66 tests, 0 fallos** (1 skip declarado de PDF).

1. **Núcleo no interactivo (aceptación 1)**: test estructural lee `nucleo.py` y verifica que no
   contiene `input(`. API pública: `descubrir_hosts()`, `escanear()` (pipeline completo con
   diferencial incluido) y `generar_informes()` (CSV siempre, PDF protegido). Las búsquedas CVE y
   el scoring son importables vía `intel_nvd`/`scoring` como antes.
2. **CLI fina (aceptación 2)**: `cve_scanner.py` pasa de 192 a ~130 líneas con solo prompts y
   presentación; la lógica está movida verbatim a `nucleo` (mismos mensajes, mismo orden de
   secciones: escaneo → resumen → diferencial → CSV/PDF → top 10). Equivalencia verificada por
   compiación + tests de agregación/diferencial/informes; NO se ejecutó el CLI interactivo E2E
   (sin nmap en el entorno), límite declarado.
3. **Contrato (aceptación 3)**: §3 del tronco con filas nucleo/cve_scanner/tests y §4 grafo
   actualizados (entrada CLI → nucleo.escanear) en la misma entrega.

## Límites de la validación

- Sin E2E interactivo (sin nmap/dotenv/tabulate instalados): la equivalencia observable se verifica
  por identidad del código movido + 7 tests unitarios del núcleo (agregación multihost, aislamiento
  de errores por host, host sin puertos, diferencial NUEVO→PERSISTENTE en dos ejecuciones,
  informes con PDF protegido).
- `descubrir_hosts()` no tiene test unitario (requiere scapy/nmap); su lógica es la de la CLI
  original movida sin cambios.
