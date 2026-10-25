---
id: DOC-001
title: "Verificación de montaje del harness documental (Fase 7 del BLUEPRINT)"
status: done
priority: P1
node: "docs/"
parent: null
claimed_by: agent
claimed_at: 2026-10-22T02:58:00+02:00
created_at: 2026-10-22T02:58:00+02:00
updated_at: 2026-10-22T03:00:00+02:00
closed_at: 2026-10-22T03:00:00+02:00
closed_reason: null
touches:
  - docs/
  - AGENTS.md
  - ARCHITECTURE.md
blocks: []
blocked_by: []
acceptance:
  - "Checklist estructural 7.1 del BLUEPRINT ejecutada con evidencia"
  - "Enlaces relativos entre contratos resuelven"
  - "INDEX.md refleja exactamente los ítems activos"
  - "Sin secretos ni placeholders sin sustituir en contratos reales"
subtasks:
  - "[x] AGENTS.md es stub ≤ 40 líneas (22 líneas) y solo enlaza"
  - "[x] Mapa maestro con §1-§6 completos y regla de oro"
  - "[x] Topología refleja directorios reales; sin nodos hipotéticos (data/ y outputs/ semillas)"
  - "[x] Tabla de ruteo §3 lista los 5 nodos con enlaces que resuelven"
  - "[x] ↑ Padre bidireccional en cada contrato (raíz ↔ docs; workboard/runbooks ↔ docs)"
  - "[x] Sin backlog en contratos (los pendientes viven solo en el workboard)"
  - "[x] Contratos reales sin marcadores de plantilla; plantillas los conservan por diseño"
  - "[x] Workboard completo: ARCHITECTURE/README/SCHEMA/INDEX + items/ + items/_done/"
  - "[x] INDEX refleja exactamente los 8 ítems activos"
  - "[x] Convención de IDs (NUC/DAT/SEG/INF/DOC) y estados documentada en README"
  - "[x] Sin secretos en toda la documentación"
  - "[x] Fechas ISO-8601 con offset (+02:00), ninguna inventada"
external:
  - null
decision_log:
  - "2026-10-22T02:58:00+02:00 (agent): ítem creado y claimado por el propio agente de montaje conforme al §10.3 del BLUEPRINT (montaje single-actor); única sesión actora."
  - "2026-10-22T03:00:00+02:00 (agent): los 3 hits de '<...' en contratos se descartan como marcadores: son convenciones de nombre de archivo (<tema>-<entorno>) y etiquetas <br> del formato establecido por el BLUEPRINT; ningún placeholder de plantilla quedó sin sustituir."
---

## Contexto

Prueba de fuego de la Fase 7 del BLUEPRINT-ORQUESTADOR (plano retirado del repo por el operador):
validar el harness end-to-end ejecutando un ciclo completo de tarea (crear → claimar → ejecutar →
cerrar → archivar) sobre el propio montaje.

## Evidencia

Ejecución del 2026-10-22T02:57+02:00 (agente agent, sesión de montaje):

1. **Inventario**: `find` confirmó los 27 archivos del harness (AGENTS.md, 2 contratos raíz, 4
   plantillas, 4 archivos de workboard, 5 de runbooks, bitácora, 8 ítems + 2 .gitkeep + BLUEPRINT).
2. **AGENTS.md**: `wc -l` → 22 líneas (≤ 40 requeridas), solo enlaces, sin reglas propias.
3. **Placeholders**: `grep -n "<[a-z]"` sobre los 5 contratos reales → solo `<br>` y convenciones
   `<tema>-<entorno>` (descartados en decision_log); plantillas conservan sus marcadores por diseño.
4. **INDEX ↔ items**: 8 archivos activos en `items/` y 8 filas de ítems en `INDEX.md` (+1 cabecera)
   — correspondencia exacta; `_done/` sin ítems todavía.
5. **Secretos**: `grep -rniE "(api_key|token|password|secret)[:=]..."` → sin coincidencias.
6. **Enlaces**: bucle de verificación de cada enlace relativo `.md` de los 9 documentos contractuales
   → 0 enlaces rotos.
7. **Fechas**: todos los `created_at` con offset `+02:00` (Europe/Madrid).

## Cierre

Los 12 criterios de la checklist 7.1 pasan. El ítem se archiva en `items/_done/` y se retira de
`INDEX.md` en la misma entrega. **Harness operativo.**
