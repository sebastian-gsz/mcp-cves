---
id: DAT-002
title: "Escaneo diferencial con historial de inventario"
status: done
priority: P2
node: "."
parent: null
claimed_by: agent
claimed_at: 2026-10-23T23:52:39+02:00
created_at: 2026-10-22T02:50:00+02:00
updated_at: 2026-10-23T23:56:58+02:00
closed_at: 2026-10-23T23:56:58+02:00
closed_reason: null
touches:
  - data/
  - cve_scanner.py
  - export_csv_pdf.py
  - store.py
  - diferencial.py
  - tests/test_dat002.py
  - ARCHITECTURE.md
blocks: []
blocked_by: [DAT-001]
acceptance:
  - "Cada escaneo persiste el inventario (host, puerto, banner, software, fecha) en scan_history"
  - "El informe marca hallazgos como NUEVOS, CERRADOS o PERSISTENTES respecto al escaneo anterior del mismo alcance"
  - "Dos ejecuciones consecutivas sobre el mismo objetivo producen un diferencial vacío (no hay falsos nuevos)"
subtasks:
  - "[x] Tabla inventario con lotes (batch) por host en la capa de persistencia de DAT-001"
  - "[x] Comparador puro diferencial.py y marcado en el pipeline (sección 3b de cve_scanner.main)"
  - "[x] Estado diferencial en consola, CSV (columna estado_diferencial) y PDF (columna Estado)"
external:
  - null
decision_log:
  - "2026-10-23T23:52:39+02:00 (agent): CLAIM — continúa la autorización del operador; DAT-002 quedó desbloqueada al cerrarse DAT-001 (su dependencia real)."
  - "2026-10-23T23:54:00+02:00 (agent): DISEÑO — la tabla usa lotes (batch incremental por host) en vez de solo timestamp: dos guardas dentro del mismo segundo no se mezclan y los puertos cerrados desaparecen del último lote (con MAX(scanned_at) habrían persistido como fantasmas). Añadidos store.py, diferencial.py y tests/test_dat002.py a touches (ampliación trazable)."
  - "2026-10-23T23:55:30+02:00 (agent): BUG ENCONTRADO POR LOS TESTS — _SCHEMA pasó a tener dos sentencias DDL y sqlite3.execute() solo admite una (ProgrammingError); corregido con executescript(). Evidencia de que la suite protege el código."
---

## Contexto

Ítem nº6 del plan de mejoras (bitácora
[2026-10-22-auditoria-y-plan-de-mejoras.md](../../../runbooks/2026-10-22-auditoria-y-plan-de-mejoras.md)):
convierte el escáner puntual en monitoreo comparando cada escaneo con el anterior por host.

## Evidencia

Ejecutado el 2026-10-23T23:56+02:00 (agente agent): `python3 tests/test_dat002.py` → **10/10 OK**;
suite completa **44 tests OK** (1 skip declarado de PDF, sin regresiones).

1. **Persistencia por lotes** (`TestHistorialInventario`): escaneo 1 (22,80) + escaneo 2 (80,443) →
   el último lote devuelve solo (80,443): el puerto 22 cerrado desaparece correctamente del estado
   actual y queda en el historial; hosts independientes; host sin historial → lista vacía.
2. **Comparador puro** (`TestCompararInventarios`): NUEVO/CERRADO/PERSISTENTE correctos; cambio de
   banner sigue siendo PERSISTENTE (el estado refleja presencia, no contenido); TCP y UDP del mismo
   puerto se distinguen; **dos inventarios idénticos consecutivos producen solo PERSISTENTE**
   (aceptación 3: cero falsos nuevos).
3. **Informe marcado**: consola imprime la tabla «Diferencial de inventario»; el CSV incorpora la
   columna `estado_diferencial` (verificado: fila con "NUEVO") y el PDF la columna «Estado» (anchos
   reajustados a 730 pt sobre A4 apaisado).
4. **Código**: `store.save_inventory()/load_last_inventory()` (tabla `inventario` con batch),
   `diferencial.comparar_inventarios()` (puro, sin red/disco), sección 3b en `cve_scanner.main()`
   que calcula el diferencial ANTES de guardar el inventario actual.
5. **Contratos**: tronco actualizado en la misma entrega (§3 filas store/diferencial/export/tests,
   §4 grafo, §7 garantías DAT-002).

## Límites de la validación

- Verificación unitaria con SQLite temporal; no se ejecutó un escaneo real (sin nmap en el entorno),
  por lo que el flujo completo consola→CSV→PDF con datos de red queda pendiente de la medición E2E
  compartida con NUC-001.
- La generación del PDF con la nueva columna no se ejecutó (reportlab ausente): anchos verificados
  aritméticamente y test listo para CI.
