# Workboard — Tablero de trabajo del repositorio

Contrato del nodo: [ARCHITECTURE.md](./ARCHITECTURE.md). Este README es el procedimiento resumido;
el contrato define autoridad, sincronización, claims, multiagente y cierre.

Fuente única de **pendientes operativos** (backlog, tareas, claims). Los `ARCHITECTURE.md` describen
contratos y estado factual; **no** alojan listas de backlog.

## Convención

| Ruta | Rol |
|---|---|
| `INDEX.md` | Vista rápida de ítems `open` / `in_progress` / `blocked` |
| `SCHEMA.md` | Campos obligatorios de cada ítem |
| `items/ID-slug.md` | Un archivo por tarea primaria |
| `items/_done/` | Ítems cerrados (mover aquí al completar o cancelar) |

**IDs estables** por dominio: `NUC-###` (núcleo/código), `DAT-###` (datos/persistencia),
`SEG-###` (seguridad de la aplicación), `INF-###` (infraestructura), `MCP-###` (servidor MCP),
`INT-###` (inteligencia/fuentes externas), `EXP-###` (experimental: opt-in, sin score, gateado),
`DOC-###` (documentación/harness).

**Estados:** `open` · `in_progress` · `blocked` · `done` · `cancelled`.

**Prioridades:** `P0` (bloqueante) · `P1` (alta) · `P2` (normal) · `P3` (baja / aplazada).

## Protocolo de claim (agentes y humanos)

1. **Antes de tocar código** de una tarea: lee los contratos hasta el nodo, abre su archivo en
   `items/` y comprueba que `status` sea `open` (o que ya eres el `claimed_by`).
2. **Claim:** cambia atómicamente `status`, `claimed_by`, `claimed_at` y `updated_at`, y refleja la
   fila en `INDEX.md`.
3. **Un claim a la vez** por agente salvo indicación expresa del owner. Ante colisión, conserva el
   primer claim persistido y no sobrescribas.
4. **No implementes** ítems aplazados o bloqueados sin la autorización y desbloqueo correspondientes.
5. **Toda modificación** del ítem exige sincronizar su archivo, `INDEX.md` si es activo y la
   evidencia/decisión en el cuerpo, en la misma entrega.
6. **Al cerrar:** verifica aceptación y validaciones, actualiza solo los contratos afectados por
   cambios reales, registra evidencia, limpia el claim, mueve el archivo a `items/_done/` y quítalo
   de `INDEX.md`.
7. **Cancelar** no equivale a completar: conserva `closed_reason`, evidencia y decisión, y mueve el
   ítem a `_done/`.
8. **Bloqueos:** usa `blocked_by` / `blocks` solo con dependencias reales; `status: blocked` exige
   explicación y referencia.

## Regla de oro

> Los pendientes viven **solo** en `docs/workboard/`. Si un `ARCHITECTURE.md` acumula otra lista de
> backlog, es un bug de documentación: migra el ítem aquí y deja un puntero corto.

## Sincronización obligatoria

La fuente primaria es el archivo del ítem. `INDEX.md` es una proyección de los ítems activos y
`_done/` es el historial. Crear, modificar, reclamar, bloquear, desbloquear, cancelar o cerrar exige
actualizar todas las proyecciones afectadas en una única entrega; nunca se edita solo el índice.

## Trabajo multiagente

Una tarea conserva un único coordinador y un único claim primario. Los colaboradores trabajan en
subtareas no solapadas y entregan evidencia; no cambian el estado global ni cierran el ítem. Si una
subtarea necesita autonomía, se promueve a ítem con ID y dependencia propia.
