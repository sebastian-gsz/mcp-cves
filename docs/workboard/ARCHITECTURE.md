---
title: ARCHITECTURE.md — Dominio Workboard
Rol: Coordinador de trabajo, claims y trazabilidad
Objetivo: Definir el contrato operativo único para registrar, asignar, bloquear, ejecutar y cerrar trabajo del repositorio.
Nivel: Rama raíz documental
Estado: contract
Padre: ../ARCHITECTURE.md
Lectura obligatoria: SÍ — antes de crear, reclamar, modificar, bloquear o cerrar un ítem.
---

<br>**↑ Padre**: [docs/ARCHITECTURE.md](../ARCHITECTURE.md) — mapa maestro y leyes universales.<br/>

## 1. Alcance y autoridad

`docs/workboard/` es la única fuente de verdad para el ciclo de vida del trabajo:

- tareas y subtareas;
- prioridades;
- claims;
- bloqueos y dependencias;
- criterios de aceptación;
- decisiones de ejecución;
- evidencias y cierre.

El Workboard no sustituye a los contratos `ARCHITECTURE.md`. La arquitectura documenta reglas, límites
y comportamiento aprobado; el Workboard documenta lo que se decide hacer, quién lo ejecuta, qué impide
avanzar y cómo se verifica el resultado.

Ningún agente puede crear, reclamar, ejecutar o cerrar trabajo basándose únicamente en una
conversación, un comentario aislado o una lista externa.

## 2. Mapa del nodo

| Archivo o directorio | Responsabilidad |
|---|---|
| `README.md` | Procedimiento operativo resumido para agentes y humanos. |
| `SCHEMA.md` | Contrato de campos y formato de cada ítem. |
| `INDEX.md` | Índice sincronizado de ítems `open`, `in_progress` y `blocked`. |
| `items/ID-slug.md` | Ítem primario activo, uno por unidad de trabajo. |
| `items/_done/` | Ítems terminados o cancelados, con evidencia y resolución. |

Un ítem cerrado no se borra: se mueve a `items/_done/`. La eliminación física solo está permitida para
corregir un duplicado, y debe dejar una nota de decisión en el ítem conservado.

## 3. Reglas contractuales

1. Cada ítem tiene un ID estable, un nodo afectado, un responsable de claim, criterios verificables y
   alcance explícito.
2. Crear, modificar, reclamar, bloquear, desbloquear, cancelar, cerrar o mover un ítem exige actualizar
   en la misma entrega todos los artefactos afectados: el archivo del ítem, `INDEX.md` cuando
   corresponda y la evidencia/decisión del cuerpo.
3. `INDEX.md` debe contener exactamente todos los ítems activos y ningún ítem de `_done/`.
4. Cada dependencia `blocks` o `blocked_by` debe representar una dependencia real. Las relaciones
   informativas se documentan en el cuerpo, nunca en esos campos.
5. Una tarea no puede marcarse `done` si falta un criterio de aceptación, una evidencia verificable o
   la actualización de los contratos afectados por el cambio.
6. Una tarea `cancelled` conserva el motivo y la decisión que la canceló; no se reutiliza su ID.
7. El contenido del Workboard no puede introducir cambios en leyes, alcance, precedencia o
   clasificación de los nodos. Si una tarea contradice un contrato superior, se corrige o cancela; no
   se relaja la arquitectura para hacerla posible.
8. Las tareas futuras pueden permanecer abiertas si tienen propósito, alcance y criterios válidos. No
   se convierten en estado dentro de un `ARCHITECTURE.md`.
9. Los secretos, credenciales, tokens y respuestas sensibles no se almacenan en ítems, evidencias ni
   logs del Workboard.

## 4. Proceso de una tarea individual

### 4.1 Crear

1. Leer la cadena de contratos hasta el nodo afectado.
2. Comprobar que no exista un ítem equivalente.
3. Crear un archivo con el esquema vigente y un ID nuevo del dominio.
4. Definir alcance, `touches`, aceptación, dependencias reales y contexto.
5. Actualizar `INDEX.md` en la misma entrega.

### 4.2 Reclamar

1. Leer el ítem y verificar `status: open`, o confirmar que el agente ya es `claimed_by`.
2. Cambiar atómicamente `status`, `claimed_by`, `claimed_at` y `updated_at`.
3. Reflejar el claim en `INDEX.md`.
4. Un agente mantiene como máximo un claim activo, salvo autorización expresa.

Si dos agentes reclaman simultáneamente, prevalece el primer cambio persistido que conserve el estado
previo esperado (`open`). El segundo agente debe detenerse, no sobrescribir el claim y registrar la
colisión en su entrega o comunicarla al owner.

Un claim abandonado no se reasigna silenciosamente: el owner libera o reasigna el ítem, actualizando
`decision_log` e `INDEX.md`.

### 4.3 Ejecutar

1. Verificar dependencias y bloqueos antes de tocar código o arquitectura.
2. Trabajar solo dentro de `touches`, salvo ampliar el alcance mediante una modificación trazable del
   ítem.
3. Para varios agentes sobre una misma tarea, dividir el trabajo en subtareas o ítems hijos con
   límites de archivos no solapados.
4. Un agente coordinador conserva el claim primario, integra resultados y es el único que cierra la
   tarea.
5. Los agentes colaboradores no cambian el estado global ni mueven archivos a `_done/`; devuelven
   evidencia al coordinador.
6. Si aparece una contradicción normativa, detener la ejecución y marcar `blocked` con la referencia
   al contrato conflictivo.

### 4.4 Bloquear y desbloquear

Un bloqueo requiere `status: blocked`, `blocked_by` con IDs existentes y una explicación concreta. Al
desaparecer la causa, el owner o el agente reclamante actualiza dependencias, evidencia y devuelve el
estado a `open` o `in_progress`; nunca se elimina el historial del bloqueo.

### 4.5 Cerrar o cancelar

El coordinador decide entre:

- **`done`**: todos los criterios se verifican y el resultado está persistido;
- **`cancelled`**: el trabajo ya no debe ejecutarse, fue sustituido o contradice una regla superior.

Antes de cerrar:

1. comprobar cada criterio de aceptación;
2. ejecutar las validaciones aplicables;
3. actualizar el `ARCHITECTURE.md` del nodo si cambió comportamiento, mapa o grafo;
4. añadir evidencia, decisión y fecha;
5. cambiar el estado y limpiar el claim;
6. mover el archivo a `items/_done/`;
7. quitarlo de `INDEX.md` en la misma entrega.

Los ítems cancelados también se mueven a `_done/`, pero conservan `closed_reason` y no se presentan
como trabajo completado.

## 5. Tareas multiagente

Una tarea única puede tener varios colaboradores, pero solo un coordinador. El coordinador debe:

- mantener el alcance y los criterios de aceptación;
- asignar subtareas no solapadas;
- exigir una evidencia por subtarea;
- integrar cambios sin sobrescribir trabajo ajeno;
- resolver conflictos de archivos;
- verificar el resultado completo;
- ejecutar el cierre atómico del ítem.

Si las subtareas tienen ciclos de vida independientes, deben promoverse a ítems primarios con IDs
propios y dependencias explícitas. No se usan subtareas para ocultar trabajo independiente ni para
multiplicar claims sobre el mismo archivo.

## 6. Trazabilidad y sincronización

Cada modificación del Workboard debe poder reconstruirse mediante:

- `updated_at`;
- autor o `claimed_by`;
- motivo en el cuerpo o `decision_log`;
- criterios y subtareas afectados;
- evidencia de validación;
- relación con los contratos o archivos tocados.

No se actualiza solo `INDEX.md` ni solo el ítem. El índice es una proyección; el archivo del ítem es
el registro primario; `_done/` es el archivo histórico.

## 7. Términos y condiciones

1. El Workboard tiene autoridad exclusiva sobre estados y coordinación de tareas, no sobre las leyes
   arquitectónicas.
2. Un contrato superior prevalece ante cualquier instrucción de un ítem.
3. No existe cierre implícito por antigüedad, comentario o commit sin evidencia.
4. Un ítem abierto no demuestra que el trabajo siga siendo válido; debe conservar alcance coherente
   con los contratos actuales.
5. Cuando cambia la arquitectura, los ítems afectados se revisan y se cierran, adaptan o cancelan con
   trazabilidad.
6. La consistencia del nodo se evalúa por la correspondencia exacta entre ítems activos, `INDEX.md` y
   el archivo histórico `_done/`.

---
*Fin del contrato del dominio Workboard. Para reglas universales vuelve a [docs/ARCHITECTURE.md](../ARCHITECTURE.md).*
