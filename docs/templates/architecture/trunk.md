---
title: ARCHITECTURE.md — Tronco «<nombre-del-dominio>»
Rol: <responsable funcional o técnico>
Objetivo: Definir el contrato transversal del dominio <dominio>.
Nivel: Tronco
Estado: contract
Padre: <ruta-relativa-al-ARCHITECTURE.md-padre>
Lectura obligatoria: SÍ — antes de modificar cualquier responsabilidad de este tronco.
---

<br>**↑ Padre**: [<nombre del contrato padre>](<enlace-relativo-al-padre>) — <autoridad y alcance heredados>.<br/>

## 1. Alcance y autoridad

Este contrato se aplica exclusivamente a `<ruta-del-tronco>/` y regula <responsabilidad transversal>.

- **Entradas**: <tipos de entrada o dependencias externas>.
- **Proceso**: <responsabilidades que pertenecen al dominio>.
- **Salidas**: <resultados y consumidores>.

No regula <responsabilidades fuera del dominio>. El detalle propio de ramas y frutos permanece en sus
contratos descendientes.

## 2. Cláusulas de comportamiento e implementación

1. Lee este contrato y todos sus contratos superiores antes de actuar; desciende al nodo específico
   de la tarea.
2. Antes de trabajo operativo, consulta [docs/workboard](<enlace-relativo-a-workboard>) y cumple su
   claim, autorización, bloqueo y cierre.
3. Si no existe autorización o hay conflicto con un contrato superior, detén la acción y registra o
   comunica el impedimento mediante el proceso del Workboard.
4. <Regla transversal del dominio>.
5. <Regla transversal del dominio>.
6. Mantén la lógica específica de un sistema en su nodo descendiente; comparte solo abstracciones
   demostrablemente comunes.
7. Para nodos nuevos, aplica el protocolo de topología de la guía de plantillas.
8. Actualiza este contrato solo cuando cambie una regla, responsabilidad, ruta o mapa bajo autoridad
   de este tronco.

## 3. Topología y tabla de ruteo

Este tronco enruta las ramas y frutos reales bajo `<ruta-del-tronco>/`. Cada fila debe describir un
nodo existente y enlazar su contrato.

| Nodo | Nivel | Estado | Responsabilidad | Contrato |
|---|---|---|---|---|
| `<ruta-hijo>/` | Rama | contract | <alcance del nodo> | [ARCHITECTURE.md](<enlace-relativo>) |

<!-- Añade ↑ Padre en cada hijo y mantén los mapas superiores que exige docs/ARCHITECTURE.md §4.
     No documentes nodos hipotéticos o tareas futuras. -->

## 4. Principios de enrutamiento y dependencias

```text
<entrada o consumidor>
    ↓
<responsabilidad de este tronco>
    ↓
<ramas/frutos concretos>
```

- <Criterio para decidir qué pertenece a este tronco>.
- <Dirección permitida de dependencias> (p. ej.: un fruto consume utilidades de `core/`, nunca al revés).
- <Límite de responsabilidad con nodos hermanos y padre>.

## 5. Validación del dominio

- <Validaciones del contrato transversal>.
- <Cómo verificar sin depender de producción, si aplica>.
- Al cerrar un trabajo, registra evidencia y límites de validación en el ítem del Workboard.

## 6. Términos y condiciones

1. **Autoridad**: este contrato está subordinado a `<contrato padre>` y, por cascada, a
   `docs/ARCHITECTURE.md`.
2. **Unidad de cambio**: <qué cambios pertenecen a este tronco>.
3. **Límite**: <qué no autoriza ni regula este contrato>.
4. **Integridad del mapa**: todo nodo bajo su autoridad debe estar correctamente enrutado; los mapas
   superiores se actualizan según la ley global de topología.
5. **Workboard**: es la fuente exclusiva de estado, coordinación y trazabilidad del trabajo.
6. **Conflicto o fallo**: no relajes una regla superior ni presentes un resultado no verificado como
   funcional; detén y escala el conflicto.

---
*Fin del contrato de `<ruta-del-tronco>/`. Sube a [<contrato padre>](<enlace-relativo>) para las normas superiores.*

<!--
Uso:
- Sustituye todos los marcadores <...>.
- Estado `contract`: conserva reglas y mapas; no añadas estado operativo detallado.
- Estado `implemented`: añade mapa real de archivos/símbolos y grafo funcional aprobado, contrastados
  con el repositorio.
- No incluyas backlog, estado de tareas ni nodos no existentes.
-->
