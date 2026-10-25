---
title: ARCHITECTURE.md — Rama «<nombre-de-rama>»
Rol: <responsable del dominio de rama>
Objetivo: Definir las reglas locales y el enrutamiento de <dominio de rama>.
Nivel: Rama
Estado: contract
Padre: <ruta-relativa-al-ARCHITECTURE.md-padre>
Lectura obligatoria: SÍ — antes de modificar o enrutar trabajo bajo esta rama.
---

<br>**↑ Padre**: [<nombre del contrato padre>](<enlace-relativo-al-padre>) — <alcance heredado>.<br/>

## 1. Alcance y autoridad

Este contrato se aplica exclusivamente a `<ruta-de-rama>/` y especializa <reglas propias de la rama>.

No redefine reglas superiores ni documenta el estado operativo detallado de sus frutos.

## 2. Cláusulas de comportamiento e implementación

1. Lee este contrato y sus contratos superiores antes de actuar; detente en este nivel si la tarea
   solo exige una decisión de enrutamiento.
2. Antes de trabajo operativo, consulta [docs/workboard](<enlace-relativo-a-workboard>) y cumple su
   contrato.
3. <Criterio de colocación entre las capas del padre, esta rama y los frutos>.
4. Mantén los detalles específicos de cada fruto en su contrato; no crees abstracciones por anticipación.
5. Una semilla adquiere contrato propio solo cuando tiene responsabilidad independiente y real.
6. Para nuevos nodos, enlaza padre e hijo, y aplica la sincronización de mapas exigida por las leyes
   universales y la guía de plantillas.
7. Si cambia comportamiento de un fruto, modifica su contrato local; modifica esta rama solo si cambia
   una regla o el mapa que gobierna.

## 3. Mapa de hijos y tabla de enrutamiento

Incluye únicamente hijos existentes con responsabilidad contractual propia. Si no hay hijos, decláralo.

| Nodo | Nivel | Estado | Responsabilidad local | Contrato |
|---|---|---|---|---|
| `<ruta-hijo>/` | Fruto | implemented | <responsabilidad específica> | [ARCHITECTURE.md](<enlace-relativo>) |

Los hijos enlazan aquí como padre inmediato. Cambiar este mapa no sustituye la actualización de los
mapas superiores cuando sea requerida por la ley universal.

## 4. Criterios de colocación y dependencias

```text
<responsabilidad del padre>
    ↓
<responsabilidad de esta rama>
    ↓
<responsabilidades de los hijos>
```

- <Qué pertenece a esta rama>.
- <Qué debe quedarse en el padre>.
- <Qué debe quedarse en un fruto>.
- <Reglas de dependencia entre hermanos, si aplican>.

## 5. Términos y condiciones

1. **Autoridad**: este contrato está subordinado a `<contrato padre>` y a `docs/ARCHITECTURE.md`.
2. **Especialización**: concreta reglas superiores sin contradecirlas ni relajarlas.
3. **Integridad del mapa**: refleja solo hijos reales con contrato propio y enlaces verificables.
4. **Workboard**: mantiene en exclusiva estados, claims, autorizaciones y trazabilidad del trabajo.
5. **Conflicto**: ante una frontera ambigua o contradicción superior, detén la acción y solicita
   resolución.

---
*Fin del contrato de `<ruta-de-rama>/`. Sube a [<contrato padre>](<enlace-relativo>) o desciende a un hijo listado arriba.*
