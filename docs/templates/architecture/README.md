# Plantillas de `ARCHITECTURE.md`

Estas plantillas permiten crear contratos locales coherentes sin reescribir las leyes del proyecto.
Son artefactos de diseño, no nodos contractuales. No copies una plantilla sin leer primero el mapa
maestro ([docs/ARCHITECTURE.md](../../ARCHITECTURE.md)) y la cadena de contratos superiores.

## Selección

| Tipo del nodo | Plantilla |
|---|---|
| Tronco subordinado | [Tronco](trunk.md) |
| Rama | [Rama](branch.md) |
| Fruto | [Fruto](fruit.md) |

El tronco maestro del repositorio (docs/ARCHITECTURE.md) tiene función singular y no se crea a partir
de estas plantillas. `contract` e `implemented` describen el estado del contrato, no el nivel del nodo.

## Protocolo de creación y actualización topológica

1. Lee `docs/ARCHITECTURE.md` y desciende por los contratos del padre inmediato hasta el nodo objetivo.
   Resuelve conflictos antes de redactar.
2. Copia la plantilla de nivel correcto al nodo real como `ARCHITECTURE.md`. Sustituye todos los
   marcadores, elimina las instrucciones de autoría y no dejes secciones de plantilla vacías.
3. Define solo alcance, reglas, responsabilidades, límites y comportamiento específico del sistema.
   No dupliques las leyes superiores ni relajes sus obligaciones.
4. Añade al contrato local un enlace hacia su padre y enlaza el nodo nuevo desde la tabla o mapa del
   padre inmediato. Mantén los enlaces relativos correctos.
5. Si el nodo nuevo es tronco raíz, rama raíz o fruto, actualiza en la misma entrega la topología (§2)
   y la tabla de ruteo (§3) del mapa maestro, según la ley universal de enrutamiento. Una semilla solo
   se añade al mapa maestro si alcanza el nivel que esa ley define.
6. Para modificaciones de comportamiento en un nodo existente, actualiza el contrato local. Actualiza
   padre y maestro únicamente si también cambia una regla del padre o la topología que ellos gobiernan;
   no propagues cambios locales sin motivo.
7. `contract`: conserva reglas, compromisos, términos, límites, responsabilidades y rutas. No añadas
   descripción operativa detallada ni pendientes.
8. `implemented`: además del contrato, documenta únicamente el comportamiento funcional aprobado que
   hayas contrastado con la implementación: mapa real de archivos/símbolos y grafo de dependencias o
   ejecución. Si no puedes verificar una parte, declara el límite; no completes con suposiciones.
9. Registra tarea, claim, evidencia, decisión y cierre exclusivamente en el Workboard conforme a su
   contrato. Ningún `ARCHITECTURE.md` mantiene estados de trabajo.
10. Antes de cerrar, valida: existencia de cada ruta y enlace, coincidencia entre hijos reales y
    tablas, sincronización de topología requerida, ausencia de marcadores y ausencia de backlog o
    estados de tarea en los contratos.

Las plantillas incluyen obligaciones heredadas de navegación, precedencia, Workboard y mantenimiento.
No reemplazan el contrato padre ni autorizan por sí mismas la creación del nodo o la ejecución de cambios.
