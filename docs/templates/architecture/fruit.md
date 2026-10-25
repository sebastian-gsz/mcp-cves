---
title: ARCHITECTURE.md — Fruto «<nombre-del-sistema>»
Rol: <responsable técnico o funcional del sistema>
Objetivo: Regular y documentar <comportamiento específico del fruto>.
Nivel: Fruto
Estado: implemented
Padre: <ruta-relativa-al-ARCHITECTURE.md-padre>
Lectura obligatoria: SÍ — antes de inspeccionar o modificar archivos de este fruto.
---

<br>**↑ Padre**: [<contrato de rama>](<enlace-relativo-al-padre>) — <reglas y enrutamiento heredados>.<br/>

<!-- Si este nodo tiene hijos con ARCHITECTURE.md, añade aquí una tabla ↓ Hijos con enlaces. -->

## 1. Alcance y autoridad

Este contrato se aplica exclusivamente a `<ruta-del-fruto>/`. Documenta <comportamiento específico
aprobado>.

- **Entrada**: <datos, configuración y actores>.
- **Proceso**: <flujo específico del sistema>.
- **Salida**: <resultado, destino y efectos>.

Quedan fuera <responsabilidades de padre, hermanos u otros dominios>.

## 2. Cláusulas de comportamiento e implementación

1. Lee este contrato, el contrato del padre y la cadena superior antes de modificar el fruto.
2. Antes de trabajo operativo, consulta [docs/workboard](<enlace-relativo-a-workboard>) y cumple
   claim, autorización, bloqueos y criterios.
3. <Reglas específicas de entrada, validación y errores>.
4. <Separación local de responsabilidades y dependencias>.
5. <Reglas de configuración, datos sensibles y persistencia>.
6. Los cambios de comportamiento, archivos, símbolos públicos o dependencias requieren actualizar
   este contrato en la misma entrega.
7. No alteres ni relajes contratos superiores. Si el cambio requiere hacerlo, detén la ejecución y
   solicita resolución.

## 3. Mapa real de archivos y símbolos

<!-- Mantener solo si Estado: implemented. Contrastar cada archivo/símbolo con la implementación. -->

| Archivo | Responsabilidad comprobada | Símbolos / contenido |
|---|---|---|
| `<ruta/al/archivo>` | <responsabilidad actual> | `<función/clase/import>` |

## 4. Grafo funcional aprobado

<!-- Mantener solo si Estado: implemented. Mostrar flujo real; no incluir trabajo futuro. -->

```text
<punto de entrada>
    ↓
<módulo / función real>
    ↓
<dependencia / módulo real>
    ↓
<salida comprobada>
```

Dependencias aprobadas:

- <Límite de dependencias/imports comprobado>.
- <Errores y efectos externos comprobados>.

## 5. Configuración, datos y resultados

| Parámetro / dato | Fuente | Efecto |
|---|---|---|
| `<nombre>` | <CLI / entorno / archivo / default> | <comportamiento efectivo> |

## 6. Validación reproducible

- **Prueba o comando**: `<comando real aplicable>`
- **Superficie cubierta**: <qué verifica>.
- **Límites**: <qué no se ha ejecutado/verificado>.

No presentes pruebas no ejecutadas como aprobadas; conserva la evidencia de cada tarea en el Workboard.

## 7. Convenciones y antipatrones locales

- <Reglas propias del sistema>.
- <Acciones prohibidas o errores que deben aflorar explícitamente>.
- <Reglas locales de privacidad, seguridad o integridad>.

## 8. Términos y condiciones

1. **Autoridad**: este contrato está subordinado a `<contrato padre>` y a la cadena superior.
2. **Estado `implemented`**: mapa y grafo describen comportamiento existente, aprobado y contrastado,
   no trabajo futuro.
3. **Propiedad**: el conocimiento específico de este sistema permanece en este fruto; las reglas
   compartidas pertenecen al nivel compartido autorizado.
4. **Workboard**: es la fuente exclusiva para ciclo de trabajo, claims, autorizaciones y evidencia.
5. **Finalización y fallo**: comunica límites, errores y validaciones fallidas; no declares éxito
   completo si queda una condición de aceptación sin verificar.

---
*Fin del contrato de `<ruta-del-fruto>/`. Sube a [<contrato padre>](<enlace-relativo>) para las reglas de la rama.*
