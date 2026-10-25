---
title: ARCHITECTURE.md — Dominio Runbooks
Rol: Registro de procedimientos y ejecuciones reales
Objetivo: Definir el contrato de los runbooks (procedimientos reutilizables) y las bitácoras (registros históricos de ejecuciones).
Nivel: Rama raíz documental
Estado: contract
Padre: ../ARCHITECTURE.md
Lectura obligatoria: SÍ — antes de crear, modificar o citar runbooks o bitácoras.
---

<br>**↑ Padre**: [docs/ARCHITECTURE.md](../ARCHITECTURE.md) — mapa maestro y leyes universales.<br/>

## 1. Alcance y autoridad

`docs/runbooks/` contiene dos tipos de documento con separación estricta:

- **Runbook**: procedimiento reutilizable que indica cómo realizar una operación
  (`<tema>-<entorno>.md`).
- **Bitácora**: registro histórico de una ejecución real y fechada
  (`YYYY-MM-DD-<tema>-<entorno>.md`; si la fecha del evento se desconoce: `sin-fecha-<tema>-<entorno>.md`
  y se registra aparte la fecha de documentación — nunca se convierte una en la otra).

Queda fuera: el estado de trabajo futuro (Workboard), las reglas arquitectónicas (contratos) y las
decisiones con autoridad normativa (mapa maestro).

## 2. Mapa del nodo

| Archivo o directorio | Responsabilidad |
|---|---|
| `README.md` | Procedimiento resumido de alta, revisión y archivo de documentos. |
| `INDEX.md` | Índice sincronizado de runbooks y bitácoras vigentes. |
| `_template-runbook.md` | Plantilla de runbook (artefacto, no documento vigente). |
| `_template-bitacora.md` | Plantilla de bitácora (artefacto, no documento vigente). |
| `YYYY-MM-DD-<tema>-<entorno>.md` | Runbooks y bitácoras reales. |

## 3. Cláusulas de comportamiento e implementación

1. Los agentes pueden redactar borradores; la aprobación y vigencia las decide el operador.
   `document_status: reviewed` solo tras aprobación expresa.
2. Distinguir siempre: observación directa / información del operador / conclusión / incertidumbre.
   No presentar un relato de segunda mano como verificación independiente.
3. Revisión de secretos obligatoria antes de publicar (`<REDACTED>`, nombres de variables sin valor).
4. No convertir recomendaciones en hechos ejecutados; las acciones futuras requieren ítem autorizado
   en el [Workboard](../workboard/README.md).
5. `INDEX.md` sincronizado en la misma entrega con cada alta, renombre o retirada.
6. No duplicar SOP del operador: en caso de duda, una única ubicación canónica.

## 4. Términos y condiciones

1. **Autoridad**: subordinado a `docs/ARCHITECTURE.md`.
2. **Historicidad**: las bitácoras son históricas; las correcciones conservan trazabilidad y no
   reescriben el pasado.
3. **Vigencia**: un runbook o bitácora describe su momento; no se extrapola al presente sin
   verificación posterior.
4. **Conflicto**: ante contradicción con un contrato superior, prevalece el contrato y se documenta
   el conflicto en el documento afectado.

---
*Fin del contrato del dominio Runbooks. Sube a [docs/ARCHITECTURE.md](../ARCHITECTURE.md) para las normas superiores.*
