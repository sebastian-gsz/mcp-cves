# Runbooks — Procedimientos y bitácoras

Contrato del nodo: [ARCHITECTURE.md](./ARCHITECTURE.md).

| Tipo | Nombre | Contenido |
|---|---|---|
| **Runbook** | `<tema>-<entorno>.md` | Procedimiento reutilizable: cómo realizar una operación (pasos, verificación, rollback). |
| **Bitácora** | `YYYY-MM-DD-<tema>-<entorno>.md` | Registro histórico de una ejecución real y fechada. Si la fecha del evento se desconoce: `sin-fecha-<tema>-<entorno>.md`. |

## Reglas esenciales

1. Plantillas: [_template-runbook.md](./_template-runbook.md) y [_template-bitacora.md](./_template-bitacora.md).
2. Los agentes redactan borradores (`document_status: draft`); solo el operador aprueba (`reviewed`).
3. Separar siempre: hecho verificado / informado / conclusión / incertidumbre.
4. Revisión de secretos antes de publicar: valores por `<REDACTED>` o nombre de variable.
5. Las recomendaciones de una bitácora NO son trabajo ejecutado: las acciones futuras se registran
   como ítems en el [Workboard](../workboard/README.md).
6. Índice: [INDEX.md](./INDEX.md) se sincroniza en la misma entrega con cada alta, renombre o retirada.
