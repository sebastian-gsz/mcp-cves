---
id: SEG-001
title: "Límites de longitud y escaping de datos hostiles en banners, CSV y PDF"
status: done
priority: P2
node: "."
parent: null
claimed_by: agent
claimed_at: 2026-10-23T01:58:30+02:00
created_at: 2026-10-22T02:50:00+02:00
updated_at: 2026-10-23T02:00:05+02:00
closed_at: 2026-10-23T02:00:05+02:00
closed_reason: null
touches:
  - utils.py
  - cpe_map.py
  - export_csv_pdf.py
  - tests/test_seg001.py
  - ARCHITECTURE.md
blocks: []
blocked_by: []
acceptance:
  - "Banners mayores de 500 caracteres se truncan antes de parsearse (mitiga ReDoS sobre BANNER_REGEX y las pistas de cpe_map)"
  - "Descripciones y banners provenientes de la red se escapan antes de inyectarse en CSV y PDF"
  - "Tests con banners trampa (expresiones regulares patológicas, metadatos PDF, UTF-8 malformado) pasan"
subtasks:
  - "[x] Truncado defensivo en la frontera de entrada (utils.parse_software_version_from_banner y cpe_map.resolve_cpe_bases)"
  - "[x] Escapado XML en export_pdf y neutralización de fórmulas en export_csv"
  - "[x] Tests de banners hostiles"
external:
  - null
decision_log:
  - "2026-10-23T01:58:30+02:00 (agent): CLAIM — continúa la autorización del operador («Comienza con las tareas más pequeñas»); SEG-001 es la tercera tarea de bajo esfuerzo."
  - "2026-10-23T01:59:00+02:00 (agent): DISEÑO — reportlab pasa a importarse de forma perezosa dentro de export_pdf(): la ruta CSV ya no lo requiere y el módulo queda testeable sin reportlab (que no está instalado aquí). Se añade tests/test_seg001.py a touches (ampliación trazable)."
  - "2026-10-23T01:59:30+02:00 (agent): ALCANCE DE LA ACEPTACIÓN — el criterio «metadatos PDF» se verifica a nivel de escaping XML en _clean_text (los valores llegan al PDF escapados); la generación real de PDF no se ejecuta por falta de reportlab (test marcado skip con motivo). «UTF-8 malformado» cubierto por el normalizado latin-1 preexistente + escape, verificado en test_clean_text_escapa_xml."
---

## Contexto

Ítem nº7 del plan de mejoras (bitácora
[2026-10-22-auditoria-y-plan-de-mejoras.md](../../../runbooks/2026-10-22-auditoria-y-plan-de-mejoras.md)).
El escáner procesa datos de hosts que no controlamos: un banner trampa llegaba sin límite de longitud
a las regex (ReDoS) y sin escapar a los generadores CSV (inyección de fórmulas) y PDF (inyección de
markup en Paragraph).

## Evidencia

Ejecutado el 2026-10-23T01:59:45+02:00 (agente agent): `python3 tests/test_seg001.py` → **7/8 OK,
1 skip** (motivo declarado: reportlab no instalado). Suite completa sin regresiones:
`test_nuc002.py` 6/6 OK, `test_dat001.py` 12/12 OK — **26 tests en total**.

1. **Truncado**: banner de ~20 KB se reduce a 500 chars antes de regex; el parseo de banners con
   regex patológica (`1.1.1...` ×5000) termina en milisegundos; `cpe_map` con banner de 10 KB
   resuelve CPE correcto.
2. **Escaping PDF**: `_clean_text("<b>&x</b>")` → `&lt;b&gt;&amp;x&lt;/b&gt;` (markup neutro para Paragraph).
3. **CSV anti-fórmulas**: host `=HYPERLINK(...)` sale como `'=HYPERLINK(...)`; datos normales
   (`192.168.1.10`, `nginx/1.18.0`) pasan intactos.
4. **Contratos**: tronco actualizado en la misma entrega (§3 filas utils/cpe_map/export_csv_pdf/tests,
   §7 con las garantías SEG-001 activas).

## Límites de la validación

- La generación real de PDF no se ejecutó (reportlab ausente en el entorno); el escaping está
  verificado a nivel unitario y el test de PDF queda listo para correr cuando haya reportlab (NUC-004/CI).
- No se probaron respuestas NVD envenenadas a tamaño real (limitación de red); el truncado de banners
  cubre la vía de entrada principal (`banner`), y `description` de NVD va recortada a 220 chars por
  `cve_scanner.py` antes del hallazgo.
