---
id: INT-003
title: "PSIRT multi-vendor: advisories de Red Hat + Ubuntu más rápidos que NVD (día 0-1)"
status: done
priority: P3
node: "."
parent: null
claimed_by: agent
claimed_at: 2026-10-24T16:21:17+02:00
created_at: 2026-10-24T11:45:16+02:00
updated_at: 2026-10-24T16:36:00+02:00
closed_at: 2026-10-24T16:36:00+02:00
closed_reason: null
touches:
  - intel_psirt.py
  - intel_nvd.py
  - nucleo.py
  - mcp_server.py
  - export_csv_pdf.py
  - tests/test_int003.py
  - ARCHITECTURE.md
blocks: []
blocked_by: []
acceptance:
  - "Dos vendors con API pública gratuita y sin OAuth (verificados en F0): Red Hat Security Data API y Ubuntu CVE API — caché TTL 6 h"
  - "Dado un CVE, devuelve el advisory del vendor con severidad propia, fecha pública y estado (USN) cuando exista; degradación elegante con última copia"
  - "Detección de 'advisory anticipa a NVD' con brecha temporal visible en el informe"
  - "MCP tool `advisories(cve_id)` (sin red local: operativa sin whitelist); tests con fixtures de ambos vendors"
subtasks:
  - "[x] F0: Red Hat verificado en vivo (threat_severity/public_date/cvss3 sin auth); Ubuntu: endpoint por-CVE no existe (404) pero el bulk /security/cves.json?q= sí funciona — filtrado por id exacto"
  - "[x] F1: intel_psirt.py con TTL 6 h; fallo de red degrada a la última copia y NUNCA cachea como 'sin advisory'"
  - "[x] F2: 12 tests con fixtures tomadas de las respuestas reales (RH completa, Ubuntu con parciales + USN, 404, sin registro, fallo de red, gap días, MCP con/sin advisory, ID inválido)"
  - "[x] F3: wiring (nucleo columna psirt con gap, intel_nvd.get_cve para la fecha de NVD, MCP tool advisories, CSV columna psirt) y contrato"
external:
  - "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2023-44487.json"
  - "https://ubuntu.com/security/cves.json?q=CVE-2023-44487"
decision_log:
  - "2026-10-24T11:45:16+02:00 (agent): CREACIÓN — plan de integraciones del operador."
  - "2026-10-24T16:21:17+02:00 (agent): CLAIM — el operador pidió implementarla mientras activa la integración Docker."
  - "2026-10-24T16:18:00+02:00 (agent): F0 — endpoint per-CVE de Ubuntu no existe (404) y api.canonical.com no responde; el bulk con q= sí y filtra por id exacto. Red Hat directo, como se verificó en el plan. Tercer vendor con OAuth (Cisco) queda fuera de v1."
  - "2026-10-24T16:33:00+02:00 (agent): BUGS PROPIOS CAZADOS POR TESTS — (1) SyntaxError por paréntesis descompensado en el fixture NVD del test; (2) get_cve referenciaba CVE_TTL_S inexistente en intel_nvd (es store.CVE_TTL_S). Ambos corregidos; suite en verde."
---

## Contexto

NVD es canónico pero arrastra lag de enriquecimiento; los PSIRT de los vendors publican a menudo
ANTES. Este ítem añade la capa de velocidad: severidad y estado según el vendor el día 0, y la
brecha temporal respecto a NVD queda visible en el informe.

## Evidencia

Ejecutado el 2026-10-24T16:35+02:00 (agente agent): `python3 tests/test_int003.py` → **12/12 OK**;
suite completa **136 tests, 0 fallos**.

1. **Red Hat** (`TestRedhat`): fixture de la respuesta REAL (F0) → severidad `Important`, fecha
   `2023-10-10`, CVSS 7.5; 2ª consulta = 0 peticiones (TTL 6 h); 404 = "Red Hat no lo cubre"
   (None cacheable, respuesta válida); fallo de red → copia local avisando (ley 11).
2. **Ubuntu** (`TestUbuntu`): búsqueda `q=` devuelve parciales → se filtra por id exacto
   (el fixture real incluye un CVE no solicitado y se ignora); priority `High` + USN-6427-1
   visibles; sin registro → None.
3. **Brecha temporal** (`TestGapYResumen`): `dias_anticipa` calcula 3/-3/None; `resumen_con_gap`
   marca `[anticipa NVD 4d]` con el máximo de ambos vendors, sin marca si 0 o negativo.
4. **NVD por ID** (`TestNvdGetCve`): `get_cve` devuelve published/cvss/description con caché;
   CVE inexistente → None.
5. **MCP tool** (`TestMcpAdvisories`): `advisories(cve-2023-44487)` (minúsculas → normaliza) →
   severidad vendor + gap + fecha NVD; sin advisories → mensaje claro; ID con formato incorrecto
   → isError.
6. **Wiring**: `nucleo._escanear_host` añade `psirt` a cada hallazgo (resumen con gap usando la
   fecha `published` de NVD); CSV con columna `psirt`; contrato §3/§7 en la misma entrega.

## Límites de la validación

- Consultas a RH/Ubuntu con fixtures (verificación en vivo hecha en F0 del endpoint, no del flujo
  completo); el gap real vendor-vs-NVD depende de cada CVE (con el de prueba ambos publicaron el
  mismo día → sin marca, comportamiento correcto comprobado).
- Cisco OpenVuln (OAuth) y otros vendors quedan para una v2 si el operador lo pide.
