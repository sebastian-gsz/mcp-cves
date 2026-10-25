---
id: NUC-004
title: "Tests pytest con fixtures de NVD + CI"
status: done
priority: P2
node: "."
parent: null
claimed_by: agent
claimed_at: 2026-10-23T23:58:32+02:00
created_at: 2026-10-22T02:50:00+02:00
updated_at: 2026-10-24T02:48:31+02:00
closed_at: 2026-10-24T02:48:31+02:00
closed_reason: null
touches:
  - tests/
  - tests/fixtures/nvd_response_sample.json
  - tests/test_nuc004.py
  - requirements.txt
  - requirements-dev.txt
  - ruff.toml
  - .github/workflows/ci.yml
  - ARCHITECTURE.md
blocks: [NUC-003]
blocked_by: []
acceptance:
  - "Cobertura de tests para los módulos puros (scoring, ports, utils, cpe_map) y para el parsing de respuestas NVD con fixtures grabadas"
  - "Banners hostiles y truncados no rompen el parsing (base para SEG-001)"
  - "CI ejecuta los tests en cada cambio (GitHub Actions o equivalente)"
subtasks:
  - "[x] Fixture JSON de respuesta NVD grabada (tests/fixtures/nvd_response_sample.json)"
  - "[x] Tests de módulos puros sin red ni disco (15 en test_nuc004; 97 en toda la suite)"
  - "[x] Pipeline de CI (ruff + pytest sobre Python 3.12/3.13) — VERDE en GitHub Actions"
external:
  - "https://github.com/sebastian-gsz/mcp-cves/actions/runs/40046695377"
decision_log:
  - "2026-10-23T23:58:32+02:00 (agent): CLAIM — NUC-003 (su bloqueada) requiere primero esta red de seguridad."
  - "2026-10-24T00:13:00+02:00 (agent): IMPLEMENTACIÓN — 15 tests + fixture + requirements-dev + workflow escritos."
  - "2026-10-24T01:45:00+02:00 (agent): EVIDENCIA LOCAL REAL — pytest 9.1.1: 97 passed (PDF incluido); ruff 0.17.2: 0 errores tras fixes + ruff.toml."
  - "2026-10-24T02:46:00+02:00 (agent): PUSH — el operador creó el repo sebastian-gsz/mcp-cves y un token fine-grained (Contents/Workflows RW + Actions R); primer commit (71 ficheros) empujado a main."
  - "2026-10-24T02:48:31+02:00 (agent): CIERRE — GitHub Actions run 40046695377: **success** (tests 3.12 y 3.13, todos los steps verdes: checkout, setup-python, apt nmap, pip install, ruff check, pytest). Criterio 3 cumplido; ítem cerrado. El commit de cierre de este ítem llega en un segundo push."
---

## Contexto

Ítem nº8 del plan de mejoras (bitácora
[2026-10-22-auditoria-y-plan-de-mejoras.md](../../../runbooks/2026-10-22-auditoria-y-plan-de-mejoras.md)).
El proyecto partía de 0 tests: cualquier refactor era a ciegas.

## Evidencia

1. **Módulos puros + parsing NVD (criterio 1)**: `tests/test_nuc004.py` 15/15 (ports, cpe_map,
   parsing de la fixture grabada con fallback CVSS v3.1→v2, construcción CPE 2.3); suite total 97.
2. **Banners hostiles (criterio 2)**: cubierto por SEG-001 (`test_seg001.py`: truncado, regex
   patológica, fórmulas CSV, escape XML).
3. **CI en cada cambio (criterio 3)**: push del 2026-10-24T02:46+02:00 →
   [run 40046695377](https://github.com/sebastian-gsz/mcp-cves/actions/runs/40046695377) →
   **success**: matriz Python 3.12 + 3.13, steps checkout/setup-python/nmap/pip/ruff/pytest
   todos verdes (verificado vía API con el token del operador; conclusión por job confirmada).
4. **Ejecución real local previa**: pytest 9.1.1 con dependencias reales → 97 passed, 6,15 s,
   incluido el test de PDF con reportlab (antes en skip); ruff limpio (109 autofixes + 7 manuales
   + `ruff.toml` documentando las exclusiones deliberadas BLE001/S110/S112).

## Límites de la validación

- El token fine-grained del operador se usó una sola vez para el push y la consulta del run; no se
  almacenó en ningún fichero, config de git ni documento (regla 10 del harness). Recomendación de
  revocación registrada al operador.
