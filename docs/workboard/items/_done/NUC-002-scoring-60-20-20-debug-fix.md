---
id: NUC-002
title: "Reponderar score a 60/20/20 y corregir el DEBUG invertido"
status: done
priority: P1
node: "."
parent: null
claimed_by: agent
claimed_at: 2026-10-23T01:49:30+02:00
created_at: 2026-10-22T02:50:00+02:00
updated_at: 2026-10-23T01:52:30+02:00
closed_at: 2026-10-23T01:52:30+02:00
closed_reason: null
touches:
  - scoring.py
  - cve_scanner.py
  - config.py
  - tests/test_nuc002.py
  - ARCHITECTURE.md
  - docs/ARCHITECTURE.md
blocks: []
blocked_by: []
acceptance:
  - "compute_score usa 60% CVSS / 20% KEV / 20% EPSS y un CVE en KEV con CVSS 7.5 deja de quedar 17 puntos por debajo de un CVE teórico 9.8"
  - "Sin la variable DEBUG definida, el modo debug queda DESACTIVADO por defecto (hoy queda activado)"
  - "Test unitario que fija ambos comportamientos"
subtasks:
  - "[x] Cambiar pesos en scoring.py (mantiene escala 0-100)"
  - "[x] Corregir la lógica DEBUG en cve_scanner.py (None → False, vía config.debug_enabled())"
  - "[x] Actualizar contrato del tronco (§3 scoring/config/tests, §5 DEBUG, grafo) y topología del mapa maestro"
external:
  - null
decision_log:
  - "2026-10-23T01:49:30+02:00 (agent): CLAIM — autorización del operador recibida por conversación («Comienza con las tareas más pequeñas»); este ítem es la tarea de menor esfuerzo del plan."
  - "2026-10-23T01:51:00+02:00 (agent): AMPLIACIÓN DE ALCANCE — se añaden config.py y tests/test_nuc002.py al touches. Motivo: el test de DEBUG no puede importar cve_scanner en este entorno (python-nmap no instalado), así que la lógica de configuración se aísla en config.py (cero dependencias, ley 5) y main() la consume."
  - "2026-10-23T01:52:00+02:00 (agent): ENTORNO — el entorno no tiene pip ni pytest; los tests se escriben con unittest (stdlib), que cumple la aceptación «test unitario». La migración a pytest + CI queda en NUC-004."
---

## Contexto

Ítem nº3 del plan de mejoras (bitácora
[2026-10-22-auditoria-y-plan-de-mejoras.md](../../../runbooks/2026-10-22-auditoria-y-plan-de-mejoras.md)).
Con los pesos 95/2,5/2,5 la explotación activa confirmada (KEV) apenas movía el orden frente a CVSS
alto teórico; y la lógica de DEBUG estaba invertida: sin `.env`, `os.getenv("DEBUG")` devuelve `None`
y `None == 'False'` es falso, de modo que el modo verbose quedaba siempre activado.

## Evidencia

Ejecutado el 2026-10-23T01:51:30+02:00 (agente agent):

1. **Tests**: `python3 tests/test_nuc002.py -v` → **6/6 OK** (0,002 s):
   - `TestScoring60_20_20`: componentes puros (CVSS 10→60, KEV→20, EPSS 1→20), extremos (máx 100, mín 0)
     y **inversión corregida**: `compute_score(7.5, KEV, 0.9) = 83.0` > `compute_score(9.8, no-KEV, 0.01) = 59.0`
     (antes: 76,0 contra 93,1 — prioridad invertida; ahora el CVE explotado activamente supera al teórico por 24 puntos).
   - `TestDebugEnabled`: sin `DEBUG` → `False`; `1/true/TRUE/yes/on` → `True`; `False/0/""/no` → `False`.
2. **Código**: `scoring.py` usa 0.60/0.20/0.20; `cve_scanner.py` consume `config.debug_enabled()`
   (la lógica invertida desapareció); `config.py` nuevo, cero dependencias.
3. **Contratos**: contrato del tronco actualizado en la misma entrega (§1 alcance con `tests/`,
   §3 filas scoring/config/tests, §5 comportamiento DEBUG, grafo) y topología del mapa maestro (§2) con `tests/`.

## Límites de la validación

- No se ejecutó un escaneo real para observar el nuevo score en un informe completo (no hay red de
  objetivos autorizada en esta sesión); la verificación es unitaria.
- Los umbrales de color del PDF (90/80/70) no se tocaron: siguen siendo válidos con la nueva escala.
