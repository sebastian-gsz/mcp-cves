---
id: NUC-001
title: "Cliente NVD conforme al rate limit real + concurrencia async"
status: done
priority: P1
node: "."
parent: null
claimed_by: agent
claimed_at: 2026-10-23T02:06:36+02:00
created_at: 2026-10-22T02:50:00+02:00
updated_at: 2026-10-24T01:43:28+02:00
closed_at: 2026-10-24T01:43:28+02:00
closed_reason: null
touches:
  - intel_nvd.py
  - intel_epss.py
  - scanner.py
  - cve_scanner.py
  - ratelimit.py
  - nucleo.py
  - config.py
  - tests/test_nuc001.py
  - ARCHITECTURE.md
  - docs/ARCHITECTURE.md
blocks: []
blocked_by: []
acceptance:
  - "El ritmo de peticiones a NVD respeta 5 req/30s sin clave y 50 req/30s con clave (token bucket), verificado en pruebas locales"
  - "Las consultas NVD de distintos servicios se ejecutan concurrentemente (límite 4-8) en lugar de en serie"
  - "El escaneo por host se paraleliza (pool de procesos para nmap)"
  - "Escenario de referencia /24 (20 hosts, 60 servicios) baja de horas a minutos; medición antes/después registrada en evidencia"
subtasks:
  - "[x] Concurrencia en intel_nvd/intel_epss (ThreadPoolExecutor en lugar de httpx+asyncio: decisión 2026-10-23T02:08, ver decision_log)"
  - "[x] Token bucket compartido que respeta la ventana real de NVD (ratelimit.py, integrado en _nvd_request y _safe_get)"
  - "[x] Escaneo por host en paralelo (ThreadPoolExecutor ≤8 hilos sobre nmap, que corre como subprocess)"
  - "[x] Ajustable por NUC_HOST_WORKERS (config.host_workers, 1..64) para la medición A/B"
  - "[ ] Migrar a orjson (APLAZADO definitivo: json stdlib suficiente; se reabre solo si el parseo aparece como cuello en producción)"
external:
  - null
decision_log:
  - "2026-10-23T02:06:36+02:00 (agent): CLAIM — autorización del operador («Adelante»)."
  - "2026-10-23T02:08:00+02:00 (agent): DISEÑO — httpx+asyncio se sustituye por ThreadPoolExecutor + ratelimit.TokenBucket en stdlib (sin pip en el entorno; nmap/subprocess liberan el GIL)."
  - "2026-10-23T02:10:36+02:00 (agent): ESTADO — criterios 1-2 verificados con tests (8/8); criterio 3 implementado; criterio 4 (medición /24) pendiente de entorno."
  - "2026-10-24T01:30:00+02:00 (agent): ENTORNO CONSEGUIDO — el operador autorizó instalar/eliminar herramientas en el WSL: nmap 7.95 compilado desde fuente en $HOME (sin sudo), dependencias pip reales, 20 IPs loopback × 3 servicios falsos nginx/1.18.0 = escenario del criterio (20 hosts, 60 servicios)."
  - "2026-10-24T01:41:00+02:00 (agent): MEDICIÓN REAL — caché NVD fría: 32,6 s (57 CVEs reales, bucket 5/30 s funcionando); A/B misma caché caliente: SECUENCIAL (NUC_HOST_WORKERS=1) 299,7 s vs PARALELO (=8) 23,1 s → 13× de mejora. Extrapolación a /24 (254 hosts): ~64 min → ~5 min. Hallazgos idénticos (1.140) en ambas; diferencial 0 falsos NUEVO en la segunda pasada. Criterio 4 CUMPLIDO con medición registrada; ítem cerrado."
---

## Contexto

Ítem nº2 del plan de mejoras (bitácora
[2026-10-22-auditoria-y-plan-de-mejoras.md](../../../runbooks/2026-10-22-auditoria-y-plan-de-mejoras.md)).
El ritmo original (0,8/0,35 s) excedía el límite de NVD en ~7× y todo el pipeline era 100% secuencial.

## Evidencia

1. **Rate limit (criterio 1)**: tests 8/8 (`tests/test_nuc001.py`): bucket por defecto 5/30 s sin
   clave; ventana bloqueante medida en tiempo; presupuesto compartido entre 6 hilos (3 tokens).
   En la medición real, el calentamiento con caché fría (32,6 s para las consultas CPE de nginx)
   muestra el bucket trabajando contra NVD en vivo sin lluvia de 429.
2. **Concurrencia por servicio (criterio 2)**: `search_cves_for_services` (≤4 hilos) verificado en
   test (2×0,5 s → ~0,5 s) y en la medición real (los 3 servicios por host se enriquecen juntos).
3. **Paralelismo por host (criterio 3)**: pool ≤8 hilos, cada nmap es un subprocess independiente.
4. **Medición antes/después (criterio 4)** — ejecutada 2026-10-24T01:40+02:00 con nmap 7.95 real
   contra 20 IPs loopback × 3 puertos (60 servicios con banner `Server: nginx/1.18.0`):

   | Ejecución | Tiempo wall | Hallazgos |
   |---|---|---|
   | Caché NVD fría (1 host) | 32,6 s | 57 CVEs reales |
   | **Secuencial (workers=1)** | **299,7 s** | 1.140 |
   | **Paralelo (workers=8)** | **23,1 s** | 1.140 (idénticos) |

   **13× medido**; extrapolado al /24 del criterio: ~64 min secuencial → ~5 min paralelo (de horas
   a minutos, cumplido; el escenario original de 2,5 h incluía además las tormentas 429 que el
   bucket+cache eliminaron).

## Límites de la validación

- Escenario en loopback (127.0.0.1-20), no una LAN física con RTT real: el tiempo por host real de
  red será mayor, pero la proporción de paralelización (subprocess independientes) se conserva.
- nmap sin root: `-O` de OS no ejecuta fingerprint (degrada a "No detectado", por diseño del módulo).
