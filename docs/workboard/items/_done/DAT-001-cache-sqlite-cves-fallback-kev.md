---
id: DAT-001
title: "Caché persistente SQLite de CVEs + fallback de última copia buena para KEV"
status: done
priority: P1
node: "."
parent: null
claimed_by: agente
claimed_at: 2026-10-23T01:52:40+02:00
created_at: 2026-10-22T02:50:00+02:00
updated_at: 2026-10-23T01:56:00+02:00
closed_at: 2026-10-23T01:56:00+02:00
closed_reason: null
touches:
  - intel_nvd.py
  - intel_kev.py
  - intel_epss.py
  - store.py
  - tests/test_dat001.py
  - ARCHITECTURE.md
  - docs/ARCHITECTURE.md
blocks: [DAT-002]
blocked_by: []
acceptance:
  - "Las consultas NVD por (CPE, versión) se sirven de SQLite con TTL 72h; solo se llama a la API si no hay copia vigente"
  - "KEV y EPSS se guardan como snapshot diario con fecha; si la descarga falla se usa la última copia buena y el informe declara su antigüedad"
  - "Un fallo de red total ya no produce informes subestimados en silencio (ley 11)"
subtasks:
  - "[x] Diseñar esquema de persistencia con TTL por tipo de dato"
  - "[x] Implementar store.py y conectarlo a intel_nvd/intel_kev/intel_epss"
  - "[x] Actualizar contrato del tronco en la misma entrega"
external:
  - null
decision_log:
  - "2026-10-23T01:52:40+02:00: CLAIM — continúa la autorización del operador («Comienza con las tareas más pequeñas»); DAT-001 es la siguiente tarea de bajo esfuerzo tras NUC-002."
  - "2026-10-23T01:53:30+02:00: DISEÑO — el esquema de dos tablas previsto (cves / intel_snapshots) se simplificó a UNA tabla kv genérica (key, payload_json, fetched_at) con TTL por tipo de dato (CVE 72h, EPSS/KEV 24h) y fallback de cualquier edad para KEV: mismas garantías de la aceptación con menos superficie. Añadido store.py e intel_epss.py a touches (ampliación trazable)."
  - "2026-10-23T01:54:00+02:00: ENTORNO — requests no está instalado en esta sesión: los tests inyectan un stub de requests y mockean todas las llamadas de red. La verificación es unitaria; no hubo red real."
  - "2026-10-23T01:54:30+02:00: NOTA DE DISEÑO — search_cves_by_cpe lanza una petición por variante de versión (_version_candidates: p. ej. 2.4.41/2.4/2) y cada variante se cachea por separado; un fallo transitorio NO se cachea (evita fijar «sin CVEs» durante 72h)."
---

## Contexto

Ítem nº1 del plan de mejoras priorizado en la bitácora
[2026-10-22-auditoria-y-plan-de-mejoras.md](../../../runbooks/2026-10-22-auditoria-y-plan-de-mejoras.md).
La caché de NVD moría con cada ejecución y un fallo de KEV devolvía un conjunto vacío que subestimaba
el informe sin avisar (violación de la ley 11 de degradación elegante).

## Evidencia

Ejecutado el 2026-10-23T01:55:30+02:00: `python3 tests/test_dat001.py` → **12/12 OK**
(y `tests/test_nuc002.py` sigue 6/6 OK, sin regresiones).

1. **NVD por CPE con TTL 72h** (`TestNvdCachePorCpe`): la 1ª consulta de
   `search_cves_by_cpe("cpe:2.3:a:apache:http_server", "2.4.41")` hace 3 peticiones (una por variante
   de versión); la repetición exacta hace **0** (`mreq.call_count` se mantiene en 3). Un fallo
   transitorio (`_nvd_request → {}`) no cachea nada: la consulta posterior vuelve a la API.
2. **KEV con fallback** (`TestKevFallback`): con copia local primada y red caída, `load_kev_set()`
   devuelve el set guardado e imprime `[!] KEV: descarga fallida (...); usando la última copia local
   (edad: 0:00:00)` — la antigüedad se declara, no se inventa un vacío. Sin copia local: aviso
   explícito de que los flags saldrán en «No» por falta de datos. Con éxito: guarda el snapshot.
3. **EPSS con caché 24h** (`TestEpssCache`): solo consulta la API de los CVEs sin copia vigente
   (mezcla cacheado+API = 1 sola petición, sin duplicados); con red caída sirve las copias locales y
   avisa de los CVEs que quedan sin dato (se puntúan como EPSS 0 de forma explícita, no silenciosa).
4. **Store** (`TestStore`): roundtrip, expiración por TTL (edad > max → None), `get_any` con edad, claves independientes.

**Código**: `store.py` nuevo (SQLite stdlib, tabla `kv`); `intel_nvd.py` cachea en disco las rutas CPE
y keyword; `intel_kev.py` e `intel_epss.py` reescritos con snapshot/fallback y avisos.

**Contratos**: tronco actualizado en la misma entrega (§3 filas store/tests, §4 grafo con la caché,
§5 `CVESCANNER_DB`, §7 antipatrones actualizados) y topología del mapa maestro (`data/` genera caché).

## Límites de la validación

- Verificación unitaria con red mockeada (el entorno no tiene `requests` ni salida de red garantizada);
  no se validó contra las APIs reales de NVD/FIRST/CISA.
- La reducción del ~90% de llamadas a NVD es estimación del plan; la medición real llegará con NUC-001.
