---
title: "Verificación en el propio WSL del operador — cierres de NUC-001 y MCP-001"
type: execution-log
document_status: draft
outcome: "97 tests reales en verde (pytest+reportlab), ruff limpio, medición A/B 13× con nmap real, escaneo real vía cliente MCP oficial; 2 ítems cerrados; herramientas instaladas y ELIMININADAS según lo acordado"
system: "mcp-cves"
environment: "WSL2 Kali del operador (sin sudo; con Internet, node y gcc)"
execution_date: "2026-10-24"
recorded_date: 2026-10-24
version: "post NUC-003/MCP-001; suite 97 tests"
source: "Ejecución directa  en el WSL del operador (autorización explícita para instalar y luego eliminar)"
confidence: "directly-verified"
---

# Verificación en el propio WSL — cierres de NUC-001 y MCP-001

## Objetivo y alcance

El operador autorizó («instala lo que requieras y luego elimínalo») usar el propio WSL como entorno
de verificación. Se ejecutaron las evidencias que faltaban para `NUC-001` (medición A/B real) y
`MCP-001` (cliente MCP oficial), y se fortaleció `NUC-004` (pytest/ruff reales). Todo lo instalado
se eliminó al final (ver Limpieza).

## Fuente y límites de evidencia

Todo lo registrado aquí es **verificación directa** (comandos ejecutados y sus salidas). Límite:
`INF-001` no se pudo verificar (sin sudo y con la integración Docker Desktop desactivada).

## Entorno observado

- Kali GNU/Linux Rolling, WSL2, 2 núcleos, systemd presente; **sudo requiere password** (sin apt);
  Internet OK; node/npm 24.x y gcc/make preexistentes; sin pip, sin nmap, sin docker al inicio.

## Pasos ejecutados

1. **Acción**: pip de usuario vía `get-pip.py --user --break-system-packages`; `pip install -r
   requirements.txt -r requirements-dev.txt` (las 8 versiones pineadas resolvieron en Python 3.14).
   **Resultado**: requests/reportlab/tabulate/scapy/python-nmap/pytest/ruff reales.
2. **Acción**: `pytest tests/` con dependencias reales.
   **Resultado**: **97 passed en 6,15 s**, incluido el test de PDF con reportlab (antes skip).
3. **Acción**: `ruff check .` → 148 avisos; 109 autofixes + 7 limpiezas manuales (variables sin
   usar, Optional implícito, ClassVar) + `ruff.toml` ignorando BLE001/S110/S112 con justificación
   (degradación elegante deliberada, ley 11). **Resultado**: 0 errores; suite sigue en verde.
4. **Acción**: compilar **nmap 7.95 desde fuente** en `/tmp/nmap-7.95` (sin sudo; el fallo inicial
   de libpcre/aclocal se resolvió satisfaciendo timestamps), wrapper en `~/.local/nmap-bin/nmap`.
   **Resultado**: `Nmap version 7.95`; servicios falsos con banner `Server: nginx/1.18.0` en
   8021-8023 visibles desde 20 IPs loopback (20 hosts × 3 servicios = 60).
5. **Acción**: medición A/B de `NUC-001` (`/tmp/ab/medicion.py`, caché caliente):
   **Resultado**: secuencial (NUC_HOST_WORKERS=1) **299,7 s** vs paralelo (=8) **23,1 s** → **13×**;
   1.140 hallazgos idénticos; calentamiento con caché fría 32,6 s (57 CVEs reales de NVD, bucket
   5/30 s); diferencial sin falsos NUEVO; extrapolación /24: ~64 min → ~5 min.
6. **Acción**: MCP Inspector oficial (`npx @modelcontextprotocol/inspector --cli`):
   handshake + tools/list (4) + `puntuar` → 97.8 + **fail-closed** (el Inspector no propaga el
   entorno del padre y el servidor se negó correctamente) + **escaneo real autorizado** de
   127.0.0.5:8021-8023 vía wrapper con `MCP_ALLOWED_CIDRS=127.0.0.0/8`:
   **Resultado**: 57 hallazgos con KEV/EPSS reales (CVE-2023-44487 en KEV, EPSS 1.000, score 85.0),
   diferencial PERSISTENTE, CSV+PDF reales, isError=false.
7. **Acción**: probar docker. **Resultado**: integración Docker Desktop desactivada en este
   distro; `INF-001` queda para el sandbox.

## Verificación

| Comprobación | Resultado observado | Fuente |
|---|---|---|
| pytest con deps reales | 97 passed, 6,15 s (PDF incluido) | directa |
| ruff check | 0 errores tras fixes + config | directa |
| nmap 7.95 compilado | detecta `nginx 1.18.0` en 3 puertos loopback | directa |
| A/B NUC-001 | 299,7 s → 23,1 s (13×) | directa |
| NVD real con bucket | 32,6 s de calentamiento, sin tormentas 429 | directa |
| Inspector MCP: tools/call escanear | 57 hallazgos reales, CSV+PDF, isError false | directa |
| Inspector MCP sin entorno | fail-closed con instrucción | directa |
| docker ps | daemon inalcanzable (integración desactivada) | directa |

## Problemas y resolución

| Incidencia | Diagnóstico | Resolución | Resultado |
|---|---|---|---|
| pip bloqueado (PEP 668) y sin sudo | distro gestionado | get-pip.py --user --break-system-packages | pip de usuario funcional |
| Compilación nmap fallaba en libpcre (aclocal 127) | make quería regenerar aclocal.m4 sin automake | touch de timestamps autotools | build completo OK |
| Inspector "no ve" MCP_ALLOWED_CIDRS | el CLI no propaga el entorno del padre al servidor | wrapper que exporta el entorno; el fallo intermedio quedó como evidencia de fail-closed | escaneo real autorizado OK |

## Rollback

Se ejecutó íntegro (ver sección Limpieza): servicios parados, nmap y fuentes borrados, paquetes pip
de usuario desinstalados, cachés de npx/pytest/ruff y artefactos de salida eliminados.

## Estado al cierre

- **Cerrados**: `NUC-001` (medición 13×) y `MCP-001` (cliente oficial + escaneo real). Tablero:
  9 cerrados, 2 en progreso (`NUC-004`: solo falta push a GitHub; `INF-001`: solo falta Docker).
- El proyecto queda **verificado en su totalidad salvo CI-push y build Docker**.

## Aspectos no acreditados

- CI de GitHub Actions no ejecutado (sin remoto del operador).
- Imagen Docker no construida (daemon inaccesible en este WSL).
- La extrapolación a /24 de la medición A/B asume proporcionalidad por host (documentada en el ítem).

## Limpieza (lo instalado y luego eliminado)

- Procesos: servidor de servicios falsos (8021-8023) detenido.
- Ficheros: `/tmp/nmap-7.95*`, `/tmp/ab`, `/tmp/get-pip.py`, `~/.local/nmap-run`, `~/.local/nmap-bin`,
  `~/.npm/_npx` (Inspector), `.pytest_cache`, `.ruff_cache`, `__pycache__`, `outputs/` generados,
  `data/cache.sqlite3` de pruebas.
- Paquetes pip de usuario: los 8 de requirements + sus dependencias transitivas, desinstalados
  (el user-site queda como estaba).

## Trazabilidad

- Workboard: cierres `NUC-001`, `MCP-001`; evidencia añadida a `NUC-004` e `INF-001`.
- Contratos: sin cambios de comportamiento (los fixes de ruff son de estilo); el tronco §6 pasa a
  citar pytest/ruff como validación reproducible.
- Fecha de registro: 2026-10-24T01:46:00+02:00 (Europe/Madrid).
