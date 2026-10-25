---
title: "Verificación final en sandbox — cierre de NUC-001, NUC-004, INF-001 y MCP-001"
type: runbook
document_status: draft
system: "mcp-cves"
environment: "sandbox (Linux con pip, nmap, Docker, git y salida a Internet)"
version: "1.0"
last_reviewed: 2026-10-24
owner: "uhm"
---

# Verificación final en sandbox — cierre de NUC-001, NUC-004, INF-001 y MCP-001

## Objetivo

Ejecutar en un entorno completo la evidencia que falta para cerrar los 4 ítems `in_progress`
del Workboard y archivarlos con medición real, no simulada.

## Alcance y límites

Cubre exclusivamente la verificación; NO introduce funcionalidad nueva. Solo se escanea
`127.0.0.1` y una red de pruebas aislada (rango de documentación `192.0.2.0/24`, TEST-NET-1,
no enrutable en Internet). Condición de parada: si un paso deja el entorno inestable, parar y
registrar la incidencia en el ítem correspondiente.

## Requisitos

- Linux x64 con **Python 3.10+ y pip** con salida a Internet (o proxy/wheels).
- **sudo/root o capabilities `NET_RAW`+`NET_ADMIN`** (ARP de scapy, SYN scan, OS fingerprint).
- **nmap** instalado (`apt-get install nmap`).
- Salida HTTPS a `services.nvd.nist.gov`, `api.first.org`, `www.cisa.gov`.
  `NVD_API_KEY` opcional (sin ella: 5 req/30 s — el token bucket ya lo respeta).
- **Docker Engine + plugin compose**.
- **git + remoto en GitHub** (solo para el cierre pleno de NUC-004; sin él, NUC-004 queda en
  "pytest local verificado").
- Node/npm solo si se usa MCP Inspector para MCP-001 (alternativa: conectar agent/Claude Desktop).

## Pasos

1. **Dependencias reales**: `pip install -r requirements.txt -r requirements-dev.txt`.
2. **Suite con runner real**: `python -m pytest tests/ -v` → esperados **97 OK, 0 fallos,
   0 skips** (el test de PDF ya no se salta: reportlab instalado).
3. **Humo CLI (criterio E2E de NUC-003/DAT-002)**: `python3 cve_scanner.py` → IP `127.0.0.1`,
   puertos abiertos conocidos (p. ej. `22,80`). Verificar CSV+PDF en `outputs/` y que una
   **segunda pasada** marca los servicios como `PERSISTENTE` (cero falsos NUEVO).
4. **Red de pruebas aislada** (objetivo autorizado para la medición):
   `docker network create --subnet 192.0.2.0/24 vulntest` y levantar 5-6 contenedores
   (nginx, openssh-server, busybox httpd…) en esa red.
5. **NUC-001 — medición A/B** con `MCP_ALLOWED_CIDRS=192.0.2.0/24` y `CVESCANNER_DB` temporal:
   - `NUC_HOST_WORKERS=1` → `time python3 -c ...nucleo.escanear(hosts, puertos)` (secuencial).
   - Default (8) → misma medición (paralelo).
   - Caché fría vs caliente: repetir y registrar la caída de llamadas NVD.
   - Registrars los tiempos en la evidencia del ítem NUC-001 y cerrarlo.
6. **INF-001**: `docker compose build`; verificar usuario no root
   (`docker run --rm --entrypoint id mcp-cves` → `scanner`); humo
   `docker compose run --rm vulnscan` contra la red de pruebas; cerrar el ítem.
7. **MCP-001**: conectar un cliente real — Inspector (`npx @modelcontextprotocol/inspector
   python3 mcp_server.py`) o configuración de agent/Claude Desktop con
   `MCP_ALLOWED_CIDRS=127.0.0.0/8,192.0.2.0/24` — y ejercitar `tools/list`, `puntuar`,
   `buscar_cves`, `descubrir_hosts`, `escanear` (incluido un rechazo fail-closed fuera de
   whitelist); cerrar el ítem.
8. **NUC-004**: `git init` + remoto + push → GitHub Actions (ruff + pytest en 3.12/3.13);
   si ruff señala estilo, corregir y volver a push; cerrar el ítem con el run verde.
9. **Cierre de sesión de verificación**: archivar los 4 ítems en `items/_done/`, actualizar
   `INDEX.md`, y registrar una bitácora de ejecución con los números medidos.

## Verificación

| Comprobación | Resultado esperado |
|---|---|
| `python -m pytest tests/ -v` | 97 passed, 0 failed, 0 skipped |
| Segunda pasada del humo CLI | todos los servicios `PERSISTENTE`; CSV/PDF regenerados |
| A/B NUC-001 | paralelo(8) significativamente menor que secuencial(1); registrar ambos tiempos |
| `docker run --entrypoint id mcp-cves` | uid/gid de `scanner`, no root |
| Cliente MCP | 4 tools listadas; escaneo autorizado OK; fuera de whitelist → isError fail-closed |
| GitHub Actions | workflow CI verde en ambas versiones de Python |

## Problemas y resolución

| Síntoma | Causa verificada | Resolución |
|---|---|---|
| 429 de NVD masivos | API key ausente y consultas nuevas frecuentes | Es esperado sin key: el bucket limita a 5/30 s; esperar o configurar `NVD_API_KEY` |
| ARP sin resultados en sandbox | faltan capabilities o la red docker no contesta ARP | usar nmap fallback (automático) o levantar la red con `--cap-add` en los contenedores |
| ruff falla por estilo | código no formateado con ruff | `ruff check --fix` y push de nuevo |

## Rollback

1. Eliminar la red y contenedores de pruebas: `docker network rm vulntest` (+ `docker rm` de los contenedores).
2. Borrar `data/cache.sqlite3` y `outputs/` generados en pruebas.
3. No hay cambios destructivos sobre el sistema anfitrión.

## Seguridad

- Escanear SOLO `127.0.0.1` y `192.0.2.0/24` (red de pruebas aislada; TEST-NET-1 no enrutable).
- `MCP_ALLOWED_CIDRS` acotada a esos rangos durante toda la verificación.
- No commitear `data/cache.sqlite3` ni `outputs/` (ya cubierto por `.gitignore`).
- La `NVD_API_KEY` vive en `.env` (nunca en el repo ni en logs).

## Trazabilidad

- Workboard: ítems `NUC-001`, `NUC-004`, `INF-001`, `MCP-001` (cada uno documenta el criterio
  pendiente en su `decision_log`).
- Bitácoras: [2026-10-24-auditoria-seguridad-codigo.md](2026-10-24-auditoria-seguridad-codigo.md)
  (hallazgos H1-H5 que motivan parte de los pasos).
- Contratos: [ARCHITECTURE.md raíz](../../ARCHITECTURE.md) §5 (variables de entorno usadas).
