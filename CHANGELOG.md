# Changelog

Formato basado en [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/).
Versionado SemVer: MAYOR.MENOR.PARCHE.

## [1.0.1] - 2026-10-25

### Added

- **SCA v2 (INT-004)**: `escanear_dependencias` audita ahora el árbol RESUELTO leyendo lockfiles
  nativamente — `pnpm-lock.yaml` (v6-v9, sin yaml-lib), `package-lock.json` (v2/v3 y legacy v1),
  `yarn.lock`, `poetry.lock` y `uv.lock` — con dependencias transitivas incluidas. Desaparece el
  workaround de sintetizar manifiestos para proyectos reales.
- **OSV por lotes**: `consultar_osv_batch()` usa `POST /v1/querybatch` en chunks de 100 con
  fallback a consulta individual si el lote falla; caché compartida con la consulta individual
  (TTL 24 h).
- Documentación: `README.md` y este `CHANGELOG`.

### Changed

- Historial del repositorio reiniciado a commit único por decisión del operador (el estado
  funcional es idéntico al acumulado: 16 tareas cerradas del workboard).
- Retirado `BLUEPRINT-ORQUESTADOR.md` y sus referencias (decisión del operador).

### Fixed

- Deduplicación en `consultar_osv_batch` preservando el orden (el `set` aleatorizaba el alineado
  de respuestas por lote).
- Lint: 5 avisos de ruff en tests (import sin uso, `open()` sin context manager).

## [1.0.0] - 2026-10-24

Primer release funcional completo (big bang del historial limpio; el trabajo previo está documentado
en el workboard `docs/workboard/items/_done/` y en las bitácoras de `docs/runbooks/`).

### Added

- **Escáner de red**: descubrimiento por ARP (scapy) con fallback nmap, escaneo de puertos/
  servicios/OS, hosts en paralelo (≤8, ajustable con `NUC_HOST_WORKERS`; A/B medido: 13× con
  nmap real), tokens bucket conforme al rate limit de NVD (5/50 por 30 s).
- **6 fuentes de inteligencia**, todas gratuitas y con caché SQLite + degradación elegante:
  NVD (CVEs/CPE), EPSS (FIRST), KEV (CISA), arma pública (Exploit-DB + Metasploit + PoC-in-GitHub),
  OSV (dependencias) y PSIRT multi-vendor (Red Hat + Ubuntu, con días de anticipación a NVD).
- **Scoring de 4 factores**: CVSS 45% + KEV 15% + EPSS 20% + arma pública 20%.
- **Escaneo diferencial**: inventario por host en SQLite (por lotes) y marcado
  NUEVO/CERRADO/PERSISTENTE entre escaneos.
- **Servidor MCP** (`mcp_server.py`, JSON-RPC 2.0 stdio sin SDK): 7 tools
  (`puntuar`, `buscar_cves`, `armas_publicas`, `advisories`, `escanear_dependencias`,
  `descubrir_hosts`, `escanear`) con fail-closed por doble whitelist
  (`MCP_ALLOWED_CIDRS`, `MCP_DEPS_ROOTS`).
- **Seguridad de la aplicación**: validación de objetivos IP/CIDR, truncado de banners (ReDoS),
  escaping XML en PDF, neutralización de fórmulas en CSV, `.gitignore` para artefactos sensibles.
- **Infraestructura**: Dockerfile usuario no-root `scanner` + capabilities al contenedor,
  docker-compose, requirements pineado, CI (ruff + pytest sobre Python 3.12/3.13).
- **Harness documental**: contratos `ARCHITECTURE.md` navegables, workboard con ciclo de vida de
  tareas, runbooks y bitácoras de auditoría (incluida auditoría de seguridad del propio código).

[1.0.1]: https://github.com/sebastian-gsz/mcp-cves/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/sebastian-gsz/mcp-cves/releases/tag/v1.0.0
