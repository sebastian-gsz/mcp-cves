---
id: INF-001
title: "Docker + capabilities en vez de root"
status: done
priority: P2
node: "."
parent: null
claimed_by: agent
claimed_at: 2026-10-24T00:40:41+02:00
created_at: 2026-10-22T02:50:00+02:00
updated_at: 2026-10-24T17:01:57+02:00
closed_at: 2026-10-24T17:01:57+02:00
closed_reason: null
touches:
  - Dockerfile
  - docker-compose.yml
  - .dockerignore
  - requirements.txt
  - ARCHITECTURE.md
  - docs/ARCHITECTURE.md
blocks: []
blocked_by: []
acceptance:
  - "Imagen Docker reproducible con nmap, dependencias pineadas y volumen para data/ y outputs/"
  - "El escaneo corre como usuario no root con capabilities mínimas (cap_net_raw, cap_net_admin) en vez de como root global"
  - "La imagen se construye y el escaneo de humo (1 host, 2 puertos) funciona desde el contenedor"
subtasks:
  - "[x] Dockerfile (python:3.12-slim + nmap 7.95 del sistema, usuario dedicado `scanner` uid 1000, ENTRYPOINT de la CLI)"
  - "[x] requirements.txt pineado a versiones exactas (mitiga H2 de la auditoría)"
  - "[x] docker-compose.yml con cap_add NET_RAW/NET_ADMIN, network_mode host y volúmenes data/outputs"
  - "[x] Construcción + escaneo de humo desde contenedor (criterio 3, ejecutado el 2026-10-24T16:55+02:00)"
external:
  - null
decision_log:
  - "2026-10-24T00:40:41+02:00 (agent): CLAIM — última tarea abierta del plan original."
  - "2026-10-24T00:41:44+02:00 (agent): DISEÑO — capabilities al CONTENEDOR en ejecución (cap_add NET_RAW/NET_ADMIN) en vez de setcap sobre binarios; usuario `scanner` sin root dentro; requirements pineado con `==` (hashes y pip-audit pendientes de pip, anotado)."
  - "2026-10-24T01:45:00+02:00 (agent): Docker inaccesible ese día (integración WSL desactivada); ítem quedó in_progress."
  - "2026-10-24T16:47:00+02:00 (agent): ENTORNO ACTIVADO — el operador habilitó la integración WSL de SU distro únicamente (no el distro por defecto); docker daemon 29.8.2 alcanzable."
  - "2026-10-24T16:50:00+02:00 (agent): BUILD + VERIFICACIÓN — `docker compose build` OK (mcp-cves:latest); `docker run --entrypoint id` → uid=1000(scanner), NO root; nmap 7.95 dentro; las 6 dependencias pineadas importan (Python 3.12)."
  - "2026-10-24T16:55:00+02:00 (agent): HUMO CON MATIZ REAL — con `--network host` el contenedor ve el loopback de la VM de Docker Desktop, NO el del distro: los servicios del distro eran invisibles (limitación documentada de Docker Desktop, no bug del escáner). Solución del humo: red Docker dedicada `humo` con contenedor objetivo (nginx/1.18.0 en 8031-8032) y el escáner en la misma red → 1 host, 2 puertos, 38 hallazgos REALES (NVD desde la imagen), estado NUEVO, CSV+PDF generados con reportlab de la imagen."
  - "2026-10-24T17:01:57+02:00 (agent): CIERRE + LIMPIEZA VERIFICADA — contenedor objetivo, red e imagen eliminados (0 contenedores, 0 imágenes, red eliminada); servicios de humo parados; outputs/ y /tmp limpios. NOTA para compose: para escanear la LAN real del distro, network_mode: host requiere Docker Engine nativo en el distro (no Desktop); con Desktop, usar una red dedicada con los objetivos dentro o el modo host de la VM."
---

## Contexto

Ítem nº5 del plan de mejoras: eliminar el modelo root-global y empaquetar todo reproducible.

## Evidencia

Ejecutado el 2026-10-24T16:47→17:01+02:00 (agente agent), con Docker 29.8.2 activado por el operador:

1. **Build (criterio 1)**: `docker compose build` → `mcp-cves:latest` (python:3.12-slim + nmap 7.95
   + 6 dependencias pineadas por `==` + `.dockerignore` excluyendo docs/tests/outputs).
2. **No root (criterio 2)**: `docker run --rm --entrypoint id mcp-cves:latest` →
   `uid=1000(scanner) gid=1000(scanner)`. Las capabilities NET_RAW/NET_ADMIN se conceden al
   CONTENEDOR en ejecución (compose cap_add), nunca root global del sistema.
3. **Humo (criterio 3)**: red dedicada con contenedor objetivo → escaneo desde el contenedor
   escáner: `1 host(s), 2 puerto(s), 38 hallazgo(s)`, banners `nginx 1.18.0 [NUEVO]`,
   `informes: outputs/reporte_vulnerabilidades.csv | pdf=True` (CVEs reales de NVD consultados
   desde la imagen; el usuario scanner escribió outputs/ vía volumen sin permisos extra).
4. **Limpieza verificada**: 0 contenedores, 0 imágenes, red eliminada, servicios parados,
   outputs/ y /tmp limpios. El operador puede REVERTIR la integración WSL de Docker Desktop.

## Límites de la validación

- El humo fue contenedor→contenedor en una red dedicada (no LAN física del distro): con Docker
  Desktop `network_mode: host` no alcanza el loopback del distro (documentado en decision_log y
  en el compose como nota); para LAN real, Docker Engine nativo o red dedicada con los objetivos.
- Pip-audit y hashes sha256 de requirements siguen pendientes de un entorno con pip (anotado en el
  propio requirements.txt; sugerencia registrada como posible ítem futuro).
