---
id: INT-001
title: "Intel de explotación pública: Exploit-DB + Metasploit + GitHub PoCs — ¿existe arma pública?"
status: done
priority: P1
node: "."
parent: null
claimed_by: agent
claimed_at: 2026-10-24T12:03:26+02:00
created_at: 2026-10-24T11:45:16+02:00
updated_at: 2026-10-24T12:27:34+02:00
closed_at: 2026-10-24T12:27:34+02:00
closed_reason: null
touches:
  - intel_exploit.py
  - scoring.py
  - nucleo.py
  - mcp_server.py
  - export_csv_pdf.py
  - tests/test_int001.py
  - tests/test_nuc002.py
  - tests/test_mcp001.py
  - ARCHITECTURE.md
blocks: []
blocked_by: []
acceptance:
  - "Dado un CVE, el módulo responde si existe arma pública y de qué tipo (exploit-db / módulo metasploit / PoC en GitHub), con enlace y fecha, servido de caché (TTL 24 h) con degradación elegante"
  - "El score pasa a 4 factores (CVSS 45 / KEV 15 / EPSS 20 / EXP 20) y tests de NUC-002 actualizados en la misma entrega"
  - "Informe CSV/PDF con columna 'Arma pública'; MCP tool `armas_publicas(cve_ids)` operativa (sin red local: sin whitelist)"
  - "Fuentes verificadas en F0 — test con fixtures grabadas"
subtasks:
  - "[x] F0: Exploit-DB migró a GitLab (rama main, files_exploits.csv, 47.182 exploits; columna `codes` con CVEs explícitos — 27.455 con CVE; author/tags marcan 2.464 módulos Metasploit); PoC-in-GitHub (nomi-sec) verificado por CVE con 404 limpio"
  - "[x] F1: intel_exploit.py con store (TTL 24 h) y fusión de fuentes"
  - "[x] F2: tests con fixtures (11 en test_int001 + actualización de nuc002/mcp001 al scoring 4 factores)"
  - "[x] F3: wiring (score, nucleo, informe CSV/PDF, MCP tool) y contrato actualizado"
external:
  - "https://gitlab.com/exploit-database/exploitdb"
  - "https://github.com/nomi-sec/PoC-in-GitHub"
decision_log:
  - "2026-10-24T11:45:16+02:00 (agent): CREACIÓN — deriva del plan original (bitácora 2026-10-22, B2)."
  - "2026-10-24T12:03:26+02:00 (agent): CLAIM — autorización del operador («Comienza a implementar…»)."
  - "2026-10-24T12:02:00+02:00 (agent): F0 SORPRESAS — (1) el CSV oficial ya NO está en GitHub: el repo migró a GitLab y el fichero se llama files_exploits.csv en rama main; (2) PREMIO: la columna `codes` trae CVEs explícitos (sin regex sobre descripciones) y author/tags marcan los módulos Metasploit → las tres fuentes del criterio caen con UN snapshot + el índice PoC-in-GitHub ya verificado; no hace falta GITHUB_TOKEN ni la búsqueda de código de GitHub (v1 sin autenticación alguna)."
  - "2026-10-24T12:26:00+02:00 (agent): BUG DE DISEÑO ENCONTRADO POR LOS TESTS — _poc_github cacheaba el vacío también tras un FALLO DE RED ( habría fijado «sin PoC» 24 h, violando la ley 11); corregido: solo se cachean respuestas válidas (200/404), el fallo de red no se cachea (test dedicado)."
---

## Contexto

La pregunta que este ítem cambia: de "¿qué CVEs tengo?" a "¿cuáles tienen arma pública?". Un CVSS 9.8
sin exploit y un 7.5 con PoC funcional en GitHub no merecen la misma cola de parcheo. Complementa a
KEV (explotación confirmada) con el escalón anterior: explotación *posible hoy*.

## Evidencia

Ejecutado el 2026-10-24T12:27+02:00 (agente agent): `python3 tests/test_int001.py` → **12/12 OK**
(11 + el test anti-caché-de-vacío añadido tras el bug); suite completa **109 tests, 0 fallos**.

1. **F0 verificado en vivo**: descarga real del CSV de Exploit-DB desde GitLab (47.182 líneas,
   27.455 con CVE, 2.464 con Metasploit); PoC-in-GitHub responde JSON por CVE y 404 limpio si no
   hay PoC (probado con CVE-2023-44487 y CVE-2001-0001).
2. **Parser puro** (`TestParseEdbCsv`): índice por CVE desde columna `codes` (separador `;`),
   detección Metasploit por author/tags, URL y fecha por entrada; exploits sin CVE fuera.
3. **Fusión** (`TestArmasFusion`): CVE presente en ambas fuentes → `tiene_arma` + resumen
   "exploit-db: N; metasploit: N; PoC GitHub: N"; CVE desconocido → "sin arma pública conocida";
   entrada en minúsculas normalizada.
4. **Caché y degradación** (`TestSnapshotYCaché`, `TestPocGithub`): segunda consulta de snapshot
   = 0 peticiones; fallo de red con copia vieja → se sirve avisando; sin copia → {} sin inventar;
   **fallo de red NO cachea "sin PoC"** (regresión de diseño cazada por el test).
5. **Score 4 factores** (test_nuc002 actualizado + TestScoring4Factores): 45/15/20/20; un 7.5 con
   arma pública (65,0) supera a un 9.8 teórico (44,3); máximo 100 con los cuatro.
6. **Wiring**: `nucleo._escanear_host` enriquece cada hallazgo con `arma_publica`/`arma_detalle`
   y puntúa con el 4º factor; CSV con columna `arma_publica`; PDF con columna «Arma» (anchos
   730 pt); MCP tool `armas_publicas` con validación de formato CVE-AAAA-NNNN (test incluido).
7. **Contrato**: §3 (intel_exploit, scoring 4F, mcp tools, tests), §4 grafo, §7 — misma entrega.

## Límites de la validación

- El wiring de `_escanear_host` no se ejecutó E2E (sin nmap en el entorno): verificado por
  compilación + los tests de las piezas que lo componen (la medición real del flujo completo
  queda cubierta por la próxima sesión con entorno).
- El snapshot de EDB (47k entradas) se descargó real en F0, pero los tests unitarios usan un CSV
  mini de fixture para no depender de la red.
