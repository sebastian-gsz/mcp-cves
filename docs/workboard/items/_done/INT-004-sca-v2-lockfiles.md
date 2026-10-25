---
id: INT-004
title: "SCA v2: soporte de lockfiles y árbol resuelto (transitivos) + querybatch de OSV"
status: done
priority: P2
node: "."
parent: null
claimed_by: zcode
claimed_at: 2026-10-25T17:28:43+01:00
created_at: 2026-10-25T17:28:43+01:00
updated_at: 2026-10-25T20:45:00+01:00
closed_at: 2026-10-25T20:45:00+01:00
closed_reason: null
touches:
  - intel_osv.py
  - nucleo.py
  - tests/test_int004.py
  - tests/test_int002.py
  - ARCHITECTURE.md
blocks: []
blocked_by: []
acceptance:
  - "escanear_dependencias audita NATIVAMENTE los lockfiles pnpm-lock.yaml, package-lock.json (v2/v3 y legacy v1), yarn.lock, poetry.lock y uv.lock: el árbol resuelto real con transitivos incluidos — el workaround de sintetizar manifiestos desaparece"
  - "Caso de la auditoría externa reproducido como test: un pnpm-lock.yaml sintético con ~240 entradas se audita entero sin intervención manual"
  - "OSV querybatch (POST /v1/querybatch) para lotes grandes con fallback por-consulta si el lote falla; caché por (ecosistema, paquete, versión) compartida"
  - "Tests con fixtures de los 5 formatos (nombres con scope @org/pkg, rangos múltiples en yarn, secciones packages/snapshots de pnpm)"
subtasks:
  - "[x] F0: derivado de auditoría externa real (otra sesión usó el servidor MCP completo sobre stdio y tuvo que sintetizar 235 versiones de pnpm-lock.yaml a mano)"
  - "[x] F1: parsers de lockfiles (pnpm línea a línea sin yaml-lib; package-lock via json; yarn por bloques; poetry/uv via tomllib)"
  - "[x] F2: consultar_osv_batch con chunks de 100 y fallback individual"
  - "[x] F3: wiring en detectar_manifiestos/escanear_dependencias + tests + contrato"
external:
  - "https://google.github.io/osv.dev/api/"
decision_log:
  - "2026-10-25T17:28:43+01:00 (zcode): CREACIÓN+CLAIM — deriva de una AUDITORÍA EXTERNA REAL: otra sesión empleó el servidor MCP de mcp-cves (protocolo stdio completo, fail-closed respetado, cero modificaciones) y tuvo que sintetizar a mano un manifiesto con 235 versiones exactas de pnpm-lock.yaml porque el parser v1 solo lee versiones exactas de manifiestos directos. La herramienta tiene que hablar lockfile nativamente. NOTA: la captura del operador está truncada antes de la sección 'errores en cómo se maneja CVEs' — pendiente de recibirla para ampliar aceptación si trae hallazgos adicionales."
  - "2026-10-25T19:00:00+01:00 (zcode): CONTEXTO DE REPOSITORIO — el operador reinició el repo y la carpeta local (historial limpio, decisión suya); este ítem se implementa sobre el snapshot del orquestador (init 3bef7c8) en un clon fresco; el ítem sobrevivió a la limpieza en la carpeta local y se recupera aquí."
  - "2026-10-25T19:30:00+01:00 (zcode): DISEÑO — pnpm-lock.yaml se parsea LÍNEA A LÍNEA sin yaml-lib (stdlib): claves `name@version:` de la sección packages: (los scope @org/pkg se resuelven por el ÚLTIMO @; los sufijos de peer de snapshots: quedan fuera por sección). package-lock: v3 (packages con rutas node_modules/, anidados incluidos) + legacy v1 (dependencies recursivos). yarn.lock v1 por bloques (múltiples rangos → una versión). poetry.lock/uv.lock via tomllib stdlib (uv excluye el propio proyecto virtual/editable)."
  - "2026-10-25T20:30:00+01:00 (zcode): BUGS CAZADOS POR TESTS — (1) consulta en lote con dedup por SET: el orden aleatorio de hash desalineaba el zip con la respuesta (intermitente); corregido con dict.fromkeys preservando orden; (2) fixture de test devolvía vulns CRUDOS de OSV donde el batch real entrega ya parseados — fixture corregido; (3) regex de pnpm sin grupos nombrados llamados como tales. Tres evidencias de que la suite protege."
---

## Contexto

Una sesión externa usó mcp-cves como herramienta (la mejor validación posible del MCP) y chocó con
la carencia v1 del vector SCA: `escanear_dependencias` solo lee manifiestos directos con versiones
exactas, así que los PROYECTOS REALES (que usan rangos ^~ y resuelven en lockfiles) auditan casi
nada de lo que realmente ejecutan. El riesgo real vive en el árbol resuelto (transitivos): 235
versiones exactas en un pnpm-lock.yaml frente a un puñado de pins en package.json.

## Evidencia

Ejecutado el 2026-10-25T20:40+01:00 (agente zcode): `python3 tests/test_int004.py` → **12/12 OK**;
suite completa **148 tests, 0 fallos**.

1. **Parsers de los 5 lockfiles** (`TestParsersLockfiles`): pnpm v9 con scope `@babel/core@7.23.0`
   resuelto por el último `@` y sección snapshots excluida; package-lock v3 con rutas anidadas
   `node_modules/a/node_modules/deep` y legacy v1 recursivo; yarn.lock con múltiples rangos → una
   versión; poetry.lock y uv.lock vía tomllib (uv excluye el proyecto virtual/editable).
2. **Detección**: pnpm-lock.yaml detectado junto a manifiestos directos en el mismo walk.
3. **Querybatch** (`TestQueryBatch`): 3 pares → 1 petición; 240 pares con chunk=100 → 3 peticiones;
   fallo del lote → cae a consulta individual (ley 11: se cachea lo válido, nunca el fallo);
   segunda llamada = 0 peticiones (caché compartida con la individual).
4. **Caso real reproducido** (`TestNucleoLockfiles`): pnpm-lock.yaml con **235 entradas** auditable
   de un tirón (el workaround de la auditoría externa desaparece); pnpm-lock mini → hallazgo del
   paquete TRANSITIVO con banner=lockfile, ecosistema npm, score de 4 factores.
5. **Contrato**: §3 (intel_osv con lockfiles+batch, nucleo, tests) y §7 en la misma entrega.

## Límites de la validación

- pnpm-lock v5.4 y anteriores (estructura `dependencies:` sin sección packages:) no soportados;
  v6+ sí (las actuales).
- yarn.lock con cabeceras que parten en varias líneas (miles de rangos) no cubierto — caso raro,
  documentado.
- OSV consultado con mocks (el endpoint se verificó en vivo en INT-002); E2E real contra OSV con
  235 paquetes pendiente del entorno con dependencias.
