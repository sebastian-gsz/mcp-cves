---
title: ARCHITECTURE.md — Raíz del proyecto (Mapa central)
Rol: Coordinador de contexto / Software Architect Senior
Objetivo: Ser el PUNTO DE ENTRADA único e ineludible para cualquier agente (LLM o programático). Define las reglas de comportamiento globales, el mapa de navegación del repositorio y el protocolo de lectura.
Lectura obligatoria: SÍ — es el primer archivo que debe leerse antes de tocar cualquier código.
---

# 🗺️ Mapa central de arquitectura — mcp-cves (escáner de vulnerabilidades y CVEs)

> **Regla de oro para agentes**: NO leas scripts "a ciegas". Este repositorio se navega como un árbol:
> cada nodo relevante tiene su propio `ARCHITECTURE.md` que actúa de **contrato local** (reglas de
> comportamiento + estado actual + mapa de archivos). Lee desde la raíz hacia abajo, detente en el nodo
> que cubre tu tarea y **solo entonces** abre código. Si la información del nodo no es suficiente, realiza
> una auditoría propia (listar directorio, abrir los archivos mínimos), pero siempre partiendo del
> contrato, nunca de cero.

## 1. Protocolo de lectura

1. **Empieza aquí.** Identifica el nodo que cubre tu tarea en la tabla de ruteo de nodos (§3).
   **Desciende por hipervínculos** hasta su `ARCHITECTURE.md`.
2. **Respeta los contratos de los nodos**: normas, estructura, estado actual y antipatrones locales.
3. **Audita solo lo necesario**: si el contrato del nodo no basta, lista el directorio y abre los archivos
   mínimos; documenta las carencias, propone la solución y pide permiso al owner antes de escribir en
   cualquier `ARCHITECTURE.md` (ver §5, mantenimiento).
4. **Nunca subas conocimiento local al tronco**: las particularidades de una rama viven en su nodo; las
   normas universales, arriba. Cascada estricta.

## 2. Topología general del repositorio

```text
mcp-cves/
├── docs/                        # ⬅ Tronco raíz documental → [docs/ARCHITECTURE.md (este archivo)]
│   ├── workboard/               #   Rama raíz: trabajo, claims y trazabilidad → [workboard/ARCHITECTURE.md]
│   ├── runbooks/                #   Rama raíz: runbooks y bitácoras → [runbooks/ARCHITECTURE.md]
│   └── templates/architecture/  #   Plantillas de contratos; artefactos de diseño, no nodo contractual
├── ARCHITECTURE.md              # ⬅ Tronco raíz de código: contrato del escáner → [ARCHITECTURE.md]
├── cve_scanner.py … utils.py    #   Módulos Python del escáner (mapa completo en el contrato del tronco)
├── mcp_server.py                #   Servidor MCP stdio (tools del núcleo; fail-closed, MCP-001)
├── targets.py · nucleo.py       #   (frontera de validación y núcleo del pipeline; ver contrato del tronco)
├── tests/                       #   Tests unitarios del tronco de código (mapa en el contrato del tronco)
├── data/                        #   Semilla: datos pasivos (puertos_comunes.txt) + caché SQLite generada
├── outputs/                     #   Semilla: artefactos generados en ejecución (CSV/PDF)
├── AGENTS.md                    # Stub de convención: redirige a este mapa central (no duplica contenido)
├── Dockerfile · docker-compose.yml · .dockerignore   # Infra del escáner (usuario no root + capabilities, INF-001)
└── (sin ficheros extra: el BLUEPRINT fue retirado por el operador)
```

## 3. Tabla de ruteo de nodos (¿A dónde voy?)

Estados de nodo:

- **contract**: contrato vigente del nodo. Define reglas, compromisos, términos y condiciones,
  estructura, límites y responsabilidades; no documenta un estado operativo detallado.
- **implemented**: contrato vigente más documentación del estado operativo aprobado y funcional.
  Incluye el mapa de archivos y el grafo de dependencias entre archivos, clases, funciones y flujos.

| Nodo | Nivel | Estado | Descripción | Enlace |
|---|---|---|---|---|
| Raíz documental (este archivo) | Tronco maestro | — | Mapa central, leyes universales, protocolo de lectura, topología y mantenimiento. | — |
| `docs/` | Tronco raíz documental | contract | Contrato de documentación y navegación de los dominios documentales. | [↘](ARCHITECTURE.md) |
| `docs/workboard/` | Rama raíz | contract | Dominio exclusivo para gestionar tareas, claims, bloqueos, trazabilidad y cierres. | [↘](workboard/ARCHITECTURE.md) |
| `docs/runbooks/` | Rama raíz | contract | Contrato de runbooks reutilizables y bitácoras de ejecuciones reales. | [↘](runbooks/ARCHITECTURE.md) |
| Raíz de código (`ARCHITECTURE.md`) | Tronco raíz | implemented | Contrato del escáner de vulnerabilidades: pipeline completo de módulos Python en la raíz del repositorio. | [↘](../ARCHITECTURE.md) |

**Enlaces de contexto general**:

- [AGENTS.md](../AGENTS.md): stub de convención que **redirige** a este mapa central (no duplica
  contenido). Las reglas viven SOLO en los archivos `ARCHITECTURE.md`.

## 4. Leyes universales del proyecto (aplican a TODOS los nodos)

1. **Cascada de contexto**: un `ARCHITECTURE.md` padre dicta normas globales; los hijos solo añaden
   particularidades, nunca las contradicen.
2. **DRY absoluto**: lógica repetida se extrae al nivel compartido inmediatamente superior.
3. **Modularidad estricta**: 1 archivo = 1 responsabilidad; tamaños fuera de rango obligan a refactor.
4. **Testeabilidad**: parsers y validaciones sin red ni disco; tests unitarios con mocks; nada depende
   de producción.
5. **Configuración centralizada**: rutas/URLs/límites vía entorno (`.env`) + helpers del nodo; prohibido
   hardcodear fuera de los módulos de constantes.
6. **Enrutamiento obligatorio**: todo nodo nuevo debe aparecer en la topología (§2) y en la tabla de
   ruteo (§3) de su tronco maestro. Todo nodo debe enlazar hacia su padre y su padre hacia él.
7. **Precedencia y conflicto**: un descendiente puede especializar las reglas de sus padres, pero no
   contradecirlas ni relajarlas. Ante contradicción prevalece el contrato superior; el agente detiene
   la acción, documenta el conflicto y solicita resolución antes de modificar código o arquitectura.
8. **Límite de la especialización**: especializar = concretar una regla general para el dominio local,
   añadir una restricción necesaria o definir una responsabilidad propia. No permite cambiar el
   significado de `contract` o `implemented`, alterar la fuente de verdad del Workboard ni sustituir
   una obligación superior.
9. **Estado de trabajo aparte**: los contratos nunca alojan backlog, tareas, claims ni pendientes;
   eso vive exclusivamente en `docs/workboard/`.
10. **Autorización de escaneo**: solo se escanea lo que el operador autoriza expresamente; los objetivos
    son entrada del usuario. Ninguna tool o función nueva (incluido un futuro servidor MCP) puede ampliar
    el alcance de objetivos sin validación explícita de autorización.
11. **Degradación elegante**: si una fuente externa (NVD, EPSS, KEV) falla, se usa la última copia buena
    local y se declara en el resultado; prohibido inventar ceros o vacíos silenciosos que subestimen un informe.
12. **Límites sobre datos hostiles**: banners, descripciones y respuestas provenientes de la red se
    truncan y escapan antes de parsearse o renderizarse (CSV/PDF); son entrada no confiable.

## 5. Mantenimiento de la red (obligatorio al trabajar)

- **Si creas un directorio con lógica propia**, crea su `ARCHITECTURE.md` usando la guía y plantillas
  de [templates/architecture](templates/architecture/README.md): front-matter
  (`title/Rol/Objetivo/Nivel/Estado/Padre`), enlaces *↑ Padre* y *↓ Hijos* cuando correspondan,
  alcance, contrato local y mapa. Un nodo `implemented` añade únicamente el estado operativo aprobado
  y su grafo de dependencias; los estados de tareas pertenecen exclusivamente al Workboard.
- **Si modificas comportamiento** descrito en un nodo (nuevo script, nueva variable de entorno, cambio
  de flujo), **actualiza únicamente el `ARCHITECTURE.md` de ese nodo en la misma entrega**. Si el
  cambio altera la topología, actualiza además el `ARCHITECTURE.md` del padre y, cuando proceda, este
  mapa maestro.

## 6. Convenciones del proyecto (Fase 0)

| Parámetro | Valor |
|---|---|
| Operador/owner | `uhm` (autoridad de aprobación, liberación de claims y resolución de conflictos) |
| Zona horaria oficial | `Europe/Madrid` — toda marca temporal en ISO-8601 con offset (p. ej. `2026-10-22T02:46:52+02:00`) |
| Idioma documental | Español |
| Prefijos de ID del Workboard | `NUC` (núcleo/código), `DAT` (datos/persistencia), `SEG` (seguridad de la app), `INF` (infraestructura), `DOC` (documentación/harness) |
| Control de versiones | Repositorio git (remoto `github.com/sebastian-gsz/mcp-cves`, rama `main`, CI en `.github/workflows/ci.yml`); la regla de la «misma entrega» se materializa como commits atómicos |
| Dominios complementarios | `docs/conocimiento/` (SOP/decisiones) omitido deliberadamente: repo pequeño, las decisiones viven en las bitácoras y `decision_log` de los ítems |

---
*Fin del mapa central. Descarga el nodo que corresponda a tu tarea antes de escribir una sola línea de código.*
