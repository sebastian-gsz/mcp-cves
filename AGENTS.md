---
title: AGENTS.md — Punto de entrada para agentes
Rol: Enlace de convención → Mapa central de arquitectura
Lectura obligatoria: SÍ
---

Este repositorio tiene **una sola fuente de verdad** de contexto por directorio: el `ARCHITECTURE.md`
de cada nivel, enlazados entre sí como una red.

👉 Empieza siempre en **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)** — mapa central, protocolo de
lectura, tabla de ruteo de nodos y leyes universales. 👈

## Instrucción mínima para cualquier agente

1. Abre **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)** y sigue su §1 *Protocolo de lectura*.
2. Identifica el nodo que cubre tu tarea en su §3 *Tabla de ruteo de nodos* y desciende por los
   hipervínculos hasta él (para el código del escáner: [ARCHITECTURE.md](ARCHITECTURE.md) en la raíz).
3. No leas scripts «a ciegas»: audita código solo si el contrato del nodo no basta.
4. Antes de crear, reclamar o ejecutar trabajo: consulta
   [docs/workboard/README.md](docs/workboard/README.md) y cumple su protocolo de claim.
5. Si modificas el comportamiento, actualiza el `ARCHITECTURE.md` del directorio afectado en la misma
   entrega (un nodo obsoleto es un bug).
