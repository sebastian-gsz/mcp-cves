---
id: SEG-002
title: "Validar objetivos (IP/CIDR) antes de pasarlos a nmap — hallazgo H3"
status: done
priority: P2
node: "."
parent: null
claimed_by: agent
claimed_at: 2026-10-24T00:53:37+02:00
created_at: 2026-10-24T00:53:37+02:00
updated_at: 2026-10-24T00:56:30+02:00
closed_at: 2026-10-24T00:56:30+02:00
closed_reason: null
touches:
  - targets.py
  - nucleo.py
  - cve_scanner.py
  - tests/test_seg002.py
  - tests/test_nuc003.py
  - ARCHITECTURE.md
blocks: []
blocked_by: []
acceptance:
  - "Un objetivo que no sea IP válida (p. ej. '-foo', 'host; rm', texto vacío) jamás llega a nmap: se rechaza con mensaje antes de cualquier subprocess"
  - "CIDR inválido se rechaza igualmente antes de tocar ARP o nmap"
  - "IPs y CIDRs válidos (IPv4 e IPv6) pasan sin cambios"
  - "Tests que fijan todo lo anterior"
subtasks:
  - "[x] targets.py: validación pura (es_ip, es_cidr, filtrar_objetivos) con ipaddress stdlib"
  - "[x] Enforcement en nucleo.escanear y nucleo.descubrir_hosts (frontera de seguridad del futuro MCP)"
  - "[x] Validación temprana en la CLI para UX"
external:
  - null
decision_log:
  - "2026-10-24T00:53:37+02:00 (agent): CREACIÓN+CLAIM — deriva del hallazgo H3 de la auditoría de seguridad del 2026-10-24; autorización del operador («continua con la que desees»)."
  - "2026-10-24T00:55:00+02:00 (agent): DISEÑO — la frontera de validación vive en el NÚCLEO (nucleo.escanear/descubrir_hosts), no solo en la CLI, porque el futuro servidor MCP llamará al núcleo directamente. Los nombres de host quedan RECHAZADOS (para 'localhost' se usa 127.0.0.1): cambio de comportamiento deliberado y documentado. filtrar_objetivos normaliza None a '' en los rechazados."
  - "2026-10-24T00:55:40+02:00 (agent): LOS TESTS VIEJOS DELATARON EL CAMBIO — test_nuc003 usaba hostnames ficticios ('h1', 'bueno') como objetivos y el nuevo enforcement los rechazó (prueba indirecta de que la frontera funciona): tests actualizados a IPs. También se ajustó la expectativa de normalización None→'' en test_seg002."
---

## Contexto

Hallazgo H3 de la bitácora
[2026-10-24-auditoria-seguridad-codigo.md](../../../runbooks/2026-10-24-auditoria-seguridad-codigo.md):
la línea de argumentos de nmap se construía con el host introducido por el operador sin validar;
una cadena tipo `-foo` podría interpretarse como flag de nmap (sin shell intermedio, pero
comportamiento alterable).

## Evidencia

Ejecutado el 2026-10-24T00:55:45+02:00 (agente agent): `python3 tests/test_seg002.py` → **9/9 OK**;
suite completa **75 tests, 0 fallos** (1 skip declarado de PDF).

1. **Nada malicioso llega a nmap**: `escanear(["-O", "192.168.1.10", "host; rm -rf /"])` ejecuta
   `_escanear_host` **solo** con la IP válida (verificado por inspección de `call_args_list`);
   con todos los objetivos inválidos, `_escanear_host` no se llama ni una vez.
2. **CIDR validado antes de scapy**: `descubrir_hosts("-p; algo")` devuelve `[]` sin importar
   scapy (la validación precede al import perezoso — testeado en un entorno sin scapy).
3. **IPv4 e IPv6 pasan**: `es_ip` acepta 192.168.1.10/127.0.0.1/::1/fe80::1; `es_cidr` acepta
   192.168.1.0/24, 10.0.0.0/8, 2001:db8::/32 y rechaza 192.168.1.0/33, "foo/24", "-sS".
4. **Prueba indirecta del enforcement**: los tests de NUC-003 usaban hostnames ficticios como
   objetivos y dejaron de pasar — el núcleo los estaba rechazando. Corregidos a IPs.
5. **Contrato**: §3 (targets.py, nucleo con validación, tests) y §2 cláusula 3 actualizados en
   la misma entrega.

## Límites de la validación

- No se ejecutó nmap real (no instalado): se verifica que la entrada inválida no alcanza la
  frontera `_escanear_host`/`descubrir_hosts`, que es el punto único por el que nmap se invoca.
- La CLI valida temprano por UX, pero la garantía de seguridad está en el núcleo (duplicidad
  deliberada: defensa en profundidad).
