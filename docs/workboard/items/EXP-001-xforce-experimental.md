---
id: EXP-001
title: "EXPERIMENTAL: Intel de amenazas IBM X-Force (reputación IP, malware, APTs) — integración opcional"
status: open
priority: P3
node: "."
parent: null
claimed_by: null
claimed_at: null
created_at: 2026-10-24T17:33:47+02:00
updated_at: 2026-10-24T17:33:47+02:00
closed_at: null
closed_reason: null
touches:
  - intel_xforce.py
  - nucleo.py
  - mcp_server.py
  - config.py
  - tests/test_exp001.py
  - ARCHITECTURE.md
blocks: []
blocked_by: []
acceptance:
  - "Módulo OPCIONAL: sin XFORCE_API_KEY/XFORCE_API_PASSWORD el escáner se comporta EXACTAMENTE igual que hoy (0 cambios; aviso único de 'fuente experimental desactivada') — test"
  - "Con credenciales (mockeadas en tests): enriquecimiento de hosts descubiertos con reputación IP de X-Force (score 1-10 + categorías) y de CVEs con riesgo X-Force — sin alterar el score de 4 factores (v1 solo display)"
  - "PROTECCIÓN DE PRIVACIDAD: por defecto se REHÚSA enviar IPs privadas (RFC1918/loopback/link-local) a IBM; solo con XFORCE_ALLOW_PRIVATE_IPS=1 explícito — test con 192.168.x.x rechazada"
  - "F0 en vivo (documentación de endpoints reales, cuotas y forma de auth) queda BLOQUEADO hasta que el operador aporte cuenta IBM Cloud + API key; los tests unitarios con mocks NO dependen de ella"
  - "Degradación elegante estándar (ley 11) y TTL propio de caché"
subtasks:
  - "[ ] F0 (bloqueado por credenciales): verificar en vivo api.xforce.ibmcloud.com — auth basic (key:password), endpoints /ipr/{ip}, /vulnerabilities/{cve}, malware/campaigns; cuotas del free tier y catálogo de límites"
  - "[ ] F1: intel_xforce.py con activación condicional por entorno + store TTL 24 h + protección de IPs privadas"
  - "[ ] F2: tests con fixtures sintéticas (sin red): activación/inactivación, reputación, rechazo de IP privada, degradación, CVE risk"
  - "[ ] F3: wiring de SOLO-lectura (columnas informativas en informe + tools MCP xforce_ip/xforce_cve con aviso experimental) y contrato con sección 'fuentes experimentales'"
  - "[ ] F4 (tras uso real): evaluación de promoción — si la calidad del dato lo merece, ítem NUC de 5º factor de score con reponderación"
external:
  - "https://api.xforce.ibmcloud.com"
  - "https://www.ibm.com/docs/en/xforce"
decision_log:
  - "2026-10-24T17:33:47+02:00: CREACIÓN a petición del operador tras el análisis comparativo (X-Force = intel de amenazas pasiva; mcp-cves = escáner activo; complementarios). Prefijo EXP = experimental: primera fuente NO gratuita del proyecto (requiere cuenta IBM Cloud) y no verificable en F0 sin credenciales; por eso NO toca el score en v1 ni se activa sin opt-in."
---

## Contexto

Conversación con el operador (2026-10-24): su MCP cubre la fase activa (descubrir TU red y
priorizar TUS activos); X-Force cubre la pasiva (quién ataca a quién, con qué malware y qué IPs
son maliciosas). Este ítem explora el puente: usar X-Force como 7ª fuente para enriquecer los
hallazgos del escáner con contexto de amenaza global.

## Valor añadido planificado (qué gana el escáner, mapeado a lo que ya tiene)

| # | Capacidad nueva | De dónde sale (X-Force) | Se cruza con | Valor concreto |
|---|---|---|---|---|
| V1 | **Detección de compromiso interno**: si un host de TU red tiene mala reputación (C2, botnet, spam), puede estar comprometido — el escáner pasa de "buscar vulnerabilidades" a "señalar indicios de intrusión" | `/ipr/{ip}` (reputación 1-10 + categorías) | Hosts descubiertos por ARP/nmap (DAT: inventario) | Señal totalmente nueva: hoy nada evalúa la SALUD de los hosts, solo sus versiones |
| V2 | **Attribución de arma**: qué familias de malware y campañas explotan los CVEs encontrados | `/vulnerabilities/{cve}` + malware/campaigns | Hallazgos + `arma_publica` (INT-001) | Pasa de "hay exploit público" a "lo usa el grupo X en la campaña Y" |
| V3 | **Segunda opinión de riesgo por CVE** | X-Force risk score propio | Score 4 factores (solo display en v1) | Contraste del score propio contra telemetría global de incidentes reales de IBM |
| V4 | **Contexto de APTs** | Grupos que usan esos CVEs | Informe ejecutivo | El informe gana narrativa de amenaza, útil para justificar parcheo a dirección |

## Diseño de la integración

1. **Activación**: opt-in por `.env` (`XFORCE_API_KEY` + `XFORCE_API_PASSWORD`, IBM usa basic auth
   key:password). Sin ambas → módulo desactivado con un aviso único; NADA del comportamiento actual
   cambia (por eso es EXP y no INT).
2. **Privacidad por diseño** (extensión del hallazgo H1 de la auditoría): consultar reputación de
   una IP = enviarla a IBM. Las IPs PRIVADAS de tu LAN no salen salvo opt-in explícito
   (`XFORCE_ALLOW_PRIVATE_IPS=1`); las públicas (objetivos autorizados externos) sí.
3. **v1 sin score**: enriquecimiento de solo lectura (columnas informativas + tools). El score de
   4 factores no se toca hasta que el dato demuestre calidad en uso real (F4: promoción a 5º
   factor sería ítem NUC aparte con reponderación y tests).
4. **Arquitectura**: `intel_xforce.py` simétrico al resto (store TTL 24 h, ley 11, fallo de red no
   cachea), consumido en `nucleo` tras el descubrimiento (V1) y tras la correlación CVE (V2/V3),
   y expuesto como tools MCP `xforce_ip`/`xforce_cve` marcadas "experimental" en su descripción.
5. **Lo que NO será**: scraping de la web pública, ni dependencia dura — el proyecto sigue
   funcionando 100% gratis sin esta fuente.

## Qué necesita el operador para desbloquear el F0 en vivo

- Cuenta (gratuita) de IBM Cloud + alta en X-Force Exchange → genera API key + password.
- Valores en `.env`: `XFORCE_API_KEY`, `XFORCE_API_PASSWORD` (opcional `XFORCE_ALLOW_PRIVATE_IPS=1`).
- Con eso: verificación real de endpoints/cuotas, medición del valor real de V1-V4 en un escaneo
  de prueba, y la decisión de promoción (F4) con datos, no con supuestos.
