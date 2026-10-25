# mcp_server.py — servidor MCP mínimo sobre stdio (MCP-001).
# JSON-RPC 2.0 puro con stdlib (una línea JSON por mensaje): sin SDK externo, el núcleo
# queda consumible por agentes (agent, Claude Desktop, MCP Inspector) sin más dependencias.
#
# Seguridad (ley 10 del mapa maestro + recomendación de la auditoría 2026-10-24):
#   - Las tools que tocan la red local (escanear, descubrir_hosts) son FAIL-CLOSED:
#     exigen whitelist MCP_ALLOWED_CIDRS y cada objetivo debe caer dentro.
#   - Todo stdout del núcleo se redirige a stderr: stdout ES el canal del protocolo.
#
# Ejecución: python3 mcp_server.py  (el cliente habla por stdin/stdout línea a línea)
import io
import json
import os
import sys
from contextlib import redirect_stdout

import config
import intel_exploit
import intel_nvd
import intel_psirt
import nucleo
import scoring
import targets

PROTOCOL_VERSION = "2024-11-05"
SERVER_INFO = {"name": "mcp-cves", "version": "0.1.0"}

TOOLS = [
    {
        "name": "puntuar",
        "description": "Score ponderado de un CVE: CVSS 60% + KEV 20% + EPSS 20% (escala 0-100).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "cvss": {"type": "number", "description": "CVSS base (0-10)"},
                "kev": {
                    "type": "boolean",
                    "description": "True si el CVE está en el catálogo KEV de CISA",
                },
                "epss": {"type": "number", "description": "Probabilidad EPSS (0-1)"},
            },
            "required": ["cvss", "kev", "epss"],
        },
    },
    {
        "name": "buscar_cves",
        "description": "Busca CVEs en NVD para un software y versión (caché local primero, CPE antes que keyword).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "software": {"type": "string"},
                "version": {"type": "string"},
                "banner": {
                    "type": "string",
                    "description": "Banner completo (opcional, mejora el mapeo CPE)",
                },
            },
            "required": ["software", "version"],
        },
    },
    {
        "name": "armas_publicas",
        "description": "¿Existe arma pública para estos CVEs? Fusiona Exploit-DB (con módulos Metasploit) y PoCs de GitHub. Sin red local: no requiere whitelist.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "cve_ids": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "IDs tipo CVE-2023-44487",
                },
            },
            "required": ["cve_ids"],
        },
    },
    {
        "name": "escanear_dependencias",
        "description": "Vector SCA: manifiestos (requirements/package.json/go.mod/Cargo/pom/Gemfile) de un directorio → OSV. FAIL-CLOSED: requiere whitelist MCP_DEPS_ROOTS.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "ruta": {
                    "type": "string",
                    "description": "Directorio del proyecto a escanear",
                },
            },
            "required": ["ruta"],
        },
    },
    {
        "name": "advisories",
        "description": "Advisories oficiales de Red Hat y Ubuntu para un CVE (severidad del vendor, fecha pública, USN) y días que se anticiparon a NVD. Sin red local: no requiere whitelist.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "cve_id": {"type": "string", "description": "p. ej. CVE-2023-44487"},
            },
            "required": ["cve_id"],
        },
    },
    {
        "name": "descubrir_hosts",
        "description": "Descubre hosts vivos en un CIDR (ARP con fallback a nmap). Requiere whitelist MCP_ALLOWED_CIDRS que contenga el CIDR pedido.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "cidr": {"type": "string", "description": "p. ej. 192.168.1.0/24"}
            },
            "required": ["cidr"],
        },
    },
    {
        "name": "escanear",
        "description": "Escanea hosts (solo IPs dentro de MCP_ALLOWED_CIDRS), correlaciona CVEs con EPSS/KEV, marca el diferencial y genera CSV/PDF en outputs/. Requiere whitelist.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "hosts": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "IPs explícitas",
                },
                "puertos": {
                    "type": "string",
                    "description": "formato nmap: '22,80' o '1-1000'",
                },
            },
            "required": ["hosts", "puertos"],
        },
    },
]


def _ok(id_, result):
    return {"jsonrpc": "2.0", "id": id_, "result": result}


def _err(id_, code, message):
    return {"jsonrpc": "2.0", "id": id_, "error": {"code": code, "message": message}}


def _tool_text(texto, is_error=False):
    return {"content": [{"type": "text", "text": texto}], "isError": is_error}


def _whitelist(allowed_cidrs):
    return config.mcp_allowed_cidrs() if allowed_cidrs is None else allowed_cidrs


def _run_tool(nombre, args, allowed):
    """Ejecuta una tool con el stdout capturado; devuelve (texto, is_error)."""
    buf = io.StringIO()
    try:
        with redirect_stdout(buf):
            if nombre == "puntuar":
                score = scoring.compute_score(
                    cvss=float(args.get("cvss") or 0.0),
                    kev=bool(args.get("kev")),
                    epss=float(args.get("epss") or 0.0),
                )
                return f"{score:.1f}", False

            if nombre == "buscar_cves":
                sw = str(args.get("software") or "").strip()
                ver = str(args.get("version") or "").strip()
                if not sw or not ver:
                    return "Se requieren 'software' y 'version' no vacíos.", True
                cves = intel_nvd.search_cves_cpe_first(
                    sw, ver, banner=str(args.get("banner") or "")
                )
                if not cves:
                    return "Sin CVEs conocidos para ese software/versión.", False
                lineas = [f"{len(cves)} CVE(s):"]
                for c in cves[:25]:
                    lineas.append(
                        f"- {c.get('cve_id')} | CVSS {c.get('cvss', 0.0):.1f} | {(c.get('description') or '')[:90]}"
                    )
                return "\n".join(lineas), False

            if nombre == "armas_publicas":
                ids_in = args.get("cve_ids")
                if not isinstance(ids_in, list) or not ids_in:
                    return (
                        "Se requiere 'cve_ids' (lista de IDs tipo CVE-2023-44487).",
                        True,
                    )
                ids = [str(c).upper().strip() for c in ids_in]
                mal_formados = [
                    c
                    for c in ids
                    if not __import__("re").fullmatch(r"CVE-\d{4}-\d{4,}", c)
                ]
                if mal_formados:
                    return "IDs no válidos (formato CVE-AAAA-NNNN): " + ", ".join(
                        mal_formados
                    ), True
                armas = intel_exploit.armas_para_cves(ids)
                lineas = []
                for cve in ids:
                    info = armas.get(cve, {})
                    if info.get("tiene_arma"):
                        lineas.append(
                            f"{cve}: ARMA PÚBLICA — {info.get('resumen', '')}"
                        )
                        for e in info.get("exploitdb", [])[:5]:
                            marca = " [metasploit]" if e.get("metasploit") else ""
                            lineas.append(
                                f"  exploit-db{marca}: {e.get('url')} ({e.get('fecha', '?')})"
                            )
                        for poc in info.get("github_poc", [])[:5]:
                            lineas.append(f"  PoC GitHub: {poc.get('url')}")
                    else:
                        lineas.append(f"{cve}: sin arma pública conocida")
                return "\n".join(lineas), False

            if nombre == "escanear_dependencias":
                ruta = str(args.get("ruta") or "").strip()
                if not ruta:
                    return "Se requiere 'ruta' (directorio del proyecto).", True
                roots = config.mcp_deps_roots()
                if not roots:
                    return (
                        "FAIL-CLOSED: la whitelist MCP_DEPS_ROOTS no está configurada; "
                        "configúrala (p. ej. '/home/yo/proyectos') para autorizar el análisis "
                        "de dependencias."
                    ), True
                real = os.path.realpath(ruta)
                dentro = False
                for rt in roots:
                    rt_real = os.path.realpath(rt)
                    try:
                        if os.path.commonpath([real, rt_real]) == rt_real:
                            dentro = True
                            break
                    except ValueError:
                        continue
                if not dentro:
                    return (
                        f"Ruta '{ruta}' fuera de la whitelist MCP_DEPS_ROOTS autorizada.",
                        True,
                    )
                hallazgos = nucleo.escanear_dependencias(real)
                csv_path, pdf_ok = nucleo.generar_informes(hallazgos)
                lineas = [
                    f"{len(hallazgos)} vulnerabilidad(es) de dependencias.",
                    f"Informe CSV: {csv_path}"
                    + (" | PDF: outputs/informe_escaneo.pdf" if pdf_ok else ""),
                ]
                for h in sorted(hallazgos, key=lambda x: x["score"], reverse=True)[:10]:
                    arma = "arma" if h["arma_publica"] else ""
                    kev = "KEV" if h["kev"] else ""
                    marcas = "/".join(m for m in (kev, arma) if m)
                    lineas.append(
                        f"- [{h['os']}] {h['software']} {h['version']}: {h['cve_id']} "
                        f"score {h['score']:.1f} {('[ ' + marcas + ' ]') if marcas else ''}"
                    )
                return "\n".join(lineas), False

            if nombre == "advisories":
                cve_id = str(args.get("cve_id") or "").upper().strip()
                if not __import__("re").fullmatch(r"CVE-\d{4}-\d{4,}", cve_id):
                    return f"ID no válido (formato CVE-AAAA-NNNN): '{cve_id}'.", True
                adv = intel_psirt.para_cve(cve_id)
                nvd = intel_nvd.get_cve(cve_id)
                fecha_nvd = (nvd or {}).get("published", "")
                lineas = [f"{cve_id} — advisories de vendor:"]
                hay = False
                for vendor in ("redhat", "ubuntu"):
                    info = adv.get(vendor)
                    if not info:
                        continue
                    hay = True
                    gap = intel_psirt.dias_anticipa(info.get("fecha"), fecha_nvd)
                    gap_txt = (
                        f" | anticipa NVD {gap}d" if gap is not None and gap > 0 else ""
                    )
                    notas = f" | {info['notas'][0]}" if info.get("notas") else ""
                    lineas.append(
                        f"- {info['vendor']}: {info['severidad']} ({info['fecha']}){notas}{gap_txt} | {info['url']}"
                    )
                if not hay:
                    lineas.append(
                        "- Ni Red Hat ni Ubuntu publican advisory para este CVE."
                    )
                if fecha_nvd:
                    cvss_txt = (
                        f" (CVSS {nvd.get('cvss')})" if nvd and nvd.get("cvss") else ""
                    )
                    lineas.append(f"NVD lo publicó: {fecha_nvd}{cvss_txt}")
                return "\n".join(lineas), False

            if nombre == "descubrir_hosts":
                cidr = str(args.get("cidr") or "").strip()
                if not cidr:
                    return "Se requiere 'cidr'.", True
                if not allowed:
                    return (
                        "FAIL-CLOSED: la whitelist MCP_ALLOWED_CIDRS no está configurada; "
                        "configúrala (p. ej. '192.168.1.0/24,127.0.0.0/8') para autorizar el discovery."
                    ), True
                if not targets.es_cidr(cidr):
                    return f"CIDR no válido: '{cidr}'.", True
                if not targets.cidr_en_whitelist(cidr, allowed):
                    return f"CIDR '{cidr}' fuera de la whitelist autorizada.", True
                hosts = nucleo.descubrir_hosts(cidr)
                return (", ".join(hosts) if hosts else "Sin hosts activos."), False

            if nombre == "escanear":
                hosts_in = args.get("hosts")
                if not isinstance(hosts_in, list) or not hosts_in:
                    return "Se requiere 'hosts' (lista de IPs).", True
                puertos = str(args.get("puertos") or "").strip()
                if not puertos:
                    return "Se requiere 'puertos' (formato nmap).", True
                if not allowed:
                    return (
                        "FAIL-CLOSED: la whitelist MCP_ALLOWED_CIDRS no está configurada; "
                        "configúrala para autorizar el escaneo."
                    ), True
                validos, rechazados = targets.filtrar_objetivos(
                    [str(h) for h in hosts_in]
                )
                if rechazados:
                    return "Objetivos no válidos como IP: " + ", ".join(
                        f"'{r}'" for r in rechazados
                    ), True
                fuera = [h for h in validos if not targets.ip_en_whitelist(h, allowed)]
                if fuera:
                    return "Objetivos fuera de la whitelist autorizada: " + ", ".join(
                        fuera
                    ), True
                resumen, hallazgos, filas_diff = nucleo.escanear(validos, puertos)
                csv_path, pdf_ok = nucleo.generar_informes(hallazgos)
                pdf_txt = (
                    " | PDF: outputs/informe_escaneo.pdf"
                    if pdf_ok
                    else " | PDF: no generado"
                )
                lineas = [
                    f"Escaneados {len(resumen)} host(s); {len(hallazgos)} hallazgo(s).",
                    (
                        f"Diferencial: {sum(1 for f in filas_diff if f[1] == 'NUEVO')} nuevos, "
                        f"{sum(1 for f in filas_diff if f[1] == 'CERRADO')} cerrados, "
                        f"{sum(1 for f in filas_diff if f[1] == 'PERSISTENTE')} persistentes."
                    ),
                    f"Informe CSV: {csv_path}{pdf_txt}",
                ]
                for h in sorted(hallazgos, key=lambda x: x["score"], reverse=True)[:10]:
                    lineas.append(
                        f"- {h['host']}:{h['port']}/{h['proto']} {h['cve_id']} "
                        f"CVSS {h['cvss']:.1f} KEV {'sí' if h['kev'] else 'no'} "
                        f"EPSS {h['epss']:.3f} score {h['score']:.1f} [{h['estado_diferencial']}]"
                    )
                return "\n".join(lineas), False

            return f"Tool desconocida: '{nombre}'.", True
    except Exception as e:
        return f"Error ejecutando '{nombre}': {e}", True
    finally:
        log = buf.getvalue().strip()
        if log:
            # el stdout del núcleo NO puede tocar el canal del protocolo: va a stderr
            print(log, file=sys.stderr)


def handle(msg, allowed_cidrs=None):
    """Procesa un mensaje JSON-RPC; devuelve la respuesta o None (notificaciones)."""
    allowed = _whitelist(allowed_cidrs)

    if not isinstance(msg, dict):
        return _err(None, -32600, "Invalid Request")
    method = msg.get("method")
    id_ = msg.get("id")
    es_notificacion = "id" not in msg

    if method == "initialize":
        params = msg.get("params") or {}
        version = params.get("protocolVersion") or PROTOCOL_VERSION
        return _ok(
            id_,
            {
                "protocolVersion": version,
                "capabilities": {"tools": {}},
                "serverInfo": SERVER_INFO,
            },
        )

    if method == "notifications/initialized":
        return None

    if method == "ping":
        return None if es_notificacion else _ok(id_, {})

    if method == "tools/list":
        return None if es_notificacion else _ok(id_, {"tools": TOOLS})

    if method == "tools/call":
        if es_notificacion:
            return None
        params = msg.get("params") or {}
        nombre = params.get("name") or ""
        args = params.get("arguments") or {}
        if not isinstance(args, dict):
            return _ok(id_, _tool_text("'arguments' debe ser un objeto.", True))
        texto, is_error = _run_tool(nombre, args, allowed)
        return _ok(id_, _tool_text(texto, is_error))

    if es_notificacion:
        return None
    return _err(id_, -32601, f"Method not found: {method}")


def serve(stream_in=None, stream_out=None):
    """Bucle stdio: una línea JSON por mensaje (transporte stdio de MCP)."""
    stream_in = stream_in or sys.stdin
    stream_out = stream_out or sys.stdout
    for line in stream_in:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            resp = _err(None, -32700, "Parse error")
        else:
            resp = handle(msg)
        if resp is not None:
            print(json.dumps(resp, ensure_ascii=False), file=stream_out, flush=True)


if __name__ == "__main__":
    serve()
