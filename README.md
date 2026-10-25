# mcp-cves

Escáner de vulnerabilidades con **servidor MCP** para agentes LLM: descubre tu red, correlaciona
CVEs desde 6 fuentes de inteligencia y prioriza por riesgo real — no por gravedad teórica.

## Qué hace

```
mcp_server.serve()   ← servidor MCP stdio (7 tools, fail-closed con whitelists)
cve_scanner.py       ← CLI interactiva
nucleo.py            ← núcleo importable (todo el pipeline)
    ↓
descubrimiento (ARP + nmap) → escaneo en paralelo (≤8 hosts) → parsing de banners
    → CVEs (NVD) → enriquecimiento (EPSS · KEV · arma pública · PSIRT) → score 4 factores
    → escaneo diferencial → informes CSV/PDF
```

| Fuente de inteligencia | Qué aporta | Gratis |
|---|---|---|
| NVD (NIST) | CVEs por CPE/keyword, CVSS | ✅ |
| EPSS (FIRST) | Probabilidad de explotación a 30 días | ✅ |
| KEV (CISA) | Explotación activa confirmada | ✅ |
| Exploit-DB + Metasploit + PoC-in-GitHub | **¿Existe arma pública?** | ✅ |
| OSV (Google) | Vulnerabilidades por **dependencia de código** (SCA) | ✅ |
| Red Hat + Ubuntu PSIRT | Severidad del vendor y **días que anticipa a NVD** | ✅ |

**Score** = CVSS 45% + KEV 15% + EPSS 20% + arma pública 20% — un CVE 7.5 con exploit público
puntúa por encima de un 9.8 teórico.

## Requisitos

- Python 3.10+ y `pip install -r requirements.txt`
- `nmap` instalado (y `NET_RAW`/`NET_ADMIN` o root para ARP/SYN)
- Opcional: `NVD_API_KEY` (sube de 5 a 50 peticiones/30 s — el token bucket respeta ambos límites)

## Uso

### CLI

```bash
python3 cve_scanner.py        # te pregunta objetivos (CIDR/IP) y puertos
```

Genera `outputs/reporte_vulnerabilidades.csv` y `outputs/informe_escaneo.pdf`, y compara cada
escaneo con el anterior (NUEVO / CERRADO / PERSISTENTE).

### Servidor MCP (ZCode, Claude Desktop, Inspector…)

```json
{
  "mcpServers": {
    "mcp-cves": {
      "command": "python3",
      "args": ["/ruta/a/mcp_server.py"],
      "env": {
        "MCP_ALLOWED_CIDRS": "192.168.1.0/24",
        "MCP_DEPS_ROOTS": "/home/tu/proyectos"
      }
    }
  }
}
```

**7 tools**: `puntuar`, `buscar_cves`, `armas_publicas`, `advisories` (sin red local), y
`descubrir_hosts`, `escanear`, `escanear_dependencias` (**fail-closed**: solo actúan dentro de
las whitelists que tú definas — un LLM no puede escanear fuera de permiso).

### SCA de dependencias

```python
import nucleo
hallazgos = nucleo.escanear_dependencias("/ruta/proyecto")  # lee lockfiles:
# pnpm-lock.yaml · package-lock.json · yarn.lock · poetry.lock · uv.lock (transitivos incluidos)
```

## Docker

```bash
docker compose build
docker compose run --rm vulnscan   # usuario `scanner` (no root) + capabilities NET_RAW/NET_ADMIN
```

## Calidad

- **136+ tests** (pytest/unittest, sin red ni disco) · **ruff** limpio · **CI** en cada push
  (Python 3.12/3.13)
- Degradación elegante: si una fuente falla, se sirve la última copia buena **avisando** — nunca
  ceros silenciosos

## Seguridad y uso responsable

⚠️ Escáner **activo**: solo apunta a redes que estás **autorizado** a escanear. Las whitelists del
servidor MCP existen para eso. Nunca envía IPs privadas fuera de tu máquina (las consultas de intel
llevan solo software/CVEs públicos; ver auditoría en `docs/runbooks/`).

## Documentación

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — mapa de contratos navegable (haz esto antes de
  tocar código)
- [`docs/workboard/`](docs/workboard/README.md) — tablero de tareas (16 cerradas) y su ciclo de vida
- [`docs/runbooks/`](docs/runbooks/INDEX.md) — auditorías y bitácoras de verificación
- [`CHANGELOG.md`](CHANGELOG.md) — historial de versiones
