# config.py — helpers de configuración centralizada (ley 5 del mapa maestro).
import os


def debug_enabled() -> bool:
    # opt-in: solo valores explícitos activan el modo debug; sin DEBUG el default es False (NUC-002).
    return (os.getenv("DEBUG") or "").strip().lower() in ("1", "true", "yes", "on")


def db_path() -> str:
    # ruta de la caché local (DAT-001); sobreescrita por entorno para pruebas.
    return os.getenv("CVESCANNER_DB") or os.path.join("data", "cache.sqlite3")


def mcp_allowed_cidrs():
    # whitelist de redes autorizadas para las tools de escaneo del servidor MCP (MCP-001).
    # Fail-closed: vacía por defecto -> las tools que tocan la red se niegan.
    raw = os.getenv("MCP_ALLOWED_CIDRS", "")
    return [c.strip() for c in raw.split(",") if c.strip()]


def host_workers() -> int:
    # grado de paralelismo del pool de hosts (NUC-001); ajustable para la medición A/B
    # de rendimiento (NUC_HOST_WORKERS=1 secuencial vs 8 por defecto). 1..64.
    try:
        return max(1, min(64, int(os.getenv("NUC_HOST_WORKERS") or 8)))
    except ValueError:
        return 8


def mcp_deps_roots():
    # whitelist de directorios autorizados para escanear_dependencias (INT-002).
    # Fail-closed: vacía por defecto -> la tool se niega.
    raw = os.getenv("MCP_DEPS_ROOTS", "")
    return [r.strip() for r in raw.split(",") if r.strip()]
