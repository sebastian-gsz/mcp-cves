# store.py — caché persistente local (SQLite) para CVEs, inteligencia e historial (DAT-001/DAT-002).
# Sostiene la ley 11 (degradación elegante): ante fallo de red, se sirve la última copia buena.
import json
import os
import sqlite3
import time

import config

CVE_TTL_S = 72 * 3600    # resultados NVD por CPE/keyword: cambian poco
EPSS_TTL_S = 24 * 3600   # EPSS se publica a diario
KEV_TTL_S = 24 * 3600    # KEV se actualiza a diario; el fallback admite cualquier edad

_SCHEMA = (
    "CREATE TABLE IF NOT EXISTS kv ("
    " key TEXT PRIMARY KEY,"
    " payload_json TEXT NOT NULL,"
    " fetched_at REAL NOT NULL);"
    "CREATE TABLE IF NOT EXISTS inventario ("
    " host TEXT NOT NULL,"
    " batch INTEGER NOT NULL,"
    " port INTEGER NOT NULL,"
    " proto TEXT NOT NULL,"
    " banner TEXT,"
    " software TEXT,"
    " version TEXT,"
    " scanned_at REAL NOT NULL,"
    " PRIMARY KEY (host, batch, port, proto))"
)


def _connect() -> sqlite3.Connection:
    path = config.db_path()
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.executescript(_SCHEMA)  # varias sentencias DDL
    return conn


def put(key: str, payload) -> None:
    conn = _connect()
    try:
        with conn:
            conn.execute(
                "INSERT OR REPLACE INTO kv (key, payload_json, fetched_at) VALUES (?, ?, ?)",
                (key, json.dumps(payload, ensure_ascii=False), time.time()),
            )
    finally:
        conn.close()


def get_fresh(key: str, max_age_s: float):
    # payload solo si existe y su edad no excede max_age_s; None en caso contrario.
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT payload_json, fetched_at FROM kv WHERE key = ?", (key,)
        ).fetchone()
    finally:
        conn.close()
    if not row:
        return None
    payload_json, fetched_at = row
    if (time.time() - fetched_at) > max_age_s:
        return None
    return json.loads(payload_json)


def get_any(key: str):
    # (payload, edad_en_segundos) sin importar la edad; None si nunca se guardó.
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT payload_json, fetched_at FROM kv WHERE key = ?", (key,)
        ).fetchone()
    finally:
        conn.close()
    if not row:
        return None
    payload_json, fetched_at = row
    return json.loads(payload_json), max(0.0, time.time() - fetched_at)


def save_inventory(host: str, entries) -> None:
    """Persiste el inventario actual de un host como un lote (batch) nuevo (DAT-002).

    Cada escaneo añade un lote completo; los lotes anteriores se conservan como historial.
    Un puerto cerrado en este escaneo simplemente no está en el lote actual.
    """
    now = time.time()
    conn = _connect()
    try:
        with conn:
            row = conn.execute(
                "SELECT COALESCE(MAX(batch), 0) + 1 FROM inventario WHERE host = ?", (host,)
            ).fetchone()
            batch = row[0]
            for e in entries:
                conn.execute(
                    "INSERT INTO inventario (host, batch, port, proto, banner, software, version, scanned_at)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (host, batch, e.get("port"), e.get("proto", "tcp"), e.get("banner", ""),
                     e.get("software", ""), e.get("version", ""), now),
                )
    finally:
        conn.close()


def load_last_inventory(host: str):
    """Último estado conocido de cada servicio del host (solo el lote más reciente)."""
    conn = _connect()
    try:
        rows = conn.execute(
            "SELECT port, proto, banner, software, version FROM inventario"
            " WHERE host = ? AND batch = (SELECT MAX(batch) FROM inventario WHERE host = ?)",
            (host, host),
        ).fetchall()
    finally:
        conn.close()
    return [
        {"port": r[0], "proto": r[1], "banner": r[2] or "", "software": r[3] or "", "version": r[4] or ""}
        for r in rows
    ]
