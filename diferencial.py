# diferencial.py — comparación pura de inventarios de servicios (DAT-002).
# Sin red ni disco: el escáner le pasa el inventario anterior (store) y el actual (escaneo).

NUEVO = "NUEVO"
CERRADO = "CERRADO"
PERSISTENTE = "PERSISTENTE"


def _clave(e):
    return (e.get("port"), e.get("proto", "tcp"))


def comparar_inventarios(anterior, actual):
    """Compara dos inventarios (listas de dicts con port/proto/banner/software/version).

    Devuelve {(port, proto): {"estado": NUEVO|CERRADO|PERSISTENTE, "antes": dict|None,
    "ahora": dict|None}}. El estado refleja presencia del servicio, no contenido: si cambia
    el banner o la versión, el servicio sigue siendo PERSISTENTE.
    """
    prev = {_clave(e): e for e in (anterior or [])}
    cur = {_clave(e): e for e in (actual or [])}

    out = {}
    for key, e in cur.items():
        estado = PERSISTENTE if key in prev else NUEVO
        out[key] = {"estado": estado, "antes": prev.get(key), "ahora": e}
    for key, e in prev.items():
        if key not in cur:
            out[key] = {"estado": CERRADO, "antes": e, "ahora": None}
    return out
