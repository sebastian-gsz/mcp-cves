# ports.py — utilidades para manejar listas/rangos de puertos
def parse_ports_input(s: str) -> str:

    if not s:
        return ""
    tokens = []
    # se adminte varias lineas por si el usuario pega bloques
    for raw in str(s).replace("\n", ",").split(","):
        t = raw.strip()
        if not t:
            continue
        # rango "a-b"
        if "-" in t:
            try:
                a_str, b_str = t.split("-", 1)
                a = int(a_str.strip())
                b = int(b_str.strip())
                if 1 <= a <= b <= 65535:
                    tokens.append(f"{a}-{b}")
                # si no es válido, se ignora
            except Exception:
                pass
        else:
            # num suelto
            if t.isdigit():
                v = int(t)
                if 1 <= v <= 65535:
                    tokens.append(str(v))
    if not tokens:
        return ""
    # quitar duplicados y preservar orden
    seen = set()
    norm = []
    for t in tokens:
        if t not in seen:
            seen.add(t)
            norm.append(t)
    return ",".join(norm)

def load_ports_file(path: str) -> str:

    try:
        with open(path, "r", encoding="utf-8") as f:
            content = []
            for line in f:
                # quitar comentarios inline
                line = line.split("#", 1)[0].strip()
                if not line:
                    continue
                content.append(line)
    except Exception as e:
        print(f"[!] No se pudo leer {path}: {e}")
        return ""
    return parse_ports_input("\n".join(content))
