# export_csv_pdf.py
import csv
from xml.sax.saxutils import escape

# reportlab se importa de forma perezosa dentro de export_pdf(): la ruta CSV no lo necesita
# y el módulo queda importable (y testeable) sin reportlab instalado (SEG-001)

def export_csv(hallazgos, csv_path):
    """
    Exporta a CSV. Conserva el orden de entrada.
    """
    headers = [
        "host", "os", "port", "proto", "banner",
        "software", "version", "cpe",
        "cve_id", "severity", "cvss", "kev", "epss", "score", "arma_publica", "psirt",
        "estado_diferencial",
        "description"
    ]
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        for h in hallazgos:
            row = {k: _csv_safe(h.get(k, "")) for k in headers}
            writer.writerow(row)


def _csv_safe(value):
    # neutraliza inyección de fórmulas en hojas de cálculo (=, +, -, @, tab, CR) (SEG-001)
    if isinstance(value, str) and value[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + value
    return value

# ---------------- PDF ----------------

def _clean_text(s: str) -> str:
    """
    Normaliza texto para evitar errores de fuentes no Unicode.
    Sustituye algunos caracteres problemáticos y fuerza latin-1 seguro
    (descartando caracteres no representables).
    """
    if not s:
        return ""
    s = str(s)
    # Sustituciones comunes
    replacements = {
        "…": "...",
        "’": "'",
        "‘": "'",
        "“": '"',
        "”": '"',
        "—": "-",
        "–": "-",
        "\u00a0": " ",   # NBSP
    }
    for k, v in replacements.items():
        s = s.replace(k, v)
    # Fuerza a latin-1 (quitar lo que no se pueda representar)
    try:
        s = s.encode("latin-1", "ignore").decode("latin-1")
    except Exception:
        # Si algo raro pasa, como fallback simple
        s = s.encode("ascii", "ignore").decode("ascii")
    # Los valores se inyectan en Paragraph (markup XML): escapar para evitar inyección (SEG-001)
    return escape(s)

def _score_color(score: float):
    """
    Devuelve el color de fondo del 'Score' según umbrales:
      >=90 rojo, 80-89.9 naranja, 70-79.9 amarillo, <70 verde
    Colores suaves para legibilidad.
    """
    if score >= 90:
        return colors.Color(0.98, 0.75, 0.75)   # rojo suave
    elif score >= 80:
        return colors.Color(1.0, 0.88, 0.70)    # naranja suave
    elif score >= 70:
        return colors.Color(1.0, 0.97, 0.70)    # amarillo suave
    else:
        return colors.Color(0.85, 0.95, 0.85)   # verde suave

def export_pdf(hallazgos, pdf_path):
    """
    Genera PDF con tabla ordenada por 'score' DESC, columnas ajustadas y leyenda.
    """
    # import perezoso enlazado a nivel de módulo: _score_color() usa `colors` (SEG-001)
    global colors, SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
    global ParagraphStyle, getSampleStyleSheet, A4, landscape, mm
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )
    # Ordena por score DESC
    rows = sorted(hallazgos, key=lambda x: x.get("score", 0.0), reverse=True)

    doc = SimpleDocTemplate(
        pdf_path,
        pagesize=landscape(A4),
        leftMargin=14 * mm,
        rightMargin=14 * mm,
        topMargin=12 * mm,
        bottomMargin=12 * mm,
        title="Informe de escaneo y priorización de vulnerabilidades"
    )

    styles = getSampleStyleSheet()
    p_small = ParagraphStyle(
        "small",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=7,
        leading=9,
        spaceAfter=0,
    )
    p_small_bold = ParagraphStyle(
        "small_bold",
        parent=p_small,
        fontName="Helvetica-Bold",
    )

    flow = []

    # Cabecera / título
    flow.append(Paragraph(
        "Informe de escaneo y priorización de vulnerabilidades",
        styles["Heading2"]
    ))
    flow.append(Spacer(1, 4 * mm))

    # Leyenda de colores (sin “pastel”)
    legend_data = [
        [
            Paragraph("&ge; 90", p_small),
            Paragraph("80–89.9", p_small),
            Paragraph("70–79.9", p_small),
            Paragraph("&lt; 70", p_small),
        ]
    ]
    legend = Table(legend_data, colWidths=[45*mm, 55*mm, 55*mm, 45*mm])
    legend_style = TableStyle([
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("BOX", (0, 0), (-1, -1), 0.25, colors.gray),
        ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.gray),
    ])
    # pinta el fondo de cada celda según la leyenda
    legend_style.add("BACKGROUND", (0, 0), (0, 0), _score_color(95))
    legend_style.add("BACKGROUND", (1, 0), (1, 0), _score_color(85))
    legend_style.add("BACKGROUND", (2, 0), (2, 0), _score_color(75))
    legend_style.add("BACKGROUND", (3, 0), (3, 0), _score_color(60))
    legend.setStyle(legend_style)

    flow.append(legend)
    flow.append(Spacer(1, 5 * mm))

    # Cabeceras de tabla
    headers = [
        "Host", "SO", "Puerto", "Banner", "CVE",
        "CVSS", "KEV", "EPSS", "Score", "Arma", "Estado", "Descripción"
    ]

    # Anchos de columna (A4 apaisado ~842 pt; margen total ~28 mm ≈ 80 pt; total 730 pt)
    col_widths = [
        72,   # Host
        60,   # SO
        42,   # Puerto
        100,  # Banner
        90,   # CVE
        38,   # CVSS
        32,   # KEV
        55,   # EPSS
        48,   # Score
        30,   # Arma pública (INT-001)
        48,   # Estado diferencial (DAT-002)
        115   # Descripción
    ]

    data = [ [Paragraph(h, p_small_bold) for h in headers] ]

    # Índices para colorear 'Score'
    SCORE_COL = headers.index("Score")

    # Filas
    for h in rows:
        host = _clean_text(h.get("host", ""))
        os_name = _clean_text(h.get("os", ""))
        port = f'{h.get("port","")}/{h.get("proto","")}'
        banner = _clean_text(h.get("banner", ""))
        cve = _clean_text(h.get("cve_id", ""))
        cvss = h.get("cvss", 0.0) or 0.0
        kev = "Sí" if h.get("kev", False) else "No"
        epss = h.get("epss", 0.0) or 0.0
        score = h.get("score", 0.0) or 0.0
        desc = _clean_text(h.get("description", ""))

        # Envuelve lo largo
        host_p = Paragraph(host, p_small)
        os_p = Paragraph(os_name, p_small)
        port_p = Paragraph(port, p_small)
        banner_p = Paragraph(banner, p_small)
        cve_p = Paragraph(cve, p_small)
        epss_p = Paragraph(f"{epss:.3f}", p_small)
        score_p = Paragraph(f"{score:.1f}", p_small)
        cvss_p = Paragraph(f"{cvss:.1f}", p_small)
        kev_p = Paragraph(kev, p_small)
        # Limita un poco la descripción (el Paragraph envuelve, pero recortamos para no dispararnos)
        if len(desc) > 300:
            desc = desc[:300] + "..."
        desc_p = Paragraph(desc, p_small)
        estado_p = Paragraph(_clean_text(h.get("estado_diferencial", "")), p_small)
        arma_p = Paragraph("Sí" if h.get("arma_publica") else "No", p_small)

        row = [
            host_p, os_p, port_p, banner_p, cve_p,
            cvss_p, kev_p, epss_p, score_p, arma_p, estado_p, desc_p
        ]
        data.append(row)

    table = Table(data, colWidths=col_widths, repeatRows=1)

    ts = TableStyle([
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 7),
        ("ALIGN", (0, 0), (-1, 0), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.lightgrey),
        ("BACKGROUND", (0, 0), (-1, 0), colors.whitesmoke),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.Color(0.98, 0.98, 0.98)]),
        # Alineaciones específicas
        ("ALIGN", (2, 1), (2, -1), "CENTER"),  # Puerto
        ("ALIGN", (5, 1), (9, -1), "CENTER"),  # CVSS, KEV, EPSS, Score, Arma
    ])

    # Colorear Score por fila
    for i in range(1, len(data)):
        # Celda (SCORE_COL, i)
        # Leemos el texto para decidir color (pero tenemos el score en rows[i-1])
        score_val = rows[i - 1].get("score", 0.0) or 0.0
        ts.add("BACKGROUND", (SCORE_COL, i), (SCORE_COL, i), _score_color(score_val))

    table.setStyle(ts)

    flow.append(table)
    doc.build(flow)
