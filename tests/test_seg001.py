# tests/test_seg001.py — datos hostiles: truncado de banners, ReDoS contenido, escaping CSV/PDF.
import csv
import os
import sys
import tempfile
import types
import unittest
from typing import ClassVar

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Bootstrap: entorno sin `tabulate` (utils la importa a nivel de módulo).
try:
    import tabulate  # noqa: F401
except ImportError:
    _fake = types.ModuleType("tabulate")

    def _tabulate(rows, headers=None, tablefmt=None):
        lines = [" | ".join(str(c) for c in (headers or []))]
        lines += [" | ".join(str(c) for c in r) for r in rows]
        return "\n".join(lines)

    _fake.tabulate = _tabulate
    sys.modules["tabulate"] = _fake

try:
    import reportlab  # noqa: F401
    REPORTLAB_DISPONIBLE = True
except ImportError:
    REPORTLAB_DISPONIBLE = False

import cpe_map
import export_csv_pdf
import utils


class TestTruncadoBanners(unittest.TestCase):
    def test_banner_largo_se_trunca_antes_de_regex(self):
        sw, ver = utils.parse_software_version_from_banner("OpenSSH/" + "9." * 10000)
        self.assertEqual(sw, "OpenSSH")
        self.assertTrue(ver.startswith("9."))

    def test_banner_con_regex_patologica_termina(self):
        sw, _ver = utils.parse_software_version_from_banner("nginx/" + "1." * 5000 + "!")
        self.assertEqual(sw, "nginx")

    def test_cpe_map_con_banner_hostil(self):
        bases = cpe_map.resolve_cpe_bases("httpd", banner="Apache " + "A" * 10000)
        self.assertEqual(bases, ["cpe:2.3:a:apache:http_server"])

    def test_banner_vacio_o_none(self):
        self.assertEqual(utils.parse_software_version_from_banner(""), (None, None))
        self.assertEqual(utils.parse_software_version_from_banner(None), (None, None))


class TestExportSeguro(unittest.TestCase):
    HALLAZGO: ClassVar[dict] = {
        "host": '=HYPERLINK("http://evil";"click")', "os": "Linux", "port": 80, "proto": "tcp",
        "banner": "<b>bold</b> & <script>x</script>", "software": "nginx", "version": "1.18.0",
        "cve_id": "CVE-2024-0001", "severity": "HIGH", "cvss": 9.8, "kev": False, "epss": 0.1,
        "score": 61.0, "description": "desc & <tag>",
    }

    def test_clean_text_escapa_xml(self):
        self.assertEqual(export_csv_pdf._clean_text("<b>&x</b>"), "&lt;b&gt;&amp;x&lt;/b&gt;")

    def test_csv_neutraliza_formulas(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "r.csv")
            export_csv_pdf.export_csv([dict(self.HALLAZGO)], path)
            with open(path, encoding="utf-8") as f:
                reader = csv.reader(f)
                cabecera = next(reader)
                fila = next(reader)
        host_idx = cabecera.index("host")
        self.assertTrue(fila[host_idx].startswith("'="),
                        "un host que empieza por '=' debe ir neutralizado como fórmula")

    def test_csv_datos_normales_intactos(self):
        h = dict(self.HALLAZGO)
        h["host"] = "192.168.1.10"
        h["banner"] = "nginx/1.18.0"
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "r.csv")
            export_csv_pdf.export_csv([h], path)
            with open(path, encoding="utf-8") as f:
                reader = csv.reader(f)
                cabecera = next(reader)
                fila = next(reader)
        self.assertEqual(fila[cabecera.index("host")], "192.168.1.10")
        self.assertEqual(fila[cabecera.index("banner")], "nginx/1.18.0")

    @unittest.skipUnless(REPORTLAB_DISPONIBLE, "reportlab no instalado en este entorno")
    def test_pdf_genera_con_datos_hostiles(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "r.pdf")
            export_csv_pdf.export_pdf([dict(self.HALLAZGO)], path)
            self.assertGreater(os.path.getsize(path), 0)


if __name__ == "__main__":
    unittest.main()
