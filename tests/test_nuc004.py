# tests/test_nuc004.py — módulos puros (ports, cpe_map) y parsing NVD con fixture grabada.
import json
import os
import sys
import tempfile
import types
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Bootstrap: entorno sin `requests` (intel_nvd la importa a nivel de módulo).
try:
    import requests  # noqa: F401
except ImportError:
    class _RequestException(Exception):
        pass

    _fake_req = types.ModuleType("requests")

    def _no_network(*_a, **_k):
        raise _RequestException("red deshabilitada en tests (requests no instalado)")

    _fake_req.get = _no_network
    _fake_req.Timeout = _RequestException
    _fake_req.RequestException = _RequestException
    sys.modules["requests"] = _fake_req

import cpe_map
import intel_nvd
import ports

_FIXTURE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "nvd_response_sample.json")


class TestPorts(unittest.TestCase):
    def test_puertos_validos_y_dedup(self):
        self.assertEqual(ports.parse_ports_input("22,80,80-82,99999,0"), "22,80,80-82")

    def test_multilinea_y_ruido(self):
        self.assertEqual(ports.parse_ports_input("22\n443\nabc\n"), "22,443")

    def test_rango_invalido(self):
        self.assertEqual(ports.parse_ports_input("100-50"), "")

    def test_entrada_vacia(self):
        self.assertEqual(ports.parse_ports_input(""), "")
        self.assertEqual(ports.parse_ports_input(None), "")

    def test_load_ports_file_con_comentarios(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
            f.write("# comentario de cabecera\n22\n\n80-81 # comentario inline\n# otra\n")
            path = f.name
        try:
            self.assertEqual(ports.load_ports_file(path), "22,80-81")
        finally:
            os.unlink(path)

    def test_load_ports_file_inexistente(self):
        self.assertEqual(ports.load_ports_file("/ruta/que/no/existe.txt"), "")


class TestCpeMap(unittest.TestCase):
    def test_producto_directo(self):
        self.assertEqual(cpe_map.resolve_cpe_bases("nginx"), ["cpe:2.3:a:f5:nginx"])

    def test_pista_de_banner(self):
        self.assertEqual(
            cpe_map.resolve_cpe_bases("postgres", banner="PostgreSQL 12.4 on x86_64"),
            ["cpe:2.3:a:postgresql:postgresql"],
        )

    def test_desconocido_devuelve_vacio(self):
        self.assertEqual(cpe_map.resolve_cpe_bases("producto_desconocido_xyz"), [])


class TestNvdParsingFixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(_FIXTURE, encoding="utf-8") as f:
            cls.respuesta = json.load(f)

    def test_parse_respuesta_completa(self):
        items = intel_nvd._parse_nvd_response(self.respuesta)
        self.assertEqual(len(items), 2)
        primero = items[0]
        self.assertEqual(primero["cve_id"], "CVE-2021-44228")
        self.assertEqual(primero["cvss"], 10.0)
        self.assertIn("CVE-2021-44228", primero["url"])
        self.assertIn("Log4j2", primero["description"])

    def test_fallback_cvss_v2(self):
        items = intel_nvd._parse_nvd_response(self.respuesta)
        self.assertEqual(items[1]["cvss"], 7.5)  # CVE-2015-9999 solo tiene v2

    def test_parse_cvss_orden_v31_v30_v2(self):
        cve = {"metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]}}
        self.assertEqual(intel_nvd._parse_cvss(cve), (9.8, "CRITICAL"))
        cve_v2 = {"metrics": {"cvssMetricV2": [{"baseSeverity": "HIGH", "cvssData": {"baseScore": 7.5}}]}}
        self.assertEqual(intel_nvd._parse_cvss(cve_v2), (7.5, "HIGH"))
        self.assertEqual(intel_nvd._parse_cvss({"metrics": {}}), (0.0, ""))

    def test_build_cpe23(self):
        self.assertEqual(
            intel_nvd._build_cpe23("cpe:2.3:a:apache:http_server", "2.4.41"),
            "cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*",
        )
        self.assertEqual(
            intel_nvd._build_cpe23("cpe:2.3:a:apache:http_server", None),
            "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
        )
        with self.assertRaises(ValueError):
            intel_nvd._build_cpe23("cpe-mal-formado", "1.0")

    def test_version_candidates(self):
        self.assertEqual(intel_nvd._version_candidates("2.4.41"), ["2.4.41", "2.4", "2"])
        self.assertEqual(intel_nvd._version_candidates(""), [])
        self.assertEqual(intel_nvd._version_candidates("8"), ["8"])

    def test_primera_cpe_del_fixture(self):
        cve = self.respuesta["vulnerabilities"][0]["cve"]
        self.assertEqual(intel_nvd._first_cpe(cve), "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*")


if __name__ == "__main__":
    unittest.main()
