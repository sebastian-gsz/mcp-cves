# tests/test_nuc003.py — núcleo importable: estructura sin input(), agregación, diferencial e informes.
import os
import sys
import tempfile
import types
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Bootstrap: entorno sin `requests` (nucleo → intel_nvd lo importa a nivel de módulo).
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

import nucleo

PUERTOS = "22,80"


def _fake_res(host):
    ports = [{"port": 22, "proto": "tcp", "banner": "OpenSSH/8.2p1", "software": "OpenSSH", "version": "8.2p1"},
             {"port": 80, "proto": "tcp", "banner": "nginx/1.18.0", "software": "nginx", "version": "1.18.0"}]
    hallazgos = [{"host": host, "os": "Linux", "port": 80, "proto": "tcp", "banner": "nginx/1.18.0",
                  "software": "nginx", "version": "1.18.0", "cve_id": "CVE-2020-0001", "severity": "HIGH",
                  "cvss": 7.5, "kev": False, "epss": 0.1, "score": 47.0, "description": "x"}]
    return "Linux", ports, hallazgos


class TestEstructuraNucleo(unittest.TestCase):
    def test_nucleo_no_llama_a_input(self):
        ruta = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "nucleo.py")
        with open(ruta, encoding="utf-8") as f:
            src = f.read()
        self.assertNotIn("input(", src, "el núcleo debe ser no interactivo (NUC-003)")

    def test_api_publica_existe(self):
        for fn in ("descubrir_hosts", "escanear", "generar_informes"):
            self.assertTrue(callable(getattr(nucleo, fn, None)), fn)


class TestEscaneaNucleo(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._env = mock.patch.dict(os.environ, {"CVESCANNER_DB": os.path.join(self._tmp.name, "cache.sqlite3")})
        self._env.start()
        self.addCleanup(self._env.stop)
        self.addCleanup(self._tmp.cleanup)

    def test_agrega_hosts_y_marca_nuevo_en_primer_scan(self):
        with mock.patch.object(nucleo, "_escanear_host", side_effect=lambda h, p, k, d: _fake_res(h)):
            resumen, hallazgos, filas_diff = nucleo.escanear(["10.0.0.1", "10.0.0.2"], PUERTOS)
        self.assertEqual(len(resumen), 2)
        self.assertEqual(len(hallazgos), 2)
        estados = {f[1] for f in filas_diff}
        self.assertEqual(estados, {"NUEVO"})  # sin historial previo
        self.assertTrue(all(h["estado_diferencial"] == "NUEVO" for h in hallazgos))

    def test_segundo_scan_marca_persistente_sin_falsos_nuevos(self):
        with mock.patch.object(nucleo, "_escanear_host", side_effect=lambda h, p, k, d: _fake_res(h)):
            nucleo.escanear(["10.0.0.1"], PUERTOS)
            _, _, filas_diff = nucleo.escanear(["10.0.0.1"], PUERTOS)
        self.assertEqual({f[1] for f in filas_diff}, {"PERSISTENTE"})

    def test_host_con_error_no_tumba_el_resto(self):
        def a_veces_explota(h, p, k, d):
            if h == "10.0.0.99":
                raise RuntimeError("boom")
            return _fake_res(h)

        with mock.patch.object(nucleo, "_escanear_host", side_effect=a_veces_explota):
            resumen, hallazgos, _ = nucleo.escanear(["10.0.0.99", "10.0.0.2"], PUERTOS)
        self.assertEqual([r["host"] for r in resumen], ["10.0.0.2"])
        self.assertEqual(len(hallazgos), 1)

    def test_host_sin_puertos_se_omitiene(self):
        with mock.patch.object(nucleo, "_escanear_host", return_value=None):
            resumen, hallazgos, filas_diff = nucleo.escanear(["10.0.0.3"], PUERTOS)
        self.assertEqual(resumen, [])
        self.assertEqual(hallazgos, [])
        self.assertEqual(filas_diff, [])


class TestGenerarInformes(unittest.TestCase):
    def test_csv_generado_y_pdf_protegido(self):
        hallazgo = dict(_fake_res("h1")[2][0])
        hallazgo["estado_diferencial"] = "NUEVO"
        with tempfile.TemporaryDirectory() as tmp:
            csv_path = os.path.join(tmp, "r.csv")
            pdf_path = os.path.join(tmp, "r.pdf")
            with mock.patch.dict(os.environ, {"CVESCANNER_DB": os.path.join(tmp, "c.sqlite3")}):
                csv_out, pdf_ok = nucleo.generar_informes([hallazgo], csv_path=csv_path, pdf_path=pdf_path)
            self.assertEqual(csv_out, csv_path)
            self.assertTrue(os.path.exists(csv_path), "el CSV debe generarse siempre")
            if not pdf_ok:  # sin reportlab en este entorno
                self.assertFalse(os.path.exists(pdf_path))
            else:
                self.assertTrue(os.path.exists(pdf_path))


if __name__ == "__main__":
    unittest.main()
