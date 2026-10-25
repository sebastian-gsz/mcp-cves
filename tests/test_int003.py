# tests/test_int003.py — PSIRT multi-vendor: parsing RH/Ubuntu, caché, gap vs NVD, MCP advisories.
import os
import sys
import tempfile
import types
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Bootstrap: entorno sin `requests`.
try:
    import requests  # noqa: F401
except ImportError:
    class _RequestException(Exception):
        pass

    _fake_req = types.ModuleType("requests")

    def _no_network(*_a, **_k):
        raise _RequestException("red deshabilitada en tests (requests no instalado)")

    _fake_req.get = _no_network
    _fake_req.post = _no_network
    _fake_req.Timeout = _RequestException
    _fake_req.RequestException = _RequestException
    sys.modules["requests"] = _fake_req

import intel_nvd
import intel_psirt
import mcp_server
import store

# fixture Red Hat: estructura de la respuesta REAL verificada en vivo (F0)
RH_FIXTURE = {
    "threat_severity": "Important",
    "public_date": "2023-10-10T00:00:00Z",
    "bugzilla": {"id": "2242803"},
    "cvss3": {"cvss3_base_score": "7.5", "cvss3_scoring_vector": "CVSS:3.1/AV:N/AC:L"},
}
# fixture Ubuntu: búsqueda q= devuelve coincidencias parciales + el registro exacto
UB_FIXTURE = {"cves": [
    {"id": "CVE-2026-47244", "published": "2026-06-12T15:16:00", "priority": "medium"},
    {"id": "CVE-2023-44487", "published": "2023-10-10T00:00:00", "priority": "high",
     "cvss3": {"base_score": 7.5}, "notices_ids": ["USN-6427-1"]},
], "total_results": 2}


class TestRedhat(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._env = mock.patch.dict(os.environ, {"CVESCANNER_DB": os.path.join(self._tmp.name, "c.sqlite3")})
        self._env.start()
        self.addCleanup(self._env.stop)
        self.addCleanup(self._tmp.cleanup)

    def test_parsea_y_cachea(self):
        resp = mock.Mock(status_code=200)
        resp.raise_for_status = lambda: None
        resp.json = lambda: RH_FIXTURE
        with mock.patch("intel_psirt.requests.get", return_value=resp) as m:
            out = intel_psirt._redhat("CVE-2023-44487")
            intel_psirt._redhat("CVE-2023-44487")  # 2ª: caché
        m.assert_called_once()
        self.assertEqual((out["vendor"], out["severidad"], out["fecha"], out["cvss"]),
                         ("RedHat", "Important", "2023-10-10", "7.5"))

    def test_404_cubre_como_none(self):
        with mock.patch("intel_psirt.requests.get", return_value=mock.Mock(status_code=404)):
            self.assertIsNone(intel_psirt._redhat("CVE-2999-0001"))

    def test_fallo_red_con_copia_vieja(self):
        resp = mock.Mock(status_code=200)
        resp.raise_for_status = lambda: None
        resp.json = lambda: RH_FIXTURE
        with mock.patch("intel_psirt.requests.get", return_value=resp):
            intel_psirt._redhat("CVE-2023-44487")
        with mock.patch.object(store, "get_fresh", return_value=None), \
             mock.patch("intel_psirt.requests.get", side_effect=Exception("sin red")):
            out = intel_psirt._redhat("CVE-2023-44487")  # degrada a la copia local
        self.assertEqual(out["severidad"], "Important")


class TestUbuntu(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._env = mock.patch.dict(os.environ, {"CVESCANNER_DB": os.path.join(self._tmp.name, "c.sqlite3")})
        self._env.start()
        self.addCleanup(self._env.stop)
        self.addCleanup(self._tmp.cleanup)

    def test_filtra_id_exacto(self):
        resp = mock.Mock(status_code=200)
        resp.raise_for_status = lambda: None
        resp.json = lambda: UB_FIXTURE
        with mock.patch("intel_psirt.requests.get", return_value=resp):
            out = intel_psirt._ubuntu("CVE-2023-44487")
        self.assertEqual((out["vendor"], out["severidad"], out["fecha"]), ("Ubuntu", "High", "2023-10-10"))
        self.assertEqual(out["notas"], ["USN-6427-1"])  # USN oficial visible

    def test_sin_registro_none(self):
        resp = mock.Mock(status_code=200)
        resp.raise_for_status = lambda: None
        resp.json = lambda: {"cves": [{"id": "CVE-2026-47244"}], "total_results": 1}
        with mock.patch("intel_psirt.requests.get", return_value=resp):
            self.assertIsNone(intel_psirt._ubuntu("CVE-2023-44487"))


class TestGapYResumen(unittest.TestCase):
    def test_dias_anticipa(self):
        self.assertEqual(intel_psirt.dias_anticipa("2023-10-10", "2023-10-13"), 3)
        self.assertEqual(intel_psirt.dias_anticipa("2023-10-13", "2023-10-10"), -3)  # NVD antes
        self.assertIsNone(intel_psirt.dias_anticipa("", "2023-10-13"))
        self.assertIsNone(intel_psirt.dias_anticipa("2023-10-10", "fecha-mala"))

    def test_resumen_con_gap(self):
        adv = {"redhat": {"vendor": "RedHat", "severidad": "Important", "fecha": "2023-10-10"},
               "ubuntu": {"vendor": "Ubuntu", "severidad": "High", "fecha": "2023-10-11",
                          "notas": ["USN-6427-1"]}}
        texto = intel_psirt.resumen_con_gap(adv, "2023-10-14")
        self.assertIn("RedHat=Important", texto)
        self.assertIn("Ubuntu=High (USN-6427-1)", texto)
        self.assertIn("[anticipa NVD 4d]", texto)  # máx(4,3)
        # sin anticipación → sin marca
        self.assertNotIn("anticipa", intel_psirt.resumen_con_gap(adv, "2023-10-10"))
        self.assertEqual(intel_psirt.resumen_con_gap({}, "2023-10-10"), "")


class TestNvdGetCve(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._env = mock.patch.dict(os.environ, {"CVESCANNER_DB": os.path.join(self._tmp.name, "c.sqlite3")})
        self._env.start()
        self.addCleanup(self._env.stop)
        self.addCleanup(self._tmp.cleanup)

    def test_ficha_por_id(self):
        js = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2023-44487",
                        "published": "2023-10-10T16:02:00",
                        "descriptions": [{"lang": "en", "value": "HTTP/2 Rapid Reset"}],
                        "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 7.5}}]},
                    }
                }
            ]
        }
        with mock.patch("intel_nvd._nvd_request", return_value=js) as m:
            out = intel_nvd.get_cve("CVE-2023-44487")
            intel_nvd.get_cve("CVE-2023-44487")  # 2ª: caché
        m.assert_called_once()
        self.assertEqual((out["published"], out["cvss"]), ("2023-10-10", 7.5))

    def test_no_existe(self):
        with mock.patch("intel_nvd._nvd_request", return_value={}):
            self.assertIsNone(intel_nvd.get_cve("CVE-2999-0001"))


class TestMcpAdvisories(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._env = mock.patch.dict(os.environ, {"CVESCANNER_DB": os.path.join(self._tmp.name, "c.sqlite3")})
        self._env.start()
        self.addCleanup(self._env.stop)
        self.addCleanup(self._tmp.cleanup)

    def test_tool_con_advisory_y_gap(self):
        adv = {"redhat": {"vendor": "RedHat", "severidad": "Important", "fecha": "2023-10-10",
                          "cvss": "7.5", "url": "https://access.redhat.com/security/cve/CVE-2023-44487"},
               "ubuntu": None}
        with mock.patch("intel_psirt.para_cve", return_value=adv), \
             mock.patch("intel_nvd.get_cve",
                        return_value={"published": "2023-10-13", "cvss": 7.5}):
            resp = mcp_server.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                                      "params": {"name": "advisories",
                                                 "arguments": {"cve_id": "cve-2023-44487"}}})
        texto = resp["result"]["content"][0]["text"]
        self.assertFalse(resp["result"]["isError"])
        self.assertIn("RedHat: Important (2023-10-10)", texto)
        self.assertIn("anticipa NVD 3d", texto)
        self.assertIn("NVD lo publicó: 2023-10-13", texto)

    def test_sin_advisories(self):
        with mock.patch("intel_psirt.para_cve", return_value={"redhat": None, "ubuntu": None}), \
             mock.patch("intel_nvd.get_cve", return_value=None):
            resp = mcp_server.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                                      "params": {"name": "advisories",
                                                 "arguments": {"cve_id": "CVE-2999-0001"}}})
        self.assertIn("Ni Red Hat ni Ubuntu", resp["result"]["content"][0]["text"])

    def test_id_invalido(self):
        resp = mcp_server.handle({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                                  "params": {"name": "advisories", "arguments": {"cve_id": "GHSA-x"}}})
        self.assertTrue(resp["result"]["isError"])


if __name__ == "__main__":
    unittest.main()
