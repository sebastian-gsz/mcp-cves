# tests/test_int001.py — arma pública: parse EDB, fusión de fuentes, caché, degradación, score 4F, MCP.
import os
import sys
import tempfile
import types
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Bootstrap: entorno sin `requests` (intel_exploit/mcp_server lo importan).
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

import intel_exploit
import mcp_server
import scoring
import store

MINI_CSV = (
    "id,file,description,date_published,author,type,platform,port,verified,codes,tags\n"
    "16929,exploits/aix/dos/16929.rb,\"AIX rpc.cmsd Overflow (Metasploit)\",2010-11-11,"
    "Metasploit,dos,aix,,1,CVE-2009-3699;OSVDB-58726,Metasploit Framework (MSF)\n"
    "48506,exploits/linux/remote/48506.py,\"Thing 1.2 RCE\",2020-03-04,Anonymous,webapps,php,,"
    "1,CVE-2020-1234,\n"
    "48507,exploits/linux/remote/48507.rb,\"Thing 1.2 RCE v2\",2020-03-05,Anonymous,webapps,php,,"
    "1,CVE-2020-1234,\n"
    "1,exploits/x/dos/1.c,\"Sin CVE\",1999-01-01,Anon,dos,cgi,,1,,\n"
)


class TestParseEdbCsv(unittest.TestCase):
    """Parser puro del CSV de Exploit-DB (columna `codes` + marcado Metasploit)."""

    def test_indice_por_cve(self):
        idx = intel_exploit.parse_edb_csv(MINI_CSV)
        self.assertEqual(set(idx), {"CVE-2009-3699", "CVE-2020-1234"})  # sin CVE → fuera
        self.assertEqual(len(idx["CVE-2020-1234"]), 2)  # dos exploits, un CVE
        entrada_msf = idx["CVE-2009-3699"][0]
        self.assertTrue(entrada_msf["metasploit"])  # author/tags Metasploit
        self.assertEqual(entrada_msf["url"], "https://www.exploit-db.com/exploits/16929")
        self.assertFalse(idx["CVE-2020-1234"][0]["metasploit"])
        self.assertEqual(idx["CVE-2020-1234"][0]["fecha"], "2020-03-04")


class TestArmasFusion(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._env = mock.patch.dict(os.environ, {"CVESCANNER_DB": os.path.join(self._tmp.name, "c.sqlite3")})
        self._env.start()
        self.addCleanup(self._env.stop)
        self.addCleanup(self._tmp.cleanup)

    @staticmethod
    def _snapshot():
        idx = intel_exploit.parse_edb_csv(MINI_CSV)
        return idx

    def test_cve_con_arma_en_todas_las_fuentes(self):
        poc = [{"repo": "x/CVE-2009-3699", "url": "https://github.com/x/CVE-2009-3699"}]
        with mock.patch.object(intel_exploit, "_edb_snapshot", return_value=self._snapshot()), \
             mock.patch.object(intel_exploit, "_poc_github", return_value=poc):
            out = intel_exploit.armas_para_cves(["cve-2009-3699"])  # minúsculas → normaliza
        info = out["CVE-2009-3699"]
        self.assertTrue(info["tiene_arma"])
        self.assertIn("exploit-db: 1", info["resumen"])
        self.assertIn("metasploit: 1", info["resumen"])
        self.assertIn("PoC GitHub: 1", info["resumen"])
        self.assertEqual(len(info["metasploit"]), 1)

    def test_cve_sin_arma(self):
        with mock.patch.object(intel_exploit, "_edb_snapshot", return_value=self._snapshot()), \
             mock.patch.object(intel_exploit, "_poc_github", return_value=[]):
            out = intel_exploit.armas_para_cves(["CVE-2999-0001"])
        self.assertFalse(out["CVE-2999-0001"]["tiene_arma"])
        self.assertEqual(out["CVE-2999-0001"]["resumen"], "sin arma pública conocida")


class TestSnapshotYCaché(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._env = mock.patch.dict(os.environ, {"CVESCANNER_DB": os.path.join(self._tmp.name, "c.sqlite3")})
        self._env.start()
        self.addCleanup(self._env.stop)
        self.addCleanup(self._tmp.cleanup)

    def test_descarga_una_vez_luego_cache(self):
        resp = mock.Mock()
        resp.status_code = 200
        resp.raise_for_status = lambda: None
        resp.text = MINI_CSV
        with mock.patch("intel_exploit.requests.get", return_value=resp) as m:
            idx1 = intel_exploit._edb_snapshot()
            n = m.call_count
            idx2 = intel_exploit._edb_snapshot()  # segunda llamada: caché, 0 peticiones
        self.assertEqual(m.call_count, n)
        self.assertIn("CVE-2020-1234", idx1)
        self.assertEqual(idx1, idx2)

    def test_fallo_de_red_con_copia_vieja(self):
        # guardar snapshot y forzar "no fresco" para simular TTL vencido + red caída
        with mock.patch("intel_exploit.requests.get", return_value=mock.Mock(
                status_code=200, raise_for_status=lambda: None, text=MINI_CSV)):
            intel_exploit._edb_snapshot()
        with mock.patch.object(store, "get_fresh", return_value=None), \
             mock.patch("intel_exploit.requests.get", side_effect=Exception("red caida")):
            idx = intel_exploit._edb_snapshot()  # degrada a la última copia buena (ley 11)
        self.assertIn("CVE-2009-3699", idx)

    def test_fallo_de_red_sin_copia(self):
        with mock.patch.object(store, "get_fresh", return_value=None), \
             mock.patch.object(store, "get_any", return_value=None), \
             mock.patch("intel_exploit.requests.get", side_effect=Exception("red caida")):
            self.assertEqual(intel_exploit._edb_snapshot(), {})


class TestPocGithub(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._env = mock.patch.dict(os.environ, {"CVESCANNER_DB": os.path.join(self._tmp.name, "c.sqlite3")})
        self._env.start()
        self.addCleanup(self._env.stop)
        self.addCleanup(self._tmp.cleanup)

    def test_404_sin_poc_y_200_con_poc(self):
        resp404 = mock.Mock(status_code=404)
        resp200 = mock.Mock(status_code=200)
        resp200.json = lambda: [{"full_name": "x/CVE-2020-1234", "html_url": "u"}]
        with mock.patch("intel_exploit.requests.get", side_effect=[resp404, resp200]):
            self.assertEqual(intel_exploit._poc_github("CVE-2023-44487"), [])  # 404 = sin PoC
            pocs = intel_exploit._poc_github("CVE-2020-1234")                  # 200 = con PoC
        self.assertEqual(pocs[0]["repo"], "x/CVE-2020-1234")
        self.assertEqual(pocs[0]["url"], "https://github.com/x/CVE-2020-1234")

    def test_fallo_de_red_no_cachea_vacio(self):
        with mock.patch("intel_exploit.requests.get", side_effect=Exception("red caida")):
            self.assertEqual(intel_exploit._poc_github("CVE-2020-5678"), [])  # fallo → vacío
        self.assertIsNone(store.get_fresh("pocgh:CVE-2020-5678", 60))         # pero NO cacheado


class TestScoring4Factores(unittest.TestCase):
    """Ponderación INT-001: CVSS 45 / KEV 15 / EPSS 20 / ARMA 20."""

    def test_componentes(self):
        self.assertEqual(scoring.compute_score(10.0, False, 0.0), 45.0)
        self.assertEqual(scoring.compute_score(0.0, True, 0.0), 15.0)
        self.assertEqual(scoring.compute_score(0.0, False, 1.0), 20.0)
        self.assertEqual(scoring.compute_score(0.0, False, 0.0, arma=True), 20.0)

    def test_maximo_y_arma_reordena(self):
        self.assertEqual(scoring.compute_score(10.0, True, 1.0, arma=True), 100.0)
        # un 7.5 con arma pública supera a un 9.8 teórico sin señales
        self.assertGreater(scoring.compute_score(7.5, False, 0.0, arma=True),
                           scoring.compute_score(9.8, False, 0.01))


class TestMcpToolArmas(unittest.TestCase):
    def test_tool_con_mock(self):
        info = {"tiene_arma": True, "resumen": "exploit-db: 1",
                "exploitdb": [{"url": "https://www.exploit-db.com/exploits/1", "fecha": "2020-01-01",
                               "metasploit": False}], "github_poc": [], "metasploit": []}
        with mock.patch("intel_exploit.armas_para_cves", return_value={"CVE-2023-44487": info}):
            resp = mcp_server.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                                      "params": {"name": "armas_publicas",
                                                 "arguments": {"cve_ids": ["cve-2023-44487"]}}})
        texto = resp["result"]["content"][0]["text"]
        self.assertIn("ARMA PÚBLICA", texto)
        self.assertIn("exploit-db.com", texto)

    def test_tool_valida_entrada(self):
        for mal in ([], "no-lista", ["CVE-BAD"]):
            args = mal if mal != "no-lista" else "no-lista"
            resp = mcp_server.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                                      "params": {"name": "armas_publicas", "arguments": {"cve_ids": args}}})
            self.assertTrue(resp["result"]["isError"], repr(mal))


if __name__ == "__main__":
    unittest.main()
