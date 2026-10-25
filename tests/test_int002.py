# tests/test_int002.py — OSV/SCA: parsers de manifiestos, consulta OSV, caché, MCP fail-closed.
import json
import os
import sys
import tempfile
import types
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Bootstrap: entorno sin `requests`; el stub necesita `post` (OSV usa POST).
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

import intel_osv
import mcp_server
import nucleo
import store


class TestParsers(unittest.TestCase):
    """Parsers puros: solo versiones exactas son consultables."""

    def test_requirements(self):
        texto = "# comentario\nrequests==2.32.3\nflask >= 2.0\nnumpy==1.26.0 ; python_version<'3.13'\n"
        deps = intel_osv._parse_requirements(texto)
        self.assertEqual(deps, [("requests", "2.32.3"), ("numpy", "1.26.0")])  # >= fuera

    def test_package_json(self):
        data = {"dependencies": {"lodash": "4.17.21", "react": "^18.0.0"},
                "devDependencies": {"mocha": "10.2.0"}}
        deps = intel_osv._parse_package_json(json.dumps(data))
        self.assertIn(("lodash", "4.17.21"), deps)
        self.assertIn(("mocha", "10.2.0"), deps)
        self.assertNotIn(("react", "^18.0.0"), deps)  # rangos ^~ fuera

    def test_go_mod(self):
        deps = intel_osv._parse_go_mod("module x\n\ngo 1.21\n\nrequire (\n\tgithub.com/x/y v1.2.3\n)\n")
        self.assertEqual(deps, [("github.com/x/y", "v1.2.3")])

    def test_cargo(self):
        deps = intel_osv._parse_cargo('[dependencies]\nserde = "1.0.190"\ntokio = { version = "1.33", features = ["full"] }\n')
        self.assertIn(("serde", "1.0.190"), deps)
        self.assertIn(("tokio", "1.33"), deps)

    def test_pom(self):
        pom = ('<project xmlns="http://maven.apache.org/POM/4.0.0">'
               "<dependencies><dependency><groupId>org.apache.logging.log4j</groupId>"
               "<artifactId>log4j-core</artifactId><version>2.14.1</version></dependency>"
               "<dependency><groupId>x</groupId><artifactId>${vers}</artifactId><version>${v}</version>"
               "</dependency></dependencies></project>")
        deps = intel_osv._parse_pom(pom)
        self.assertEqual(deps, [("org.apache.logging.log4j:log4j-core", "2.14.1")])

    def test_gemfile(self):
        deps = intel_osv._parse_gemfile("source 'https://rubygems.org'\ngem 'rails', '7.0.8'\ngem 'puma'\n")
        self.assertEqual(deps, [("rails", "7.0.8")])


class TestDetectarManifiestos(unittest.TestCase):
    def test_encuentra_y_excluye(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "node_modules", "x"))
            os.makedirs(os.path.join(d, "sub"))
            for ruta in ("requirements.txt", os.path.join("node_modules", "x", "requirements.txt"),
                         os.path.join("sub", "package.json")):
                open(os.path.join(d, ruta), "w").close()
            encontrados = {n for n, _ in intel_osv.detectar_manifiestos(d)}
        self.assertEqual(encontrados, {"requirements.txt", "package.json"})  # node_modules excluido


class TestConsultarOsv(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._env = mock.patch.dict(os.environ, {"CVESCANNER_DB": os.path.join(self._tmp.name, "c.sqlite3")})
        self._env.start()
        self.addCleanup(self._env.stop)
        self.addCleanup(self._tmp.cleanup)

    @staticmethod
    def _resp(vulns):
        r = mock.Mock()
        r.raise_for_status = lambda: None
        r.json = lambda: {"vulns": vulns}
        return r

    def test_consulta_y_parsea(self):
        vulns = [{"id": "GHSA-xxxx", "aliases": ["CVE-2021-44228"],
                  "summary": "RCE en log4j", "database_specific": {"severity": "critical"}}]
        with mock.patch("intel_osv.requests.post", return_value=self._resp(vulns)) as m:
            out = intel_osv.consultar_osv("Maven", "org.apache.logging.log4j:log4j-core", "2.14.1")
            m.assert_called_once()
            self.assertEqual(out[0]["cve_id"], "CVE-2021-44228")
            self.assertEqual(out[0]["cvss"], 9.5)  # proxy por severidad declarada
            self.assertIn("osv.dev/vulnerability/GHSA-xxxx", out[0]["url"])
            # segunda llamada: caché, 0 peticiones
            intel_osv.consultar_osv("Maven", "org.apache.logging.log4j:log4j-core", "2.14.1")
            self.assertEqual(m.call_count, 1)

    def test_fallo_de_red_no_cachea_vacio(self):
        with mock.patch("intel_osv.requests.post", side_effect=Exception("sin red")):
            self.assertEqual(intel_osv.consultar_osv("PyPI", "requests", "2.0.0"), [])
        self.assertIsNone(store.get_fresh("osv:PyPI:requests:2.0.0", 60))


class TestNucleoDeps(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._env = mock.patch.dict(os.environ, {"CVESCANNER_DB": os.path.join(self._tmp.name, "c.sqlite3")})
        self._env.start()
        self.addCleanup(self._env.stop)
        self.addCleanup(self._tmp.cleanup)

    def test_proyecto_mixto_genera_hallazgos_puntuados(self):
        with tempfile.TemporaryDirectory() as proyecto:
            with open(os.path.join(proyecto, "requirements.txt"), "w") as f:
                f.write("vulnpkg==1.0.0\n")
            with open(os.path.join(proyecto, "package.json"), "w") as f:
                f.write(json.dumps({"dependencies": {"sanopkg": "2.0.0"}}))
            vuln = {"cve_id": "CVE-2021-44228", "osv_id": "GHSA-x", "resumen": "RCE",
                    "cvss": 9.5, "url": "https://osv.dev/vulnerability/GHSA-x"}
            with mock.patch("intel_osv.consultar_osv_batch",
                            return_value={("PyPI", "vulnpkg", "1.0.0"): [vuln],
                                          ("npm", "sanopkg", "2.0.0"): []}), \
                 mock.patch("intel_kev.load_kev_set", return_value={"CVE-2021-44228"}), \
                 mock.patch("intel_exploit.armas_para_cves",
                            return_value={"CVE-2021-44228": {"tiene_arma": True, "resumen": "exploit-db: 1"}}):
                hallazgos = nucleo.escanear_dependencias(proyecto)
        self.assertEqual(len(hallazgos), 1)
        h = hallazgos[0]
        self.assertEqual((h["os"], h["software"], h["version"]), ("PyPI", "vulnpkg", "1.0.0"))
        self.assertEqual(h["banner"], "requirements.txt")
        self.assertTrue(h["kev"] and h["arma_publica"])
        self.assertEqual(h["score"], 9.5 * 10 * 0.45 + 15 + 20)  # 77.5: 4 factores

    def test_sin_manifiestos(self):
        with tempfile.TemporaryDirectory() as vacio:
            self.assertEqual(nucleo.escanear_dependencias(vacio), [])


class TestMcpFailClosedDeps(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._env = mock.patch.dict(os.environ, {"CVESCANNER_DB": os.path.join(self._tmp.name, "c.sqlite3")})
        self._env.start()
        self.addCleanup(self._env.stop)
        self.addCleanup(self._tmp.cleanup)

    @staticmethod
    def _call(ruta):
        return mcp_server.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                                  "params": {"name": "escanear_dependencias",
                                             "arguments": {"ruta": ruta}}})

    def test_sin_whitelist_se_niega(self):
        with mock.patch.object(mcp_server.config, "mcp_deps_roots", return_value=[]):
            resp = self._call("/tmp")
        self.assertTrue(resp["result"]["isError"])
        self.assertIn("MCP_DEPS_ROOTS", resp["result"]["content"][0]["text"])

    def test_ruta_fuera_de_whitelist_se_niega(self):
        with mock.patch.object(mcp_server.config, "mcp_deps_roots", return_value=[self._tmp.name]), \
             mock.patch("nucleo.escanear_dependencias") as m:
            resp = self._call("/etc")
        m.assert_not_called()
        self.assertTrue(resp["result"]["isError"])

    def test_ruta_autorizada_escanea(self):
        proyecto = os.path.join(self._tmp.name, "proyecto")
        os.makedirs(proyecto, exist_ok=True)
        hallazgo = {"os": "PyPI", "software": "x", "version": "1", "cve_id": "CVE-1",
                    "score": 50.0, "kev": False, "arma_publica": False}
        with mock.patch.object(mcp_server.config, "mcp_deps_roots", return_value=[self._tmp.name]), \
             mock.patch("nucleo.escanear_dependencias", return_value=[hallazgo]) as m, \
             mock.patch("nucleo.generar_informes", return_value=("outputs/r.csv", True)):
            resp = self._call(proyecto)
        m.assert_called_once_with(proyecto)
        self.assertFalse(resp["result"]["isError"])
        self.assertIn("1 vulnerabilidad", resp["result"]["content"][0]["text"])

    def test_ruta_maliciosa_con_puntos_no_escapa(self):
        with mock.patch.object(mcp_server.config, "mcp_deps_roots", return_value=[self._tmp.name]), \
             mock.patch("nucleo.escanear_dependencias") as m:
            resp = self._call(os.path.join(self._tmp.name, "proyecto", "..", "..", "etc"))
        m.assert_not_called()  # realpath sale de la whitelist → rechazado
        self.assertTrue(resp["result"]["isError"])


if __name__ == "__main__":
    unittest.main()
