# tests/test_dat001.py — caché SQLite (store), fallback KEV, caché EPSS y caché NVD por CPE.
import os
import sys
import tempfile
import types
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Bootstrap: el entorno de esta sesión no tiene `requests` instalado. Se inyecta un stub mínimo
# con las excepciones que intel_* capturan; todas las llamadas de red de estos tests van mockeadas.
try:
    import requests  # noqa: F401
except ImportError:
    class _RequestException(Exception):
        pass

    _fake = types.ModuleType("requests")

    def _no_network(*_a, **_k):
        raise _RequestException("red deshabilitada en tests (requests no instalado)")

    _fake.get = _no_network
    _fake.Timeout = _RequestException
    _fake.RequestException = _RequestException
    sys.modules["requests"] = _fake

import intel_epss
import intel_kev
import intel_nvd
import store


def _env_db(tmp_root):
    """Aísla la caché de cada test en su propio fichero SQLite temporal."""
    p = mock.patch.dict(os.environ, {"CVESCANNER_DB": os.path.join(tmp_root, "cache.sqlite3")})
    p.start()
    return p


class TestStore(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._env = _env_db(self._tmp.name)
        self.addCleanup(self._env.stop)
        self.addCleanup(self._tmp.cleanup)

    def test_roundtrip(self):
        store.put("cpe:x:1", [{"cve_id": "CVE-1"}])
        self.assertEqual(store.get_fresh("cpe:x:1", 60), [{"cve_id": "CVE-1"}])

    def test_ttl_expira(self):
        store.put("cpe:x:2", ["a"])
        self.assertIsNone(store.get_fresh("cpe:x:2", 0))

    def test_get_any_da_edad(self):
        store.put("kev", ["CVE-9"])
        payload, edad = store.get_any("kev")
        self.assertEqual(payload, ["CVE-9"])
        self.assertLess(edad, 60)

    def test_claves_independientes(self):
        store.put("a", 1)
        store.put("b", 2)
        self.assertEqual(store.get_fresh("a", 60), 1)
        self.assertEqual(store.get_fresh("b", 60), 2)


class TestKevFallback(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._env = _env_db(self._tmp.name)
        self.addCleanup(self._env.stop)
        self.addCleanup(self._tmp.cleanup)

    def test_fallo_con_copia_local_sirve_ultima_copia(self):
        store.put("kev", ["CVE-A", "CVE-B"])
        with mock.patch("intel_kev.requests.get", side_effect=Exception("red caida")):
            s = intel_kev.load_kev_set()
        self.assertEqual(s, {"CVE-A", "CVE-B"})

    def test_fallo_sin_copia_local_devuelve_vacio(self):
        with mock.patch("intel_kev.requests.get", side_effect=Exception("red caida")):
            s = intel_kev.load_kev_set()
        self.assertEqual(s, set())

    def test_exito_guarda_snapshot(self):
        resp = mock.Mock()
        resp.raise_for_status = lambda: None
        resp.json = lambda: {"vulnerabilities": [{"cveID": "CVE-C"}]}
        with mock.patch("intel_kev.requests.get", return_value=resp):
            s = intel_kev.load_kev_set()
        self.assertEqual(s, {"CVE-C"})
        self.assertEqual(store.get_any("kev")[0], ["CVE-C"])


class TestEpssCache(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._env = _env_db(self._tmp.name)
        self.addCleanup(self._env.stop)
        self.addCleanup(self._tmp.cleanup)

    @staticmethod
    def _fake_response(rows):
        resp = mock.Mock()
        resp.raise_for_status = lambda: None
        resp.json = lambda: {"data": rows}
        return resp

    def test_consulta_y_persiste(self):
        rows = [{"cve": "CVE-1", "epss": "0.5", "percentile": "0.7"}]
        with mock.patch("intel_epss.requests.get", return_value=self._fake_response(rows)) as mget:
            out = intel_epss.get_epss_for_cves(["CVE-1"])
        self.assertEqual(out["CVE-1"]["epss"], 0.5)
        mget.assert_called_once()
        self.assertEqual(store.get_fresh("epss:CVE-1", 60)["epss"], 0.5)

    def test_segunda_llamada_sin_red_sale_de_cache(self):
        store.put("epss:CVE-2", {"epss": 0.4, "percentile": 0.6})
        with mock.patch("intel_epss.requests.get", side_effect=Exception("no red")):
            out = intel_epss.get_epss_for_cves(["CVE-2"])
        self.assertEqual(out["CVE-2"]["epss"], 0.4)

    def test_mixto_cacheado_y_api_sin_duplicar_peticiones(self):
        store.put("epss:CVE-3", {"epss": 0.1, "percentile": 0.2})
        rows = [{"cve": "CVE-4", "epss": "0.9", "percentile": "0.95"}]
        with mock.patch("intel_epss.requests.get", return_value=self._fake_response(rows)) as mget:
            out = intel_epss.get_epss_for_cves(["CVE-3", "CVE-4", "CVE-4"])
        self.assertEqual(out["CVE-3"]["epss"], 0.1)
        self.assertEqual(out["CVE-4"]["epss"], 0.9)
        mget.assert_called_once()  # solo se pidió el CVE sin copia, y una sola vez


class TestNvdCachePorCpe(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._env = _env_db(self._tmp.name)
        self.addCleanup(self._env.stop)
        self.addCleanup(self._tmp.cleanup)

    def test_segunda_llamada_sin_tocar_la_api(self):
        resp = {
            "vulnerabilities": [
                {"cve": {"id": "CVE-10", "descriptions": [{"lang": "en", "value": "x"}], "metrics": {}}}
            ],
            "totalResults": 1,
        }
        with mock.patch("intel_nvd._nvd_request", return_value=resp) as mreq:
            intel_nvd.search_cves_by_cpe("cpe:2.3:a:apache:http_server", "2.4.41")
            n_primera = mreq.call_count
            self.assertEqual(n_primera, 3)  # una petición por variante de versión (2.4.41, 2.4, 2)
            intel_nvd.search_cves_by_cpe("cpe:2.3:a:apache:http_server", "2.4.41")
            self.assertEqual(mreq.call_count, n_primera)  # la 2ª consulta salió entera de la caché

    def test_fallo_transitorio_no_cachea_vacio(self):
        with mock.patch("intel_nvd._nvd_request", return_value={}):
            self.assertEqual(intel_nvd.search_cves_by_cpe("cpe:2.3:a:nginx:nginx", "1.18.0"), [])
        self.assertIsNone(store.get_fresh("cpe:cpe:2.3:a:nginx:nginx:1.18.0", 60))
        # y una vez recuperada la red, la misma consulta vuelve a preguntar a la API
        resp = {
            "vulnerabilities": [
                {"cve": {"id": "CVE-11", "descriptions": [{"lang": "en", "value": "y"}], "metrics": {}}}
            ],
            "totalResults": 1,
        }
        with mock.patch("intel_nvd._nvd_request", return_value=resp) as mreq:
            r2 = intel_nvd.search_cves_by_cpe("cpe:2.3:a:nginx:nginx", "1.18.0")
        self.assertEqual([c["cve_id"] for c in r2], ["CVE-11"])
        self.assertEqual(mreq.call_count, 3)  # tras el fallo, ninguna variante estaba cacheada


if __name__ == "__main__":
    unittest.main()
