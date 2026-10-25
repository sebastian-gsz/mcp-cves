# tests/test_nuc001.py — token bucket, cumplimiento del ritmo NVD y concurrencia por servicio.
import os
import sys
import threading
import time
import types
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Bootstrap: entorno sin `tabulate` (utils la importa) ni `requests` (módulos intel_*).
try:
    import tabulate  # noqa: F401
except ImportError:
    _fake_tab = types.ModuleType("tabulate")

    def _tabulate(rows, headers=None, tablefmt=None):
        lines = [" | ".join(str(c) for c in (headers or []))]
        lines += [" | ".join(str(c) for c in r) for r in rows]
        return "\n".join(lines)

    _fake_tab.tabulate = _tabulate
    sys.modules["tabulate"] = _fake_tab

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

import intel_nvd
import ratelimit


class TestHostWorkers(unittest.TestCase):
    """NUC_HOST_WORKERS: grado de paralelismo del pool de hosts (medición A/B de NUC-001)."""

    def test_default_8(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual(__import__("config").host_workers(), 8)

    def test_env_override(self):
        with mock.patch.dict(os.environ, {"NUC_HOST_WORKERS": "3"}):
            self.assertEqual(__import__("config").host_workers(), 3)

    def test_valores_basura_y_limites(self):
        for valor, esperado in (("mal", 8), ("0", 1), ("-5", 1), ("999", 64), ("", 8)):
            with mock.patch.dict(os.environ, {"NUC_HOST_WORKERS": valor}):
                self.assertEqual(__import__("config").host_workers(), esperado, valor)


class TestTokenBucket(unittest.TestCase):
    def test_presupuesto_y_renovacion_de_ventana(self):
        b = ratelimit.TokenBucket(2, 1.0)
        self.assertTrue(b.acquire())
        self.assertTrue(b.acquire())
        t0 = time.monotonic()
        self.assertTrue(b.acquire())  # bloquea hasta que renueve la ventana
        self.assertGreaterEqual(time.monotonic() - t0, 0.9)

    def test_presupuesto_compartido_entre_hilos(self):
        b = ratelimit.TokenBucket(3, 30.0)
        resultados = []

        def worker():
            resultados.append(b.acquire(timeout_s=0.2))

        hilos = [threading.Thread(target=worker) for _ in range(6)]
        for t in hilos:
            t.start()
        for t in hilos:
            t.join()
        self.assertEqual(resultados.count(True), 3)   # solo el presupuesto de la ventana
        self.assertEqual(resultados.count(False), 3)  # el resto se agota en el timeout

    def test_parametros_invalidos(self):
        with self.assertRaises(ValueError):
            ratelimit.TokenBucket(0, 30.0)
        with self.assertRaises(ValueError):
            ratelimit.TokenBucket(5, 0)


class TestNvdRitmo(unittest.TestCase):
    def test_nvd_request_respeta_la_ventana(self):
        old = intel_nvd._BUCKET
        intel_nvd._BUCKET = ratelimit.TokenBucket(2, 1.0)
        try:
            resp = mock.Mock()
            resp.status_code = 200
            resp.raise_for_status = lambda: None
            resp.json = lambda: {"totalResults": 0, "vulnerabilities": []}
            with mock.patch("intel_nvd.requests.get", return_value=resp) as m:
                t0 = time.monotonic()
                for _ in range(4):
                    intel_nvd._nvd_request({"q": 1})
                dt = time.monotonic() - t0
        finally:
            intel_nvd._BUCKET = old
        self.assertEqual(m.call_count, 4)
        # 2 peticiones en la 1ª ventana + espera de ventana + 2 en la 2ª: no puede ser instantáneo
        self.assertGreaterEqual(dt, 0.9)

    def test_bucket_por_defecto_segun_api_key(self):
        # sin NVD_API_KEY en el entorno de tests, el bucket arranca en 5 req/30s
        self.assertEqual(intel_nvd._BUCKET.capacity, 5)
        self.assertEqual(intel_nvd._BUCKET.window_s, 30.0)


class TestConcurrenciaServicios(unittest.TestCase):
    def test_parse_y_mapeo_por_servicio(self):
        servicios = [
            {"port": 80, "proto": "tcp", "banner": "nginx/1.18.0"},
            {"port": 22, "proto": "tcp", "banner": "OpenSSH/8.2p1"},
            {"port": 9999, "proto": "tcp", "banner": "sin version clara"},
        ]
        with mock.patch.object(intel_nvd, "search_cves_cpe_first", return_value=[]) as m:
            out = intel_nvd.search_cves_for_services(servicios, max_workers=4)
        self.assertEqual(out[(80, "tcp")], [])
        self.assertEqual(out[(22, "tcp")], [])
        self.assertEqual(out[(9999, "tcp")], [])
        self.assertEqual(m.call_count, 2)  # solo los servicios con software/versión claros
        self.assertEqual(servicios[0]["software"], "nginx")
        self.assertEqual(servicios[0]["version"], "1.18.0")

    def test_ejecucion_realmente_paralela(self):
        def lento(*_a, **_k):
            time.sleep(0.5)
            return []

        servicios = [
            {"port": 80, "proto": "tcp", "banner": "nginx/1.18.0"},
            {"port": 443, "proto": "tcp", "banner": "nginx/1.18.0"},
        ]
        with mock.patch.object(intel_nvd, "search_cves_cpe_first", side_effect=lento):
            t0 = time.monotonic()
            intel_nvd.search_cves_for_services(servicios, max_workers=2)
            dt = time.monotonic() - t0
        self.assertLess(dt, 0.9)  # en serie serían ≥1.0s; en paralelo ronda 0.5s

    def test_error_de_un_servicio_no_tumba_los_demas(self):
        servicios = [
            {"port": 80, "proto": "tcp", "banner": "nginx/1.18.0"},
            {"port": 443, "proto": "tcp", "banner": "nginx/1.18.0"},
        ]

        def a_veces_explota(*_a, **_k):
            raise RuntimeError("boom")

        with mock.patch.object(intel_nvd, "search_cves_cpe_first", side_effect=a_veces_explota):
            out = intel_nvd.search_cves_for_services(servicios, max_workers=2)
        self.assertEqual(out[(80, "tcp")], [])
        self.assertEqual(out[(443, "tcp")], [])


if __name__ == "__main__":
    unittest.main()
