# tests/test_seg002.py — validación de objetivos (H3): nada que no sea IP llega a nmap.
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
import targets


class TestValidacionPura(unittest.TestCase):
    def test_ips_validas(self):
        for ip in ("192.168.1.10", "127.0.0.1", "10.0.0.1", "::1", "fe80::1"):
            self.assertTrue(targets.es_ip(ip), ip)

    def test_ips_invalidas(self):
        # cadenas que podrían interpretarse como flags/argumentos de nmap (hallazgo H3)
        for no_ip in ("-O", "-foo", "host; rm -rf /", "192.168.1.1; cat /etc/passwd",
                      "localhost", "example.com", "", "  ", "192.168.1", "1.2.3.4.5", None):
            self.assertFalse(targets.es_ip(no_ip), repr(no_ip))

    def test_cidrs(self):
        for cidr in ("192.168.1.0/24", "10.0.0.0/8", "2001:db8::/32", "192.168.1.5/24"):
            self.assertTrue(targets.es_cidr(cidr), cidr)
        for no_cidr in ("foo/24", "192.168.1.0/33", "-sS", "", None, "192.168.1.1/24/24"):
            self.assertFalse(targets.es_cidr(no_cidr), repr(no_cidr))

    def test_filtrar_objetivos(self):
        validos, rechazados = targets.filtrar_objetivos(
            ["192.168.1.10", "-O", "10.0.0.5", "host; rm", "", None, "::1"])
        self.assertEqual(validos, ["192.168.1.10", "10.0.0.5", "::1"])
        self.assertEqual(rechazados, ["-O", "host; rm", "", ""])  # None se normaliza a ""

    def test_lista_nula_o_vacia(self):
        self.assertEqual(targets.filtrar_objetivos(None), ([], []))
        self.assertEqual(targets.filtrar_objetivos([]), ([], []))


class TestNucleoEnforces(unittest.TestCase):
    """La frontera es el NÚCLEO (no la CLI): el futuro servidor MCP llamará aquí."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._env = mock.patch.dict(os.environ, {"CVESCANNER_DB": os.path.join(self._tmp.name, "cache.sqlite3")})
        self._env.start()
        self.addCleanup(self._env.stop)
        self.addCleanup(self._tmp.cleanup)

    @staticmethod
    def _fake_res(host):
        ports = [{"port": 80, "proto": "tcp", "banner": "nginx/1.18.0", "software": "nginx", "version": "1.18.0"}]
        hallazgos = [{"host": host, "os": "Linux", "port": 80, "proto": "tcp", "banner": "nginx/1.18.0",
                      "software": "nginx", "version": "1.18.0", "cve_id": "CVE-2020-0001", "severity": "HIGH",
                      "cvss": 7.5, "kev": False, "epss": 0.1, "score": 47.0, "description": "x"}]
        return "Linux", ports, hallazgos

    def test_objetivo_malicioso_nunca_llega_a_nmap(self):
        with mock.patch.object(nucleo, "_escanear_host",
                               side_effect=lambda h, p, k, d: self._fake_res(h)) as m:
            resumen, _, _ = nucleo.escanear(["-O", "192.168.1.10", "host; rm -rf /"], "22,80")
        hosts_escaneados = [c.args[0] for c in m.call_args_list]
        self.assertEqual(hosts_escaneados, ["192.168.1.10"])  # solo la IP válida
        self.assertEqual([r["host"] for r in resumen], ["192.168.1.10"])

    def test_todos_invalidos_cero_llamadas(self):
        with mock.patch.object(nucleo, "_escanear_host") as m:
            resumen, hallazgos, filas = nucleo.escanear(["-sS", "evil.com"], "22,80")
        m.assert_not_called()
        self.assertEqual((resumen, hallazgos, filas), ([], [], []))

    def test_descubrir_cidr_invalido_sin_tocar_scapy(self):
        # la validación ocurre ANTES del import perezoso de scapy: sin scapy instalado,
        # un CIDR inválido se rechaza limpiamente (con uno válido fallaría el import)
        resultado = nucleo.descubrir_hosts("-p; algo")
        self.assertEqual(resultado, [])

    def test_objetivo_valido_pasa(self):
        with mock.patch.object(nucleo, "_escanear_host",
                               side_effect=lambda h, p, k, d: self._fake_res(h)) as m:
            nucleo.escanear(["127.0.0.1"], "80")
        m.assert_called_once()


if __name__ == "__main__":
    unittest.main()
