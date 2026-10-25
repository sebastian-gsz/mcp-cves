# tests/test_mcp001.py — servidor MCP: protocolo JSON-RPC, framing stdio y fail-closed.
import io
import json
import os
import sys
import tempfile
import types
import unittest
from contextlib import redirect_stdout
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Bootstrap: entorno sin `requests` (mcp_server → nucleo/intel_nvd lo importan).
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

import config
import mcp_server
import targets

LOCALHOST_ALLOWED = ["127.0.0.0/8"]


def _call(nombre, args, allowed=None):
    msg = {"jsonrpc": "2.0", "id": 7, "method": "tools/call",
           "params": {"name": nombre, "arguments": args}}
    return mcp_server.handle(msg, allowed_cidrs=allowed)


class TestProtocolo(unittest.TestCase):
    def test_initialize(self):
        resp = mcp_server.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                                  "params": {"protocolVersion": "2025-06-18", "capabilities": {}}})
        self.assertEqual(resp["id"], 1)
        self.assertEqual(resp["result"]["protocolVersion"], "2025-06-18")  # eco de la versión del cliente
        self.assertEqual(resp["result"]["serverInfo"]["name"], "mcp-cves")
        self.assertIn("tools", resp["result"]["capabilities"])

    def test_tools_list_expone_el_nucleo(self):
        resp = mcp_server.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        names = {t["name"] for t in resp["result"]["tools"]}
        self.assertEqual(names, {"puntuar", "buscar_cves", "armas_publicas", "escanear_dependencias",
                                 "advisories", "descubrir_hosts", "escanear"})
        for t in resp["result"]["tools"]:
            self.assertIn("inputSchema", t)

    def test_ping_y_metodo_desconocido(self):
        self.assertEqual(mcp_server.handle({"jsonrpc": "2.0", "id": 3, "method": "ping"})["result"], {})
        resp = mcp_server.handle({"jsonrpc": "2.0", "id": 4, "method": "metodo/raro"})
        self.assertEqual(resp["error"]["code"], -32601)

    def test_notificaciones_no_producen_respuesta(self):
        self.assertIsNone(mcp_server.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}))

    def test_framing_stdio_linea_a_linea(self):
        entrada = io.StringIO(
            json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}) + "\n"
            "esto no es json\n"
            + json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n"
        )
        salida = io.StringIO()
        with redirect_stdout(salida):  # el redirect protege el stdout real del runner
            mcp_server.serve(stream_in=entrada, stream_out=salida)
        lineas = [l for l in salida.getvalue().splitlines() if l.strip()]
        self.assertEqual(len(lineas), 2)  # initialize + parse error; la notificación no responde
        self.assertEqual(json.loads(lineas[0])["result"]["serverInfo"]["name"], "mcp-cves")
        self.assertEqual(json.loads(lineas[1])["error"]["code"], -32700)


class TestToolsSeguras(unittest.TestCase):
    """puntuar y buscar_cves no tocan la red local: funcionan sin whitelist."""

    def test_puntuar(self):
        resp = _call("puntuar", {"cvss": 7.5, "kev": False, "epss": 0.1})
        result = resp["result"]
        self.assertFalse(result["isError"])
        self.assertEqual(result["content"][0]["text"], "35.8")  # 4 factores INT-001: 33.75 + 0 + 2

    def test_buscar_cves_con_mock(self):
        cves = [{"cve_id": "CVE-2020-0001", "cvss": 7.5, "description": "algo grave"}]
        with mock.patch("intel_nvd.search_cves_cpe_first", return_value=cves) as m:
            resp = _call("buscar_cves", {"software": "nginx", "version": "1.18.0"})
        m.assert_called_once()
        self.assertIn("CVE-2020-0001", resp["result"]["content"][0]["text"])

    def test_buscar_cves_valida_entrada(self):
        resp = _call("buscar_cves", {"software": "", "version": "1.0"})
        self.assertTrue(resp["result"]["isError"])

    def test_tool_desconocida(self):
        resp = _call("no_existe", {})
        self.assertTrue(resp["result"]["isError"])


class TestFailClosed(unittest.TestCase):
    """escanear/descubrir_hosts tocan la red: sin whitelist o fuera de ella, se niegan."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._env = mock.patch.dict(os.environ, {"CVESCANNER_DB": os.path.join(self._tmp.name, "cache.sqlite3")})
        self._env.start()
        self.addCleanup(self._env.stop)
        self.addCleanup(self._tmp.cleanup)

    def test_escanear_sin_whitelist_se_niega(self):
        with mock.patch("nucleo.escanear") as m:
            resp = _call("escanear", {"hosts": ["127.0.0.1"], "puertos": "22,80"}, allowed=[])
        m.assert_not_called()
        self.assertTrue(resp["result"]["isError"])
        self.assertIn("MCP_ALLOWED_CIDRS", resp["result"]["content"][0]["text"])

    def test_escanear_host_fuera_de_whitelist_se_niega(self):
        with mock.patch("nucleo.escanear") as m:
            resp = _call("escanear", {"hosts": ["8.8.8.8"], "puertos": "80"}, allowed=LOCALHOST_ALLOWED)
        m.assert_not_called()
        self.assertTrue(resp["result"]["isError"])
        self.assertIn("whitelist", resp["result"]["content"][0]["text"])

    def test_escanear_host_no_ip_se_niega(self):
        resp = _call("escanear", {"hosts": ["-O", "127.0.0.1"], "puertos": "80"}, allowed=LOCALHOST_ALLOWED)
        self.assertTrue(resp["result"]["isError"])

    def test_escanear_autorizado_ejecuta_y_resume(self):
        resumen = [{"host": "127.0.0.1", "os": "Linux",
                    "ports": [{"port": 80, "proto": "tcp", "banner": "nginx/1.18.0"}]}]
        hallazgos = [{"host": "127.0.0.1", "os": "Linux", "port": 80, "proto": "tcp",
                      "banner": "nginx/1.18.0", "software": "nginx", "version": "1.18.0",
                      "cve_id": "CVE-2020-0001", "severity": "HIGH", "cvss": 7.5, "kev": False,
                      "epss": 0.1, "score": 47.0, "description": "x", "estado_diferencial": "NUEVO"}]
        with mock.patch("nucleo.escanear", return_value=(resumen, hallazgos, [["127.0.0.1", "NUEVO", "80/tcp", ""]])) as m, \
             mock.patch("nucleo.generar_informes", return_value=("outputs/r.csv", True)):
            resp = _call("escanear", {"hosts": ["127.0.0.1"], "puertos": "80"}, allowed=LOCALHOST_ALLOWED)
        m.assert_called_once_with(["127.0.0.1"], "80")
        texto = resp["result"]["content"][0]["text"]
        self.assertFalse(resp["result"]["isError"])
        self.assertIn("1 hallazgo", texto)
        self.assertIn("CVE-2020-0001", texto)
        self.assertIn("outputs/r.csv", texto)

    def test_descubrir_sin_whitelist_o_cidr_fuera(self):
        with mock.patch("nucleo.descubrir_hosts") as m:
            r1 = _call("descubrir_hosts", {"cidr": "127.0.0.0/24"}, allowed=[])
            r2 = _call("descubrir_hosts", {"cidr": "10.0.0.0/24"}, allowed=LOCALHOST_ALLOWED)
        m.assert_not_called()
        self.assertTrue(r1["result"]["isError"])
        self.assertTrue(r2["result"]["isError"])

    def test_descubrir_autorizado(self):
        with mock.patch("nucleo.descubrir_hosts", return_value=["127.0.0.1", "127.0.0.9"]) as m:
            resp = _call("descubrir_hosts", {"cidr": "127.0.0.0/29"}, allowed=LOCALHOST_ALLOWED)
        m.assert_called_once_with("127.0.0.0/29")
        self.assertEqual(resp["result"]["content"][0]["text"], "127.0.0.1, 127.0.0.9")

    def test_stdout_del_nucleo_no_toca_el_canal(self):
        # nucleo.escanear imprime progreso: el texto del protocolo debe llegar limpio
        with mock.patch("nucleo.escanear", side_effect=lambda *a, **k: print("[*] progreso ruidoso") or ([], [], [])), \
             mock.patch("nucleo.generar_informes", return_value=("outputs/r.csv", True)):
            resp = _call("escanear", {"hosts": ["127.0.0.1"], "puertos": "80"}, allowed=LOCALHOST_ALLOWED)
        self.assertNotIn("progreso ruidoso", resp["result"]["content"][0]["text"])


class TestWhitelistPura(unittest.TestCase):
    def test_ip_en_whitelist(self):
        self.assertTrue(targets.ip_en_whitelist("127.0.0.1", LOCALHOST_ALLOWED))
        self.assertFalse(targets.ip_en_whitelist("8.8.8.8", LOCALHOST_ALLOWED))
        self.assertFalse(targets.ip_en_whitelist("-O", LOCALHOST_ALLOWED))
        self.assertFalse(targets.ip_en_whitelist("::1", LOCALHOST_ALLOWED))  # v6 no está en una lista v4
        self.assertTrue(targets.ip_en_whitelist("::1", ["::1/128"]))

    def test_cidr_en_whitelist_subred(self):
        self.assertTrue(targets.cidr_en_whitelist("192.168.1.0/24", ["192.168.0.0/16"]))
        self.assertFalse(targets.cidr_en_whitelist("192.168.1.0/24", ["192.168.1.128/25"]))  # NO subred
        self.assertFalse(targets.cidr_en_whitelist("foo", LOCALHOST_ALLOWED))

    def test_config_parsea_env(self):
        with mock.patch.dict(os.environ, {"MCP_ALLOWED_CIDRS": " 10.0.0.0/8 , 127.0.0.0/8 ,,"}):
            self.assertEqual(config.mcp_allowed_cidrs(), ["10.0.0.0/8", "127.0.0.0/8"])
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual(config.mcp_allowed_cidrs(), [])  # fail-closed por defecto


if __name__ == "__main__":
    unittest.main()
