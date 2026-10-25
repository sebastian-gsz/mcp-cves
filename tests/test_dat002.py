# tests/test_dat002.py — diferencial de inventario: comparador puro, historial en store y CSV.
import csv
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import diferencial
import export_csv_pdf
import store

INV_22 = {"port": 22, "proto": "tcp", "banner": "OpenSSH/8.2p1", "software": "OpenSSH", "version": "8.2p1"}
INV_80 = {"port": 80, "proto": "tcp", "banner": "nginx/1.18.0", "software": "nginx", "version": "1.18.0"}
INV_443 = {"port": 443, "proto": "tcp", "banner": "nginx/1.19.0", "software": "nginx", "version": "1.19.0"}


class TestCompararInventarios(unittest.TestCase):
    def test_inventarios_vacios(self):
        self.assertEqual(diferencial.comparar_inventarios([], []), {})
        self.assertEqual(diferencial.comparar_inventarios(None, None), {})

    def test_nuevo_cerrado_y_persistente(self):
        previo = [INV_22]
        actual = [dict(INV_22), INV_80]  # 22 sigue, 80 se abre
        d = diferencial.comparar_inventarios(previo, actual)
        self.assertEqual(d[(22, "tcp")]["estado"], "PERSISTENTE")
        self.assertEqual(d[(80, "tcp")]["estado"], "NUEVO")

        d2 = diferencial.comparar_inventarios([INV_22, INV_80], [INV_80])  # 22 se cierra
        self.assertEqual(d2[(22, "tcp")]["estado"], "CERRADO")
        self.assertEqual(d2[(22, "tcp")]["ahora"], None)
        self.assertEqual(d2[(80, "tcp")]["estado"], "PERSISTENTE")

    def test_banner_cambiado_sigue_persistente(self):
        actual = [dict(INV_22, banner="OpenSSH/9.6p1", version="9.6p1")]
        d = diferencial.comparar_inventarios([INV_22], actual)
        self.assertEqual(d[(22, "tcp")]["estado"], "PERSISTENTE")

    def test_mismo_inventario_sin_falsos_nuevos(self):
        inv = [INV_22, INV_80, INV_443]
        d = diferencial.comparar_inventarios(inv, [dict(x) for x in inv])
        self.assertEqual({v["estado"] for v in d.values()}, {"PERSISTENTE"})

    def test_udp_se_distingue_de_tcp(self):
        actual = [{"port": 53, "proto": "udp", "banner": "", "software": "", "version": ""}]
        d = diferencial.comparar_inventarios([{"port": 53, "proto": "tcp", "banner": "", "software": "", "version": ""}], actual)
        self.assertEqual(d[(53, "udp")]["estado"], "NUEVO")
        self.assertEqual(d[(53, "tcp")]["estado"], "CERRADO")


class TestHistorialInventario(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._env = mock.patch.dict(os.environ, {"CVESCANNER_DB": os.path.join(self._tmp.name, "cache.sqlite3")})
        self._env.start()
        self.addCleanup(self._env.stop)
        self.addCleanup(self._tmp.cleanup)

    def test_cada_escaneo_es_un_lote_y_el_ultimo_manda(self):
        store.save_inventory("h1", [INV_22, INV_80])          # escaneo 1
        store.save_inventory("h1", [INV_80, INV_443])         # escaneo 2: el 22 se cerró
        ultimo = store.load_last_inventory("h1")
        claves = {(e["port"], e["proto"]) for e in ultimo}
        self.assertEqual(claves, {(80, "tcp"), (443, "tcp")})  # el 22 cerrado no está en el último lote

    def test_host_independientes(self):
        store.save_inventory("h1", [INV_22])
        store.save_inventory("h2", [INV_80])
        self.assertEqual({(e["port"], e["proto"]) for e in store.load_last_inventory("h1")}, {(22, "tcp")})
        self.assertEqual({(e["port"], e["proto"]) for e in store.load_last_inventory("h2")}, {(80, "tcp")})

    def test_host_sin_historial(self):
        self.assertEqual(store.load_last_inventory("fantasma"), [])

    def test_dos_escaneos_consecutivos_sin_falsos_nuevos(self):
        inv = [INV_22, INV_80]
        store.save_inventory("h1", inv)
        previo = store.load_last_inventory("h1")
        d = diferencial.comparar_inventarios(previo, inv)
        self.assertEqual({v["estado"] for v in d.values()}, {"PERSISTENTE"})


class TestCsvEstadoDiferencial(unittest.TestCase):
    def test_csv_incluye_columna_estado(self):
        hallazgo = {
            "host": "192.168.1.10", "os": "Linux", "port": 80, "proto": "tcp",
            "banner": "nginx/1.18.0", "software": "nginx", "version": "1.18.0",
            "cve_id": "CVE-2024-0001", "severity": "HIGH", "cvss": 7.5, "kev": False,
            "epss": 0.1, "score": 47.0, "estado_diferencial": "NUEVO", "description": "d",
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "r.csv")
            export_csv_pdf.export_csv([hallazgo], path)
            with open(path, encoding="utf-8") as f:
                reader = csv.reader(f)
                cabecera = next(reader)
                fila = next(reader)
        self.assertIn("estado_diferencial", cabecera)
        self.assertEqual(fila[cabecera.index("estado_diferencial")], "NUEVO")


if __name__ == "__main__":
    unittest.main()
