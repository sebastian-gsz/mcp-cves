# tests/test_nuc002.py — fija los pesos del score y el comportamiento opt-in de DEBUG.
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import scoring
from config import debug_enabled


class TestScoring4Factores(unittest.TestCase):
    """Ponderación vigente desde INT-001: CVSS 45 / KEV 15 / EPSS 20 / ARMA 20 (antes 60/20/20)."""

    def test_componentes_puros(self):
        self.assertEqual(scoring.compute_score(10.0, False, 0.0), 45.0)
        self.assertEqual(scoring.compute_score(0.0, True, 0.0), 15.0)
        self.assertEqual(scoring.compute_score(0.0, False, 1.0), 20.0)

    def test_escala_y_extremos(self):
        self.assertAlmostEqual(scoring.compute_score(10.0, True, 1.0), 80.0)  # sin arma pública
        self.assertEqual(scoring.compute_score(0.0, False, 0.0), 0.0)

    def test_kev_prioriza_sobre_cvss_teorico(self):
        # CVE explotado activamente (KEV, CVSS 7.5) debe superar al teórico (CVSS 9.8 sin explotar)
        explotado = scoring.compute_score(7.5, True, 0.9)   # 33.75 + 15 + 18 = 66.75
        teorico = scoring.compute_score(9.8, False, 0.01)   # 44.1 + 0 + 0.2 = 44.3
        self.assertGreater(explotado, teorico)


class TestDebugEnabled(unittest.TestCase):
    def test_desactivado_por_defecto(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertIs(debug_enabled(), False)

    def test_opt_in_valores_validos(self):
        for v in ("1", "true", "TRUE", "yes", "on"):
            with mock.patch.dict(os.environ, {"DEBUG": v}):
                self.assertIs(debug_enabled(), True)

    def test_valores_no_validos(self):
        for v in ("False", "false", "0", "", "no"):
            with mock.patch.dict(os.environ, {"DEBUG": v}):
                self.assertIs(debug_enabled(), False)


if __name__ == "__main__":
    unittest.main()
