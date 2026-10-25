def compute_score(cvss: float, kev: bool, epss: float, arma: bool = False) -> float:
    """
    Ponderación vigente (INT-001, 2026-10-24): 4 factores.
      - CVSS 45% (normalizado a 0-100 multiplicando por 10)
      - KEV 15% (explotación confirmada por CISA)
      - EPSS 20% (probabilidad de explotación a 30 días)
      - ARMA 20% (exploit/PoC público disponible)
    """
    cvss_component = (cvss * 10.0) * 0.45
    kev_component = (100.0 if kev else 0.0) * 0.15
    epss_component = (epss * 100.0) * 0.20
    arma_component = (100.0 if arma else 0.0) * 0.20
    return cvss_component + kev_component + epss_component + arma_component
