# Dockerfile — imagen reproducible del escáner (INF-001).
# Modelo de privilegios: usuario NO root dentro del contenedor; las capabilities mínimas
# (NET_RAW para ARP/SYN, NET_ADMIN si el entorno lo pide) se conceden al CONTENEDOR en
# tiempo de ejecución (--cap-add / compose cap_add), nunca root global.
FROM python:3.12-slim

# nmap del sistema (python-nmap lo invoca como binario)
RUN apt-get update \
    && apt-get install -y --no-install-recommends nmap \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# usuario dedicado sin privilegios
RUN useradd -m scanner
COPY --chown=scanner:scanner . /app
RUN mkdir -p /app/outputs && chown -R scanner:scanner /app
USER scanner

ENV PYTHONUNBUFFERED=1
# La CLI es interactiva (pregunta objetivos y puertos por stdin)
ENTRYPOINT ["python3", "cve_scanner.py"]
