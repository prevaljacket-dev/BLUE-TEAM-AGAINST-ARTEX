# Contexte de build : racine du depot (pour embarquer tools/artex_triage.py)
#   docker build -f soar/Dockerfile -t artex-soar .
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    ARTEX_TRIAGE_PATH=/app/tools/artex_triage.py \
    SOAR_CONFIG=/app/soar/config/soar.yml SOAR_HOST=0.0.0.0 SOAR_PORT=8080

# nftables/ipset ne servent qu'en mode enforce (conteneur en network_mode: host + NET_ADMIN).
RUN apt-get update && apt-get install -y --no-install-recommends nftables ipset \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app/soar
COPY soar/requirements.txt /app/soar/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY tools/artex_triage.py /app/tools/artex_triage.py
COPY rules /app/rules
COPY soar/artex_soar /app/soar/artex_soar
COPY soar/config /app/soar/config

RUN useradd --system --uid 10001 soar && mkdir -p /app/soar/data && chown soar /app/soar/data
USER soar
VOLUME ["/app/soar/data"]
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request,sys; urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=3)" || exit 1
ENTRYPOINT ["python", "-m", "artex_soar"]
CMD ["serve"]
