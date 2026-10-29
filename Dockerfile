FROM python:3.12-slim

LABEL org.opencontainers.image.title="sbom-scanner"
LABEL org.opencontainers.image.description="On-premise SBOM + CVE scanner (Syft + Grype) with continuous tracking, mail alerts and REST API"
LABEL org.opencontainers.image.licenses="MIT"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Install Syft + Grype via official Anchore install scripts
RUN apt-get update && apt-get install -y curl ca-certificates && rm -rf /var/lib/apt/lists/*

RUN curl -sSfL https://get.anchore.io/syft | sh -s -- -b /usr/local/bin
RUN curl -sSfL https://get.anchore.io/grype | sh -s -- -b /usr/local/bin

# Optional: bake the Grype vulnerability DB into the image (only needed for air-gapped hosts).
#   docker build --build-arg SEED_GRYPE_DB=1 .
# Off by default: the DB lives in the `grype-db` volume and is refreshed by the scheduler. Baking it in
# adds several hundred MB to every image build and every old image the host keeps around.
ARG SEED_GRYPE_DB=0
RUN if [ "$SEED_GRYPE_DB" = "1" ]; then grype db update || true; fi

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ .

RUN mkdir -p /data/sbom-reports /data/sbom-data

EXPOSE 8100

HEALTHCHECK --interval=60s --timeout=5s --start-period=30s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8100/health', timeout=3)" || exit 1

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8100"]
