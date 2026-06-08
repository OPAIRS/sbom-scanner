FROM python:3.12-slim

LABEL org.opencontainers.image.title="sbom-scanner"
LABEL org.opencontainers.image.description="On-premise SBOM + CVE scanner (Syft + Grype) with REST API"
LABEL org.opencontainers.image.licenses="MIT"

# Install Syft + Grype via official Anchore install scripts
RUN apt-get update && apt-get install -y curl ca-certificates && rm -rf /var/lib/apt/lists/*

RUN curl -sSfL https://get.anchore.io/syft | sh -s -- -b /usr/local/bin
RUN curl -sSfL https://get.anchore.io/grype | sh -s -- -b /usr/local/bin

# Pre-seed Grype vulnerability database during build
# (avoids first-run download delay; update anytime via: docker exec sbom-scanner grype db update)
RUN grype db update || true

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ .

RUN mkdir -p /data/sbom-reports

EXPOSE 8100

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8100"]
