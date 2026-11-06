# ── Stage 1: Syft and Grype, built from source at pinned versions ─────────────────────────────────────────
# Pinned so an update is a visible change in this file instead of whatever the install script fetched when the
# layer was first cached. Built from source so a vulnerable dependency can be overridden before upstream ships
# a release with the fix.
FROM golang:1.26-bookworm AS tools

ARG SYFT_VERSION=v1.57.0
ARG GRYPE_VERSION=v0.121.2
# Go modules forced to a newer version on top of the upstream go.mod, "module@version" separated by spaces.
#   andybalholm/brotli: GO-2026-6888 / CVE-2026-111497 (CISA KEV). Syft v1.57.0 and Grype v0.121.2 still
#   ship v1.2.0 (via mholt/archives). Remove the entry once an upstream release carries v1.2.7 or later.
ARG GO_DEP_OVERRIDES="github.com/andybalholm/brotli@v1.2.8"

ENV CGO_ENABLED=0 GOTOOLCHAIN=auto GOFLAGS=-mod=mod

RUN set -eux; \
    for tool in "syft:${SYFT_VERSION}" "grype:${GRYPE_VERSION}"; do \
      name="${tool%%:*}"; ver="${tool#*:}"; \
      git clone --quiet --depth 1 --branch "$ver" "https://github.com/anchore/$name.git" "/src/$name"; \
      cd "/src/$name"; \
      for dep in $GO_DEP_OVERRIDES; do go get "$dep"; done; \
      go build -trimpath \
        -ldflags "-s -w -X main.version=${ver#v} -X main.gitDescription=${ver}-patched" \
        -o "/out/$name" "./cmd/$name"; \
      "/out/$name" version; \
    done

# ── Stage 2: the service ──────────────────────────────────────────────────────────────────────────────────
FROM python:3.12-slim

LABEL org.opencontainers.image.title="sbom-scanner"
LABEL org.opencontainers.image.description="On-premise SBOM + CVE scanner (Syft + Grype) with continuous tracking, mail alerts and REST API"
LABEL org.opencontainers.image.licenses="MIT"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=tools /out/syft /out/grype /usr/local/bin/

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
