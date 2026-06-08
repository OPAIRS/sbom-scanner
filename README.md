# sbom-scanner

**On-premise SBOM generation + CVE scanning for Docker, Kubernetes and filesystems — with a REST API.**

Built on [Syft](https://github.com/anchore/syft) (SBOM) and [Grype](https://github.com/anchore/grype) (CVE matching) from [Anchore](https://anchore.com). No cloud dependency, no data leaves your environment.

Designed to help teams comply with the **EU Cyber Resilience Act (CRA)** and similar regulations that require a maintained Software Bill of Materials and documented vulnerability management process.

---

## Features

- **Docker image scanning** — scans all running containers automatically
- **Kubernetes scanning** — discovers and scans pod images via the K8s API
- **Filesystem scanning** — scan any mounted path (application directories, vendor bundles, etc.)
- **Async REST API** — fire-and-forget scan jobs; poll for status; retrieve JSON reports
- **Consolidated summary** — single `summary.json` per scan with per-image and per-source breakdowns
- **Persistent reports** — scan results survive container restarts (volume-backed)
- **Grype DB caching** — vulnerability database pre-seeded at build time; one-command updates
- **Fully air-gap capable** — after the initial DB seed, no outbound connections required

---

## Quick start

```bash
git clone https://github.com/your-org/sbom-scanner
cd sbom-scanner

# Build and start
docker compose up -d --build

# Verify
curl http://localhost:8100/health
# {"status":"ok","service":"sbom-scanner","version":"1.1.0"}

# Scan all running Docker images
curl -X POST http://localhost:8100/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "images", "severity_threshold": "high"}'
# → returns scan_id immediately; job runs in background

# Check status
curl http://localhost:8100/scan/scan_20260601_124344

# View consolidated results
curl http://localhost:8100/reports/scan_20260601_124344/summary | python3 -m json.tool
```

---

## Architecture

```
Docker images / K8s pods / Filesystem paths
              ↓
           Syft
              ↓
        SBOM (JSON)
              ↓
           Grype
              ↓
       CVE Report (JSON)
              ↓
  /data/sbom-reports/<scan_id>/summary.json
```

The FastAPI service wraps both tools as async background tasks. Each scan creates:

```
/data/sbom-reports/scan_<timestamp>/
├── sbom_docker_<image>.json        ← Syft SBOM per image
├── vulns_docker_<image>.json       ← Grype CVE report per image
├── k8s_namespace_map.json          ← (if k8s scan) namespace → image mapping
└── summary.json                    ← consolidated cross-image report
```

---

## Configuration

All configuration is via environment variables (see `docker-compose.yml`):

| Variable | Default | Description |
|---|---|---|
| `REPORT_DIR` | `/data/sbom-reports` | Directory where scan reports are written |
| `SCAN_SOURCES` | *(empty)* | Comma-separated filesystem paths for `target=filesystem` |
| `SYFT_TIMEOUT` | `900` | Max seconds per target for Syft (increase for large images) |
| `GRYPE_TIMEOUT` | `600` | Max seconds per SBOM for Grype |
| `KUBECONFIG` | `/root/.kube/config` | Path to kubeconfig for Kubernetes scanning |

---

## API reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/health` | Health check |
| `GET` | `/images` | List scannable Docker images (running containers) |
| `GET` | `/k8s/images` | Preview K8s pod images (`?namespace=<ns>` optional) |
| `POST` | `/scan` | Start a scan job |
| `GET` | `/scan/{scan_id}` | Get job status |
| `GET` | `/scans` | List all jobs (current session) |
| `GET` | `/reports` | List all persisted report files |
| `GET` | `/reports/{scan_id}/summary` | Get consolidated summary for a scan |

### POST /scan

```json
{
  "target": "images",
  "severity_threshold": "high",
  "k8s_namespace": null
}
```

**`target` options:**

| Value | Scans |
|---|---|
| `images` | All running Docker container images |
| `filesystem` | Paths in `SCAN_SOURCES` env var |
| `k8s` | All Kubernetes pod images (requires kubeconfig) |
| `all` | `images` + `filesystem` + `k8s` |
| `nginx:1.27-alpine` | A specific Docker image |
| `/opt/myapp` | A specific filesystem path |

**`severity_threshold`:** `low` \| `medium` \| `high` \| `critical`

Reported in the summary for prioritization; does not abort the scan.

---

## CLI helper

```bash
chmod +x scripts/sbom-scan.sh

# Scan all running images
SBOM_API=http://localhost:8100 bash scripts/sbom-scan.sh images

# Watch progress
bash scripts/sbom-scan.sh watch scan_20260601_124344

# Top offenders table (sorted by Critical + High)
bash scripts/sbom-scan.sh top scan_20260601_124344
# Image                                                         Crit   High    Med
# --------------------------------------------------------------------------------
# ghcr.io/open-webui/open-terminal:latest                         95    668    926
# postgres:16                                                      14     61     71
# redis:7-alpine                                                    0      0      3
```

---

## Kubernetes scanning

Mount your kubeconfig and set the env var:

```yaml
# docker-compose.yml additions
environment:
  KUBECONFIG: /root/.kube/config
volumes:
  - ~/.kube:/root/.kube:ro
```

```bash
# Preview what would be scanned
curl http://localhost:8100/k8s/images

# Scan a specific namespace
curl -X POST http://localhost:8100/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "k8s", "k8s_namespace": "production", "severity_threshold": "high"}'
```

---

## Updating the Grype vulnerability database

The Grype DB is pre-seeded during `docker build`. To refresh it:

```bash
docker exec sbom-scanner grype db update
```

In air-gapped environments, follow the [Grype offline DB docs](https://github.com/anchore/grype#offline-and-air-gapped-environments) to populate the `grype-db` volume from an internal mirror.

---

## Known limitations

- **Very large images** (>15 GB, e.g. CUDA runtimes) can exceed `SYFT_TIMEOUT`. They appear in `targets_failed`; the scan continues with remaining targets.
- **Digest-only images** (no tag) are scanned but show as `sha256:…` in reports — correlate with `docker ps` if needed.
- **Scan status is session-scoped** — after a container restart, past job statuses are gone. Report files under `REPORT_DIR` are always persisted.

---

## EU Cyber Resilience Act (CRA) context

The CRA (applicable from late 2027) requires manufacturers of products with digital elements to:

- Maintain an up-to-date SBOM for their software
- Identify, document and address vulnerabilities in a timely manner
- Report actively exploited vulnerabilities to authorities

`sbom-scanner` supports this by providing:

- Machine-readable SBOMs in Syft JSON format per scan target
- CVE reports with severity classification and fix version information
- A persistent audit trail of all scans under `REPORT_DIR`
- REST API integration for CI/CD pipelines and dashboards

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## License

[MIT](LICENSE)
