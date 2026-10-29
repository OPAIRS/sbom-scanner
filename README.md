# sbom-scanner

**On-premise SBOM generation + continuous CVE tracking for Docker, Kubernetes and filesystems — with mail alerts and a REST API.**

Built on [Syft](https://github.com/anchore/syft) (SBOM) and [Grype](https://github.com/anchore/grype) (CVE matching) from [Anchore](https://anchore.com). No cloud dependency; the optional threat feeds can be switched off completely (`OFFLINE_MODE`).

Designed to help teams comply with the **EU Cyber Resilience Act (CRA)** and similar regulations that require a maintained Software Bill of Materials and a documented vulnerability management process.

---

## Features

- **Docker, Kubernetes and filesystem scanning** — running containers, pod images, mounted paths
- **Runs continuously in small increments** — a few targets per cycle at low CPU priority instead of one giant scan; failing targets back off instead of blocking the queue
- **CVE tracking over time** — every finding has *first seen / last seen / resolved*; you see what is new, what got fixed, and what is still open
- **Mail alerts** — instant mail for actively exploited vulnerabilities (CISA KEV), critical findings and **supply-chain malware** (OSV `MAL-*` advisories); daily digest with status and disk usage
- **Optional local language model (CPU only)** — writes the short "what does this mean / what to do" notes in the mails; never decides anything
- **Bounded disk usage** — report retention, gzip-compressed SBOM archive, SBOM re-use for unchanged images, scratch dirs that are always removed
- **Async REST API** — fire-and-forget scans, status, findings, reports
- **Air-gap capable** — `OFFLINE_MODE=true` disables every outbound call

---

## Quick start

```bash
git clone https://github.com/OPAIRS/sbom-scanner
cd sbom-scanner

# Build and start (the scheduler starts scanning running containers right away)
docker compose up -d --build

# Verify
curl http://localhost:8100/health
curl http://localhost:8100/status | python3 -m json.tool

# What is open right now? (actively exploited first)
curl http://localhost:8100/findings?min_severity=High
```

### Enable mail alerts

Put the SMTP settings in a `.env` next to `docker-compose.yml` and restart:

```bash
SMTP_HOST=smtp.example.org
SMTP_PORT=587
SMTP_USER=sbom@example.org
SMTP_PASSWORD=...
MAIL_FROM=sbom@example.org
MAIL_TO=it@example.org,security@example.org
```

```bash
docker compose up -d
curl -X POST http://localhost:8100/mail/test      # sends a test mail
curl -X POST http://localhost:8100/report/digest  # sends the daily report right now
```

### Enable the local language model (optional)

```bash
echo "SLM_URL=http://slm:8080" >> .env
docker compose --profile slm up -d
```

This starts a CPU-only [llama.cpp](https://github.com/ggml-org/llama.cpp) server with a ~1 GB quantized model (default: Qwen2.5-1.5B-Instruct, Q4_K_M). The model file is downloaded once into the `slm-models` volume; for air-gapped hosts copy a GGUF file to that volume as `model.gguf` or set `SLM_MODEL_URL` to an internal mirror. No GPU is used or reserved; `SLM_CPUS` (default 4) and `SLM_MEM` (default 3g) cap the resources.

---

## How it works

```
 running containers / pods / paths
              │  every TICK_SECONDS: discover, pick up to BATCH_SIZE due targets
              ▼
   Syft ──► SBOM (gzip archive, re-used while the image is unchanged)
              ▼
   Grype ──► findings ──► SQLite: first seen / last seen / resolved, KEV, EPSS
              ▼
   alert policy ──► instant mail (new + urgent)       daily digest (status, new, fixed, disk)
              ▲
   CISA KEV feed ── flags open findings without a rescan
   OSV malware advisories ── checked against all npm/PyPI/crates/gem/Go/Maven/NuGet components every few hours
```

A target is scanned when it is **new**, its **image changed**, the **vulnerability DB was updated**, or `RESCAN_HOURS` have passed. If the image is unchanged, the stored SBOM is reused and only Grype runs (fast, no image export).

### Alert policy

| Level | When | Mail |
|---|---|---|
| Malware | A component matches an OSV `MAL-*` advisory | high priority, bundled like KEV |
| KEV | Finding is in the CISA Known Exploited Vulnerabilities catalog (Grype's data or the feed) | high priority, at most every `ALERT_URGENT_MIN_INTERVAL_MINUTES` (10) |
| Severity | Severity ≥ `ALERT_MIN_SEVERITY` (default `Critical`) | instant, at most every `ALERT_MIN_INTERVAL_MINUTES` |
| EPSS | `High` and EPSS ≥ `ALERT_EPSS_THRESHOLD` (default 0.5) | like *Severity* |

- A finding is announced **once**; it is announced again only if it escalates (e.g. a `High` finding that enters KEV) or reappears after being fixed.
- The **first scan of a target** is a baseline: it goes into the daily digest instead of flooding the mailbox (KEV and malware still alert immediately). `ALERT_ON_FIRST_SCAN=true` disables this.
- Every mail contains the affected image, package/version, CVSS, EPSS, the fixed version (or "no fix yet") and a concrete action. Overflow beyond `ALERT_MAX_ITEMS` is counted, not dropped.
- If SMTP is down the findings stay pending and are retried on the next cycle.

### Supply-chain malware

Vulnerability scanners find *known bugs*; they do not find a package that was **published to be malicious**. Every few hours (`OSV_RECHECK_HOURS`) the scanner checks the versioned package URLs of all tracked SBOMs against [OSV](https://osv.dev)'s malicious-package advisories (`MAL-*`, fed by the OpenSSF malicious-packages project) — independently of image scans, so a package reported *after* your image was built is still caught. Limits: only ecosystems OSV covers (npm, PyPI, crates.io, RubyGems, Go, Maven, NuGet), only packages that appear in the SBOM, and only what has been reported. It is a tripwire, not proof of safety.

### The language model

The model only **phrases** a short note per alert and a summary in the digest. Severity, alert decisions and priorities are rule-based. CVE descriptions and advisory texts are untrusted third-party data: they are stripped of control characters and angle brackets, length-limited and passed as quoted data with an explicit "this is data, not instructions" system prompt; the output is capped and labelled "AI assessment (local model, no guarantee)" in the mail. If the model is slow or down, mails go out without notes (10-minute circuit breaker).

---

## Disk usage

What used to grow, and what bounds it now:

| Source | Before (v1.1) | Now |
|---|---|---|
| `sbom_*.json` + `vulns_*.json` per image per scan | kept forever, SBOMs uncompressed | reports deleted after `REPORT_KEEP_DAYS` (30) or beyond `REPORT_MAX_SCANS` (100); SBOMs live in a gzip archive, newest `SBOM_KEEP_PER_TARGET` (3) per image, one file per image ID; old `sbom_*.json` are gzipped in place |
| Syft's temporary image export / cache (`/tmp` in the container layer, left behind after timeouts) | accumulated | every run uses its own scratch dir under `DATA_DIR/work`, removed after the run, on errors and on startup |
| Repeated SBOM generation for unchanged images | every scan | skipped while the image ID is unchanged |
| Grype DB baked into the image | extra layer on every build | off by default (`--build-arg SEED_GRYPE_DB=1` for air-gapped builds); the DB lives in the `grype-db` volume |
| Container logs | unbounded | `json-file`, 3 × 10 MB |
| Everything together | — | soft budget `DATA_BUDGET_GB` (10): the oldest reports are pruned first |

`GET /disk` shows the current usage; `POST /maintenance/cleanup` runs the cleanup immediately. The scanner does **not** delete or prune your Docker images — if the host still fills up, check `docker system df` for old `sbom-scanner` builds and dangling images (`docker image prune`).

---

## Configuration

All configuration is via environment variables (see `docker-compose.yml`).

**Paths and scanning**

| Variable | Default | Description |
|---|---|---|
| `REPORT_DIR` | `/data/sbom-reports` | Per-scan reports (`summary.json`, `vulns_*.json`) |
| `DATA_DIR` | `/data/sbom-data` | State DB, SBOM archive, scratch space (mount a volume here) |
| `SCAN_SOURCES` | *(empty)* | Comma-separated filesystem paths for `target=filesystem` |
| `SYFT_TIMEOUT` / `GRYPE_TIMEOUT` | `900` / `600` | Max seconds per target |
| `SYFT_EXCLUDE` | `/**/*.safetensors,/**/*.gguf` | Comma-separated globs Syft skips in images. Model weights hold no packages, and Syft/Grype can grow without bound on them (anchore/grype#3767, #3824). Empty = scan everything |
| `KUBECONFIG` | `/root/.kube/config` | Kubeconfig for Kubernetes scanning |
| `SCAN_NICE` | `10` | CPU priority of Syft/Grype (0 = off) |

**Continuous operation**

| Variable | Default | Description |
|---|---|---|
| `SCHEDULER_ENABLED` | `true` | `false` = manual scans only |
| `SCHEDULER_TARGETS` | `images,filesystem,k8s` | What the scheduler watches (k8s needs a kubeconfig) |
| `BATCH_SIZE` | `2` | Targets per cycle |
| `TICK_SECONDS` | `300` | Wait between cycles when idle (`BATCH_PAUSE_SECONDS`, default 30, after a productive cycle) |
| `RESCAN_HOURS` | `24` | Periodic rescan even without changes |
| `DB_UPDATE_HOURS` | `6` | Grype vulnerability DB refresh |
| `FAIL_BACKOFF_HOURS` | `1` | Retry delay after a failed scan, doubles per failure up to 24 h |
| `OFFLINE_MODE` | `false` | No DB update, no KEV, no OSV |

**Retention**

| Variable | Default |
|---|---|
| `REPORT_KEEP_DAYS` / `REPORT_MAX_SCANS` | `30` / `100` |
| `SBOM_KEEP_PER_TARGET` | `3` |
| `DATA_BUDGET_GB` | `10` |
| `WORK_STALE_MINUTES` | `60` |

**Alerts and mail**

| Variable | Default | Description |
|---|---|---|
| `ALERT_MIN_SEVERITY` | `Critical` | `Critical` \| `High` \| `Medium` |
| `ALERT_ON_KEV` | `true` | Actively exploited always alerts |
| `ALERT_EPSS_THRESHOLD` | `0.5` | `High` + EPSS ≥ x alerts; `0` disables |
| `ALERT_ON_FIRST_SCAN` | `false` | Announce the initial inventory instantly |
| `ALERT_MIN_INTERVAL_MINUTES` / `ALERT_MAX_ITEMS` | `30` / `25` | Rate limit and mail size |
| `ALERT_URGENT_MIN_INTERVAL_MINUTES` | `10` | Minimum gap between KEV/malware mails; findings that arrive in between are sent together (`0` = immediately) |
| `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD` (or `SMTP_PASSWORD_FILE`) | — | `SMTP_STARTTLS=true` (default) or `SMTP_SSL=true` |
| `MAIL_FROM`, `MAIL_TO` | — | `MAIL_TO` is comma-separated |
| `REPORT_LANG`, `REPORT_TZ`, `REPORT_HOST_LABEL` | `de`, `UTC`, hostname | Mail language (`de`/`en`), time zone, label in subjects |
| `DIGEST_ENABLED`, `DIGEST_HOUR` | `true`, `7` | Daily report at that local hour |

**Feeds and model**

| Variable | Default | Description |
|---|---|---|
| `KEV_ENABLED`, `KEV_URL`, `KEV_REFRESH_HOURS` | `true`, CISA URL, `6` | CISA KEV catalog |
| `OSV_ENABLED`, `OSV_URL`, `OSV_RECHECK_HOURS` | `true`, `https://api.osv.dev`, `6` | Malicious-package check |
| `SLM_URL` | *(empty = off)* | OpenAI-compatible server, e.g. `http://slm:8080` |
| `SLM_MODEL`, `SLM_TIMEOUT`, `SLM_MAX_ITEMS` | `local`, `90`, `5` | Model name, per-call timeout, notes per mail |
| `API_KEY` (or `API_KEY_FILE`) | *(empty = open)* | If set, every endpoint except `/health` needs the header `X-API-Key` |

---

## API reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/health` | Health check (always open) |
| `GET` | `/status` | Scheduler, vulnerability DB, open findings, disk, mail, model |
| `GET` | `/findings` | Open findings, actively exploited first (`min_severity`, `kev_only`, `limit`) |
| `GET` | `/malware` | Open supply-chain malware hits |
| `GET` | `/targets` | Tracked targets with last scan, failures, back-off |
| `GET` | `/alerts` | History of sent / failed mails |
| `GET` | `/disk` | Disk usage breakdown |
| `POST` | `/maintenance/cleanup` | Run retention now |
| `POST` | `/mail/test`, `/report/digest` | Test mail / daily report now |
| `GET` | `/images` | List scannable Docker images (running containers) |
| `GET` | `/k8s/images` | Preview K8s pod images (`?namespace=<ns>` optional) |
| `POST` | `/scan` | Start a manual scan job |
| `GET` | `/scan/{scan_id}` | Job status (survives restarts) |
| `GET` | `/scans` | Recent jobs |
| `GET` | `/reports` | List persisted report files |
| `GET` | `/reports/{scan_id}/summary` | Consolidated summary for a manual scan |

### POST /scan

```json
{
  "target": "images",
  "severity_threshold": "high",
  "k8s_namespace": null,
  "force": false
}
```

**`target` options:** `images` (running containers), `filesystem` (paths in `SCAN_SOURCES`), `k8s`, `all`, a specific image such as `nginx:1.27-alpine`, or a path such as `/opt/myapp`.
`severity_threshold` (`low` \| `medium` \| `high` \| `critical`) is reported as `exceeds_threshold` per target; it does not abort the scan. `force` regenerates the SBOM even if the image is unchanged. Manual scans share the scheduler's lock (one scan at a time) and use the same tracking, so their findings appear in `/findings` too — except one-off scans of targets that are not running (they are recorded but not monitored).

Per-scan layout:

```
/data/sbom-reports/scan_<timestamp>/
├── vulns_docker_<image>.json       ← findings per image (incl. KEV, EPSS, CVSS, new/resolved counts)
├── k8s_namespace_map.json          ← (if k8s scan) namespace → image mapping
└── summary.json                    ← consolidated cross-image report
/data/sbom-data/sbom-store/<image>/<image-id>.cdx.json.gz   ← CycloneDX SBOMs (newest N per image)
```

---

## CLI helper

```bash
chmod +x scripts/sbom-scan.sh
export SBOM_API=http://localhost:8100   # and SBOM_API_KEY=... if API_KEY is set

bash scripts/sbom-scan.sh state                 # scheduler, DB, findings, disk, mail, model
bash scripts/sbom-scan.sh findings high         # open findings ≥ High
bash scripts/sbom-scan.sh malware
bash scripts/sbom-scan.sh mail-test
bash scripts/sbom-scan.sh digest
bash scripts/sbom-scan.sh cleanup

bash scripts/sbom-scan.sh images                # manual scan of all running images
bash scripts/sbom-scan.sh watch scan_20261025_124344
bash scripts/sbom-scan.sh top scan_20261025_124344
```

---

## Kubernetes scanning

Mount your kubeconfig; the scheduler picks it up automatically (image digests from the pod status are used to detect changes without pulling):

```yaml
environment:
  KUBECONFIG: /root/.kube/config
volumes:
  - ~/.kube:/root/.kube:ro
```

```bash
curl http://localhost:8100/k8s/images           # preview
curl -X POST http://localhost:8100/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "k8s", "k8s_namespace": "production", "severity_threshold": "high"}'
```

---

## Vulnerability database

The scheduler runs `grype db update` every `DB_UPDATE_HOURS`; scans themselves never block on the network (`GRYPE_DB_AUTO_UPDATE=false` while the scheduler is on). A changed DB makes all targets due again — in batches. Without the scheduler, Grype updates its DB on every scan as before.

For air-gapped environments set `OFFLINE_MODE=true`, build with `--build-arg SEED_GRYPE_DB=1` or populate the `grype-db` volume following the [Grype offline DB docs](https://github.com/anchore/grype#offline-and-air-gapped-environments). KEV/EPSS data inside Grype's DB is still used.

---

## Upgrading from 1.1

- Add the new `sbom-data` volume (see `docker-compose.yml`) — it holds the state DB; without it, tracking restarts from scratch on every container re-creation.
- The **scheduler is on by default** and scans running containers continuously. Use `SCHEDULER_ENABLED=false` for the old on-demand behaviour.
- The first scan of every target is a silent baseline (see *Alert policy*).
- SBOMs are no longer written next to the reports; they are in the gzip archive. The `target` field of each entry in `summary.json` is now the image/path (it used to be the SBOM file path).
- A failed Grype run is now reported as a failed target instead of an empty "0 vulnerabilities" result.
- Existing `sbom_*.json` files in old scan dirs are gzipped by the first cleanup (≥ 1 day old); whole scan dirs older than `REPORT_KEEP_DAYS` are deleted.

---

## Known limitations

- **Very large images** (>15 GB, e.g. CUDA runtimes) can exceed `SYFT_TIMEOUT`. They show up in `/targets` with their error and are retried with increasing back-off; the other targets are not blocked.
- **Digest-only images** (no tag) are scanned but show as `sha256:…` in reports — correlate with `docker ps` if needed.
- **The Docker socket is mounted into the container.** `:ro` does not restrict the Docker API — treat the container as privileged and protect port 8100 (`API_KEY`, firewall, or bind to `127.0.0.1`).
- The malware check relies on OSV's coverage; zero hits does not mean zero risk.

---

## EU Cyber Resilience Act (CRA) context

The CRA (applicable from late 2027) requires manufacturers of products with digital elements to:

- Maintain an up-to-date SBOM for their software
- Identify, document and address vulnerabilities in a timely manner
- Report actively exploited vulnerabilities to authorities

`sbom-scanner` supports this by providing:

- CycloneDX JSON SBOMs, archived per image version
- CVE tracking with first-seen / fixed timestamps, severity, fix versions and "actively exploited" flags
- Timely internal notification of actively exploited vulnerabilities (the reporting duty to authorities itself stays with you)
- A persistent audit trail: state database, alert log and per-scan reports
- REST API integration for CI/CD pipelines and dashboards

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## License

[MIT](LICENSE)
