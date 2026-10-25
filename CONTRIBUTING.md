# Contributing

Contributions are welcome! Here's how to get started.

## Development setup

```bash
git clone https://github.com/your-org/sbom-scanner
cd sbom-scanner

# Build the image locally
docker compose build

# Start the service
docker compose up -d

# Verify it's running
curl http://localhost:8100/health
```

## Running the unit tests

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
pytest -q
```

The tests need neither Docker nor Syft/Grype: the scan tools, SMTP, OSV/KEV and the language model are
replaced by fakes. When you touch the scan pipeline, add a test next to the existing ones in `tests/`.

## Running a test scan

```bash
# Scan all running Docker images
curl -X POST http://localhost:8100/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "images", "severity_threshold": "high"}'

# Or use the CLI script
SBOM_API=http://localhost:8100 bash scripts/sbom-scan.sh images
```

## Guidelines

- Keep the service dependency-free of any specific orchestration platform
- New scan target types (e.g. `podman`, `containerd`) are welcome — add discovery to `app/inventory.py`
  (`discover()` for the scheduler, `_plan_targets()` in `app/main.py` for manual scans)
- Add entries to the `by_source` breakdown in `run_scan_job()` for any new source type
- Everything Syft/Grype writes must go through `scanner.run_dir()` so temp data is always removed
- The language model may only *phrase* text. It must never influence severity, alert decisions or be given
  unsanitized third-party text (use `slm.clean()`)
- Document new environment variables in both `docker-compose.yml` and `README.md`

## Reporting issues

Please open a GitHub issue with:
- Your Docker / OS version
- The scan target that failed
- Relevant log output from `docker logs sbom-scanner`
