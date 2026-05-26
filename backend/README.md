# EgressLens Backend

FastAPI backend for processing and serving egress monitoring reports.

## Setup

1. Create and activate virtual environment:
```bash
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Run the server:
```bash
uvicorn app.main:app --reload --port 8000
```

The API will be available at `http://localhost:8000`

## Configuration

The backend uses configurable thresholds for security flags calculation. Configuration can be set via:

1. **config.yaml file** (recommended for persistent configuration):
   ```yaml
   flags:
     high_dest_threshold: 50          # Unique IP:port pairs threshold
     failure_threshold: 0.10          # Failure rate threshold (0.0-1.0)
     usual_ports: [80, 443, 53, 22]  # Ports not considered "unusual"

   enrichment:
     enabled: true
     reverse_dns_enabled: true
     reverse_dns_timeout_seconds: 0.5
     reverse_dns_max_ips: 100
   ```

2. **Environment variables** (highest priority, overrides config.yaml):
   ```bash
   FLAG_HIGH_DEST_THRESHOLD=50                 # int
   FLAG_FAILURE_THRESHOLD=0.10                 # float
   FLAG_USUAL_PORTS=80,443,53,22              # comma-separated ports
   ENRICHMENT_ENABLED=true                    # bool
   ENRICHMENT_REVERSE_DNS_ENABLED=true        # bool
   ENRICHMENT_REVERSE_DNS_TIMEOUT_SECONDS=0.5 # positive float
   ENRICHMENT_REVERSE_DNS_MAX_IPS=100         # int >= 0
   ```
   
   Example:
   ```bash
   FLAG_HIGH_DEST_THRESHOLD=100 uvicorn app.main:app --reload --port 8000
   ```

## API Endpoints

- `POST /api/reports/upload` - Upload JSONL file as `file`, optional `run.json` as `metadata_file`, and optional `egress.strace` as `strace_file`
- `GET /api/reports/{id}` - Get report by ID
- `GET /api/reports/{id}/events` - Get events for a report
- `GET /api/reports/{id}/export.md` - Export report as markdown
- `GET /health` - Health check

## Domain enrichment

When `strace_file` is supplied, the backend extracts passive DNS mappings from UDP DNS response payloads visible in `egress.strace`. Current passive DNS support covers A records for IPv4 events. Malformed or truncated DNS payloads are ignored without failing the upload.

For IPs not resolved by passive DNS, bounded reverse DNS can fill public IPv4 destinations. Reverse DNS skips private, loopback, link-local, multicast, unspecified, and reserved ranges. Defaults are enabled, `0.5` seconds per lookup, and at most `100` reverse lookups per upload.

Report events may include `domain` and `domain_source`. Top destinations may include `domain`, `domain_source`, and `domains`, where `domains` preserves all candidates as `{domain, source, count}`. Primary domain selection prefers `passive_dns` over `reverse_dns`; ties among passive names use highest observed count, then lexical order. `summary.enrichment` reports passive matches, reverse matches, unresolved IPs, skipped reverse lookups, and lookup errors. Markdown export includes the enrichment summary and domain source.

## Compatibility

The backend accepts JSONL output from both CLI commands:
- `egresslens watch` - For arbitrary commands
- `egresslens run-app` - For Python projects with automatic dependency installation

Both commands produce the same JSONL event format and are fully compatible with the backend API.
