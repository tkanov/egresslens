# EgressLens Backend

FastAPI service that ingests CLI trace artifacts, aggregates them into a report,
enriches destinations with domains, and judges them against an optional egress
policy.

## Setup

Requires Python 3.10+ (FastAPI and `python-multipart` both declare that floor).

```bash
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
pip install -e ../cli
uvicorn app.main:app --reload --port 8000
```

The second install is not optional: the policy and enrichment engine lives in the
`egresslens` CLI package, and `app.policy` / `app.enrichment` re-export it.

The API is then at `http://localhost:8000`, with interactive docs at `/docs`.

## API

| Endpoint | Purpose |
|---|---|
| `POST /api/reports/upload` | Create a report from uploaded artifacts |
| `GET /api/reports/{id}` | Fetch a report |
| `GET /api/reports/{id}/events` | List events; optional `?limit=` (1–1000) |
| `GET /api/reports/{id}/export.md` | Export the report as Markdown |
| `GET /health` | Health check |

### Upload

Multipart form, one required field and three optional ones:

| Field | Required | File | Effect |
|---|---|---|---|
| `file` | yes | `egress.jsonl` | The events themselves |
| `metadata_file` | no | `run.json` | Adds command, image, exit code, timing |
| `strace_file` | no | `egress.strace` | Enables domain enrichment |
| `policy_file` | no | `policy.json` | Enables the allowlist verdict |

Each file is capped at `max_upload_mb` (default 50 MB) and rejected with HTTP 413
if larger; a malformed policy is rejected with HTTP 400.

`GET /events` returns `{report_id, total, returned, events}` — `total` is the
stored event count, `returned` reflects `limit`.

## Egress policy

When `policy_file` is supplied, every observed destination is judged against the
allowlist and the result lands in `summary.policy`:

```json
{
  "enabled": true,
  "verdict": "pass",
  "destinations_evaluated": 12,
  "allow_rules": 4,
  "has_domain_rules": true,
  "expected_count": 12,
  "unexpected_count": 0,
  "unexpected": []
}
```

The verdict is **three-way**, not a boolean:

- `pass` — every observed destination matched a rule.
- `fail` — at least one did not. Raises a **high**-severity "Unexpected
  destinations" flag.
- `inconclusive` — an allowlist was uploaded but no destinations were observed,
  so nothing was checked. Raises a **medium**-severity "Egress policy not
  evaluated" flag. This case is deliberately not `pass`: a failed capture, the
  wrong file, and a genuinely quiet run are indistinguishable here, and calling
  that compliance would be a vacuous truth reported as a security result.

Both flags render in the flags panel and in the Markdown export, which also
carries a dedicated `## Egress Policy` section with the verdict and the
unexpected-destination table.

Two bounds worth knowing: an allowlist may hold at most 1000 rules (more is a
400), and the stored `unexpected` list is truncated to 50 entries while
`unexpected_count` stays exact.

Rule syntax and the trust model — why `domain` rules are advisory and `ip`/CIDR
rules are a hard gate — are in [docs/policy.md](../docs/policy.md).

> **Caveat:** unknown *top-level* keys in a policy file are currently ignored
> without warning, so a `deny` list written by mistake is silently dropped and
> the run can report `pass`. Unknown keys *inside* a rule object are rejected.
> Only `allow` is honoured.

## Domain enrichment

With `strace_file` supplied, the backend first extracts passive DNS from UDP DNS
responses in the trace (A records, IPv4 only), then falls back to bounded reverse
DNS for public IPv4 addresses still unresolved. Private, loopback, link-local,
multicast, unspecified, and reserved ranges are skipped. Malformed or truncated
DNS payloads are ignored rather than failing the upload.

Only `recvfrom` and `recvmsg` lines are scanned, so a resolver that reads answers
with `recvmmsg` yields no passive DNS at all — those destinations fall through to
reverse DNS or stay unresolved.

Events gain `domain` and `domain_source`; top destinations also carry `domains`,
the full candidate list as `{domain, source, count}`. The primary domain prefers
`passive_dns` over `reverse_dns`, then the highest observed count, then lexical
order. `summary.enrichment` reports passive matches, reverse matches, unresolved
IPs, skipped lookups, and errors.

## Configuration

Settings come from `config.yaml`, overridden by environment variables.

```yaml
flags:
  high_dest_threshold: 50         # unique IP:port pairs before flagging
  failure_threshold: 0.10         # connection failure rate, 0.0–1.0
  usual_ports: [80, 443, 53, 22]  # ports not considered "unusual"

enrichment:
  enabled: true
  reverse_dns_enabled: true
  reverse_dns_timeout_seconds: 0.5
  reverse_dns_max_ips: 100

uploads:
  max_upload_mb: 50
```

| Variable | Type | Default |
|---|---|---|
| `FLAG_HIGH_DEST_THRESHOLD` | int | 50 |
| `FLAG_FAILURE_THRESHOLD` | float | 0.10 |
| `FLAG_USUAL_PORTS` | comma-separated ints | 80,443,53,22 |
| `ENRICHMENT_ENABLED` | bool | true |
| `ENRICHMENT_REVERSE_DNS_ENABLED` | bool | true |
| `ENRICHMENT_REVERSE_DNS_TIMEOUT_SECONDS` | float > 0 | 0.5 |
| `ENRICHMENT_REVERSE_DNS_MAX_IPS` | int ≥ 0 | 100 |
| `MAX_UPLOAD_MB` | int > 0 | 50 |
| `ALLOWED_ORIGINS` | comma-separated origins | — |

`ALLOWED_ORIGINS` extends the CORS allowlist, which already covers
`localhost`/`127.0.0.1` on ports 5173 and 3000. Set it if you serve the UI from
anywhere else.

```bash
FLAG_HIGH_DEST_THRESHOLD=100 uvicorn app.main:app --reload --port 8000
```

## Tests

pytest is not in `requirements.txt`, so install it too:

```bash
pip install -r requirements.txt -e ../cli pytest
pytest -v
```

## Compatibility

Both `egresslens watch` and `egresslens run-app` emit the same JSONL event
format, and the backend accepts either.
