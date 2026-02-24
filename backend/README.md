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
   ```

2. **Environment variables** (highest priority, overrides config.yaml):
   ```bash
   FLAG_HIGH_DEST_THRESHOLD=50          # int
   FLAG_FAILURE_THRESHOLD=0.10          # float
   FLAG_USUAL_PORTS=80,443,53,22       # comma-separated ports
   ```
   
   Example:
   ```bash
   FLAG_HIGH_DEST_THRESHOLD=100 uvicorn app.main:app --reload --port 8000
   ```

## API Endpoints

- `POST /api/reports/upload` - Upload JSONL file
- `GET /api/reports/{id}` - Get report by ID
- `GET /api/reports/{id}/events` - Get events for a report
- `GET /api/reports/{id}/export.md` - Export report as markdown
- `GET /health` - Health check

## Compatibility

The backend accepts JSONL output from both CLI commands:
- `egresslens watch` - For arbitrary commands
- `egresslens run-app` - For Python projects with automatic dependency installation

Both commands produce the same JSONL event format and are fully compatible with the backend API.
