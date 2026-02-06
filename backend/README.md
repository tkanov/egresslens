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

## API Endpoints

- `POST /api/reports/upload` - Upload JSONL file
- `GET /api/reports/{id}` - Get report by ID
- `GET /api/reports/{id}/events` - Get events for a report
- `GET /api/reports/{id}/export.md` - Export report as markdown
- `GET /health` - Health check
