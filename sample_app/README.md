# Sample app

A deliberately tiny app that makes predictable outbound requests, used as a
tracing target in demos and integration tests. It does two things:

- DNS lookups (`A`, `AAAA`, `MX`) via `dnspython`
- Certificate transparency queries against crt.sh (JSON over HTTPS)

## Trace it with EgressLens

From the repo root:

```bash
egresslens run-app ./sample_app --args "dns example.com"
egresslens run-app ./sample_app --args "crt example.com"
egresslens run-app ./sample_app --args "all python.org"
```

`run-app` discovers the entry point (`app.py` here), installs
`requirements.txt` inside the container before tracing starts, and writes the
trace to `egresslens-output/`. `requests` and `dnspython` are fetched from PyPI,
which is not in the trace: only the app is.

Use `run-app` rather than `watch` for this app: `watch` runs a command in the
tracing image as-is and never installs dependencies, and the base image has
neither `dnspython` nor `requests`.

## Run it directly

```bash
pip install -r requirements.txt
python app.py dns example.com
python app.py crt example.com
python app.py all example.com
```

Example output:

```json
$ python app.py all python.org
{
  "domain": "python.org",
  "dns": {
    "A": [
      "151.101.192.223",
      "151.101.64.223",
      "151.101.128.223",
      "151.101.0.223"
    ],
    "AAAA": [],
    "MX": [
      {
        "preference": 50,
        "exchange": "mail.python.org"
      }
    ]
  },
  "crt": []
}
```

Kept small and dependency-light on purpose so it stays usable in integration
tests.
