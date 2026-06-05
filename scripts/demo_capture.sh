#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_DIR="${OUTPUT_DIR:-$ROOT_DIR/demo-output}"
IMAGE="${IMAGE:-egresslens/base:latest}"
DOMAIN="${DOMAIN:-example.com}"
REBUILD=0

for arg in "$@"; do
  case "$arg" in
    --rebuild)
      REBUILD=1
      ;;
    --help|-h)
      cat <<HELP
Usage: scripts/demo_capture.sh [--rebuild]

Runs the live EgressLens demo capture against sample_app.
Environment overrides:
  OUTPUT_DIR  Output directory. Default: ./demo-output
  IMAGE       Docker image. Default: egresslens/base:latest
  DOMAIN      Demo domain. Default: example.com
HELP
      exit 0
      ;;
    *)
      echo "Unknown argument: $arg" >&2
      exit 2
      ;;
  esac
done

cd "$ROOT_DIR"

if [[ "$REBUILD" == "1" ]] || ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  echo "Building $IMAGE..."
  docker build -t "$IMAGE" .
fi

rm -rf "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR"
chmod 0777 "$OUTPUT_DIR"

echo "Running live demo capture for $DOMAIN..."
if command -v egresslens >/dev/null 2>&1; then
  egresslens run-app ./sample_app --args "all $DOMAIN" --out "$OUTPUT_DIR" --image "$IMAGE"
elif [[ -x "$ROOT_DIR/cli/.venv/bin/egresslens" ]]; then
  "$ROOT_DIR/cli/.venv/bin/egresslens" run-app ./sample_app --args "all $DOMAIN" --out "$OUTPUT_DIR" --image "$IMAGE"
else
  PYTHONPATH="$ROOT_DIR/cli" python3 -m egresslens run-app ./sample_app --args "all $DOMAIN" --out "$OUTPUT_DIR" --image "$IMAGE"
fi

for artifact in egress.jsonl egress.strace run.json; do
  path="$OUTPUT_DIR/$artifact"
  if [[ ! -s "$path" ]]; then
    echo "Missing or empty artifact: $path" >&2
    exit 1
  fi
done

echo
printf 'Demo artifacts ready:\n'
printf '  JSONL:  %s\n' "$OUTPUT_DIR/egress.jsonl"
printf '  Run:    %s\n' "$OUTPUT_DIR/run.json"
printf '  Strace: %s\n' "$OUTPUT_DIR/egress.strace"
