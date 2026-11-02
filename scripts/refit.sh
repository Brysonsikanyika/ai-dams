#!/usr/bin/env bash
# Scheduled batch refit: retrains the Isolation Forest and the LSTM (the aggregator
# refits both from scratch), rebuilds risk scores, and regenerates explanations.
# Capture stays live; this is the batch half. Log: refit.log in the repo root.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT/ml-engine/data"
source "$ROOT/.venv/bin/activate"
{
  echo "== refit start $(date -Is)"
  python build_risk_aggregator.py
  python explain_alerts.py
  echo "== refit done  $(date -Is)"
} >> "$ROOT/refit.log" 2>&1
