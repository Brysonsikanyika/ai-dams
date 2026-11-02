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
  for f in alerts.json risk_scores.csv; do
    cp "$ROOT/ml-engine/data/$f" "$ROOT/dashboard-server/data/$f.tmp"
    mv "$ROOT/dashboard-server/data/$f.tmp" "$ROOT/dashboard-server/data/$f"
  done
  echo "== synced alerts.json and risk_scores.csv to dashboard-server/data"
  echo "== refit done  $(date -Is)"
} >> "$ROOT/refit.log" 2>&1
