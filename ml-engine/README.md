# ML Engine

Ensemble of three models, per proposal 1.4 / 1.8:

- **Isolation Forest** — volumetric/statistical outlier detection
- **LSTM Autoencoder** — sequential session anomalies (reconstruction error)
- **NLP SQL-injection classifier** — raw query text at the agent level

Outputs feed a confidence-weighted risk aggregator producing one unified
severity score per event, with SHAP-based explanation generation before
it reaches the dashboard.

Nothing to build here yet — needs real event data flowing through Kafka
from at least one agent first.
