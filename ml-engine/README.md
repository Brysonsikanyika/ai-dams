# ML Engine

Three models and a risk aggregator, in `data/`:

- Isolation Forest: per-event behavioural outliers
- LSTM autoencoder: sequence anomalies (reconstruction error)
- SQL-injection classifier: character n-gram TF-IDF with logistic regression on query text

`build_risk_aggregator.py` fuses them (max of behavioural and SQL-text risk) and `explain_alerts.py` writes alerts. All data is synthetic. See the root README for run order.
