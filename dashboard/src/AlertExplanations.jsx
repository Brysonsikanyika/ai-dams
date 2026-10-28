import { useEffect, useState } from 'react'

const API = import.meta.env.VITE_API_URL || 'http://localhost:4000'

export default function AlertExplanations({ token }) {
  const [alerts, setAlerts] = useState(null)
  const [error, setError] = useState('')
  const [open, setOpen] = useState(null)

  useEffect(() => {
    if (!token) return
    fetch(`${API}/api/alerts`, { headers: { Authorization: `Bearer ${token}` } })
      .then((r) => (r.ok ? r.json() : Promise.reject(new Error(`HTTP ${r.status}`))))
      .then(setAlerts)
      .catch((e) => setError(e.message))
  }, [token])

  return (
    <div className="panel">
      <div className="panel-head">
        <span>ALERT EXPLANATIONS</span>
        <span className="panel-head-sub">plain-English reason for each alert, click to expand</span>
      </div>
      {error && <p className="mono">Could not load alerts: {error}</p>}
      {!alerts && !error && <p className="mono">Loading...</p>}
      {alerts && alerts.length === 0 && <p className="mono">No alerts above the line.</p>}
      {alerts && alerts.slice(0, 50).map((a) => (
        <div key={a.alert_id} style={{ borderTop: '1px solid #1f2937', padding: '8px 12px', cursor: 'pointer' }}
             onClick={() => setOpen(open === a.alert_id ? null : a.alert_id)}>
          <div className="mono">
            {a.alert_id} · {a.pseudonym} · {a.time_bucket} · risk {Number(a.combined_risk).toFixed(3)} ·{' '}
            {a.source === 'sql_text' ? 'SQL TEXT' : 'BEHAVIOUR'}
          </div>
          <div><strong>{a.headline}</strong>: {a.explanation}</div>
          {open === a.alert_id && (
            <div className="mono" style={{ marginTop: 6, opacity: 0.85 }}>
              {a.sql && <div>SQL: {a.sql}</div>}
              {a.patterns && a.patterns.length > 0 && <div>Patterns: {a.patterns.join(', ')}</div>}
              {a.top_ngrams && a.top_ngrams.length > 0 && (
                <div>Top n-grams: {a.top_ngrams.map((g) => `"${g.fragment}" (${g.contribution})`).join(', ')}</div>
              )}
              {a.top_features && a.top_features.length > 0 && (
                <div>Top features: {a.top_features.map((f) => `${f.feature}=${f.value} (SHAP ${f.shap})`).join(', ')}</div>
              )}
            </div>
          )}
        </div>
      ))}
    </div>
  )
}
