import { useEffect, useState } from 'react'

const API = import.meta.env.VITE_API_URL || 'http://localhost:4000'

export default function LiveAlerts({ token }) {
  const [alerts, setAlerts] = useState(null)
  const [error, setError] = useState('')
  const [updated, setUpdated] = useState('')

  useEffect(() => {
    if (!token) return undefined
    let stop = false
    const load = () =>
      fetch(`${API}/api/live-alerts`, { headers: { Authorization: `Bearer ${token}` } })
        .then((r) => (r.ok ? r.json() : Promise.reject(new Error(`HTTP ${r.status}`))))
        .then((data) => {
          if (!stop) {
            setAlerts(data)
            setError('')
            setUpdated(new Date().toLocaleTimeString())
          }
        })
        .catch((e) => {
          if (!stop) setError(e.message)
        })
    load()
    const id = setInterval(load, 5000)
    return () => {
      stop = true
      clearInterval(id)
    }
  }, [token])

  return (
    <div className="panel">
      <div className="panel-head">
        <span>LIVE ALERTS</span>
        <span className="panel-head-sub">
          SQL text and Isolation Forest behaviour, scored from Kafka as statements arrive, refreshes every 5 s{updated && ` · updated ${updated}`}
        </span>
      </div>
      {error && <p className="mono">Could not load live alerts: {error}</p>}
      {!alerts && !error && <p className="mono">Loading...</p>}
      {alerts && alerts.length === 0 && <p className="mono">No live alerts yet.</p>}
      {alerts && alerts.slice(0, 20).map((a) => (
        <div key={`${a.record_id}-${a.scored_at}`} style={{ borderTop: '1px solid #1f2937', padding: '8px 12px' }}>
          <div className="mono">
            {a.scored_at} · {a.account || 'unattributed'} · {a.source === 'live_behaviour' ? 'behaviour score' : 'SQL score'} {Number(a.nlp_prob).toFixed(3)} (line {Number(a.cutoff).toFixed(3)})
            {a.delay_s != null && ` · ${a.delay_s}s from log to score`}
          </div>
          <div className="mono" style={{ opacity: 0.85 }}>{a.source === 'live_behaviour' ? 'Why: ' + String(a.sql_text).replace('[behaviour] ', '') : 'SQL: ' + a.sql_text}</div>
        </div>
      ))}
    </div>
  )
}
