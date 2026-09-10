import { useState, useEffect, useMemo } from 'react'
import Papa from 'papaparse'
import {
  ComposedChart, Area, ScatterChart, Scatter, XAxis, YAxis, ZAxis,
  CartesianGrid, Tooltip, ResponsiveContainer, ReferenceLine,
} from 'recharts'
import Login from './Login.jsx'
import { fetchRiskScoresCsv } from './api'
import './App.css'

const THRESHOLD = 0.95
const TOKEN_KEY = 'aidams_token'

function Readout({ label, value, tone }) {
  return (
    <div className={`readout ${tone ? `readout-${tone}` : ''}`}>
      <div className="readout-value">{value}</div>
      <div className="readout-label">{label}</div>
    </div>
  )
}

function SignalDot(props) {
  const { cx, cy, payload } = props
  if (!payload?.is_true_anomaly) return null
  return <circle cx={cx} cy={cy} r={3.5} fill="#ef4444" stroke="#0a0e14" strokeWidth={1} />
}

function verdict(row) {
  const flagged = row.combined_risk > THRESHOLD
  const real = row.bucket_has_anomaly === 1
  if (flagged && real) return 'TP'
  if (flagged && !real) return 'FP'
  if (!flagged && real) return 'FN'
  return 'TN'
}

const VERDICT_META = {
  TP: { label: 'Confirmed anomaly', className: 'v-tp' },
  FP: { label: 'False alarm', className: 'v-fp' },
  FN: { label: 'Missed', className: 'v-fn' },
  TN: { label: 'Nominal', className: 'v-tn' },
}

function DetailPanel({ row, onClose }) {
  if (!row) return null
  const v = verdict(row)
  const meta = VERDICT_META[v]
  return (
    <div className="detail-overlay" onClick={onClose}>
      <div className="detail-panel" onClick={(e) => e.stopPropagation()}>
        <div className="detail-head">
          <span>WINDOW DETAIL</span>
          <button className="detail-close" onClick={onClose}>×</button>
        </div>
        <div className={`detail-verdict ${meta.className}`}>{meta.label}</div>
        <dl className="detail-grid">
          <dt>Customer</dt><dd className="mono">{String(row.customer_id).padStart(3, '0')}</dd>
          <dt>Time window</dt><dd className="mono">{row.time_bucket}</dd>
          <dt>Isolation Forest risk</dt><dd className="mono">{row.if_risk != null ? row.if_risk.toFixed(3) : '--'}</dd>
          <dt>LSTM risk</dt><dd className="mono">{row.lstm_risk != null ? row.lstm_risk.toFixed(3) : '--'}</dd>
          <dt>Combined risk</dt><dd className="mono risk-cell">{row.combined_risk.toFixed(3)}</dd>
          <dt>Flagged (top 5%)?</dt><dd className="mono">{row.combined_risk > THRESHOLD ? 'YES' : 'no'}</dd>
          <dt>Ground truth</dt><dd className="mono">{row.bucket_has_anomaly === 1 ? 'ANOMALY' : 'normal'}</dd>
        </dl>
      </div>
    </div>
  )
}

function IconWave() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <path d="M2 12h3l2-7 4 14 3-10 2 5h6" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  )
}

function IconTarget() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <circle cx="12" cy="12" r="9" />
      <circle cx="12" cy="12" r="4" />
      <circle cx="12" cy="12" r="0.5" fill="currentColor" />
    </svg>
  )
}

function IconList() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01" strokeLinecap="round" />
    </svg>
  )
}

function VerdictBreakdown({ rows }) {
  const counts = useMemo(() => {
    const c = { TP: 0, FP: 0, FN: 0, TN: 0 }
    rows.forEach((r) => { c[verdict(r)]++ })
    return c
  }, [rows])

  const max = Math.max(counts.TP, counts.FP, counts.FN, counts.TN, 1)
  const bars = [
    { key: 'TP', label: 'Confirmed anomaly', count: counts.TP, className: 'v-tp' },
    { key: 'FP', label: 'False alarm', count: counts.FP, className: 'v-fp' },
    { key: 'FN', label: 'Missed', count: counts.FN, className: 'v-fn' },
    { key: 'TN', label: 'Nominal', count: counts.TN, className: 'v-tn' },
  ]

  return (
    <div className="panel">
      <div className="panel-head">
        <IconTarget />
        <span>VERDICT BREAKDOWN</span>
        <span className="panel-head-sub">how every window classified against ground truth</span>
      </div>
      <div className="verdict-bars">
        {bars.map((b) => (
          <div className="verdict-bar-row" key={b.key}>
            <span className="verdict-bar-label">{b.label}</span>
            <div className="verdict-bar-track">
              <div
                className={`verdict-bar-fill ${b.className}`}
                style={{ width: `${(b.count / max) * 100}%` }}
              />
            </div>
            <span className="verdict-bar-count mono">{b.count}</span>
          </div>
        ))}
      </div>
    </div>
  )
}

function SystemInfo() {
  return (
    <div className="system-info">
      <div className="system-info-item">
        <span className="system-info-label">MODELS</span>
        <span className="system-info-value">Isolation Forest + LSTM Autoencoder</span>
      </div>
      <div className="system-info-item">
        <span className="system-info-label">WINDOW</span>
        <span className="system-info-value">15 min, per customer</span>
      </div>
      <div className="system-info-item">
        <span className="system-info-label">THRESHOLD</span>
        <span className="system-info-value">top 5% combined risk</span>
      </div>
      <div className="system-info-item">
        <span className="system-info-label">SOURCE</span>
        <span className="system-info-value">build_risk_aggregator.py</span>
      </div>
    </div>
  )
}

export default function App() {
  const [token, setToken] = useState(() => localStorage.getItem(TOKEN_KEY))
  const [riskRows, setRiskRows] = useState(null)
  const [loadError, setLoadError] = useState(null)
  const [selectedCustomer, setSelectedCustomer] = useState('all')
  const [dateFrom, setDateFrom] = useState('')
  const [dateTo, setDateTo] = useState('')
  const [selectedRow, setSelectedRow] = useState(null)

  function handleLogin(newToken) {
    localStorage.setItem(TOKEN_KEY, newToken)
    setToken(newToken)
  }

  function handleLogout() {
    localStorage.removeItem(TOKEN_KEY)
    setToken(null)
    setRiskRows(null)
  }

  useEffect(() => {
    if (!token) return
    fetchRiskScoresCsv(token)
      .then((text) => {
        const parsed = Papa.parse(text, { header: true, dynamicTyping: true, skipEmptyLines: true })
        setRiskRows(parsed.data)
      })
      .catch((err) => {
        if (err.message === 'SESSION_EXPIRED') {
          handleLogout()
        } else {
          setLoadError(err.message)
        }
      })
  }, [token])

  const customerIds = useMemo(() => {
    if (!riskRows) return []
    const ids = [...new Set(riskRows.map((r) => r.customer_id))].filter((v) => v != null)
    return ids.sort((a, b) => a - b)
  }, [riskRows])

  const filteredRows = useMemo(() => {
    if (!riskRows) return []
    return riskRows
      .filter((r) => r.combined_risk != null)
      .filter((r) => selectedCustomer === 'all' || r.customer_id === Number(selectedCustomer))
      .filter((r) => !dateFrom || String(r.time_bucket) >= dateFrom)
      .filter((r) => !dateTo || String(r.time_bucket) <= dateTo)
      .sort((a, b) => String(a.time_bucket).localeCompare(String(b.time_bucket)))
  }, [riskRows, selectedCustomer, dateFrom, dateTo])

  const stats = useMemo(() => {
    if (!filteredRows.length) return null
    const total = filteredRows.length
    const flagged = filteredRows.filter((r) => r.combined_risk > THRESHOLD)
    const trueAnomalies = filteredRows.filter((r) => r.bucket_has_anomaly === 1)
    const truePositives = flagged.filter((r) => r.bucket_has_anomaly === 1)
    const precision = flagged.length ? truePositives.length / flagged.length : 0
    const recall = trueAnomalies.length ? truePositives.length / trueAnomalies.length : 0
    return { total, flaggedCount: flagged.length, trueAnomalyCount: trueAnomalies.length, precision, recall }
  }, [filteredRows])

  const signalData = useMemo(() => {
    return filteredRows.map((r, i) => ({
      index: i, combined_risk: r.combined_risk,
      is_true_anomaly: r.bucket_has_anomaly === 1,
    }))
  }, [filteredRows])

  const scatterData = useMemo(() => {
    return filteredRows.map((r, i) => ({ ...r, index: i, is_true_anomaly: r.bucket_has_anomaly === 1 }))
  }, [filteredRows])

  const normalPoints = scatterData.filter((d) => !d.is_true_anomaly)
  const anomalyPoints = scatterData.filter((d) => d.is_true_anomaly)

  const alertLog = useMemo(() => {
    return [...filteredRows].sort((a, b) => b.combined_risk - a.combined_risk).slice(0, 20)
  }, [filteredRows])

  if (!token) {
    return <Login onLogin={handleLogin} />
  }

  if (loadError) {
    return (
      <div className="console">
        <div className="titlebar"><span className="dot dot-red" /> AI-DAMS :: RISK CONSOLE</div>
        <p className="error">SIGNAL LOST -- {loadError}</p>
      </div>
    )
  }

  if (!riskRows) {
    return (
      <div className="console">
        <div className="titlebar"><span className="dot dot-amber" /> AI-DAMS :: RISK CONSOLE</div>
        <p className="loading">ACQUIRING SIGNAL...</p>
      </div>
    )
  }

  return (
    <div className="console">
      <div className="titlebar">
        <span className="dot dot-cyan" />
        AI-DAMS :: RISK CONSOLE
        <button className="logout-btn" onClick={handleLogout}>LOG OUT</button>
      </div>

      <p className="deck">
        Isolation Forest + LSTM Autoencoder, fused per (customer, 15-minute
        window). Click any point for detail. Flags anything above the 95th
        percentile of combined risk.
      </p>
      <p className="scope-note">
        NLP query-text classifier not represented here -- captured text
        currently cannot be attributed to a customer_id. See
        build_risk_aggregator.py.
      </p>

      <SystemInfo />

      <div className="signal-panel">
        <div className="panel-head">
          <IconWave />
          <span>RISK SIGNAL</span>
          <span className="panel-head-sub">{filteredRows.length} windows observed</span>
        </div>
        <ResponsiveContainer width="100%" height={160}>
          <ComposedChart data={signalData} margin={{ top: 8, right: 12, bottom: 0, left: 0 }}>
            <defs>
              <linearGradient id="signalFill" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#22d3c8" stopOpacity={0.35} />
                <stop offset="100%" stopColor="#22d3c8" stopOpacity={0} />
              </linearGradient>
            </defs>
            <XAxis dataKey="index" hide />
            <YAxis domain={[0, 1]} hide />
            <ReferenceLine y={THRESHOLD} stroke="#f2b134" strokeDasharray="3 3" />
            <Area type="monotone" dataKey="combined_risk" stroke="#22d3c8" strokeWidth={1.5}
                  fill="url(#signalFill)" dot={<SignalDot />} isAnimationActive={false} />
          </ComposedChart>
        </ResponsiveContainer>
      </div>

      <div className="controls">
        <label>
          FILTER :: CUSTOMER
          <select value={selectedCustomer} onChange={(e) => setSelectedCustomer(e.target.value)}>
            <option value="all">ALL</option>
            {customerIds.map((id) => (
              <option key={id} value={id}>{String(id).padStart(3, '0')}</option>
            ))}
          </select>
        </label>
        <label>
          FROM
          <input type="text" placeholder="YYYY-MM-DD" value={dateFrom}
                 onChange={(e) => setDateFrom(e.target.value)} />
        </label>
        <label>
          TO
          <input type="text" placeholder="YYYY-MM-DD" value={dateTo}
                 onChange={(e) => setDateTo(e.target.value)} />
        </label>
      </div>

      {stats && (
        <div className="readout-row">
          <Readout label="WINDOWS" value={stats.total} />
          <Readout label="FLAGGED" value={stats.flaggedCount} tone="amber" />
          <Readout label="CONFIRMED ANOMALIES" value={stats.trueAnomalyCount} tone="red" />
          <Readout label="PRECISION" value={`${(stats.precision * 100).toFixed(1)}%`} tone="cyan" />
          <Readout label="RECALL" value={`${(stats.recall * 100).toFixed(1)}%`} tone="cyan" />
        </div>
      )}

      <div className="panel">
        <div className="panel-head">
          <IconTarget />
          <span>DETECTION FIELD</span>
          <span className="panel-head-sub">click a point for detail, red = confirmed anomaly</span>
        </div>
        <ResponsiveContainer width="100%" height={340}>
          <ScatterChart margin={{ top: 12, right: 20, bottom: 8, left: 8 }}>
            <CartesianGrid stroke="#1c2531" strokeDasharray="2 4" />
            <XAxis type="number" dataKey="index" name="Window" tick={{ fill: '#7d8a9c', fontSize: 11 }} />
            <YAxis type="number" dataKey="combined_risk" name="Risk" domain={[0, 1]}
                   tick={{ fill: '#7d8a9c', fontSize: 11 }} />
            <ZAxis range={[24, 24]} />
            <Tooltip
              contentStyle={{ background: '#10161f', border: '1px solid #1c2531', fontFamily: 'JetBrains Mono, monospace', fontSize: 12 }}
              formatter={(value, name) => [typeof value === 'number' ? value.toFixed(3) : value, name]}
              labelFormatter={() => ''}
            />
            <ReferenceLine y={THRESHOLD} stroke="#f2b134" strokeDasharray="4 4" />
            <Scatter name="Nominal" data={normalPoints} fill="#22d3c8" fillOpacity={0.45}
                      onClick={(d) => setSelectedRow(d)} style={{ cursor: 'pointer' }} />
            <Scatter name="Confirmed anomaly" data={anomalyPoints} fill="#ef4444"
                      onClick={(d) => setSelectedRow(d)} style={{ cursor: 'pointer' }} />
          </ScatterChart>
        </ResponsiveContainer>
      </div>

      <VerdictBreakdown rows={filteredRows} />

      <div className="panel">
        <div className="panel-head">
          <IconList />
          <span>ALERT LOG</span>
          <span className="panel-head-sub">top 20 by risk, click a row for detail</span>
        </div>
        <table className="alert-log">
          <thead>
            <tr>
              <th>Verdict</th><th>Customer</th><th>Window</th><th>IF</th><th>LSTM</th><th>Combined</th>
            </tr>
          </thead>
          <tbody>
            {alertLog.map((r, i) => {
              const v = verdict(r)
              const meta = VERDICT_META[v]
              return (
                <tr key={i} className={meta.className} onClick={() => setSelectedRow(r)} style={{ cursor: 'pointer' }}>
                  <td><span className="verdict-tag">{meta.label}</span></td>
                  <td className="mono">{String(r.customer_id).padStart(3, '0')}</td>
                  <td className="mono">{r.time_bucket}</td>
                  <td className="mono">{r.if_risk != null ? r.if_risk.toFixed(3) : '--'}</td>
                  <td className="mono">{r.lstm_risk != null ? r.lstm_risk.toFixed(3) : '--'}</td>
                  <td className="mono risk-cell">{r.combined_risk.toFixed(3)}</td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>

      <DetailPanel row={selectedRow} onClose={() => setSelectedRow(null)} />
    </div>
  )
}
