require('dotenv').config()
const express = require('express')
const cors = require('cors')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const fs = require('fs')
const path = require('path')
const crypto = require('crypto')

const app = express()
const PORT = process.env.PORT || 4000
const JWT_SECRET = process.env.JWT_SECRET
const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN || 'http://localhost:5173'
const ROLES = ['admin', 'analyst']
const roleOf = (value) => (ROLES.includes(value) ? value : 'analyst')
const USERS = [
  { username: process.env.ANALYST_USERNAME, passwordHash: process.env.ANALYST_PASSWORD_HASH, role: roleOf(process.env.ANALYST_ROLE) },
  { username: process.env.ANALYST_USERNAME_2, passwordHash: process.env.ANALYST_PASSWORD_HASH_2, role: roleOf(process.env.ANALYST_ROLE_2) },
].filter((user) => user.username && user.passwordHash)

if (!JWT_SECRET || !USERS.length) {
  throw new Error('Missing required env vars. Copy .env.example to .env and configure at least one analyst account.')
}

app.use(cors({ origin: FRONTEND_ORIGIN }))
app.use(express.json())

const AUDIT_PATH = path.join(__dirname, 'audit.log')
// Hash-chained audit log: each line stores prev (hash of the previous line) and hash
// (SHA-256 of prev + the entry's fields). Editing or deleting a line breaks the chain.
function lastAuditHash() {
  try {
    const text = fs.readFileSync(AUDIT_PATH, 'utf8').trimEnd()
    if (!text) return 'GENESIS'
    return JSON.parse(text.slice(text.lastIndexOf('\n') + 1)).hash || 'GENESIS'
  } catch (e) {
    return 'GENESIS'
  }
}
function auditHash(prev, e) {
  return crypto.createHash('sha256').update([prev, e.ts, e.user || '', e.action, e.outcome, e.ip || ''].join('|')).digest('hex')
}
function audit(req, user, action, outcome) {
  const entry = { ts: new Date().toISOString(), user: user || null, action, outcome: String(outcome), ip: req.ip }
  entry.prev = lastAuditHash()
  entry.hash = auditHash(entry.prev, entry)
  fs.appendFileSync(AUDIT_PATH, JSON.stringify(entry) + '\n')
}

// Lockout: 5 failed logins for a username lock it for 15 minutes (in memory; a restart clears it).
const MAX_FAILS = 5
const LOCK_MS = 15 * 60 * 1000
const fails = new Map()
function lockedFor(username) {
  const f = fails.get(String(username).toLowerCase())
  return f && f.lockedUntil > Date.now()
}
function noteFail(req, username) {
  const key = String(username).toLowerCase()
  const now = Date.now()
  let f = fails.get(key)
  if (!f || f.lockedUntil <= now && f.lockedUntil !== 0 || now - f.first > LOCK_MS) f = { count: 0, first: now, lockedUntil: 0 }
  f.count += 1
  if (f.count >= MAX_FAILS) {
    f.lockedUntil = now + LOCK_MS
    audit(req, username, 'login', 'locked')
  }
  fails.set(key, f)
}

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body || {}
  if (!username || !password) {
    return res.status(400).json({ error: 'username and password required' })
  }
  if (lockedFor(username)) {
    audit(req, username, 'login', 'blocked')
    return res.status(429).json({ error: 'Too many failed attempts. Try again later.' })
  }
  const user = USERS.find((candidate) => candidate.username === username)
  if (!user) {
    audit(req, username, 'login', 'failed')
    noteFail(req, username)
    return res.status(401).json({ error: 'Invalid credentials' })
  }
  const valid = await bcrypt.compare(password, user.passwordHash)
  if (!valid) {
    audit(req, username, 'login', 'failed')
    noteFail(req, username)
    return res.status(401).json({ error: 'Invalid credentials' })
  }
  const token = jwt.sign({ sub: username, role: user.role }, JWT_SECRET, { expiresIn: '8h' })
  fails.delete(String(username).toLowerCase())
  audit(req, username, 'login', 'ok')
  res.json({ token })
})

function requireAuth(req, res, next) {
  const header = req.headers.authorization || ''
  const token = header.startsWith('Bearer ') ? header.slice(7) : null
  if (!token) {
    return res.status(401).json({ error: 'Missing token' })
  }
  try {
    req.user = jwt.verify(token, JWT_SECRET)
    next()
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token' })
  }
}

app.get('/api/risk-scores', requireAuth, (req, res) => {
  audit(req, req.user.sub, 'view_risk_scores', 'ok')
  const csvPath = path.join(__dirname, 'data', 'risk_scores.csv')
  if (!fs.existsSync(csvPath)) {
    return res.status(404).json({ error: 'risk_scores.csv not found in dashboard-server/data/' })
  }
  res.type('text/csv')
  fs.createReadStream(csvPath).pipe(res)
})

app.get('/api/alerts', requireAuth, (req, res) => {
  audit(req, req.user.sub, 'view_alerts', 'ok')
  const jsonPath = path.join(__dirname, 'data', 'alerts.json')
  if (!fs.existsSync(jsonPath)) {
    return res.status(404).json({ error: 'alerts.json not found in dashboard-server/data/' })
  }
  // Analysts get the alert text and the pseudonym, not the account name or the synthetic ground-truth label.
  const alerts = JSON.parse(fs.readFileSync(jsonPath, 'utf8')).map(({ account, truth, ...rest }) => rest)
  res.json(alerts)
})

function requireRole(role) {
  return (req, res, next) => {
    if (req.user.role !== role) {
      audit(req, req.user.sub, 'forbidden', req.path)
      return res.status(403).json({ error: 'Forbidden' })
    }
    next()
  }
}

app.get('/api/audit', requireAuth, requireRole('admin'), (req, res) => {
  audit(req, req.user.sub, 'view_audit', 'ok')
  let lines = []
  if (fs.existsSync(AUDIT_PATH)) {
    lines = fs.readFileSync(AUDIT_PATH, 'utf8').split('\n').filter(Boolean).slice(-200)
  }
  const entries = lines.map((line) => {
    try { return JSON.parse(line) } catch (err) { return null }
  }).filter(Boolean)
  res.json(entries)
})

const LIVE_ALERTS_PATH = process.env.LIVE_ALERTS_PATH || path.join(__dirname, '..', 'ml-engine', 'data', 'live_alerts.jsonl')

app.get('/api/live-alerts', requireAuth, (req, res) => {
  audit(req, req.user.sub, 'view_live_alerts', 'ok')
  if (!fs.existsSync(LIVE_ALERTS_PATH)) {
    return res.json([])
  }
  const lines = fs.readFileSync(LIVE_ALERTS_PATH, 'utf8').split('\n').filter(Boolean).slice(-50)
  const alerts = lines.map((line) => {
    try { return JSON.parse(line) } catch (err) { return null }
  }).filter(Boolean).reverse()
  // Only admins see who the alert is about. Everyone else gets the alert without the account
  // name or customer_id (customer_id is the student number, so it identifies the person).
  if (req.user.role === 'admin') return res.json(alerts)
  res.json(alerts.map(({ account, customer_id, ...rest }) => rest))
})

app.get('/api/health', (req, res) => res.json({ status: 'ok' }))

app.listen(PORT, () => {
  console.log(`AI-DAMS dashboard backend listening on http://localhost:${PORT}`)
})
