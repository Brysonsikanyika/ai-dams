require('dotenv').config()
const express = require('express')
const cors = require('cors')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const fs = require('fs')
const path = require('path')

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
function audit(req, user, action, outcome) {
  const entry = { ts: new Date().toISOString(), user: user || null, action, outcome, ip: req.ip }
  fs.appendFile(AUDIT_PATH, JSON.stringify(entry) + '\n', () => {})
}

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body || {}
  if (!username || !password) {
    return res.status(400).json({ error: 'username and password required' })
  }
  const user = USERS.find((candidate) => candidate.username === username)
  if (!user) {
    audit(req, username, 'login', 'failed')
    return res.status(401).json({ error: 'Invalid credentials' })
  }
  const valid = await bcrypt.compare(password, user.passwordHash)
  if (!valid) {
    audit(req, username, 'login', 'failed')
    return res.status(401).json({ error: 'Invalid credentials' })
  }
  const token = jwt.sign({ sub: username, role: user.role }, JWT_SECRET, { expiresIn: '8h' })
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
  res.type('application/json')
  fs.createReadStream(jsonPath).pipe(res)
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

app.get('/api/health', (req, res) => res.json({ status: 'ok' }))

app.listen(PORT, () => {
  console.log(`AI-DAMS dashboard backend listening on http://localhost:${PORT}`)
})
