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
const USERS = [
  { username: process.env.ANALYST_USERNAME, passwordHash: process.env.ANALYST_PASSWORD_HASH },
  { username: process.env.ANALYST_USERNAME_2, passwordHash: process.env.ANALYST_PASSWORD_HASH_2 },
].filter((user) => user.username && user.passwordHash)

if (!JWT_SECRET || !USERS.length) {
  throw new Error('Missing required env vars. Copy .env.example to .env and configure at least one analyst account.')
}

app.use(cors({ origin: FRONTEND_ORIGIN }))
app.use(express.json())

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body || {}
  if (!username || !password) {
    return res.status(400).json({ error: 'username and password required' })
  }
  const user = USERS.find((candidate) => candidate.username === username)
  if (!user) {
    return res.status(401).json({ error: 'Invalid credentials' })
  }
  const valid = await bcrypt.compare(password, user.passwordHash)
  if (!valid) {
    return res.status(401).json({ error: 'Invalid credentials' })
  }
  const token = jwt.sign({ sub: username, role: 'analyst' }, JWT_SECRET, { expiresIn: '8h' })
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
  const csvPath = path.join(__dirname, 'data', 'risk_scores.csv')
  if (!fs.existsSync(csvPath)) {
    return res.status(404).json({ error: 'risk_scores.csv not found in dashboard-server/data/' })
  }
  res.type('text/csv')
  fs.createReadStream(csvPath).pipe(res)
})

app.get('/api/health', (req, res) => res.json({ status: 'ok' }))

app.listen(PORT, () => {
  console.log(`AI-DAMS dashboard backend listening on http://localhost:${PORT}`)
})
