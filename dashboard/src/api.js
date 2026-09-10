export const API_BASE = 'http://localhost:4000'

export async function login(username, password) {
  const res = await fetch(`${API_BASE}/api/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password }),
  })
  const data = await res.json()
  if (!res.ok) {
    throw new Error(data.error || 'Login failed')
  }
  return data.token
}

export async function fetchRiskScoresCsv(token) {
  const res = await fetch(`${API_BASE}/api/risk-scores`, {
    headers: { Authorization: `Bearer ${token}` },
  })
  if (res.status === 401) {
    throw new Error('SESSION_EXPIRED')
  }
  if (!res.ok) {
    throw new Error(`Failed to fetch risk scores: ${res.status}`)
  }
  return res.text()
}
