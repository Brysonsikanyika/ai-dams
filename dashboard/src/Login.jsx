import { useState } from 'react'
import { login } from './api'

export default function Login({ onLogin }) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  async function handleSubmit(e) {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      const token = await login(username, password)
      onLogin(token)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="login-screen">
      <form className="login-panel" onSubmit={handleSubmit}>
        <div className="login-title">
          <span className="dot dot-cyan" /> AI-DAMS :: ANALYST ACCESS
        </div>
        <p className="login-sub">Authenticate to view the risk console.</p>

        <label className="login-field">
          USERNAME
          <input
            type="text"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            autoFocus
          />
        </label>

        <label className="login-field">
          PASSWORD
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
        </label>

        {error && <p className="login-error">{error}</p>}

        <button type="submit" disabled={loading}>
          {loading ? 'AUTHENTICATING...' : 'AUTHENTICATE'}
        </button>
      </form>
    </div>
  )
}
