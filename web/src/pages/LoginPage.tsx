import { useState, type FormEvent } from 'react'
import { loginApi } from '../api'

export default function LoginPage() {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  async function handleSubmit(e: FormEvent) {
    e.preventDefault()
    setError('')
    setLoading(true)

    try {
      const res = await loginApi(username, password)
      const data = await res.json()

      if (!res.ok) {
        setError(data.error_description || data.error || 'Login failed')
        return
      }

      window.location.href = data.redirect || '/auth'
    } catch {
      setError('Network error. Please try again.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div style={{
      display: 'flex', justifyContent: 'center', alignItems: 'center',
      minHeight: '100vh', background: '#f5f5f5',
    }}>
      <div style={{
        background: '#fff', padding: '2rem', borderRadius: '8px',
        boxShadow: '0 2px 10px rgba(0,0,0,0.1)', width: '360px',
      }}>
        <h2 style={{ textAlign: 'center', color: '#333', marginTop: 0 }}>Sign In</h2>

        {error && (
          <div style={{
            color: '#e74c3c', textAlign: 'center', marginBottom: '1rem',
            fontSize: '0.9rem',
          }}>
            {error}
          </div>
        )}

        <form onSubmit={handleSubmit}>
          <label htmlFor="username" style={{
            display: 'block', marginBottom: '0.3rem', color: '#555', fontSize: '0.9rem',
          }}>Username</label>
          <input
            id="username"
            type="text"
            value={username}
            onChange={e => setUsername(e.target.value)}
            required
            autoFocus
            style={{
              width: '100%', padding: '0.6rem', border: '1px solid #ddd',
              borderRadius: '4px', fontSize: '1rem', marginBottom: '1rem',
            }}
          />

          <label htmlFor="password" style={{
            display: 'block', marginBottom: '0.3rem', color: '#555', fontSize: '0.9rem',
          }}>Password</label>
          <input
            id="password"
            type="password"
            value={password}
            onChange={e => setPassword(e.target.value)}
            required
            style={{
              width: '100%', padding: '0.6rem', border: '1px solid #ddd',
              borderRadius: '4px', fontSize: '1rem', marginBottom: '1rem',
            }}
          />

          <button
            type="submit"
            disabled={loading}
            style={{
              width: '100%', padding: '0.7rem', background: loading ? '#95c8ee' : '#3498db',
              color: '#fff', border: 'none', borderRadius: '4px',
              fontSize: '1rem', cursor: loading ? 'not-allowed' : 'pointer',
            }}
          >
            {loading ? 'Signing in...' : 'Login'}
          </button>
        </form>

        <div style={{ textAlign: 'center', marginTop: '1rem', color: '#999', fontSize: '0.8rem' }}>
          Demo: admin/admin or test/test
        </div>
      </div>
    </div>
  )
}
