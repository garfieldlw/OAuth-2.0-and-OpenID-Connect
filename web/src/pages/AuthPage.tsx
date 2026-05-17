import { useState, useEffect } from 'react'
import { useSearchParams, useNavigate } from 'react-router-dom'
import { getAuthContext, postAuthDecision } from '../api'

interface AuthContext {
  user_id: string
  client_id: string
  scope: string
}

export default function AuthPage() {
  const [searchParams] = useSearchParams()
  const navigate = useNavigate()
  const [context, setContext] = useState<AuthContext | null>(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    getAuthContext(searchParams).then(async res => {
      if (res.status === 401) {
        navigate('/login')
        return
      }
      const data = await res.json()
      if (!res.ok) {
        setError(data.error_description || 'Failed to load authorization context')
        return
      }
      setContext(data)
    }).catch(() => {
      setError('Network error')
    })
  }, [searchParams, navigate])

  async function handleDecision(authorize: boolean) {
    setLoading(true)
    setError('')

    try {
      const res = await postAuthDecision({ authorize, deny: !authorize })
      const data = await res.json()

      if (!res.ok) {
        setError(data.error_description || 'Decision failed')
        setLoading(false)
        return
      }

      window.location.href = data.redirect || '/login'
    } catch {
      setError('Network error')
      setLoading(false)
    }
  }

  if (error && !context) {
    return (
      <div style={{
        display: 'flex', justifyContent: 'center', alignItems: 'center',
        minHeight: '100vh', background: '#f5f5f5',
      }}>
        <div style={{
          background: '#fff', padding: '2rem', borderRadius: '8px',
          boxShadow: '0 2px 10px rgba(0,0,0,0.1)', width: '420px', textAlign: 'center',
        }}>
          <h2 style={{ color: '#e74c3c', marginTop: 0 }}>Error</h2>
          <p style={{ color: '#555' }}>{error}</p>
          <a href="/login" style={{ color: '#3498db' }}>Back to Login</a>
        </div>
      </div>
    )
  }

  return (
    <div style={{
      display: 'flex', justifyContent: 'center', alignItems: 'center',
      minHeight: '100vh', background: '#f5f5f5',
    }}>
      <div style={{
        background: '#fff', padding: '2rem', borderRadius: '8px',
        boxShadow: '0 2px 10px rgba(0,0,0,0.1)', width: '420px',
      }}>
        <h2 style={{ textAlign: 'center', color: '#333', marginTop: 0 }}>
          Authorization Request
        </h2>

        {context && (
          <div style={{
            background: '#f8f9fa', padding: '1rem', borderRadius: '4px',
            marginBottom: '1.5rem',
          }}>
            <p style={{ margin: '0.3rem 0', fontSize: '0.9rem', color: '#555' }}>
              <strong style={{ color: '#333' }}>Client ID:</strong> {context.client_id}
            </p>
            <p style={{ margin: '0.3rem 0', fontSize: '0.9rem', color: '#555' }}>
              <strong style={{ color: '#333' }}>Scope:</strong> {context.scope}
            </p>
            <p style={{ margin: '0.3rem 0', fontSize: '0.9rem', color: '#555' }}>
              An application is requesting access to your account.
            </p>
          </div>
        )}

        {error && (
          <div style={{
            color: '#e74c3c', textAlign: 'center', marginBottom: '1rem', fontSize: '0.9rem',
          }}>
            {error}
          </div>
        )}

        <div style={{ display: 'flex', gap: '1rem' }}>
          <button
            onClick={() => handleDecision(true)}
            disabled={loading}
            style={{
              flex: 1, padding: '0.7rem',
              background: loading ? '#6dc990' : '#27ae60',
              color: '#fff', border: 'none', borderRadius: '4px',
              fontSize: '1rem', cursor: loading ? 'not-allowed' : 'pointer',
            }}
          >
            Allow
          </button>
          <button
            onClick={() => handleDecision(false)}
            disabled={loading}
            style={{
              flex: 1, padding: '0.7rem',
              background: loading ? '#ee8073' : '#e74c3c',
              color: '#fff', border: 'none', borderRadius: '4px',
              fontSize: '1rem', cursor: loading ? 'not-allowed' : 'pointer',
            }}
          >
            Deny
          </button>
        </div>
      </div>
    </div>
  )
}
