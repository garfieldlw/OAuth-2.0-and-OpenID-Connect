import { useSearchParams, Link } from 'react-router-dom'

export default function ErrorPage() {
  const [searchParams] = useSearchParams()
  const error = searchParams.get('error') || searchParams.get('error_description') || 'An unknown error occurred'

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
        <Link to="/login" style={{ color: '#3498db' }}>Back to Login</Link>
      </div>
    </div>
  )
}
