import { type FormEvent, useEffect, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { getAuthContext, postAuthDecision, ApiRequestError, safeRedirect } from '@/lib/api'
import { useDocumentTitle } from '@/lib/use-document-title'
import { Button } from '@/components/ui/button'
import { Card, CardHeader, CardTitle, CardContent, CardFooter } from '@/components/ui/card'
import { Alert, AlertDescription } from '@/components/ui/alert'

interface AuthContext {
  userId: string
  clientId: string
  scope: string
}

export function AuthPage() {
  useDocumentTitle('Authorization Request — OAuth2 Server')

  const [searchParams] = useSearchParams()
  const [context, setContext] = useState<AuthContext | null>(null)
  const [loading, setLoading] = useState(true)
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState('')

  useEffect(() => {
    async function loadContext() {
      try {
        const res = await getAuthContext(searchParams)
        setContext({ userId: res.user_id, clientId: res.client_id, scope: res.scope })
      } catch (err) {
        if (err instanceof ApiRequestError) {
          setError(err.description)
        } else {
          setError('Failed to load authorization context.')
        }
      } finally {
        setLoading(false)
      }
    }
    void loadContext()
  }, [searchParams])

  const handleDecision = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault()
    const formData = new FormData(e.currentTarget)
    const authorize = formData.get('decision') === 'allow'

    setSubmitting(true)
    setError('')

    try {
      const res = await postAuthDecision({ authorize, deny: !authorize })
      safeRedirect(res.redirect, '/login')
    } catch (err) {
      if (err instanceof ApiRequestError) {
        setError(err.description)
      } else {
        setError('An unexpected error occurred. Please try again.')
      }
    } finally {
      setSubmitting(false)
    }
  }

  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-background p-4">
        <p className="text-sm text-muted-foreground">Loading\u2026</p>
      </div>
    )
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-background p-4">
      <Card className="w-full max-w-md">
        <CardHeader>
          <CardTitle>Authorization Request</CardTitle>
        </CardHeader>
        <CardContent className="grid gap-4">
          {context && (
            <Alert>
              <AlertDescription>
                <span className="grid gap-1 text-sm">
                  <span><span className="font-medium">Client ID:</span> {context.clientId}</span>
                  <span><span className="font-medium">Scope:</span> {context.scope}</span>
                </span>
              </AlertDescription>
            </Alert>
          )}
          <p className="text-sm text-muted-foreground">
            An application is requesting access to your account.
          </p>
          {error && (
            <Alert variant="destructive">
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          )}
        </CardContent>
        <CardFooter>
          <form onSubmit={(e) => { void handleDecision(e) }} className="flex w-full gap-4">
            <Button type="submit" name="decision" value="allow" disabled={submitting} className="flex-1">
              {submitting ? 'Processing\u2026' : 'Allow'}
            </Button>
            <Button type="submit" name="decision" value="deny" variant="destructive" disabled={submitting} className="flex-1">
              Deny
            </Button>
          </form>
        </CardFooter>
      </Card>
    </div>
  )
}
