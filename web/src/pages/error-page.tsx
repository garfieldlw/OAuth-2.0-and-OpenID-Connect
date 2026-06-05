import { Link } from 'react-router-dom'
import { useDocumentTitle } from '@/lib/use-document-title'
import { Button } from '@/components/ui/button'
import { Card, CardHeader, CardTitle, CardContent, CardFooter } from '@/components/ui/card'
import { Alert, AlertDescription } from '@/components/ui/alert'

export function ErrorPage() {
  useDocumentTitle('Error — OAuth2 Server')

  const params = new URLSearchParams(window.location.search)
  const errorCode = params.get('error') ?? 'unknown_error'
  const errorDescription = params.get('error_description') ?? 'An unexpected error occurred.'

  return (
    <div className="flex min-h-screen items-center justify-center bg-background p-4">
      <Card className="w-full max-w-md">
        <CardHeader>
          <CardTitle>Error</CardTitle>
        </CardHeader>
        <CardContent className="grid gap-4">
          <Alert variant="destructive">
            <AlertDescription>
              <span className="grid gap-1">
                <span className="font-medium">{errorCode}</span>
                <span>{errorDescription}</span>
              </span>
            </AlertDescription>
          </Alert>
        </CardContent>
        <CardFooter>
          <Button variant="outline" asChild>
            <Link to="/login">Back to Login</Link>
          </Button>
        </CardFooter>
      </Card>
    </div>
  )
}
