export async function loginApi(username: string, password: string): Promise<Response> {
  return fetch('/api/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify({ username, password }),
  })
}

export async function getLoginStatus(): Promise<Response> {
  return fetch('/api/login', {
    method: 'GET',
    credentials: 'include',
  })
}

export async function getAuthContext(params: URLSearchParams): Promise<Response> {
  return fetch(`/api/auth?${params.toString()}`, {
    method: 'GET',
    credentials: 'include',
  })
}

export async function postAuthDecision(data: {
  authorize: boolean
  deny: boolean
}): Promise<Response> {
  return fetch('/api/auth', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify(data),
  })
}
