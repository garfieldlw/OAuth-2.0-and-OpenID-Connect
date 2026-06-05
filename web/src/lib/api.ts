// --- Type definitions ---

interface ApiError {
  error: string
  error_description?: string
}

export interface LoginResponse {
  redirect: string
}

export interface AuthContextResponse {
  user_id: string
  client_id: string
  scope: string
}

export interface AuthDecisionResponse {
  redirect: string
}

// --- Safe redirect validator ---

export function isSafeRedirect(url: string): boolean {
  // Allow relative paths starting with / (but not protocol-relative //)
  if (url.startsWith('/') && !url.startsWith('//')) {
    return true
  }
  // Allow same-origin absolute URLs
  try {
    const parsed = new URL(url, window.location.origin)
    return parsed.origin === window.location.origin
  } catch {
    return false
  }
}

export function safeRedirect(url: string, fallback: string): void {
  const target = isSafeRedirect(url) ? url : fallback
  window.location.href = target
}

// --- Generic API fetch wrapper ---

export class ApiRequestError extends Error {
  readonly code: string
  readonly description: string
  constructor(code: string, description: string) {
    super(description)
    this.name = 'ApiRequestError'
    this.code = code
    this.description = description
  }
}

async function apiFetch<T>(url: string, options: RequestInit): Promise<T> {
  const res = await fetch(url, { credentials: 'include', ...options })
  const data: unknown = await res.json()
  if (!res.ok) {
    const apiErr = data as ApiError
    throw new ApiRequestError(
    apiErr.error ?? 'unknown_error',
    apiErr.error_description ?? apiErr.error ?? 'Request failed',
    )
  }
  return data as T
}

// --- API functions ---

export async function loginApi(
  username: string,
  password: string,
): Promise<LoginResponse> {
  return apiFetch<LoginResponse>('/api/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password }),
  })
}

export async function getAuthContext(
  params: URLSearchParams,
): Promise<AuthContextResponse> {
  return apiFetch<AuthContextResponse>(`/api/auth?${params.toString()}`, {
    method: 'GET',
  })
}

export async function postAuthDecision(
  data: { authorize: boolean; deny: boolean },
): Promise<AuthDecisionResponse> {
  return apiFetch<AuthDecisionResponse>('/api/auth', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  })
}
