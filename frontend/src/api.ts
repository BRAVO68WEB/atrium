export type Brand = {
  product_name: string
  primary_color: string
  background_color: string
  text_color: string
  logo_url: string
  favicon_url: string
  footer_text: string
}

export type Meta = {
  product_name: string
  brand?: Brand
  csrf?: string
  org_enabled: boolean
  org_autolookup: boolean
  mfa_enabled: boolean
  management_client_id: string
  issuer: string
  endpoints: Record<string, string>
  grant_types: string[]
  auth_methods: string[]
  webhook_events: string[]
  in_docker: boolean
  embedded: boolean
  config_path: string
}

export type Restart = {
  saved: boolean
  restart_required: boolean
  in_docker: boolean
  auto_restart: boolean
  path: string
}

export class ApiError extends Error {
  status: number
  code: string
  constructor(status: number, code: string, message: string) {
    super(message)
    this.status = status
    this.code = code
  }
}

const csrfCookie = 'atrium_dashboard_csrf'

let csrf = ''

export function rememberCSRF(value: string) {
  csrf = value
}

// The session cookie survives a reload. The token does not, unless it is read
// back from the non-HttpOnly cookie or from GET /dashboard/api/meta.
function csrfFromCookie(): string {
  if (typeof document === 'undefined') return ''
  for (const part of document.cookie.split(';')) {
    const trimmed = part.trim()
    const eq = trimmed.indexOf('=')
    if (eq === -1 || trimmed.slice(0, eq) !== csrfCookie) continue
    const value = trimmed.slice(eq + 1)
    try {
      return decodeURIComponent(value)
    } catch {
      return value
    }
  }
  return ''
}

function currentCSRF(): string {
  return csrfFromCookie() || csrf
}

export async function api<T>(path: string, opts: RequestInit = {}): Promise<T> {
  const headers = new Headers(opts.headers)
  if (opts.body && !headers.has('Content-Type')) headers.set('Content-Type', 'application/json')
  const method = (opts.method || 'GET').toUpperCase()
  const token = currentCSRF()
  if (token && method !== 'GET' && method !== 'HEAD') headers.set('X-CSRF-Token', token)
  const res = await fetch(path, { ...opts, headers, credentials: 'same-origin' })
  const text = await res.text()
  const data = text ? JSON.parse(text) as { error?: string; error_description?: string } : {}
  if (!res.ok) {
    throw new ApiError(res.status, data.error || 'error', data.error_description || res.statusText)
  }
  return data as T
}

export function login(clientId: string, clientSecret: string) {
  return api<{ status: string; csrf: string }>('/dashboard/session', {
    method: 'POST',
    body: JSON.stringify({ client_id: clientId, client_secret: clientSecret }),
  }).then((body) => {
    rememberCSRF(body.csrf)
    return body
  })
}

export function logout() {
  return api('/dashboard/logout', { method: 'POST', body: '{}' })
}

export const WINDOWS = [
  { value: '5m', label: 'Last 5 minutes' },
  { value: '15m', label: 'Last 15 minutes' },
  { value: '30m', label: 'Last 30 minutes' },
  { value: '1h', label: 'Last 1 hour' },
  { value: '6h', label: 'Last 6 hours' },
  { value: '24h', label: 'Last 24 hours' },
  { value: '168h', label: 'Last 7 days' },
]

export const STANDARD_SCOPES = ['openid', 'profile', 'email', 'address', 'phone', 'offline_access']
