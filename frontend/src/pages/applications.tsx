import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import { Button, Form, Input, Modal, Select, Table, Tabs, Tag, Typography, message } from 'antd'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { api } from '../api'
import { useMeta } from '../App'
import { Flag, Stage, confirmName, errText, joinLines, lines, showSecret } from '../widgets'

function faceColor(name: string) {
  let n = 0
  for (const ch of name) n = (n * 33 + ch.charCodeAt(0)) % 360
  return `hsl(${n} 42% 42%)`
}

type Client = {
  id: string
  name: string
  secret?: string
  redirect_uris: string[]
  post_logout_redirect_uris?: string[]
  grant_types: string[]
  scopes: string[]
  token_endpoint_auth_method: string
  dpop_bound_access_tokens: boolean
  require_pushed_authorization_requests: boolean
  skip_consent: boolean
  dcr_enabled: boolean
  cimd_enabled: boolean
  subject_type?: string
  sector_identifier_uri?: string
  backchannel_logout_uri?: string
  backchannel_logout_session_required?: boolean
  backchannel_token_delivery_mode?: string
  backchannel_client_notification_endpoint?: string
  backchannel_authentication_request_signing_alg?: string
  jwks?: string
  jwks_uri?: string
  signing_kid?: string
  signing_alg?: string
  org_id?: string
  registration_source?: string
  request_object_signing_alg?: string
  id_token_encrypted_response_alg?: string
  id_token_encrypted_response_enc?: string
  userinfo_encrypted_response_alg?: string
  userinfo_encrypted_response_enc?: string
  created_at?: string
  updated_at?: string
}

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div className="config-section">
      <h3>{title}</h3>
      {children}
    </div>
  )
}

function Sub({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div className="config-subsection">
      <h4>{title}</h4>
      <div className="field-grid">{children}</div>
    </div>
  )
}

const grantDocs: Record<string, { title: string; text: string; href: string; doc: string }> = {
  authorization_code: {
    title: 'Authorization code',
    text: 'Exchange an authorization code for an access token.',
    href: 'https://www.rfc-editor.org/rfc/rfc6749#section-4.1',
    doc: 'RFC 6749',
  },
  client_credentials: {
    title: 'Client credentials',
    text: 'The client gets a token for itself, with no user.',
    href: 'https://www.rfc-editor.org/rfc/rfc6749#section-4.4',
    doc: 'RFC 6749',
  },
  refresh_token: {
    title: 'Refresh token',
    text: 'Exchange a refresh token for a new access token.',
    href: 'https://www.rfc-editor.org/rfc/rfc6749#section-6',
    doc: 'RFC 6749',
  },
  password: {
    title: 'Password',
    text: 'Exchange the resource owner’s password for an access token.',
    href: 'https://www.rfc-editor.org/rfc/rfc6749#section-4.3',
    doc: 'RFC 6749',
  },
  'urn:ietf:params:oauth:grant-type:device_code': {
    title: 'Device code',
    text: 'The user approves a device code on another device.',
    href: 'https://www.rfc-editor.org/rfc/rfc8628',
    doc: 'RFC 8628',
  },
  'urn:openid:params:grant-type:ciba': {
    title: 'CIBA',
    text: 'The client starts sign-in on the user’s authentication device.',
    href: 'https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html',
    doc: 'CIBA 1.0',
  },
  'urn:ietf:params:oauth:grant-type:token-exchange': {
    title: 'Token exchange',
    text: 'Exchange a token this client holds for another token.',
    href: 'https://www.rfc-editor.org/rfc/rfc8693',
    doc: 'RFC 8693',
  },
  'urn:ietf:params:oauth:grant-type:jwt-bearer': {
    title: 'JWT bearer',
    text: 'Exchange a JWT assertion for an access token.',
    href: 'https://www.rfc-editor.org/rfc/rfc7523',
    doc: 'RFC 7523',
  },
}

function grantInfo(grant: string) {
  const known = grantDocs[grant]
  if (known) return known
  const leaf = grant.includes(':') ? grant.slice(grant.lastIndexOf(':') + 1) : grant
  const words = leaf.replace(/[_-]/g, ' ')
  return { title: words.charAt(0).toUpperCase() + words.slice(1), text: 'A grant type configured on this server.', href: '', doc: '' }
}

function GrantMenu({ value = [], onChange, disabled, options }: { value?: string[]; onChange?: (next: string[]) => void; disabled?: boolean; options: string[] }) {
  const selected = new Set(value)
  const grants = [...new Set([...(options || []), ...value])]
  const toggle = (grant: string) => {
    if (disabled) return
    const next = selected.has(grant) ? value.filter((item) => item !== grant) : [...value, grant]
    onChange?.(next)
  }
  return (
    <div className="grant-menu" role="group" aria-label="Grant types">
      {grants.map((grant) => {
        const info = grantInfo(grant)
        const on = selected.has(grant)
        return (
          <div key={grant} className={on ? 'grant-row on' : 'grant-row'}>
            <button type="button" className="grant-pick" disabled={disabled} aria-pressed={on} title={grant} onClick={() => toggle(grant)}>
              <span className="grant-check" aria-hidden="true">{on ? '✓' : ''}</span>
              <span>
                <strong>{info.title}</strong>
                <span className="grant-id mono">{grant}</span>
                <span className="grant-text">{info.text}</span>
              </span>
            </button>
            {info.href ? <a className="grant-rfc" href={info.href} target="_blank" rel="noreferrer">{info.doc}</a> : null}
          </div>
        )
      })}
    </div>
  )
}

const emptyClient = {
  name: '',
  redirect_uris: '',
  post_logout_redirect_uris: '',
  grant_types: ['authorization_code'],
  scopes: ['openid'],
  token_endpoint_auth_method: 'client_secret_basic',
}

export function Applications() {
  const meta = useMeta()
  const [rows, setRows] = useState<Client[]>([])
  const [q, setQ] = useState('')
  const [open, setOpen] = useState(false)
  const [error, setError] = useState('')
  const load = () => api<Client[]>('/dashboard/api/clients').then(setRows).catch((err) => setError(errText(err)))
  useEffect(() => { load() }, [])
  const shown = useMemo(() => rows.filter((row) => `${row.name} ${row.id}`.toLowerCase().includes(q.trim().toLowerCase())), [rows, q])
  return (
    <div>
      <div className="dash-toolbar">
        <Input.Search allowClear placeholder="Search name or id" style={{ width: 280 }} onChange={(e) => setQ(e.target.value)} />
        <div className="spacer" />
        <Button type="primary" onClick={() => setOpen(true)}>Create</Button>
      </div>
      {error && <Typography.Paragraph type="danger" style={{ padding: 16 }}>{error}</Typography.Paragraph>}
      <Stage kicker="Applications" title={`${shown.length} clients`} text="OAuth and OIDC applications registered with this issuer." />
      <div className="directory">
        {shown.length === 0 ? <p className="hint">No applications match.</p> : shown.map((row) => (
          <Link key={row.id} className="person app-card" to={`/applications/${row.id}`}>
            <span className="face" style={{ background: faceColor(row.name) }}>{(row.name || '?').slice(0, 1).toUpperCase()}</span>
            <span className="who">
              <strong>{row.name}</strong>
              <span className="mono">{row.id === meta.management_client_id ? 'Management client' : row.token_endpoint_auth_method || 'client'}</span>
            </span>
            <span className="chips">{(row.grant_types || []).slice(0, 2).map((grant) => <Tag key={grant} title={grant}>{grantInfo(grant).title}</Tag>)}</span>
          </Link>
        ))}
      </div>
      <Modal title="Create application" open={open} onCancel={() => setOpen(false)} footer={null} destroyOnClose width={720}>
        <Form layout="vertical" initialValues={emptyClient} onFinish={async (values) => {
          try {
            const created = await api<Client>('/dashboard/api/clients', {
              method: 'POST',
              body: JSON.stringify({
                name: values.name,
                redirect_uris: lines(values.redirect_uris || ''),
                post_logout_redirect_uris: lines(values.post_logout_redirect_uris || ''),
                grant_types: values.grant_types,
                scopes: values.scopes,
                token_endpoint_auth_method: values.token_endpoint_auth_method,
              }),
            })
            setOpen(false)
            if (created.secret) showSecret('Client secret', created.secret)
            load()
          } catch (err) {
            message.error(errText(err))
          }
        }}>
          <Form.Item name="name" label="Name" rules={[{ required: true }]}><Input /></Form.Item>
          <Form.Item name="redirect_uris" label="Redirect URIs" extra="One URI per line."><Input.TextArea autoSize /></Form.Item>
          <Form.Item name="post_logout_redirect_uris" label="Post-logout redirect URIs"><Input.TextArea autoSize /></Form.Item>
          <Form.Item name="grant_types" label="Grant types"><GrantMenu options={meta.grant_types || []} /></Form.Item>
          <Form.Item name="scopes" label="Scopes"><Select mode="tags" /></Form.Item>
          <Form.Item name="token_endpoint_auth_method" label="Token endpoint auth method">
            <Select options={(meta.auth_methods || []).map((value) => ({ value, label: value }))} />
          </Form.Item>
          <Button type="primary" htmlType="submit">Create</Button>
        </Form>
      </Modal>
    </div>
  )
}

function withCurrent(supported: string[], current?: string) {
  const values = current && !supported.includes(current) ? [...supported, current] : supported
  return values.map((value) => ({ value, label: value }))
}

function encAlgOptions(current?: string) {
  return withCurrent(['RSA-OAEP-256'], current)
}

function encEncOptions(current?: string) {
  return withCurrent(['A256GCM'], current)
}

const endpointLabels: Record<string, string> = {
  issuer: 'Issuer',
  discovery: 'OpenID Provider configuration',
  as_metadata: 'OAuth Authorization Server Metadata',
  push_discovery: 'OAuth Push-Based Authentication',
  jwks: 'JSON Web Key Set',
  userinfo: 'UserInfo',
  authorize: 'Authorization',
  par: 'Pushed authorization',
  device: 'Device authorization',
  bc_authorize: 'Back-channel authentication',
  token: 'Token',
  revoke: 'Revocation',
  introspect: 'Introspection',
  register: 'Dynamic registration',
}

function EndpointRow({ name, url }: { name: string; url: string }) {
  const [copied, setCopied] = useState(false)
  useEffect(() => {
    if (!copied) return
    const id = window.setTimeout(() => setCopied(false), 1200)
    return () => window.clearTimeout(id)
  }, [copied])
  return (
    <button type="button" className="endpoint-row" title="Click to copy" onClick={() => {
      navigator.clipboard.writeText(url).then(() => setCopied(true)).catch(() => message.error('Could not copy'))
    }}>
      <span className="endpoint-name">{name}</span>
      <span className="mono endpoint-url">{url}</span>
      <span className="endpoint-state">{copied ? 'Copied' : 'Copy'}</span>
    </button>
  )
}

function EndpointGroups({ endpoints }: { endpoints: Record<string, string> }) {
  const groups = [
    { title: 'Discovery', sections: [{ title: 'Documents', keys: ['issuer', 'discovery', 'as_metadata', 'push_discovery'] }, { title: 'Keys and claims', keys: ['jwks', 'userinfo'] }] },
    { title: 'Authorization', sections: [{ title: 'Code', keys: ['authorize', 'par'] }, { title: 'Device and CIBA', keys: ['device', 'bc_authorize'] }] },
    { title: 'Tokens', sections: [{ title: 'Issuance', keys: ['token'] }, { title: 'Management', keys: ['revoke', 'introspect', 'register'] }] },
  ]
  return (
    <>
      {groups.map((group) => (
        <Section key={group.title} title={group.title}>
          {group.sections.map((section) => {
            const rows = section.keys.filter((key) => endpoints[key])
            if (rows.length === 0) return null
            return (
              <div key={section.title} className="config-subsection">
                <h4>{section.title}</h4>
                {rows.map((key) => <EndpointRow key={key} name={endpointLabels[key] || key} url={endpoints[key]} />)}
              </div>
            )
          })}
        </Section>
      ))}
    </>
  )
}

function escapeHtml(value: string) {
  return value.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
}

function highlightJson(src: string) {
  const re = /("(?:\\u[\da-fA-F]{4}|\\[^u]|[^\\"])*")(\s*:)?|\b(?:true|false|null)\b|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?/g
  let out = ''
  let last = 0
  for (const match of src.matchAll(re)) {
    const index = match.index ?? 0
    out += escapeHtml(src.slice(last, index))
    if (match[1]) {
      out += `<span class="${match[2] ? 'tok-key' : 'tok-str'}">${escapeHtml(match[1])}</span>`
      if (match[2]) out += escapeHtml(match[2])
    } else if (match[0] === 'true' || match[0] === 'false' || match[0] === 'null') {
      out += `<span class="tok-lit">${match[0]}</span>`
    } else {
      out += `<span class="tok-num">${escapeHtml(match[0])}</span>`
    }
    last = index + match[0].length
  }
  return out + escapeHtml(src.slice(last))
}

function rsaBits(modulus: string) {
  const raw = modulus.replace(/=+$/, '').replace(/-/g, '+').replace(/_/g, '/')
  const pad = raw.length % 4 === 0 ? '' : '='.repeat(4 - (raw.length % 4))
  try {
    const bytes = atob(raw + pad).length
    return bytes > 0 ? `${bytes * 8}-bit` : ''
  } catch {
    return ''
  }
}

type JwksKey = { title: string; kind: string; use: string; alg: string; detail: string; privateKey: boolean }

function jwksView(raw: string): { error: string; keys: JwksKey[] } {
  const text = raw.trim()
  if (!text) return { error: '', keys: [] }
  let doc: unknown
  try {
    doc = JSON.parse(text)
  } catch {
    return { error: 'This is not valid JSON.', keys: [] }
  }
  let list: unknown[] | null = null
  if (Array.isArray(doc)) list = doc
  else if (doc && typeof doc === 'object' && Array.isArray((doc as { keys?: unknown }).keys)) list = (doc as { keys: unknown[] }).keys
  else if (doc && typeof doc === 'object' && typeof (doc as { kty?: unknown }).kty === 'string') list = [doc]
  if (!list) return { error: 'Use a JWKS object with a keys array.', keys: [] }
  const keys = list.map((item, index) => {
    if (!item || typeof item !== 'object' || Array.isArray(item)) {
      return { title: `Key ${index + 1}`, kind: 'Invalid', use: '', alg: '', detail: 'This entry is not a key.', privateKey: false }
    }
    const key = item as Record<string, unknown>
    const str = (name: string) => (typeof key[name] === 'string' ? (key[name] as string) : '')
    const kty = str('kty')
    const use = str('use')
    const detail = kty === 'RSA' && str('n') ? rsaBits(str('n')) : str('crv')
    return {
      title: str('kid') || `Key ${index + 1}`,
      kind: kty || 'Unknown',
      use: use === 'sig' ? 'Signing' : use === 'enc' ? 'Encryption' : use,
      alg: str('alg'),
      detail,
      privateKey: ['d', 'p', 'q', 'dp', 'dq', 'qi', 'k'].some((name) => key[name] != null && key[name] !== ''),
    }
  })
  return { error: '', keys }
}

function JwksEditor({ value = '', onChange, disabled }: { value?: string; onChange?: (value: string) => void; disabled?: boolean }) {
  const preRef = useRef<HTMLPreElement>(null)
  const view = jwksView(value)
  const format = () => {
    try {
      onChange?.(JSON.stringify(JSON.parse(value), null, 2))
    } catch {
      /* the preview already explains the JSON */
    }
  }
  return (
    <div className="jwks-split">
      <section className="jwks-pane">
        <div className="jwks-bar">
          <span>Editor</span>
          <button type="button" className="jwks-format" disabled={disabled || !value.trim() || !!view.error} onClick={format}>Format</button>
        </div>
        <div className="jwks-code">
          <pre ref={preRef} className="jwks-highlight" aria-hidden="true" dangerouslySetInnerHTML={{ __html: highlightJson(value) + '\n' }} />
          <textarea
            className="jwks-input"
            aria-label="JWKS JSON"
            spellCheck={false}
            readOnly={disabled}
            placeholder={'{\n  "keys": []\n}'}
            value={value}
            onChange={(e) => onChange?.(e.target.value)}
            onScroll={(e) => { if (preRef.current) preRef.current.scrollTop = e.currentTarget.scrollTop }}
          />
        </div>
      </section>
      <section className="jwks-pane" aria-label="JWKS preview">
        <div className="jwks-bar">
          <span>Preview</span>
          <span>{view.keys.length === 0 ? '' : `${view.keys.length} ${view.keys.length === 1 ? 'key' : 'keys'}`}</span>
        </div>
        <div className="jwks-preview">
          {view.error ? <p className="jwks-error">{view.error}</p> : null}
          {!view.error && view.keys.length === 0 ? <p className="jwks-empty">No keys yet. A set is {'{ "keys": [ … ] }'}.</p> : null}
          {view.keys.map((key, index) => (
            <article key={`${key.title}-${index}`} className="jwks-key">
              <strong>{key.title}</strong>
              <span className="jwks-chips">
                <em>{key.kind}</em>
                {key.detail ? <em>{key.detail}</em> : null}
                {key.use ? <em>{key.use}</em> : null}
                {key.alg ? <em>{key.alg}</em> : null}
                {key.privateKey ? <em className="jwks-warn">Private material</em> : null}
              </span>
            </article>
          ))}
        </div>
      </section>
    </div>
  )
}

export function ApplicationDetail() {
  const { id = '' } = useParams()
  const meta = useMeta()
  const navigate = useNavigate()
  const [client, setClient] = useState<Client | null>(null)
  const [scopes, setScopes] = useState<string[]>([])
  const [consents, setConsents] = useState<{ user_id: string; scopes: string[]; granted_at: string }[]>([])
  const [orgName, setOrgName] = useState('')
  const [copiedId, setCopiedId] = useState(false)
  const [error, setError] = useState('')

  const load = () => {
    api<Client>(`/dashboard/api/clients/${id}`).then((row) => {
      setClient(row)
      if (row.org_id && meta.org_enabled) {
        api<{ name: string }>(`/dashboard/api/orgs/${row.org_id}`).then((org) => setOrgName(org.name)).catch(() => setOrgName(''))
      } else {
        setOrgName('')
      }
    }).catch((err) => setError(errText(err)))
    api<{ name: string }[]>('/dashboard/api/scopes').then((rows) => setScopes(rows.map((row) => row.name))).catch(() => undefined)
    api<typeof consents>(`/dashboard/api/consents?client_id=${encodeURIComponent(id)}`).then(setConsents).catch(() => setConsents([]))
  }
  useEffect(() => { load() }, [id, meta.org_enabled])
  useEffect(() => {
    if (!copiedId) return
    const timer = window.setTimeout(() => setCopiedId(false), 1200)
    return () => window.clearTimeout(timer)
  }, [copiedId])

  if (!client) return <Typography.Paragraph style={{ padding: 16 }}>{error || 'Loading…'}</Typography.Paragraph>

  const managed = client.id === meta.management_client_id
  const save = async (values: Record<string, unknown>) => {
    if (managed) return
    const text = (key: string, fallback = '') => (key in values ? String(values[key] ?? '') : fallback)
    const flag = (key: keyof Client) => (key in values ? !!values[key] : !!client[key])
    const body: Client = {
      ...client,
      name: 'name' in values ? String(values.name || client.name) : client.name,
      redirect_uris: 'redirect_uris' in values ? lines(String(values.redirect_uris || '')) : client.redirect_uris,
      post_logout_redirect_uris: 'post_logout_redirect_uris' in values ? lines(String(values.post_logout_redirect_uris || '')) : client.post_logout_redirect_uris,
      grant_types: 'grant_types' in values ? ((values.grant_types as string[]) || []) : client.grant_types,
      scopes: 'scopes' in values ? ((values.scopes as string[]) || []) : client.scopes,
      token_endpoint_auth_method: text('token_endpoint_auth_method', client.token_endpoint_auth_method),
      subject_type: text('subject_type', client.subject_type || ''),
      sector_identifier_uri: text('sector_identifier_uri', client.sector_identifier_uri || ''),
      dpop_bound_access_tokens: flag('dpop_bound_access_tokens'),
      require_pushed_authorization_requests: flag('require_pushed_authorization_requests'),
      skip_consent: flag('skip_consent'),
      dcr_enabled: flag('dcr_enabled'),
      cimd_enabled: flag('cimd_enabled'),
      backchannel_logout_uri: text('backchannel_logout_uri', client.backchannel_logout_uri || ''),
      backchannel_logout_session_required: flag('backchannel_logout_session_required'),
      backchannel_token_delivery_mode: text('backchannel_token_delivery_mode', client.backchannel_token_delivery_mode || ''),
      backchannel_client_notification_endpoint: text('backchannel_client_notification_endpoint', client.backchannel_client_notification_endpoint || ''),
      backchannel_authentication_request_signing_alg: text('backchannel_authentication_request_signing_alg', client.backchannel_authentication_request_signing_alg || ''),
      jwks: text('jwks', client.jwks || ''),
      id_token_encrypted_response_alg: text('id_token_encrypted_response_alg', client.id_token_encrypted_response_alg || ''),
      id_token_encrypted_response_enc: text('id_token_encrypted_response_enc', client.id_token_encrypted_response_enc || ''),
      userinfo_encrypted_response_alg: text('userinfo_encrypted_response_alg', client.userinfo_encrypted_response_alg || ''),
      userinfo_encrypted_response_enc: text('userinfo_encrypted_response_enc', client.userinfo_encrypted_response_enc || ''),
    }
    delete body.secret
    try {
      const next = await api<Client>(`/dashboard/api/clients/${id}`, { method: 'PUT', body: JSON.stringify(body) })
      setClient(next)
      message.success('Saved')
    } catch (err) {
      message.error(errText(err))
    }
  }

  const scopeOptions = [...new Set([...(client.scopes || []), ...scopes])].map((value) => ({ value, label: value }))
  const authMethods = (meta.auth_methods || []).map((value) => ({ value, label: value }))
  const hosted = Boolean(client.signing_kid)
  const createKey = async () => {
    if ((client.jwks || '').trim() && !(await confirmName('create', 'Type create to replace the current key set'))) return
    try {
      const result = await api<{ private_pem: string; client: Client }>(`/dashboard/api/clients/${id}/keys`, { method: 'POST', body: '{}' })
      setClient(result.client)
      if (result.private_pem) showSecret('Signing key', result.private_pem)
      message.success('Signing key created')
    } catch (err) { message.error(errText(err)) }
  }
  const resetSecret = async () => {
    if (!(await confirmName('reset', 'Type reset to replace the client secret'))) return
    try {
      const result = await api<{ secret: string }>(`/dashboard/api/clients/${id}/secret`, { method: 'POST', body: '{}' })
      if (result.secret) showSecret('Client secret', result.secret)
      message.success('Client secret reset')
    } catch (err) { message.error(errText(err)) }
  }
  const rotateKey = async () => {
    if (!(await confirmName('rotate', 'Type rotate to rotate this signing key'))) return
    try {
      const result = await api<{ private_pem: string; client: Client }>(`/dashboard/api/clients/${id}/keys/rotate`, { method: 'POST', body: '{}' })
      setClient(result.client)
      if (result.private_pem) showSecret('Signing key', result.private_pem)
      message.success('Signing key rotated')
    } catch (err) { message.error(errText(err)) }
  }
  return (
    <div className="page-pad org-page">
      <div className="org-head">
        <div className="org-mark"><span>{(client.name || '?').slice(0, 1).toUpperCase()}</span></div>
        <div>
          <h2>{client.name}</h2>
          <button type="button" className="id-copy" title="Click to copy" onClick={() => {
            navigator.clipboard.writeText(client.id).then(() => setCopiedId(true)).catch(() => message.error('Could not copy the client ID'))
          }}>
            <span className="mono">{copiedId ? 'Copied' : client.id}</span>
          </button>
        </div>
      </div>
      {managed && <div className="locked-note">This is the management client from the config file. The dashboard and the CLI sign in with it. It is not edited here.</div>}
      <Tabs items={[
        {
          key: 'overview',
          label: 'Overview',
          children: (
            <>
            <Section title="At a glance">
              <div className="config-subsection">
                <h4>Grants</h4>
                <div className="domain-list">{(client.grant_types || []).length === 0 ? <Typography.Text type="secondary">None</Typography.Text> : client.grant_types.map((grant) => <Tag key={grant} title={grant}>{grantInfo(grant).title}</Tag>)}</div>
              </div>
              <div className="config-subsection">
                <h4>Scopes</h4>
                <div className="domain-list">{(client.scopes || []).length === 0 ? <Typography.Text type="secondary">None</Typography.Text> : client.scopes.map((scope) => <Tag key={scope}>{scope}</Tag>)}</div>
              </div>
              <div className="config-subsection">
                <h4>Redirects</h4>
                <div className="endpoint-list">
                  {(client.redirect_uris || []).length === 0 ? <Typography.Text type="secondary">None</Typography.Text> : client.redirect_uris.map((uri) => <div key={uri} className="mono endpoint-url">{uri}</div>)}
                </div>
              </div>
              <div className="config-subsection">
                <h4>Sign-in</h4>
                <p className="hint">Token endpoint authentication is {client.token_endpoint_auth_method || 'unset'}. Subject type is {client.subject_type || 'public'}.</p>
              </div>
            </Section>
            <Form key={client.updated_at} layout="vertical" disabled={managed} initialValues={{ name: client.name, dcr_enabled: client.dcr_enabled, cimd_enabled: client.cimd_enabled }} onFinish={save}>
              <Section title="Identity">
                <Sub title="Application">
                  <Form.Item name="name" label="Name" rules={[{ required: true }]}><Input /></Form.Item>
                  <Form.Item label="Client ID"><Input className="mono" value={client.id} disabled /></Form.Item>
                  {!managed ? <Button htmlType="button" onClick={() => { void resetSecret() }}>Reset client secret</Button> : null}
                </Sub>
              </Section>
              <Section title="Registration">
                <Sub title="Dynamic">
                  <Flag name="dcr_enabled" label="Dynamic registration enabled" />
                  <Flag name="cimd_enabled" label="CIMD enabled" />
                </Sub>
                <Sub title="Organization">
                  <Form.Item label="Organization">
                    {client.org_id ? <Link to={`/organizations/${client.org_id}`}>{orgName || client.org_id}</Link> : <Input disabled value="Not bound to an organization" />}
                  </Form.Item>
                  <Form.Item label="org_id"><Input className="mono" value={client.org_id || ''} disabled /></Form.Item>
                </Sub>
              </Section>
              <div className="form-actions">
                {!managed && <Button type="primary" htmlType="submit">Save</Button>}
                {!managed && (
                  <Button danger onClick={async () => {
                    if (!(await confirmName(client.name, `Delete ${client.name}?`))) return
                    await api(`/dashboard/api/clients/${client.id}`, { method: 'DELETE' })
                    navigate('/applications')
                  }}>Delete</Button>
                )}
              </div>
            </Form>
            </>
          ),
        },
        {
          key: 'tokens',
          label: 'Tokens',
          children: (
            <Form key={`tokens-${client.updated_at}`} layout="vertical" initialValues={{
              ...client,
              id_token_encrypted_response_alg: client.id_token_encrypted_response_alg || undefined,
              id_token_encrypted_response_enc: client.id_token_encrypted_response_enc || undefined,
              userinfo_encrypted_response_alg: client.userinfo_encrypted_response_alg || undefined,
              userinfo_encrypted_response_enc: client.userinfo_encrypted_response_enc || undefined,
            }} disabled={managed} onFinish={save}>
              <Section title="Authentication">
                <Sub title="Token endpoint">
                  <Form.Item name="token_endpoint_auth_method" label="Token endpoint auth method"><Select options={authMethods} /></Form.Item>
                  <Flag name="dpop_bound_access_tokens" label="DPoP-bound access tokens" />
                  <Flag name="require_pushed_authorization_requests" label="Require pushed authorization requests" />
                </Sub>
              </Section>
              <Section title="Keys">
                <Sub title="Signing key">
                  {hosted && client.jwks_uri ? <div className="span-2"><EndpointRow name="JWKS" url={client.jwks_uri} /></div> : null}
                  {hosted ? <div className="span-2 locked-grid">
                    <div className="locked-field" title="signing_kid"><span className="locked-label">Key id</span><span className="locked-value">{client.signing_kid}</span></div>
                    <div className="locked-field" title="signing_alg"><span className="locked-label">Algorithm</span><span className="locked-value">{client.signing_alg}</span></div>
                  </div> : null}
                  {!managed && !hosted ? <Button htmlType="button" onClick={() => { void createKey() }}>Create signing key</Button> : null}
                  {!managed && hosted ? <Button htmlType="button" onClick={() => { void rotateKey() }}>Rotate signing key</Button> : null}
                  {hosted ? <div className="span-2 locked-note">Atrium stores this keypair. Its public key is one entry in the tenant JWKS keys array. The private key is shown once, when it is created or rotated. The previous public key stays in that array until the retain period ends.</div> : null}
                </Sub>
                <Sub title="JSON Web Key Set">
                  <Form.Item className="span-2" name="jwks"><JwksEditor disabled={managed || hosted} /></Form.Item>
                  {!hosted ? <Form.Item label="jwks_uri"><Input className="mono" value={client.jwks_uri} disabled /></Form.Item> : null}
                </Sub>
                <Sub title="Request objects">
                  <Form.Item label="Request object signing algorithm"><Input value={client.request_object_signing_alg} disabled /></Form.Item>
                </Sub>
              </Section>
              <Section title="Encryption">
                <p className="hint">RSA-OAEP-256 and A256GCM. Leave both empty for a signed token only. Set both, and publish an RSA encryption key.</p>
                <Sub title="ID token">
                  <Form.Item name="id_token_encrypted_response_alg" label="Algorithm">
                    <Select allowClear placeholder="None" style={{ width: '100%' }} options={encAlgOptions(client.id_token_encrypted_response_alg)} />
                  </Form.Item>
                  <Form.Item name="id_token_encrypted_response_enc" label="Encoding">
                    <Select allowClear placeholder="None" style={{ width: '100%' }} options={encEncOptions(client.id_token_encrypted_response_enc)} />
                  </Form.Item>
                </Sub>
                <Sub title="UserInfo">
                  <Form.Item name="userinfo_encrypted_response_alg" label="Algorithm">
                    <Select allowClear placeholder="None" style={{ width: '100%' }} options={encAlgOptions(client.userinfo_encrypted_response_alg)} />
                  </Form.Item>
                  <Form.Item name="userinfo_encrypted_response_enc" label="Encoding">
                    <Select allowClear placeholder="None" style={{ width: '100%' }} options={encEncOptions(client.userinfo_encrypted_response_enc)} />
                  </Form.Item>
                </Sub>
              </Section>
              {!managed && <div className="form-actions"><Button type="primary" htmlType="submit">Save</Button></div>}
            </Form>
          ),
        },
        {
          key: 'endpoints',
          label: 'Endpoints',
          children: (
            <EndpointGroups endpoints={meta.endpoints || {}} />
          ),
        },
        {
          key: 'oauth',
          label: 'OAuth',
          children: (
            <Form key={`oauth-${client.updated_at}`} layout="vertical" initialValues={{
              ...client,
              redirect_uris: joinLines(client.redirect_uris),
              post_logout_redirect_uris: joinLines(client.post_logout_redirect_uris),
              subject_type: client.subject_type || 'public',
              backchannel_token_delivery_mode: client.backchannel_token_delivery_mode || undefined,
              backchannel_authentication_request_signing_alg: client.backchannel_authentication_request_signing_alg || undefined,
            }} disabled={managed} onFinish={save}>
              <Section title="Redirects">
                <Sub title="Authorization">
                  <Form.Item className="span-2" name="redirect_uris" label="Redirect URIs" extra="One per line. Authorization-code clients need at least one."><Input.TextArea autoSize /></Form.Item>
                </Sub>
                <Sub title="Logout">
                  <Form.Item className="span-2" name="post_logout_redirect_uris" label="Post-logout redirect URIs"><Input.TextArea autoSize /></Form.Item>
                </Sub>
              </Section>
              <Section title="Access">
                <Sub title="Grants">
                  <Form.Item className="span-2" name="grant_types" label="Grant types"><GrantMenu options={meta.grant_types || []} disabled={managed} /></Form.Item>
                </Sub>
                <Sub title="Scopes">
                  <Form.Item className="span-2" name="scopes" label="Scopes"><Select mode="tags" options={scopeOptions} /></Form.Item>
                </Sub>
              </Section>
              <Section title="Subject">
                <Sub title="Identifier">
                  <Form.Item name="subject_type" label="Subject type"><Select options={[{ value: 'public' }, { value: 'pairwise' }]} /></Form.Item>
                  <Form.Item name="sector_identifier_uri" label="Sector identifier URI" extra="Pairwise without a sector uses the redirect host."><Input /></Form.Item>
                </Sub>
                <Sub title="Consent">
                  <Flag name="skip_consent" label="Skip consent" />
                </Sub>
              </Section>
              <Section title="Logout">
                <Sub title="Back-channel">
                  <Form.Item name="backchannel_logout_uri" label="Back-channel logout URI"><Input /></Form.Item>
                  <Flag name="backchannel_logout_session_required" label="Back-channel logout session required" />
                </Sub>
              </Section>
              <Section title="CIBA">
                <Sub title="Delivery">
                  <Form.Item name="backchannel_token_delivery_mode" label="Delivery mode" extra="One mode. Ping and push need a notification endpoint.">
                    <Select allowClear placeholder="None" style={{ width: '100%' }} options={withCurrent(['poll', 'ping', 'push'], client.backchannel_token_delivery_mode)} />
                  </Form.Item>
                  <Form.Item name="backchannel_client_notification_endpoint" label="Notification endpoint"><Input /></Form.Item>
                </Sub>
                <Sub title="Signing">
                  <Form.Item name="backchannel_authentication_request_signing_alg" label="Signing algorithm" extra="Leave empty for an unsigned request.">
                    <Select allowClear placeholder="None" style={{ width: '100%' }} options={withCurrent(['RS256', 'ES256'], client.backchannel_authentication_request_signing_alg)} />
                  </Form.Item>
                </Sub>
              </Section>
              {!managed && <div className="form-actions"><Button type="primary" htmlType="submit">Save</Button></div>}
            </Form>
          ),
        },
        {
          key: 'consents',
          label: 'Consents',
          children: (
            <Table
              size="small"
              rowKey={(row) => row.user_id + row.granted_at}
              dataSource={consents}
              pagination={{ pageSize: 20, showTotal: (n) => `${n} consents` }}
              columns={[
                { title: 'User', dataIndex: 'user_id', render: (id: string) => <Link to={`/users/${id}`} className="mono">{id}</Link> },
                { title: 'Scopes', dataIndex: 'scopes', render: (v: string[]) => (v || []).join(' ') },
                { title: 'Granted', dataIndex: 'granted_at' },
                { title: '', render: (_, row) => <Button size="small" onClick={async () => {
                  await api(`/dashboard/api/consents?user_id=${encodeURIComponent(row.user_id)}&client_id=${encodeURIComponent(id)}`, { method: 'DELETE' })
                  load()
                }}>Revoke</Button> },
              ]}
            />
          ),
        },
      ]} />
    </div>
  )
}
