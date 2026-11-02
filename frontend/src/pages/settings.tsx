import { useEffect, useState, type ReactNode } from 'react'
import { Button, Collapse, Form, Input, InputNumber, Select, Typography, message } from 'antd'
import { Link } from 'react-router-dom'
import { Restart, api } from '../api'
import { useMeta, useRestart } from '../App'
import { Flag, confirmName, errText } from '../widgets'

type Doc = Record<string, any>

const oidcKeys = [
  'supported_scopes',
  'supported_claims',
  'supported_grant_types',
  'supported_auth_methods',
  'claim_mappings',
  'key_rotation_interval',
  'key_retain',
]

const securityKeys = [
  'access_token_lifetime',
  'refresh_token_lifetime',
  'authorization_code_lifetime',
  'device_code_lifetime',
  'ciba_request_lifetime',
  'request_uri_lifetime',
  'reset_token_lifetime',
  'session_lifetime',
  'require_pkce',
  'allow_plain_pkce',
  'access_token_format',
  'issuer',
  'oob_helper',
]

function pick(source: Doc | undefined, keys: string[]) {
  const out: Doc = {}
  if (!source) return out
  for (const key of keys) {
    if (source[key] !== undefined) out[key] = source[key]
  }
  return out
}

export function Settings() {
  const askRestart = useRestart()
  const [cfg, setCfg] = useState<Doc | null>(null)
  useEffect(() => { api<Doc>('/dashboard/api/config').then(setCfg).catch((err) => message.error(errText(err))) }, [])
  if (!cfg) return <Typography.Paragraph style={{ padding: 16 }}>Loading…</Typography.Paragraph>
  return (
    <div className="page-pad">
      <Typography.Paragraph type="secondary">
        Save writes {cfg.path}. Issuer, lifetimes, protocol, key rotation, and feature switches are the settings you change here. Branding and sign-in stay on the Sign-in page. Runtime is what the server, this console, and the CLI read from the file.
      </Typography.Paragraph>
      <Form layout="vertical" initialValues={cfg} onFinish={async (values: Doc) => {
        const security = pick(values.security, securityKeys)
        if (values.security?.dpop) security.dpop = values.security.dpop
        if (values.security?.mtls) security.mtls = values.security.mtls
        const oidc = pick(values.oidc, oidcKeys)
        if (security.issuer !== undefined) oidc.issuer = security.issuer
        const body = {
          org: pick(values.org, ['enabled', 'enabled_domain_based_autolookup']),
          push: pick(values.push, ['enabled']),
          aauth: pick(values.aauth, ['enabled', 'resource_mode']),
          xaa: pick(values.xaa, ['enabled']),
          oidc,
          security,
        }
        try {
          askRestart(await api<Restart>('/dashboard/api/config', { method: 'PUT', body: JSON.stringify(body) }))
          message.success('Config file updated')
        } catch (err) { message.error(errText(err)) }
      }}>
        <Collapse destroyOnHidden={false} items={[
          { key: 'issuer', label: 'Issuer', children: <Issuer /> },
          { key: 'life', label: 'Lifetimes', children: <Lifetimes /> },
          { key: 'proto', label: 'Protocol', children: <Protocol /> },
          { key: 'keys', label: 'Signing keys', children: <Keys cfg={cfg} /> },
          { key: 'features', label: 'Features', children: <Features /> },
          { key: 'process', label: 'Runtime', children: <Runtime cfg={cfg} /> },
        ]} />
        <Button type="primary" htmlType="submit" style={{ marginTop: 16 }}>Save settings</Button>
      </Form>
    </div>
  )
}

function text(name: (string | number)[], label: string, extra?: string) {
  return <Form.Item name={name} label={label} extra={extra}><Input /></Form.Item>
}

function duration(name: string) {
  return text(['security', name], `security.${name}`, 'Go duration, such as 1h or 30m.')
}

function Issuer() {
  return (
    <>
      <Section title="Issuer">
        {text(['security', 'issuer'], 'security.issuer', 'Tokens, discovery, and the header use this URL.')}
      </Section>
      <Section title="Access tokens">
        <Form.Item name={['security', 'access_token_format']} label="security.access_token_format">
          <Select options={[{ value: 'opaque' }, { value: 'jwt' }]} />
        </Form.Item>
      </Section>
      <Section title="Discovery">
        <Form.Item name={['oidc', 'supported_scopes']} label="oidc.supported_scopes"><Select mode="tags" /></Form.Item>
        <Form.Item name={['oidc', 'supported_claims']} label="oidc.supported_claims"><Select mode="tags" /></Form.Item>
        <Form.Item name={['oidc', 'supported_grant_types']} label="oidc.supported_grant_types"><Select mode="tags" /></Form.Item>
        <Form.Item name={['oidc', 'supported_auth_methods']} label="oidc.supported_auth_methods"><Select mode="tags" /></Form.Item>
      </Section>
      <Section title="Claim mappings">
        <Form.List name={['oidc', 'claim_mappings']}>
          {(fields, { add, remove }) => (
            <>
              {fields.map((field) => (
                <div key={field.key} className="claim-row">
                  <Form.Item name={[field.name, 'claim']}><Input placeholder="claim" /></Form.Item>
                  <Form.Item name={[field.name, 'source']}><Input placeholder="source" /></Form.Item>
                  <Form.Item name={[field.name, 'scopes']}><Select mode="tags" placeholder="scopes" style={{ minWidth: 160 }} /></Form.Item>
                  <Button onClick={() => remove(field.name)}>Remove</Button>
                </div>
              ))}
              <Button onClick={() => add({ claim: '', source: '', scopes: [] })}>Add claim mapping</Button>
            </>
          )}
        </Form.List>
      </Section>
    </>
  )
}

function Lifetimes() {
  return (
    <>
      <Section title="Tokens">
        {duration('access_token_lifetime')}
        {duration('refresh_token_lifetime')}
      </Section>
      <Section title="Codes">
        {duration('authorization_code_lifetime')}
        {duration('device_code_lifetime')}
        {duration('ciba_request_lifetime')}
        {duration('request_uri_lifetime')}
      </Section>
      <Section title="Account">
        {duration('reset_token_lifetime')}
        {duration('session_lifetime')}
      </Section>
    </>
  )
}

function Protocol() {
  return (
    <>
      <Section title="PKCE">
        <Flag name={['security', 'require_pkce']} label="security.require_pkce" />
        <Flag name={['security', 'allow_plain_pkce']} label="security.allow_plain_pkce" />
      </Section>
      <Section title="Out of band">
        <Flag name={['security', 'oob_helper']} label="security.oob_helper" />
      </Section>
      <Section title="DPoP">
        <Flag name={['security', 'dpop', 'enabled']} label="security.dpop.enabled" />
        <Flag name={['security', 'dpop', 'nonce_required']} label="security.dpop.nonce_required" />
        <Form.Item name={['security', 'dpop', 'proof_lifetime']} label="security.dpop.proof_lifetime"><InputNumber /></Form.Item>
        <Form.Item name={['security', 'dpop', 'nonce_lifetime']} label="security.dpop.nonce_lifetime"><InputNumber /></Form.Item>
      </Section>
      <Section title="mTLS">
        <Flag name={['security', 'mtls', 'enabled']} label="security.mtls.enabled" />
        <Flag name={['security', 'mtls', 'cert_binding']} label="security.mtls.cert_binding" />
        <Flag name={['security', 'mtls', 'bind_refresh_token']} label="security.mtls.bind_refresh_token" />
        <Flag name={['security', 'mtls', 'require_for_token']} label="security.mtls.require_for_token" />
      </Section>
    </>
  )
}

type TenantKey = {
  kid: string
  alg: string
  kty: string
  status: string
  created_at?: string
  retire_at?: string
  client_id?: string
}

function keyState(key: TenantKey) {
  if (key.status === 'active') return 'Active'
  if (key.status === 'retiring' && key.retire_at) return `Public until ${new Date(key.retire_at).toLocaleString()}`
  return 'Expired'
}

function Keys({ cfg }: { cfg: Doc }) {
  const meta = useMeta()
  const [keys, setKeys] = useState<TenantKey[]>([])
  const loadKeys = () => {
    api<{ keys: TenantKey[] }>('/dashboard/api/keys').then((result) => setKeys(result.keys || [])).catch((err) => message.error(errText(err)))
  }
  useEffect(() => { loadKeys() }, [])
  const jwks = meta.endpoints?.jwks || (meta.issuer ? `${meta.issuer.replace(/\/$/, '')}/oidc/jwks` : '')
  return (
    <>
      <Section title="JWKS">
        {jwks ? <div className="span-2"><CopyURL name="JWKS" url={jwks} /></div> : null}
        <div className="span-2 grant-menu">
          {keys.length === 0 ? <p className="jwks-empty">No signing keys yet.</p> : keys.map((key) => (
            <div key={key.kid} className={key.status === 'active' ? 'grant-row on' : 'grant-row'}>
              <div className="grant-pick" style={{ cursor: 'default' }}>
                <span className="grant-check" aria-hidden="true">{key.status === 'active' ? '✓' : ''}</span>
                <span>
                  <strong>{key.alg} · {key.kty}</strong>
                  <span className="grant-id mono">{key.kid}</span>
                  <span className="grant-text">
                    {keyState(key)}
                    {key.client_id ? <> · <Link to={`/applications/${key.client_id}`}>{key.client_id}</Link></> : ' · Tenant'}
                  </span>
                </span>
              </div>
            </div>
          ))}
        </div>
        <Button htmlType="button" onClick={async () => {
          if (!(await confirmName('rotate', 'Type rotate to rotate the tenant signing keys'))) return
          try {
            await api('/dashboard/api/keys/rotate', { method: 'POST', body: '{}' })
            loadKeys()
            message.success('Tenant signing keys rotated')
          } catch (err) { message.error(errText(err)) }
        }}>Rotate tenant keys</Button>
      </Section>
      <div className="locked-note">Every public signing key is in that JWKS keys array. Rotate replaces the active tenant RSA and EC keys. Application keys are created and rotated on the application. The previous public keys stay until the retain period ends. Private keys stay on the server.</div>
      <Section title="Rotation">
        {text(['oidc', 'key_rotation_interval'], 'oidc.key_rotation_interval')}
        {text(['oidc', 'key_retain'], 'oidc.key_retain')}
      </Section>
      <Section title="Stored secrets" mode="read">
        {fact('Config signing key', secretOf(cfg.oidc?.signing_key_set), 'oidc.signing_key')}
        {fact('Pairwise salt', secretOf(cfg.oidc?.pairwise_salt_set), 'oidc.pairwise_salt')}
      </Section>
    </>
  )
}

function CopyURL({ name, url }: { name: string; url: string }) {
  const [copied, setCopied] = useState(false)
  useEffect(() => {
    if (!copied) return
    const timer = window.setTimeout(() => setCopied(false), 1200)
    return () => window.clearTimeout(timer)
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

function Features() {
  return (
    <>
      <Section title="Organizations">
        <Flag name={['org', 'enabled']} label="org.enabled" />
        <Flag name={['org', 'enabled_domain_based_autolookup']} label="org.enabled_domain_based_autolookup" />
      </Section>
      <Section title="Push">
        <Flag name={['push', 'enabled']} label="push.enabled" />
      </Section>
      <Section title="Agent authorization">
        <Flag name={['aauth', 'enabled']} label="aauth.enabled" />
        {text(['aauth', 'resource_mode'], 'aauth.resource_mode')}
      </Section>
      <Section title="Cross-app access">
        <Flag name={['xaa', 'enabled']} label="xaa.enabled" />
      </Section>
    </>
  )
}

function Runtime({ cfg }: { cfg: Doc }) {
  const server = cfg.server || {}
  const tls = server.tls || {}
  const database = cfg.database || {}
  const redis = cfg.redis || {}
  const queue = cfg.queue || {}
  const notify = cfg.notify || {}
  const rabbit = notify.rabbitmq || {}
  const telemetry = cfg.telemetry || {}
  const dashboard = cfg.dashboard || {}
  const management = cfg.management || {}
  const security = cfg.security || {}
  return (
    <>
      <div className="locked-note">The dashboard and the CLI read this wiring. Change it in the config file, then restart. Secrets are not shown.</div>
      <Section title="Listen" mode="read">
        {fact('Address', address(server.host, server.port), 'server.host')}
        {fact('TLS', onOff(tls.enabled), 'server.tls.enabled')}
        {fact('Client authentication', textOf(tls.client_auth), 'server.tls.client_auth')}
        {fact('Certificate', textOf(tls.cert_file), 'server.tls.cert_file')}
        {fact('Private key', textOf(tls.key_file), 'server.tls.key_file')}
        {fact('Client CA', textOf(tls.client_ca), 'server.tls.client_ca')}
        {fact('CRL', textOf(tls.crl_file), 'server.tls.crl_file')}
      </Section>
      <Section title="Database" mode="read">
        {fact('Driver', textOf(database.driver), 'database.driver')}
        {fact('File', textOf(database.path), 'database.path')}
        {fact('Connection', secretOf(database.dsn_set), 'database.dsn')}
        {fact('Migrations', onOff(database.migrations), 'database.migrations')}
      </Section>
      <Section title="Redis" mode="read">
        {fact('Address', textOf(redis.addr), 'redis.addr')}
        {fact('Username', textOf(redis.username), 'redis.username')}
        {fact('Password', secretOf(redis.password_set), 'redis.password')}
        {fact('Database', textOf(redis.db), 'redis.db')}
        {fact('Prefix', textOf(redis.prefix), 'redis.prefix')}
      </Section>
      <Section title="Cache" mode="read">
        {fact('Provider', textOf(cfg.cache?.provider), 'cache.provider')}
      </Section>
      <Section title="Queue" mode="read">
        {fact('Type', textOf(queue.type), 'queue.type')}
        {fact('Poll interval', textOf(queue.poll_interval), 'queue.poll_interval')}
        {fact('Max pending', textOf(queue.max_pending), 'queue.max_pending')}
      </Section>
      <Section title="Notifications" mode="read">
        {fact('Type', textOf(notify.type), 'notify.type')}
        {fact('Exchange', textOf(rabbit.exchange), 'notify.rabbitmq.exchange')}
        {fact('Queue', textOf(rabbit.queue), 'notify.rabbitmq.queue')}
        {fact('Broker', secretOf(rabbit.url_set), 'notify.rabbitmq.url')}
      </Section>
      <Section title="Logging" mode="read">
        {fact('Format', textOf(cfg.log?.format), 'log.format')}
      </Section>
      <Section title="Telemetry" mode="read">
        {fact('Traces', onOff(telemetry.enabled), 'telemetry.enabled')}
        {fact('Service name', textOf(telemetry.service_name), 'telemetry.service_name')}
        {fact('Collector', textOf(telemetry.otlp_endpoint), 'telemetry.otlp_endpoint')}
        {fact('Insecure', onOff(telemetry.insecure), 'telemetry.insecure')}
        {fact('Sample ratio', textOf(telemetry.sample_ratio), 'telemetry.sample_ratio')}
      </Section>
      <Section title="Console" mode="read">
        {fact('Dashboard', onOff(dashboard.enabled), 'dashboard.enabled')}
        {fact('Session', textOf(dashboard.session_lifetime), 'dashboard.session_lifetime')}
        {fact('Management client', textOf(management.client_id), 'management.client_id')}
        {fact('Management secret', secretOf(management.client_secret_set), 'management.client_secret')}
        {fact('Debug pages', onOff(cfg.debug?.ui), 'debug.ui')}
      </Section>
      <Section title="Files and keys" mode="read">
        {fact('Hash algorithm file', textOf(security.hash_algo), 'security.hash_algo')}
        {fact('Data key', secretOf(security.data_key_set), 'security.data_key')}
      </Section>
    </>
  )
}

function Section({ title, children, mode = 'edit' }: { title: string; children: ReactNode; mode?: 'edit' | 'read' }) {
  return (
    <div className="config-section">
      <h3>{title}</h3>
      <div className={mode === 'read' ? 'locked-grid' : 'field-grid'}>{children}</div>
    </div>
  )
}

function address(host: unknown, port: unknown) {
  const name = textOf(host)
  if (port === undefined || port === null || port === '') return name
  if (name === '—') return String(port)
  return `${name}:${port}`
}

function textOf(value: unknown) {
  if (value === undefined || value === null || value === '') return '—'
  return String(value)
}

function onOff(value: unknown) {
  return value ? 'Enabled' : 'Off'
}

function secretOf(set: unknown) {
  return set ? 'Set' : 'Not set'
}

function fact(label: string, value: string, key: string) {
  return (
    <div className="locked-field" title={key} data-config-key={key}>
      <span className="locked-label">{label}</span>
      <span className="locked-value">{value}</span>
    </div>
  )
}
