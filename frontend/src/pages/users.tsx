import { useEffect, useMemo, useState } from 'react'
import { Button, Form, Input, Modal, Select, Table, Tabs, Tag, Typography, message } from 'antd'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { api } from '../api'
import { useMeta } from '../App'
import { Flag, Stage, WindowSelect, confirmName, errText } from '../widgets'

function faceColor(name: string) {
  let n = 0
  for (const ch of name) n = (n * 33 + ch.charCodeAt(0)) % 360
  return `hsl(${n} 42% 42%)`
}

type User = {
  id: string
  username: string
  email?: string
  phone_number?: string
  given_name?: string
  family_name?: string
  email_verified?: boolean
  disabled?: boolean
  has_password?: boolean
  migration_pending?: boolean
  last_login_at?: string
  created_at?: string
  attributes?: Record<string, string>
  user_metadata?: Record<string, string>
}

type Bag = { key: string; value: string }
type Grant = { role_id: string; name?: string; org_id?: string; org_name?: string }
type ScopeGrant = { resource: string; scope: string; org_id?: string; org_name?: string }

function OrgName({ org }: { org: { org_id?: string; org_name?: string } }) {
  if (!org.org_id) return <span>All organizations</span>
  return <Link to={`/organizations/${org.org_id}`}>{org.org_name || org.org_id}</Link>
}

function bagToRows(bag?: Record<string, string>): Bag[] {
  return Object.entries(bag || {}).map(([key, value]) => ({ key, value }))
}

function rowsToPatch(rows: Bag[], previous?: Record<string, string>) {
  const out: Record<string, string | null> = {}
  const keep = new Set<string>()
  for (const row of rows) {
    if (!row.key) continue
    out[row.key] = row.value
    keep.add(row.key)
  }
  for (const key of Object.keys(previous || {})) {
    if (!keep.has(key)) out[key] = null
  }
  return out
}

export function Users() {
  const [rows, setRows] = useState<User[]>([])
  const [q, setQ] = useState('')
  const [open, setOpen] = useState(false)
  const load = () => api<User[]>('/dashboard/api/users').then(setRows).catch((err) => message.error(errText(err)))
  useEffect(() => { load() }, [])
  const shown = useMemo(() => rows.filter((row) => `${row.username} ${row.email || ''} ${row.id}`.toLowerCase().includes(q.trim().toLowerCase())), [rows, q])
  return (
    <div>
      <div className="dash-toolbar">
        <Input.Search allowClear placeholder="Search username, email, or id" style={{ width: 320 }} onChange={(e) => setQ(e.target.value)} />
        <div className="spacer" />
        <Button type="primary" onClick={() => setOpen(true)}>Create</Button>
      </div>
      <Stage kicker="People" title={`${shown.length} accounts`} text="People who can sign in. Open an account for sessions, access, and organizations." />
      <div className="directory">
        {shown.length === 0 ? <p className="hint">No accounts match.</p> : shown.map((row) => (
          <Link key={row.id} className="person" to={`/users/${row.id}`}>
            <span className="face" style={{ background: faceColor(row.username) }}>{row.username.slice(0, 1).toUpperCase()}</span>
            <span className="who">
              <strong>{row.username}</strong>
              <span>{row.email || 'No email'}</span>
            </span>
            {row.disabled ? <Tag color="error">disabled</Tag> : row.migration_pending ? <Tag>migration</Tag> : <Tag color="success">active</Tag>}
          </Link>
        ))}
      </div>
      <Modal title="Create user" open={open} onCancel={() => setOpen(false)} footer={null} destroyOnClose>
        <Form layout="vertical" onFinish={async (values: { username: string; password: string; email?: string; given_name?: string; family_name?: string }) => {
          try {
            await api('/dashboard/api/users', { method: 'POST', body: JSON.stringify(values) })
            setOpen(false); load()
          } catch (err) { message.error(errText(err)) }
        }}>
          <Form.Item name="username" label="Username" rules={[{ required: true }]}><Input /></Form.Item>
          <Form.Item name="password" label="Password" rules={[{ required: true }]}><Input.Password /></Form.Item>
          <Form.Item name="email" label="Email"><Input /></Form.Item>
          <Form.Item name="given_name" label="Given name"><Input /></Form.Item>
          <Form.Item name="family_name" label="Family name"><Input /></Form.Item>
          <Button type="primary" htmlType="submit">Create</Button>
        </Form>
      </Modal>
    </div>
  )
}

export function UserDetail() {
  const { id = '' } = useParams()
  const meta = useMeta()
  const navigate = useNavigate()
  const [user, setUser] = useState<User | null>(null)
  const [window, setWindow] = useState('24h')
  const [sessions, setSessions] = useState<Record<string, string>[]>([])
  const [activity, setActivity] = useState<Record<string, unknown>[]>([])
  const [analytics, setAnalytics] = useState<Record<string, unknown> | null>(null)
  const [access, setAccess] = useState<{ roles: Grant[]; scopes: ScopeGrant[] }>({ roles: [], scopes: [] })
  const [roles, setRoles] = useState<{ id: string; name: string }[]>([])
  const [orgChoices, setOrgChoices] = useState<{ id: string; name: string }[]>([])
  const [consents, setConsents] = useState<{ client_id: string; scopes: string[]; granted_at: string }[]>([])
  const [orgs, setOrgs] = useState<{ id: string; name: string; slug: string }[]>([])
  const [mfa, setMfa] = useState(false)
  const [attrs, setAttrs] = useState<Bag[]>([])
  const [metaBag, setMetaBag] = useState<Bag[]>([])

  const load = () => {
    api<User>(`/dashboard/api/users/${id}`).then((row) => { setUser(row); setAttrs(bagToRows(row.attributes)); setMetaBag(bagToRows(row.user_metadata)) }).catch((err) => message.error(errText(err)))
    api<Record<string, string>[]>(`/dashboard/api/users/${id}/sessions`).then(setSessions).catch(() => setSessions([]))
    api<Record<string, unknown>[]>(`/dashboard/api/users/${id}/activity`).then(setActivity).catch(() => setActivity([]))
    api<typeof access>(`/dashboard/api/users/${id}/access`).then(setAccess).catch(() => undefined)
    api<{ id: string; name: string }[]>('/dashboard/api/roles').then(setRoles).catch(() => undefined)
    api<typeof consents>(`/dashboard/api/consents?user_id=${encodeURIComponent(id)}`).then(setConsents).catch(() => setConsents([]))
    api<{ mfa_enabled: boolean }>(`/dashboard/api/users/${id}/mfa/status`).then((row) => setMfa(row.mfa_enabled)).catch(() => undefined)
    if (meta.org_enabled) {
      api<typeof orgs>(`/dashboard/api/users/${id}/organizations`).then(setOrgs).catch(() => setOrgs([]))
      api<{ id: string; name: string }[]>('/dashboard/api/orgs').then(setOrgChoices).catch(() => setOrgChoices([]))
    }
  }
  useEffect(() => { load() }, [id, meta.org_enabled])
  useEffect(() => {
    api<Record<string, unknown>>(`/dashboard/api/users/${id}/login-analytics?window=${window}`).then(setAnalytics).catch(() => setAnalytics(null))
  }, [id, window])

  if (!user) return <Typography.Paragraph style={{ padding: 16 }}>Loading…</Typography.Paragraph>
  const byIP = (analytics?.by_ip as Record<string, unknown>[]) || []
  const byDay = (analytics?.by_day as Record<string, unknown>[]) || []

  return (
    <div className="page-pad">
      <Typography.Title level={4} style={{ marginTop: 0 }}>{user.username}</Typography.Title>
      <Typography.Paragraph type="secondary">
        Attempts {String(analytics?.attempts ?? 0)} · failure rate {analytics ? `${Math.round(Number(analytics.failure_rate) * 1000) / 10}%` : '—'} · new addresses {String(analytics?.new_ips ?? 0)} · MFA attempts {String(analytics?.mfa_attempts ?? 0)}
      </Typography.Paragraph>
      <Tabs items={[
        {
          key: 'profile', label: 'Profile',
          children: (
            <Form layout="vertical" initialValues={user} onFinish={async (values: User) => {
              try {
                const next = await api<User>(`/dashboard/api/users/${id}`, {
                  method: 'PATCH',
                  body: JSON.stringify({
                    email: values.email, phone_number: values.phone_number, given_name: values.given_name, family_name: values.family_name,
                    email_verified: values.email_verified, disabled: values.disabled,
                    attributes: rowsToPatch(attrs, user.attributes),
                    user_metadata: rowsToPatch(metaBag, user.user_metadata),
                  }),
                })
                setUser(next)
                message.success('Saved')
              } catch (err) { message.error(errText(err)) }
            }}>
              <div className="field-row">
                <Form.Item label="Username"><Input value={user.username} disabled /></Form.Item>
                <Form.Item label="User ID"><Input className="mono" value={user.id} readOnly /></Form.Item>
              </div>
              <div className="field-row">
                <Form.Item name="email" label="Email"><Input /></Form.Item>
                <Form.Item name="phone_number" label="Phone"><Input /></Form.Item>
              </div>
              <div className="field-row">
                <Form.Item name="given_name" label="Given name"><Input /></Form.Item>
                <Form.Item name="family_name" label="Family name"><Input /></Form.Item>
              </div>
              <div className="field-row">
                <Flag name="email_verified" label="Email verified" />
                <Flag name="disabled" label="Disabled" />
              </div>
              <BagEditor title="Attributes" rows={attrs} onChange={setAttrs} />
              <BagEditor title="User metadata" rows={metaBag} onChange={setMetaBag} />
              <div className="form-actions">
                <Button type="primary" htmlType="submit">Save</Button>
                <Button danger onClick={async () => {
                  if (!(await confirmName(user.username, `Delete ${user.username}?`))) return
                  await api(`/dashboard/api/users/${id}`, { method: 'DELETE' })
                  navigate('/users')
                }}>Delete</Button>
              </div>
            </Form>
          ),
        },
        {
          key: 'security', label: 'Security',
          children: (
            <div>
              <Form layout="inline" onFinish={async (values: { password: string }) => {
                try {
                  await api(`/dashboard/api/users/${id}/password`, { method: 'POST', body: JSON.stringify(values) })
                  message.success('Password set')
                } catch (err) { message.error(errText(err)) }
              }}>
                <Form.Item name="password" rules={[{ required: true }]}><Input.Password placeholder="New password" /></Form.Item>
                <Button htmlType="submit">Set password</Button>
              </Form>
              <Button style={{ margin: '12px 0' }} onClick={async () => {
                try { await api(`/dashboard/api/users/${id}/password/reset-email`, { method: 'POST', body: '{}' }); message.success('Reset email sent') }
                catch (err) { message.error(errText(err)) }
              }}>Send reset email</Button>
              <Typography.Paragraph>MFA on this server is {meta.mfa_enabled ? 'enabled' : 'off'} (<Typography.Text code>security.mfa.enabled</Typography.Text>). This user is {mfa ? 'enrolled' : 'not enrolled'}.</Typography.Paragraph>
              {meta.mfa_enabled && !mfa && <Button onClick={async () => {
                const result = await api<{ secret: string; qr_base64?: string }>(`/dashboard/api/users/${id}/mfa/enable`, { method: 'POST', body: '{}' })
                Modal.info({ title: 'Authenticator secret', width: 480, content: <div><p>Copy the secret. It is shown once.</p><Input.TextArea value={result.secret} readOnly />{result.qr_base64 && <img alt="QR" src={result.qr_base64.startsWith('data:') ? result.qr_base64 : `data:image/png;base64,${result.qr_base64}`} />}</div> })
              }}>Enable MFA</Button>}
              {meta.mfa_enabled && !mfa && (
                <Form layout="inline" style={{ marginTop: 12 }} onFinish={async (values: { code: string }) => {
                  try { await api(`/dashboard/api/users/${id}/mfa/verify`, { method: 'POST', body: JSON.stringify(values) }); setMfa(true); message.success('MFA confirmed') }
                  catch (err) { message.error(errText(err)) }
                }}>
                  <Form.Item name="code" rules={[{ required: true }]}><Input placeholder="Code" /></Form.Item>
                  <Button htmlType="submit">Verify</Button>
                </Form>
              )}
              {mfa && <Button danger style={{ marginLeft: 8 }} onClick={async () => {
                if (!(await confirmName(user.username, 'Disable MFA?'))) return
                await api(`/dashboard/api/users/${id}/mfa/disable`, { method: 'POST', body: '{}' })
                setMfa(false)
              }}>Disable MFA</Button>}
            </div>
          ),
        },
        {
          key: 'sessions', label: 'Sessions',
          children: (
            <Table size="small" rowKey="id" dataSource={sessions} pagination={{ pageSize: 20, showTotal: (n) => `${n} sessions` }}
              columns={[
                { title: 'Created', dataIndex: 'created_at' },
                { title: 'Expires', dataIndex: 'expires_at' },
                { title: 'IP', dataIndex: 'ip' },
                { title: 'User agent', dataIndex: 'user_agent' },
                { title: 'MFA', dataIndex: 'mfa_verified', render: (v: boolean) => v ? 'yes' : 'no' },
                { title: '', render: (_, row) => <Button size="small" onClick={async () => {
                  await api(`/dashboard/api/users/${id}/sessions/${row.id}`, { method: 'DELETE' }); load()
                }}>Revoke</Button> },
              ]}
            />
          ),
        },
        {
          key: 'access', label: 'Access',
          children: (
            <div>
              <Typography.Paragraph type="secondary">The role list cannot grant <Typography.Text code>management</Typography.Text>.</Typography.Paragraph>
              <Form layout="inline" onFinish={async (values: { role_id: string; org_id?: string }) => {
                try { await api(`/dashboard/api/users/${id}/roles`, { method: 'POST', body: JSON.stringify(values) }); load() }
                catch (err) { message.error(errText(err)) }
              }}>
                <Form.Item name="role_id" rules={[{ required: true }]}><Select style={{ width: 200 }} placeholder="Role" options={roles.map((role) => ({ value: role.id, label: role.name }))} /></Form.Item>
                {meta.org_enabled && <Form.Item name="org_id"><Select allowClear style={{ width: 240 }} placeholder="All organizations" options={orgChoices.map((org) => ({ value: org.id, label: org.name }))} /></Form.Item>}
                <Button htmlType="submit">Assign role</Button>
              </Form>
              <Table style={{ marginTop: 12 }} size="small" rowKey={(row) => row.role_id + (row.org_id || '')} dataSource={access.roles} pagination={false}
                columns={[
                  { title: 'Role', dataIndex: 'name' },
                  ...(meta.org_enabled ? [{ title: 'Organization', render: (_: unknown, row: Grant) => <OrgName org={row} /> }] : []),
                  { title: '', render: (_, row) => <Button size="small" onClick={async () => {
                    await api(`/dashboard/api/users/${id}/roles`, { method: 'DELETE', body: JSON.stringify({ role_id: row.role_id, org_id: row.org_id || '' }) })
                    load()
                  }}>Remove</Button> },
                ]}
              />
              <Form layout="inline" style={{ marginTop: 16 }} onFinish={async (values: { resource: string; scope: string; org_id?: string }) => {
                if (values.scope === 'management') { message.error('management cannot be granted'); return }
                try { await api(`/dashboard/api/users/${id}/scopes`, { method: 'POST', body: JSON.stringify(values) }); load() }
                catch (err) { message.error(errText(err)) }
              }}>
                <Form.Item name="resource" rules={[{ required: true }]}><Input placeholder="Resource" /></Form.Item>
                <Form.Item name="scope" rules={[{ required: true }]}><Input placeholder="Scope" /></Form.Item>
                {meta.org_enabled && <Form.Item name="org_id"><Select allowClear style={{ width: 240 }} placeholder="All organizations" options={orgChoices.map((org) => ({ value: org.id, label: org.name }))} /></Form.Item>}
                <Button htmlType="submit">Assign scope</Button>
              </Form>
              <Table style={{ marginTop: 12 }} size="small" rowKey={(row) => row.resource + row.scope + (row.org_id || '')} dataSource={access.scopes} pagination={false}
                columns={[
                  { title: 'Resource', dataIndex: 'resource' },
                  { title: 'Scope', dataIndex: 'scope' },
                  ...(meta.org_enabled ? [{ title: 'Organization', render: (_: unknown, row: ScopeGrant) => <OrgName org={row} /> }] : []),
                  { title: '', render: (_, row) => <Button size="small" onClick={async () => {
                    await api(`/dashboard/api/users/${id}/scopes`, { method: 'DELETE', body: JSON.stringify(row) }); load()
                  }}>Remove</Button> },
                ]}
              />
            </div>
          ),
        },
        {
          key: 'consents', label: 'Consents',
          children: (
            <Table size="small" rowKey="client_id" dataSource={consents} pagination={{ pageSize: 20 }}
              columns={[
                { title: 'Application', dataIndex: 'client_id', render: (cid: string) => <Link to={`/applications/${cid}`} className="mono">{cid}</Link> },
                { title: 'Scopes', dataIndex: 'scopes', render: (v: string[]) => (v || []).join(' ') },
                { title: 'Granted', dataIndex: 'granted_at' },
                { title: '', render: (_, row) => <Button size="small" onClick={async () => {
                  await api(`/dashboard/api/consents?user_id=${encodeURIComponent(id)}&client_id=${encodeURIComponent(row.client_id)}`, { method: 'DELETE' }); load()
                }}>Revoke</Button> },
              ]}
            />
          ),
        },
        {
          key: 'activity', label: 'Activity',
          children: (
            <div>
              <WindowSelect value={window} onChange={setWindow} />
              <Typography.Title level={5}>Events</Typography.Title>
              <Table size="small" rowKey="id" dataSource={activity} pagination={{ pageSize: 20 }}
                columns={[
                  { title: 'Time', dataIndex: 'created_at' },
                  { title: 'Success', dataIndex: 'success', render: (v: boolean) => v ? 'yes' : 'no' },
                  { title: 'MFA', dataIndex: 'mfa', render: (v: boolean) => v ? 'yes' : 'no' },
                  { title: 'IP', dataIndex: 'ip' },
                  { title: 'User agent', dataIndex: 'user_agent' },
                ]}
              />
              <Typography.Title level={5}>Addresses</Typography.Title>
              <Table size="small" rowKey="ip" dataSource={byIP} pagination={false}
                columns={['ip', 'attempts', 'successes', 'failures', 'last_seen', 'new'].map((key) => ({ title: key, dataIndex: key }))} />
              <Typography.Title level={5}>Days</Typography.Title>
              <Table size="small" rowKey="date" dataSource={byDay} pagination={false}
                columns={['date', 'successes', 'failures'].map((key) => ({ title: key, dataIndex: key }))} />
            </div>
          ),
        },
        ...(meta.org_enabled ? [{
          key: 'orgs', label: 'Organizations',
          children: (
            <div>
              <Typography.Paragraph type="secondary">Membership role is not on this list. Add a member from the organization page.</Typography.Paragraph>
              <Table size="small" rowKey="id" dataSource={orgs} pagination={false}
                columns={[
                  { title: 'Name', dataIndex: 'name', render: (name: string, row: { id: string }) => <Link to={`/organizations/${row.id}`}>{name}</Link> },
                  { title: 'Organization ID', dataIndex: 'id', render: (value: string) => <span className="mono">{value}</span> },
                  { title: 'Slug', dataIndex: 'slug' },
                ]}
              />
            </div>
          ),
        }] : []),
      ]} />
    </div>
  )
}

function BagEditor({ title, rows, onChange }: { title: string; rows: Bag[]; onChange: (rows: Bag[]) => void }) {
  return (
    <div style={{ marginBottom: 12 }}>
      <Typography.Text strong>{title}</Typography.Text>
      {rows.map((row, index) => (
        <div key={index} className="bag-row">
          <Input placeholder="Key" value={row.key} onChange={(e) => onChange(rows.map((item, i) => i === index ? { ...item, key: e.target.value } : item))} />
          <Input placeholder="Value" value={row.value} onChange={(e) => onChange(rows.map((item, i) => i === index ? { ...item, value: e.target.value } : item))} />
          <Button onClick={() => onChange(rows.filter((_, i) => i !== index))}>Remove</Button>
        </div>
      ))}
      <Button style={{ marginTop: 8 }} onClick={() => onChange([...rows, { key: '', value: '' }])}>Add key</Button>
    </div>
  )
}
