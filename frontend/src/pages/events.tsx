import { useEffect, useState } from 'react'
import { Button, Descriptions, Drawer, Form, Input, Modal, Segmented, Select, Table, Tabs, Typography, message } from 'antd'
import { api } from '../api'
import { useMeta } from '../App'
import { Flag, PageHead, WindowSelect, confirmName, errText, showSecret } from '../widgets'

type Audit = {
  id?: string
  created_at: string
  actor_type: string
  actor_id: string
  action: string
  target_type?: string
  target_id?: string
  ip?: string
  user_agent?: string
  metadata?: Record<string, unknown>
}
type Analytics = {
  attempts: number
  successes: number
  failures: number
  failure_rate: number
  by_ip: Record<string, unknown>[]
  by_day: Record<string, unknown>[]
}
type Hook = { id: string; url: string; events: string[]; enabled: boolean; description?: string; secret?: string }
type CIBA = { auth_req_id: string; client_id: string; user_id?: string; status: string; expires_at: string; binding_message?: string; user_code?: string }

export function Events() {
  const meta = useMeta()
  const [view, setView] = useState('Audit')
  const [range, setRange] = useState('24h')
  const [action, setAction] = useState('')
  const [actor, setActor] = useState('')
  const [audit, setAudit] = useState<Audit[]>([])
  const [selected, setSelected] = useState<Audit | null>(null)
  const [stats, setStats] = useState<Analytics | null>(null)
  const [hooks, setHooks] = useState<Hook[]>([])
  const [ciba, setCiba] = useState<CIBA[]>([])
  const [hook, setHook] = useState<Hook | null>(null)

  const loadAudit = () => {
    const q = new URLSearchParams({ window: range })
    if (action) q.set('action', action)
    if (actor) q.set('actor_id', actor)
    api<Audit[]>(`/dashboard/api/audit?${q}`).then(setAudit).catch((err) => message.error(errText(err)))
  }
  useEffect(() => { if (view === 'Audit') loadAudit() }, [view, range])
  useEffect(() => {
    if (view === 'Addresses' || view === 'Days') {
      api<Analytics>(`/dashboard/api/analytics/logins?window=${range}`).then(setStats).catch((err) => message.error(errText(err)))
    }
    if (view === 'Webhooks') api<Hook[]>('/dashboard/api/webhooks').then(setHooks).catch((err) => message.error(errText(err)))
    if (view === 'CIBA') api<CIBA[]>('/dashboard/api/ciba/pending').then(setCiba).catch(() => setCiba([]))
  }, [view, range])

  const options = ['Audit', 'Addresses', 'Days', 'Webhooks', 'CIBA']
  return (
    <div className="console">
      <PageHead title="Events" text="Audit records, sign-in addresses, webhooks, and pending sign-in requests." extra={<span style={{ display: 'flex', gap: 8 }}><Segmented options={options} value={view} onChange={(value) => setView(String(value))} />{(view === 'Audit' || view === 'Addresses' || view === 'Days') && <WindowSelect value={range} onChange={setRange} />}</span>} />
      {view === 'Audit' && (
        <div className="explorer">
          <aside className="filter-col">
            <Typography.Text type="secondary">Action</Typography.Text>
            <Input value={action} onChange={(e) => setAction(e.target.value)} style={{ margin: '6px 0 12px' }} />
            <Typography.Text type="secondary">Actor id</Typography.Text>
            <Input value={actor} onChange={(e) => setActor(e.target.value)} style={{ margin: '6px 0 12px' }} />
            <Button type="primary" onClick={loadAudit}>Run</Button>
          </aside>
          <div className="main">
            <Table size="small" rowKey={(row) => row.id || `${row.created_at}-${row.action}-${row.target_id}`}
              dataSource={audit} pagination={{ pageSize: 20, showTotal: (n) => `${n} events` }}
              onRow={(row) => ({ onClick: () => setSelected(row) })}
              columns={[
                { title: 'Time', dataIndex: 'created_at', render: (v: string) => <span className="mono">{v}</span> },
                { title: 'Actor type', dataIndex: 'actor_type' },
                { title: 'Actor', dataIndex: 'actor_id', render: (v: string) => <span className="mono">{v}</span> },
                { title: 'Action', dataIndex: 'action' },
                { title: 'Target type', dataIndex: 'target_type' },
                { title: 'Target', dataIndex: 'target_id', render: (v?: string) => <span className="mono">{v}</span> },
                { title: 'IP', dataIndex: 'ip' },
              ]}
            />
          </div>
        </div>
      )}
      {(view === 'Addresses' || view === 'Days') && stats && (
        <div className="page-pad">
          <div className="stat-strip">
            <div className="stat"><b>{stats.attempts}</b><span>Attempts</span></div>
            <div className="stat"><b>{stats.successes}</b><span>Successes</span></div>
            <div className="stat"><b>{stats.failures}</b><span>Failures</span></div>
            <div className="stat"><b>{Math.round(stats.failure_rate * 1000) / 10}%</b><span>Failure rate</span></div>
          </div>
          <Typography.Paragraph type="secondary">Sign-in rows are not stored per application, so this view cannot filter by client.</Typography.Paragraph>
          {view === 'Addresses' && <Table size="small" rowKey="ip" dataSource={stats.by_ip} pagination={{ pageSize: 20, showTotal: (n) => `${n} addresses` }}
            columns={['ip', 'attempts', 'successes', 'failures', 'users', 'last_seen', 'new'].map((key) => ({ title: key, dataIndex: key }))} />}
          {view === 'Days' && <Table size="small" rowKey="date" dataSource={stats.by_day} pagination={{ pageSize: 20, showTotal: (n) => `${n} days` }}
            columns={['date', 'successes', 'failures'].map((key) => ({ title: key, dataIndex: key }))} />}
        </div>
      )}
      {view === 'Webhooks' && (
        <div className="page-pad">
          <Button type="primary" onClick={() => setHook({ id: '', url: '', events: [], enabled: true })}>Create</Button>
          <Table style={{ marginTop: 12 }} size="small" rowKey="id" dataSource={hooks} pagination={{ pageSize: 20, showTotal: (n) => `${n} webhooks` }}
            columns={[
              { title: 'URL', dataIndex: 'url', render: (url: string, row) => <Button type="link" onClick={() => setHook(row)}>{url}</Button> },
              { title: 'Events', dataIndex: 'events', render: (v: string[]) => (v || []).join(', ') },
              { title: 'Enabled', dataIndex: 'enabled', render: (v: boolean) => v ? 'yes' : 'no' },
              { title: 'Description', dataIndex: 'description' },
            ]}
          />
          <Drawer title={hook?.id ? 'Webhook' : 'Create webhook'} width={440} open={!!hook} onClose={() => setHook(null)}>
            {hook && (
              <Form layout="vertical" initialValues={{ ...hook, events: hook.events || [] }} onFinish={async (values: Hook) => {
                try {
                  const path = hook.id ? `/dashboard/api/webhooks/${hook.id}` : '/dashboard/api/webhooks'
                  const saved = await api<Hook>(path, { method: hook.id ? 'PATCH' : 'POST', body: JSON.stringify({ ...values, enabled: values.enabled }) })
                  if (!hook.id && saved.secret) showSecret('Webhook secret', saved.secret)
                  setHook(null)
                  api<Hook[]>('/dashboard/api/webhooks').then(setHooks)
                } catch (err) { message.error(errText(err)) }
              }}>
                <Form.Item name="url" label="URL" rules={[{ required: true }]}><Input /></Form.Item>
                <Form.Item name="description" label="Description"><Input /></Form.Item>
                <Flag name="enabled" label="Enabled" />
                <Form.Item name="events" label="Events"><Select mode="multiple" options={[...meta.webhook_events, '*'].map((value) => ({ value, label: value }))} /></Form.Item>
                {!hook.id && <Form.Item name="secret" label="Secret"><Input.Password /></Form.Item>}
                {hook.id && <Form.Item name="secret" label="Secret" extra="Leave blank to keep the saved secret."><Input.Password /></Form.Item>}
                <Button type="primary" htmlType="submit">Save</Button>
                {hook.id && <Button style={{ marginLeft: 8 }} onClick={async () => {
                  try {
                    const result = await api<{ status: string }>(`/dashboard/api/webhooks/${hook.id}/test`, { method: 'POST', body: '{}' })
                    message.success(result.status || 'Delivered')
                  } catch (err) { message.error(errText(err)) }
                }}>Test</Button>}
                {hook.id && <Button danger style={{ marginLeft: 8 }} onClick={async () => {
                  if (!(await confirmName(hook.url, 'Delete webhook?'))) return
                  await api(`/dashboard/api/webhooks/${hook.id}`, { method: 'DELETE' })
                  setHook(null)
                  api<Hook[]>('/dashboard/api/webhooks').then(setHooks)
                }}>Delete</Button>}
              </Form>
            )}
          </Drawer>
        </div>
      )}
      {view === 'CIBA' && (
        <Table size="small" rowKey="auth_req_id" dataSource={ciba} pagination={{ pageSize: 20, showTotal: (n) => `${n} pending` }}
          columns={[
            { title: 'Request', dataIndex: 'auth_req_id', render: (v: string) => <span className="mono">{v}</span> },
            { title: 'Client', dataIndex: 'client_id' },
            { title: 'User', dataIndex: 'user_id' },
            { title: 'Status', dataIndex: 'status' },
            { title: 'Expires', dataIndex: 'expires_at' },
            { title: 'Binding', dataIndex: 'binding_message' },
            { title: 'User code', dataIndex: 'user_code' },
            { title: '', render: (_, row) => (
              <>
                <Button size="small" onClick={async () => {
                  const userID = row.user_id || window.prompt('User id') || ''
                  if (!userID) return
                  try {
                    await api(`/dashboard/api/ciba/${row.auth_req_id}/approve`, { method: 'POST', body: JSON.stringify({ user_id: userID }) })
                    api<CIBA[]>('/dashboard/api/ciba/pending').then(setCiba)
                  } catch (err) { message.error(errText(err)) }
                }}>Approve</Button>
                <Button size="small" style={{ marginLeft: 8 }} onClick={async () => {
                  let reason = ''
                  Modal.confirm({
                    title: 'Deny request',
                    content: <Input placeholder="Reason" onChange={(e) => { reason = e.target.value }} />,
                    onOk: async () => {
                      await api(`/dashboard/api/ciba/${row.auth_req_id}/deny`, { method: 'POST', body: JSON.stringify({ reason }) })
                      api<CIBA[]>('/dashboard/api/ciba/pending').then(setCiba)
                    },
                  })
                }}>Deny</Button>
              </>
            ) },
          ]}
        />
      )}
      <Drawer title="Audit" width={440} open={!!selected} onClose={() => setSelected(null)}>
        {selected && (
          <Tabs items={[
            { key: 'pretty', label: 'Pretty', children: (
              <Descriptions column={1} size="small">
                <Descriptions.Item label="Time">{selected.created_at}</Descriptions.Item>
                <Descriptions.Item label="Actor">{selected.actor_type} {selected.actor_id}</Descriptions.Item>
                <Descriptions.Item label="Action">{selected.action}</Descriptions.Item>
                <Descriptions.Item label="Target">{selected.target_type} {selected.target_id}</Descriptions.Item>
                <Descriptions.Item label="IP">{selected.ip}</Descriptions.Item>
                <Descriptions.Item label="User agent">{selected.user_agent}</Descriptions.Item>
                {Object.entries(selected.metadata || {}).map(([key, value]) => (
                  <Descriptions.Item key={key} label={key}>{typeof value === 'string' ? value : JSON.stringify(value)}</Descriptions.Item>
                ))}
              </Descriptions>
            ) },
            { key: 'json', label: 'JSON', children: <pre className="mono">{JSON.stringify(selected, null, 2)}</pre> },
          ]} />
        )}
      </Drawer>
    </div>
  )
}
