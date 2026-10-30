import { useEffect, useMemo, useState } from 'react'
import { Button, Form, Input, Modal, Select, Table, Tabs, Tag, Typography, message } from 'antd'
import { Link, useNavigate, useSearchParams } from 'react-router-dom'
import { STANDARD_SCOPES, api } from '../api'
import { confirmName, errText } from '../widgets'

type Resource = { uri: string; name: string; description?: string; scopes?: string[] }
type Scope = { name: string; description?: string; resource_server?: string; is_default?: boolean }

export function Resources() {
  const [rows, setRows] = useState<Resource[]>([])
  const [q, setQ] = useState('')
  const [open, setOpen] = useState(false)
  const load = () => api<Resource[]>('/dashboard/api/resources').then(setRows).catch((err) => message.error(errText(err)))
  useEffect(() => { load() }, [])
  const shown = useMemo(() => rows.filter((row) => `${row.name} ${row.uri}`.toLowerCase().includes(q.trim().toLowerCase())), [rows, q])
  return (
    <div>
      <Tabs style={{ padding: '0 16px' }} items={[
        { key: 'resources', label: <Link to="/resources">Resources</Link> },
        { key: 'scopes', label: <Link to="/scopes">Scopes</Link> },
      ]} activeKey="resources" />
      <div className="dash-toolbar">
        <Input.Search allowClear placeholder="Search name or URI" style={{ width: 280 }} onChange={(e) => setQ(e.target.value)} />
        <div className="spacer" />
        <Button type="primary" onClick={() => setOpen(true)}>Create</Button>
      </div>
      <Table
        size="small" rowKey="uri" dataSource={shown}
        pagination={{ pageSize: 20, showTotal: (n) => `${n} resources` }}
        columns={[
          { title: 'Name', dataIndex: 'name', render: (name: string, row) => <Link to={`/resources/detail?uri=${encodeURIComponent(row.uri)}`}>{name}</Link> },
          { title: 'URI', dataIndex: 'uri', render: (v: string) => <span className="mono">{v}</span> },
          { title: 'Scopes', render: (_, row) => (row.scopes || []).length },
        ]}
      />
      <Modal title="Create resource" open={open} onCancel={() => setOpen(false)} footer={null} destroyOnClose>
        <Form layout="vertical" onFinish={async (values: Resource) => {
          try {
            await api('/dashboard/api/resources', { method: 'POST', body: JSON.stringify(values) })
            setOpen(false)
            load()
          } catch (err) { message.error(errText(err)) }
        }}>
          <Form.Item name="name" label="Name" rules={[{ required: true }]}><Input /></Form.Item>
          <Form.Item name="uri" label="URI" rules={[{ required: true }]} extra="The URI is the id and stays fixed."><Input /></Form.Item>
          <Form.Item name="description" label="Description"><Input /></Form.Item>
          <Form.Item name="scopes" label="Scopes"><Select mode="tags" /></Form.Item>
          <Button type="primary" htmlType="submit">Create</Button>
        </Form>
      </Modal>
    </div>
  )
}

export function ResourceDetail() {
  const [params] = useSearchParams()
  const uri = params.get('uri') || ''
  const navigate = useNavigate()
  const [row, setRow] = useState<Resource | null>(null)
  useEffect(() => {
    api<Resource>(`/dashboard/api/resource?uri=${encodeURIComponent(uri)}`).then(setRow).catch((err) => message.error(errText(err)))
  }, [uri])
  if (!row) return <Typography.Paragraph style={{ padding: 16 }}>Loading…</Typography.Paragraph>
  return (
    <div className="page-pad">
      <Typography.Title level={4}>{row.name}</Typography.Title>
      <Form layout="vertical" initialValues={row} onFinish={async (values: Resource) => {
        try {
          const next = await api<Resource>(`/dashboard/api/resource?uri=${encodeURIComponent(uri)}`, {
            method: 'PUT', body: JSON.stringify({ name: values.name, description: values.description || '', scopes: values.scopes || [] }),
          })
          setRow(next)
          message.success('Saved')
        } catch (err) { message.error(errText(err)) }
      }}>
        <Form.Item label="URI"><Input className="mono" value={uri} disabled /></Form.Item>
        <Form.Item name="name" label="Name" rules={[{ required: true }]}><Input /></Form.Item>
        <Form.Item name="description" label="Description"><Input /></Form.Item>
        <Form.Item name="scopes" label="Scopes"><Select mode="tags" /></Form.Item>
        <Button type="primary" htmlType="submit">Save</Button>
        <Button danger style={{ marginLeft: 8 }} onClick={async () => {
          if (!(await confirmName(row.name, `Delete ${row.name}?`))) return
          await api(`/dashboard/api/resource?uri=${encodeURIComponent(uri)}`, { method: 'DELETE' })
          navigate('/resources')
        }}>Delete</Button>
      </Form>
    </div>
  )
}

export function Scopes() {
  const [rows, setRows] = useState<Scope[]>([])
  const [q, setQ] = useState('')
  const [open, setOpen] = useState(false)
  const load = () => api<Scope[]>('/dashboard/api/scopes').then(setRows).catch((err) => message.error(errText(err)))
  useEffect(() => { load() }, [])
  const shown = useMemo(() => rows.filter((row) => row.name.toLowerCase().includes(q.trim().toLowerCase())), [rows, q])
  return (
    <div>
      <Tabs style={{ padding: '0 16px' }} items={[
        { key: 'resources', label: <Link to="/resources">Resources</Link> },
        { key: 'scopes', label: <Link to="/scopes">Scopes</Link> },
      ]} activeKey="scopes" />
      <div className="dash-toolbar">
        <Input.Search allowClear placeholder="Search scope" style={{ width: 240 }} onChange={(e) => setQ(e.target.value)} />
        <div className="spacer" />
        <Button type="primary" onClick={() => setOpen(true)}>Create</Button>
      </div>
      <Table
        size="small" rowKey="name" dataSource={shown}
        pagination={{ pageSize: 20, showTotal: (n) => `${n} scopes` }}
        columns={[
          { title: 'Name', dataIndex: 'name', render: (name: string) => <span>{name} {STANDARD_SCOPES.includes(name) && <Tag>standard</Tag>} {name === 'management' && <Tag>management</Tag>}</span> },
          { title: 'Description', dataIndex: 'description' },
          { title: 'Resource', dataIndex: 'resource_server' },
          { title: 'Default', dataIndex: 'is_default', render: (v: boolean) => v ? 'yes' : '' },
          { title: '', render: (_, row) => row.name === 'management' ? null : <Button size="small" danger onClick={async () => {
            if (!(await confirmName(row.name, `Delete ${row.name}?`))) return
            try { await api(`/dashboard/api/scopes/${encodeURIComponent(row.name)}`, { method: 'DELETE' }); load() }
            catch (err) { message.error(errText(err)) }
          }}>Delete</Button> },
        ]}
      />
      <Modal title="Create scope" open={open} onCancel={() => setOpen(false)} footer={null} destroyOnClose>
        <Form layout="vertical" onFinish={async (values: Scope) => {
          try {
            await api('/dashboard/api/scopes', { method: 'POST', body: JSON.stringify(values) })
            setOpen(false); load()
          } catch (err) { message.error(errText(err)) }
        }}>
          <Form.Item name="name" label="Name" rules={[{ required: true }]}><Input /></Form.Item>
          <Form.Item name="description" label="Description"><Input /></Form.Item>
          <Form.Item name="resource_server" label="Resource server"><Input /></Form.Item>
          <Button type="primary" htmlType="submit">Create</Button>
        </Form>
      </Modal>
    </div>
  )
}
