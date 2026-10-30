import { useEffect, useState } from 'react'
import { Button, Form, Input, Modal, Select, Table, Typography, message } from 'antd'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { api } from '../api'
import { Stage, confirmName, errText } from '../widgets'

type Role = { id: string; name: string; description?: string; scopes?: { resource: string; scope: string }[] }
type Resource = { uri: string; name: string; scopes?: string[] }

export function Roles() {
  const [rows, setRows] = useState<Role[]>([])
  const [open, setOpen] = useState(false)
  const load = () => api<Role[]>('/dashboard/api/roles').then(setRows).catch((err) => message.error(errText(err)))
  useEffect(() => { load() }, [])
  return (
    <div className="sheet">
      <Stage
        kicker="Access"
        title={`${rows.length} roles`}
        text="A role is a bundle of scopes. Assign one from a person's account."
        extra={<Button type="primary" onClick={() => setOpen(true)}>Create</Button>}
      />
      <Table size="small" rowKey="id" dataSource={rows} pagination={{ pageSize: 20, showTotal: (n) => `${n} roles` }}
        columns={[
          { title: 'Name', dataIndex: 'name', width: 220, render: (name: string, row) => <Link to={`/roles/${row.id}`}>{name}</Link> },
          { title: 'Description', dataIndex: 'description' },
          { title: 'Scopes', width: 120, render: (_, row) => (row.scopes || []).length },
        ]}
      />
      <Modal title="Create role" open={open} onCancel={() => setOpen(false)} footer={null} destroyOnClose>
        <Form layout="vertical" onFinish={async (values: { name: string; description?: string }) => {
          try {
            await api('/dashboard/api/roles', { method: 'POST', body: JSON.stringify(values) })
            setOpen(false); load()
          } catch (err) { message.error(errText(err)) }
        }}>
          <Form.Item name="name" label="Name" rules={[{ required: true }]}><Input /></Form.Item>
          <Form.Item name="description" label="Description"><Input /></Form.Item>
          <Button type="primary" htmlType="submit">Create</Button>
        </Form>
      </Modal>
    </div>
  )
}

export function RoleDetail() {
  const { id = '' } = useParams()
  const navigate = useNavigate()
  const [role, setRole] = useState<Role | null>(null)
  const [resources, setResources] = useState<Resource[]>([])
  const [scopes, setScopes] = useState<{ resource: string; scope: string }[]>([])
  useEffect(() => {
    api<Role>(`/dashboard/api/roles/${id}`).then((row) => { setRole(row); setScopes(row.scopes || []) }).catch((err) => message.error(errText(err)))
    api<Resource[]>('/dashboard/api/resources').then(setResources).catch(() => undefined)
  }, [id])
  if (!role) return <Typography.Paragraph style={{ padding: 16 }}>Loading…</Typography.Paragraph>
  const choices = resources.flatMap((resource) => (resource.scopes || []).filter((scope) => scope !== 'management').map((scope) => ({
    value: `${resource.uri} ${scope}`,
    label: `${resource.name}: ${scope}`,
    resource: resource.uri,
    scope,
  })))
  return (
    <div className="page-pad org-page">
      <div className="org-head">
        <div className="org-mark"><span>{(role.name || '?').slice(0, 1).toUpperCase()}</span></div>
        <div>
          <h2>{role.name}</h2>
          <span className="mono">{role.description || 'No description'}</span>
        </div>
      </div>
      <div className="config-section">
        <h3>Profile</h3>
        <Form layout="vertical" initialValues={role} onFinish={async (values: { name?: string; description?: string }) => {
          try {
            const next = await api<Role>(`/dashboard/api/roles/${id}`, { method: 'PATCH', body: JSON.stringify(values) })
            setRole({ ...next, scopes })
            message.success('Saved')
          } catch (err) { message.error(errText(err)) }
        }}>
          <div className="field-row">
            <Form.Item name="name" label="Name" rules={[{ required: true }]}><Input /></Form.Item>
            <Form.Item name="description" label="Description"><Input /></Form.Item>
          </div>
          <div className="form-actions">
            <Button type="primary" htmlType="submit">Save profile</Button>
            <Button danger onClick={async () => {
              if (!(await confirmName(role.name, `Delete ${role.name}?`))) return
              await api(`/dashboard/api/roles/${id}`, { method: 'DELETE' })
              navigate('/roles')
            }}>Delete</Button>
          </div>
        </Form>
      </div>
      <div className="config-section">
        <h3>Scopes</h3>
        <p className="hint">Saving replaces the role's scopes. It does not append. Users who hold the role are not listed.</p>
        <Select
          mode="multiple"
          style={{ width: '100%', marginTop: 12 }}
          value={scopes.map((item) => `${item.resource} ${item.scope}`)}
          options={choices}
          onChange={(values: string[]) => setScopes(values.map((value) => {
            const found = choices.find((item) => item.value === value)
            return found ? { resource: found.resource, scope: found.scope } : { resource: value, scope: '' }
          }).filter((item) => item.scope && item.scope !== 'management'))}
        />
        <div className="form-actions">
          <Button type="primary" onClick={async () => {
            try {
              const next = await api<Role>(`/dashboard/api/roles/${id}/scopes`, { method: 'PUT', body: JSON.stringify({ scopes }) })
              setRole(next); setScopes(next.scopes || [])
              message.success('Scopes replaced')
            } catch (err) { message.error(errText(err)) }
          }}>Save scopes</Button>
        </div>
      </div>
    </div>
  )
}
