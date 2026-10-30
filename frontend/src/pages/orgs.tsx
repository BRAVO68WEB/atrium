import { useEffect, useState, type ReactNode } from 'react'
import { Button, Form, Input, Modal, Select, Tag, Typography, message } from 'antd'
import { Link, useParams } from 'react-router-dom'
import { api } from '../api'
import { useMeta } from '../App'
import { PageHead, errText } from '../widgets'

function faceColor(name: string) {
  let n = 0
  for (const ch of name) n = (n * 33 + ch.charCodeAt(0)) % 360
  return `hsl(${n} 42% 42%)`
}

type Org = { id: string; name: string; slug: string; logo_url?: string; domains?: string[]; created_at?: string }
type Member = { user_id: string; username: string; email?: string; given_name?: string; family_name?: string; role: string }

function memberName(member: Member) {
  const person = [member.given_name, member.family_name].filter(Boolean).join(' ')
  return person || member.username
}

export function Organizations() {
  const [rows, setRows] = useState<Org[]>([])
  const [open, setOpen] = useState(false)
  const load = () => api<Org[]>('/dashboard/api/orgs').then(setRows).catch((err) => message.error(errText(err)))
  useEffect(() => { load() }, [])
  return (
    <div className="console">
      <PageHead title="Organizations" text="Members, email domains, and the applications that belong with them." extra={<Button type="primary" onClick={() => setOpen(true)}>Create organization</Button>} />
      <div className="roster">
        {rows.length === 0 ? <p className="hint" style={{ padding: 16 }}>No organizations yet.</p> : rows.map((row) => (
          <Link key={row.id} className="roster-row" to={`/organizations/${row.id}`}>
            {row.logo_url ? <img className="face" src={row.logo_url} alt="" /> : <span className="face" style={{ background: faceColor(row.name) }}>{row.name.slice(0, 1).toUpperCase()}</span>}
            <span>
              <strong>{row.name}</strong>
              <span className="sub">{row.slug}</span>
            </span>
            <span className="mono">{row.id}</span>
            <span className="chips">{(row.domains || []).slice(0, 2).map((domain) => <Tag key={domain}>{domain}</Tag>)}</span>
          </Link>
        ))}
      </div>
      <Modal title="Create organization" open={open} onCancel={() => setOpen(false)} footer={null} destroyOnClose>
        <Form layout="vertical" onFinish={async (values: { name: string; slug: string; domains?: string; logo_url?: string }) => {
          try {
            await api('/dashboard/api/orgs', { method: 'POST', body: JSON.stringify({
              name: values.name, slug: values.slug, logo_url: values.logo_url,
              domains: (values.domains || '').split(/[,\s]+/).map((d) => d.trim()).filter(Boolean),
            }) })
            setOpen(false); load()
          } catch (err) { message.error(errText(err)) }
        }}>
          <Form.Item name="name" label="Name" rules={[{ required: true }]}><Input /></Form.Item>
          <Form.Item name="slug" label="Slug" rules={[{ required: true }]}><Input /></Form.Item>
          <Form.Item name="domains" label="Domains" extra="Separated by spaces or commas."><Input /></Form.Item>
          <Form.Item name="logo_url" label="Logo URL" extra="Absolute http or https URL. Empty keeps the letter avatar."><Input /></Form.Item>
          <Button type="primary" htmlType="submit">Create</Button>
        </Form>
      </Modal>
    </div>
  )
}

function Panel({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div className="config-section">
      <h3>{title}</h3>
      {children}
    </div>
  )
}

export function OrganizationDetail() {
  const { id = '' } = useParams()
  const meta = useMeta()
  const [org, setOrg] = useState<Org | null>(null)
  const [members, setMembers] = useState<Member[]>([])
  const [domainForm] = Form.useForm()
  const [memberForm] = Form.useForm()
  const load = () => {
    api<Org>(`/dashboard/api/orgs/${id}`).then(setOrg).catch((err) => message.error(errText(err)))
    api<Member[]>(`/dashboard/api/orgs/${id}/members`).then(setMembers).catch((err) => message.error(errText(err)))
  }
  useEffect(() => { load() }, [id])
  if (!org) return <Typography.Paragraph style={{ padding: 16 }}>Loading…</Typography.Paragraph>
  const domains = org.domains || []
  return (
    <div className="page-pad org-page">
      <Link className="back-link" to="/organizations">Organizations</Link>
      <div className="org-head">
        <div className="org-mark">
          {org.logo_url ? <img src={org.logo_url} alt="" /> : <span>{(org.name || '?').slice(0, 1).toUpperCase()}</span>}
        </div>
        <div>
          <h2>{org.name}</h2>
          <span className="mono">{org.slug}</span>
        </div>
      </div>
      <Panel title="Profile">
        <Form
          key={`${org.name}\0${org.slug}\0${org.logo_url || ''}`}
          layout="vertical"
          initialValues={{ name: org.name, slug: org.slug, logo_url: org.logo_url || '' }}
          onFinish={async (values: { name: string; slug: string; logo_url?: string }) => {
            try {
              const next = await api<Org>(`/dashboard/api/orgs/${id}`, {
                method: 'PATCH',
                body: JSON.stringify({ name: values.name, slug: values.slug, logo_url: values.logo_url || '' }),
              })
              setOrg(next)
              message.success('Saved')
            } catch (err) { message.error(errText(err)) }
          }}
        >
          <div className="field-row">
            <Form.Item name="name" label="Name" rules={[{ required: true }]}><Input /></Form.Item>
            <Form.Item label="Organization ID"><Input className="mono" value={org.id} readOnly /></Form.Item>
          </div>
          <div className="field-row">
            <Form.Item name="slug" label="Slug" rules={[{ required: true }]} extra="Lowercase letters, numbers, and hyphens."><Input className="mono" /></Form.Item>
            <Form.Item name="logo_url" label="Logo URL" extra="Absolute http or https URL. Leave blank for the letter mark."><Input placeholder="https://" /></Form.Item>
          </div>
          <Button type="primary" htmlType="submit">Save</Button>
        </Form>
      </Panel>
      <Panel title="Domains">
        <div className="domain-list">
          {domains.length === 0 ? <Typography.Text type="secondary">No domains yet.</Typography.Text> : domains.map((domain) => <Tag key={domain}>{domain}</Tag>)}
        </div>
        <p className="hint">Domains can be added. Removing one is not available from this page.</p>
        {meta.org_autolookup && <p className="hint">Domain autolookup is on. A member whose email domain matches is selected when a non-interactive request omits organization.</p>}
        <Form form={domainForm} layout="vertical" onFinish={async (values: { domain: string }) => {
          try {
            setOrg(await api<Org>(`/dashboard/api/orgs/${id}/domains`, { method: 'POST', body: JSON.stringify(values) }))
            domainForm.resetFields()
            message.success('Domain added')
          } catch (err) { message.error(errText(err)) }
        }}>
          <div className="field-row">
            <Form.Item name="domain" label="Domain" rules={[{ required: true }]}><Input placeholder="example.com" /></Form.Item>
            <Form.Item label=" ">
              <Button htmlType="submit">Add domain</Button>
            </Form.Item>
          </div>
        </Form>
      </Panel>
      <Panel title="Members">
        <div className="member-list">
          {members.length === 0 ? <Typography.Text type="secondary">No members yet.</Typography.Text> : members.map((member) => (
            <Link key={member.user_id} to={`/users/${member.user_id}`} className="member-row">
              <span className="org-mark sm">{memberName(member).slice(0, 1).toUpperCase()}</span>
              <span className="member-who">
                <strong>{memberName(member)}</strong>
                <span>{[member.username !== memberName(member) ? member.username : '', member.email].filter(Boolean).join(' · ') || member.user_id}</span>
              </span>
              <Tag>{member.role === 'admin' ? 'Admin' : 'Member'}</Tag>
            </Link>
          ))}
        </div>
        <Form form={memberForm} layout="vertical" initialValues={{ role: 'member' }} onFinish={async (values: { user_id: string; role: string }) => {
          try {
            await api(`/dashboard/api/orgs/${id}/members`, { method: 'POST', body: JSON.stringify(values) })
            memberForm.resetFields(['user_id'])
            const next = await api<Member[]>(`/dashboard/api/orgs/${id}/members`)
            setMembers(next)
            message.success('Member added')
          } catch (err) { message.error(errText(err)) }
        }}>
          <div className="field-row">
            <Form.Item name="user_id" label="User ID" rules={[{ required: true }]}><Input className="mono" placeholder="User id" /></Form.Item>
            <Form.Item name="role" label="Role"><Select options={[{ value: 'member', label: 'Member' }, { value: 'admin', label: 'Admin' }]} /></Form.Item>
          </div>
          <Button htmlType="submit">Add member</Button>
        </Form>
      </Panel>
    </div>
  )
}
