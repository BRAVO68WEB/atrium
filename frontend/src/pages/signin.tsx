import { useEffect, useState, type ReactNode } from 'react'
import { Button, Collapse, Form, Input, InputNumber, Select, Typography, message } from 'antd'
import { api, Restart } from '../api'
import { useRestart } from '../App'
import { Flag, errText } from '../widgets'

type Doc = Record<string, any>

export function SignInSettings() {
  const askRestart = useRestart()
  const [cfg, setCfg] = useState<Doc | null>(null)
  useEffect(() => { api<Doc>('/dashboard/api/config').then(setCfg).catch((err) => message.error(errText(err))) }, [])
  if (!cfg) return <Typography.Paragraph style={{ padding: 16 }}>Loading…</Typography.Paragraph>
  return (
    <div className="page-pad">
      <Typography.Paragraph type="secondary">These values are saved into the config file. The process keeps using the previous values until it restarts. Leave a secret blank to keep the saved one.</Typography.Paragraph>
      <Form layout="vertical" initialValues={cfg} onFinish={async (values: Doc) => {
        const body = {
          branding: values.branding,
          security: {
            login_identifier: values.security?.login_identifier,
            identifier_first: values.security?.identifier_first,
            disable_passwords: values.security?.disable_passwords,
            passwordless_mode: values.security?.passwordless_mode,
            disable_registration: values.security?.disable_registration,
            disable_social_registration: values.security?.disable_social_registration,
            password: values.security?.password,
            mfa: values.security?.mfa,
            bot_protection: {
              provider: values.security?.bot_protection?.provider,
              site_key: values.security?.bot_protection?.site_key,
              secret_key: values.security?.bot_protection?.secret_key,
            },
          },
          smtp: values.smtp,
          email: values.email,
          social: values.social,
        }
        try {
          askRestart(await api<Restart>('/dashboard/api/config', { method: 'PUT', body: JSON.stringify(body) }))
          message.success('Config file updated')
        } catch (err) { message.error(errText(err)) }
      }}>
        <Collapse defaultActiveKey={['branding', 'identifiers']} items={[
          { key: 'branding', label: 'Branding', children: <Branding /> },
          { key: 'identifiers', label: 'Identifiers', children: <Identifiers /> },
          { key: 'password', label: 'Password policy', children: <Password /> },
          { key: 'mfa', label: 'MFA', children: <MFA /> },
          { key: 'social', label: 'Social providers', children: <Social /> },
          { key: 'bot', label: 'Bot protection', children: <Bot /> },
          { key: 'email', label: 'Email', children: <Email /> },
        ]} />
        <Button type="primary" htmlType="submit" style={{ marginTop: 16 }}>Save sign-in settings</Button>
      </Form>
    </div>
  )
}

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div className="config-section">
      <h3>{title}</h3>
      {children}
    </div>
  )
}

function Sub({ title, children, cols = 2 }: { title: string; children: ReactNode; cols?: 2 | 3 }) {
  return (
    <div className="config-subsection">
      <h4>{title}</h4>
      <div className={cols === 3 ? 'field-grid cols-3' : 'field-grid'}>{children}</div>
    </div>
  )
}

function brand(name: string, extra?: string) {
  return <Form.Item name={['branding', name]} label={`branding.${name}`} extra={extra}><Input /></Form.Item>
}

function Branding() {
  return (
    <>
      <Section title="Product">
        <Sub title="Name">
          {brand('product_name')}
          {brand('login_title')}
        </Sub>
        <Sub title="Form labels">
          {brand('username_label')}
          {brand('password_label')}
          {brand('submit_label')}
          <div className="field-break" />
          <Flag name={['branding', 'show_register']} label="branding.show_register" />
          <Flag name={['branding', 'show_forgot_password']} label="branding.show_forgot_password" />
        </Sub>
      </Section>
      <Section title="Appearance">
        <Sub title="Colors">
          {brand('primary_color')}
          {brand('background_color', 'Empty uses the page default.')}
          {brand('text_color', 'Empty uses the page default.')}
        </Sub>
        <Sub title="Footer">
          {brand('footer_text')}
          {brand('support_url')}
          {brand('privacy_url')}
          {brand('terms_url')}
        </Sub>
      </Section>
      <Section title="Files">
        <Sub title="Directories">
          {brand('assets_dir')}
          {brand('templates', 'HTML files here replace a page by file name after a restart.')}
        </Sub>
        <Sub title="Images">
          {brand('logo_file')}
          {brand('favicon_file')}
          {brand('background_file')}
        </Sub>
      </Section>
    </>
  )
}

function Identifiers() {
  return (
    <>
      <Section title="Login">
        <Sub title="Identifier">
          <Form.Item name={['security', 'login_identifier']} label="security.login_identifier" extra="username or email. The password grant field stays username.">
            <Select options={[{ value: 'username' }, { value: 'email' }]} />
          </Form.Item>
          <Flag name={['security', 'identifier_first']} label="security.identifier_first" />
        </Sub>
        <Sub title="Passwordless">
          <Flag name={['security', 'disable_passwords']} label="security.disable_passwords" />
          <Form.Item name={['security', 'passwordless_mode']} label="security.passwordless_mode" extra="otp or link. Used when passwords are disabled.">
            <Select options={[{ value: 'otp' }, { value: 'link' }]} />
          </Form.Item>
        </Sub>
      </Section>
      <Section title="Registration">
        <Sub title="Accounts">
          <Flag name={['security', 'disable_registration']} label="security.disable_registration" />
          <Flag name={['security', 'disable_social_registration']} label="security.disable_social_registration" />
        </Sub>
      </Section>
    </>
  )
}

function Password() {
  return (
    <Section title="Policy">
      <Sub title="Length">
        <Form.Item name={['security', 'password', 'min_length']} label="security.password.min_length"><InputNumber /></Form.Item>
        <Form.Item name={['security', 'password', 'max_length']} label="security.password.max_length"><InputNumber /></Form.Item>
      </Sub>
      <Sub title="Characters">
        <Flag name={['security', 'password', 'require_uppercase']} label="security.password.require_uppercase" />
        <Flag name={['security', 'password', 'require_lowercase']} label="security.password.require_lowercase" />
        <Flag name={['security', 'password', 'require_number']} label="security.password.require_number" />
        <Flag name={['security', 'password', 'require_symbol']} label="security.password.require_symbol" />
        <Flag name={['security', 'password', 'block_username']} label="security.password.block_username" />
      </Sub>
    </Section>
  )
}

function MFA() {
  return (
    <Section title="Authenticator">
      <Sub title="Enrollment">
        <Flag name={['security', 'mfa', 'enabled']} label="security.mfa.enabled" />
        <Flag name={['security', 'mfa', 'required']} label="security.mfa.required" />
      </Sub>
      <Sub title="Codes">
        <Form.Item name={['security', 'mfa', 'issuer']} label="security.mfa.issuer"><Input /></Form.Item>
        <Form.Item name={['security', 'mfa', 'digits']} label="security.mfa.digits"><InputNumber /></Form.Item>
        <Form.Item name={['security', 'mfa', 'period']} label="security.mfa.period" extra="TOTP step, in seconds."><InputNumber /></Form.Item>
      </Sub>
    </Section>
  )
}

type ProviderPreset = {
  id?: string
  name?: string
  client_id?: string
  issuer?: string
  authorization_endpoint?: string
  token_endpoint?: string
  userinfo_endpoint?: string
  scopes?: string
  subject_field?: string
  email_field?: string
  username_field?: string
  email_verified_field?: string
}

const providerPresets: Record<string, ProviderPreset> = {
  google: {
    id: 'google', name: 'Google', client_id: '1234567890-abc.apps.googleusercontent.com',
    issuer: 'https://accounts.google.com', scopes: 'openid email profile',
    subject_field: 'sub', email_field: 'email', email_verified_field: 'email_verified',
  },
  github: {
    id: 'github', name: 'GitHub', client_id: 'GitHub OAuth App client ID',
    authorization_endpoint: 'https://github.com/login/oauth/authorize',
    token_endpoint: 'https://github.com/login/oauth/access_token',
    userinfo_endpoint: 'https://api.github.com/user',
    scopes: 'read:user user:email', subject_field: 'id', email_field: 'email', username_field: 'login',
  },
  gitlab: {
    id: 'gitlab', name: 'GitLab', client_id: 'GitLab application ID',
    issuer: 'https://gitlab.com',
    authorization_endpoint: 'https://gitlab.com/oauth/authorize',
    token_endpoint: 'https://gitlab.com/oauth/token',
    userinfo_endpoint: 'https://gitlab.com/oauth/userinfo',
    scopes: 'openid profile email', subject_field: 'sub', email_field: 'email',
    username_field: 'preferred_username', email_verified_field: 'email_verified',
  },
  facebook: {
    id: 'facebook', name: 'Facebook', client_id: 'Facebook app ID',
    authorization_endpoint: 'https://www.facebook.com/v19.0/dialog/oauth',
    token_endpoint: 'https://graph.facebook.com/v19.0/oauth/access_token',
    userinfo_endpoint: 'https://graph.facebook.com/v19.0/me?fields=id,name,email',
    scopes: 'email public_profile', subject_field: 'id', email_field: 'email', username_field: 'name',
  },
  oidc: {
    client_id: 'Client ID from the provider', issuer: 'https://issuer.example.com',
    scopes: 'openid email profile', subject_field: 'sub', email_field: 'email',
    username_field: 'preferred_username', email_verified_field: 'email_verified',
  },
  oauth2: {
    client_id: 'OAuth client ID', scopes: 'openid email',
    subject_field: 'sub', email_field: 'email', username_field: 'preferred_username', email_verified_field: 'email_verified',
  },
}

const providerTypes = ['google', 'github', 'gitlab', 'facebook', 'oidc', 'oauth2']

function ProviderCard({ field, remove }: { field: { name: number; key: number }; remove: (name: number) => void }) {
  const form = Form.useFormInstance()
  const kind = (Form.useWatch(['social', 'providers', field.name, 'type']) as string) || 'oidc'
  const preset = providerPresets[kind] || {}
  const [fetching, setFetching] = useState(false)
  const path = (key: string) => ['social', 'providers', field.name, key] as (string | number)[]
  async function fetchIssuer() {
    const issuer = String(form.getFieldValue(path('issuer')) || '').trim()
    if (!issuer) {
      message.error('Enter the issuer URL first')
      return
    }
    setFetching(true)
    try {
      const doc = await api<{ issuer?: string; authorization_endpoint: string; token_endpoint: string; userinfo_endpoint?: string }>('/dashboard/api/social/discover', {
        method: 'POST', body: JSON.stringify({ issuer }),
      })
      if (doc.issuer) form.setFieldValue(path('issuer'), doc.issuer)
      form.setFieldValue(path('authorization_endpoint'), doc.authorization_endpoint)
      form.setFieldValue(path('token_endpoint'), doc.token_endpoint)
      form.setFieldValue(path('userinfo_endpoint'), doc.userinfo_endpoint || '')
      message.success('Fetched OpenID configuration')
    } catch (err) {
      message.error(errText(err))
    } finally {
      setFetching(false)
    }
  }
  return (
    <div className="provider-card">
      <Sub title="Identity">
        <Form.Item name={[field.name, 'id']} label="id"><Input placeholder={preset.id} /></Form.Item>
        <Form.Item name={[field.name, 'type']} label="type"><Select options={providerTypes.map((value) => ({ value }))} /></Form.Item>
        <Form.Item name={[field.name, 'name']} label="name"><Input placeholder={preset.name} /></Form.Item>
        <Flag name={[field.name, 'enabled']} label="enabled" />
      </Sub>
      <Sub title="Credentials">
        <Form.Item name={[field.name, 'client_id']} label="client_id"><Input placeholder={preset.client_id} /></Form.Item>
        <Form.Item name={[field.name, 'client_secret']} label="client_secret" extra="Leave blank to keep the saved secret."><Input.Password /></Form.Item>
        <Form.Item name={[field.name, 'scopes']} label="scopes"><Select mode="tags" placeholder={preset.scopes} /></Form.Item>
      </Sub>
      <Sub title="Endpoints">
        <div className="issuer-fetch span-2">
          <Form.Item name={[field.name, 'issuer']} label="issuer"><Input placeholder={preset.issuer} /></Form.Item>
          {kind === 'oidc' ? <Button loading={fetching} onClick={() => { void fetchIssuer() }}>Fetch</Button> : <span />}
        </div>
        <Form.Item name={[field.name, 'authorization_endpoint']} label="authorization_endpoint"><Input placeholder={preset.authorization_endpoint} /></Form.Item>
        <Form.Item name={[field.name, 'token_endpoint']} label="token_endpoint"><Input placeholder={preset.token_endpoint} /></Form.Item>
        <Form.Item name={[field.name, 'userinfo_endpoint']} label="userinfo_endpoint"><Input placeholder={preset.userinfo_endpoint} /></Form.Item>
      </Sub>
      <Sub title="Profile">
        <Form.Item name={[field.name, 'subject_field']} label="subject_field"><Input placeholder={preset.subject_field} /></Form.Item>
        <Form.Item name={[field.name, 'email_field']} label="email_field"><Input placeholder={preset.email_field} /></Form.Item>
        <Form.Item name={[field.name, 'username_field']} label="username_field"><Input placeholder={preset.username_field} /></Form.Item>
        <Form.Item name={[field.name, 'email_verified_field']} label="email_verified_field"><Input placeholder={preset.email_verified_field} /></Form.Item>
      </Sub>
      <div className="form-actions">
        <Button onClick={() => remove(field.name)}>Remove provider</Button>
      </div>
    </div>
  )
}

function Social() {
  return (
    <Form.List name={['social', 'providers']}>
      {(fields, { add, remove }) => (
        <>
          {fields.map((field) => <ProviderCard key={field.key} field={field} remove={remove} />)}
          <div className="form-actions">
            <Button onClick={() => add({ id: '', type: 'oidc', enabled: false, scopes: [] })}>Add provider</Button>
          </div>
        </>
      )}
    </Form.List>
  )
}

function Bot() {
  return (
    <Section title="Challenge">
      <Sub title="Service">
        <Form.Item name={['security', 'bot_protection', 'provider']} label="security.bot_protection.provider" extra="Empty skips the check. turnstile, or recaptcha for Google.">
          <Select allowClear options={[{ value: '' }, { value: 'turnstile' }, { value: 'recaptcha' }]} />
        </Form.Item>
      </Sub>
      <Sub title="Keys">
        <Form.Item name={['security', 'bot_protection', 'site_key']} label="security.bot_protection.site_key"><Input /></Form.Item>
        <Form.Item name={['security', 'bot_protection', 'secret_key']} label="security.bot_protection.secret_key" extra="Leave blank to keep the saved secret."><Input.Password /></Form.Item>
      </Sub>
    </Section>
  )
}

function Email() {
  return (
    <>
      <Section title="SMTP">
        <Sub title="Server">
          <Flag name={['smtp', 'enabled']} label="smtp.enabled" />
          <Form.Item name={['smtp', 'host']} label="smtp.host"><Input /></Form.Item>
          <Form.Item name={['smtp', 'port']} label="smtp.port"><InputNumber /></Form.Item>
        </Sub>
        <Sub title="Authentication">
          <Form.Item name={['smtp', 'username']} label="smtp.username"><Input /></Form.Item>
          <Form.Item name={['smtp', 'password']} label="smtp.password" extra="Leave blank to keep the saved password."><Input.Password /></Form.Item>
        </Sub>
        <Sub title="Message">
          <Form.Item name={['smtp', 'from']} label="smtp.from"><Input /></Form.Item>
          <Flag name={['smtp', 'starttls']} label="smtp.starttls" />
          <Flag name={['smtp', 'implicit_tls']} label="smtp.implicit_tls" />
        </Sub>
      </Section>
      <Section title="Templates">
        <Sub title="Files">
          <Form.Item name={['email', 'templates_dir']} label="email.templates_dir" extra="reset.txt, verify.txt, password_changed.txt, new_sign_in.txt, and login_failed.txt. The first line is Subject:."><Input /></Form.Item>
        </Sub>
      </Section>
    </>
  )
}
