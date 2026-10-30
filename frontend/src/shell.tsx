import { useEffect, useState } from 'react'
import { Layout, Menu, Button, message } from 'antd'
import {
  AppstoreOutlined, ApiOutlined, UserOutlined, BankOutlined, SafetyCertificateOutlined,
  LoginOutlined, ProfileOutlined, SettingOutlined, DashboardOutlined, LogoutOutlined, SkinOutlined,
  MoonOutlined, SunOutlined,
} from '@ant-design/icons'
import { Outlet, useLocation, useNavigate } from 'react-router-dom'
import { useBrand, useColorMode, useMeta } from './App'
import mark from './mark.png'

const { Sider, Header, Content } = Layout

export function ThemeToggle() {
  const { mode, toggle } = useColorMode()
  const dark = mode === 'dark'
  return (
    <Button
      type="text"
      className="theme-toggle"
      aria-label={dark ? 'Use light mode' : 'Use dark mode'}
      icon={dark ? <SunOutlined /> : <MoonOutlined />}
      onClick={toggle}
    />
  )
}

const titles: Record<string, string> = {
  '/': 'Overview',
  '/applications': 'Applications',
  '/resources': 'API resources',
  '/scopes': 'Scopes',
  '/users': 'Users',
  '/organizations': 'Organizations',
  '/roles': 'Access',
  '/sign-in': 'Sign-in',
  '/events': 'Events',
  '/settings': 'Settings',
  '/themes': 'Themes',
}

const configKey = /^[a-z][a-z0-9_.]*$/

const keyWords: Record<string, string> = {
  url: 'URL', uri: 'URI', id: 'ID', ui: 'UI', ip: 'IP', json: 'JSON', html: 'HTML',
  tls: 'TLS', jwks: 'JWKS', mfa: 'MFA', smtp: 'SMTP', oidc: 'OIDC', oauth: 'OAuth',
  totp: 'TOTP', pkce: 'PKCE', dpop: 'DPoP', cimd: 'CIMD', dcr: 'DCR', api: 'API',
  db: 'database', dir: 'directory', min: 'minimum', max: 'maximum', algo: 'algorithm',
  cert: 'certificate', oob: 'out-of-band', auth: 'authentication', starttls: 'STARTTLS',
  userinfo: 'UserInfo', org: 'organization',
}

function titleForKey(key: string) {
  const leaf = key.split('.').pop() || key
  return leaf.split('_').map((part, index) => {
    const mapped = keyWords[part] || part
    if (index === 0 && mapped === mapped.toLowerCase()) return mapped.charAt(0).toUpperCase() + mapped.slice(1)
    return mapped
  }).join(' ')
}

function keyText(node: HTMLElement) {
  return (node.textContent || '').replace(/\*/g, '').trim()
}

function titleTarget(node: HTMLElement) {
  if (!node.classList.contains('ant-checkbox-wrapper')) return node
  const spans = [...node.querySelectorAll<HTMLElement>(':scope > span')].filter((el) => !el.classList.contains('ant-checkbox'))
  return spans.at(-1) || null
}

function retitleConfigKeys(root: ParentNode) {
  root.querySelectorAll<HTMLElement>('.ant-form-item-label > label, .ant-checkbox-wrapper').forEach((node) => {
    const target = titleTarget(node)
    if (!target) return
    const current = keyText(target)
    const stored = node.dataset.configKey || ''
    const key = configKey.test(current) ? current : stored
    if (!configKey.test(key)) return
    const title = titleForKey(key)
    if (keyText(target) !== title) target.textContent = title
    node.dataset.configKey = key
    node.title = key
    node.classList.remove('config-key')
  })
}

export function Shell({ onLogout }: { onLogout: () => void }) {
  const meta = useMeta()
  const brand = useBrand()
  const logo = brand.logo_url || mark
  const navigate = useNavigate()
  const { pathname } = useLocation()
  const key = '/' + (pathname.split('/')[1] || '')
  const selected = key === '/' ? '/' : key
  const items = [
    { key: '/', icon: <DashboardOutlined />, label: 'Overview' },
    { key: '/applications', icon: <AppstoreOutlined />, label: 'Applications' },
    { key: '/resources', icon: <ApiOutlined />, label: 'APIs' },
    { key: '/users', icon: <UserOutlined />, label: 'Users' },
    ...(meta.org_enabled ? [{ key: '/organizations', icon: <BankOutlined />, label: 'Organizations' }] : []),
    { key: '/roles', icon: <SafetyCertificateOutlined />, label: 'Access' },
    { key: '/sign-in', icon: <LoginOutlined />, label: 'Sign-in' },
    { key: '/events', icon: <ProfileOutlined />, label: 'Events' },
    { key: '/themes', icon: <SkinOutlined />, label: 'Themes' },
    { key: '/settings', icon: <SettingOutlined />, label: 'Settings' },
  ]
  const title = titles[selected] || meta.product_name
  useEffect(() => {
    const root = document.querySelector('.dash-content')
    if (!root) return
    let frame = 0
    const paint = () => {
      cancelAnimationFrame(frame)
      frame = requestAnimationFrame(() => retitleConfigKeys(root))
    }
    paint()
    const observer = new MutationObserver(paint)
    observer.observe(root, { subtree: true, childList: true, characterData: true })
    return () => {
      observer.disconnect()
      cancelAnimationFrame(frame)
    }
  }, [pathname])
  const [copied, setCopied] = useState(false)
  useEffect(() => {
    if (!copied) return
    const id = window.setTimeout(() => setCopied(false), 1200)
    return () => window.clearTimeout(id)
  }, [copied])
  async function copyIssuer() {
    try {
      await navigator.clipboard.writeText(meta.issuer)
      setCopied(true)
    } catch {
      message.error('Could not copy the issuer')
    }
  }
  return (
    <Layout style={{ minHeight: '100vh', background: 'var(--page)' }}>
      <Sider className="dash-sider" collapsed collapsedWidth={64} trigger={null} theme="light">
        <div className="dash-mark" title={brand.product_name}>
          <img src={logo} alt={brand.product_name} />
        </div>
        <Menu
          theme="light"
          mode="inline"
          selectedKeys={[selected === '/scopes' ? '/resources' : selected]}
          items={items}
          onClick={({ key }) => navigate(key)}
        />
        <div style={{ marginTop: 'auto', padding: 8 }}>
          <Button type="text" icon={<LogoutOutlined />} onClick={onLogout} aria-label="Sign out" />
        </div>
      </Sider>
      <Layout className="dash-main">
        <Header className="dash-header">
          <h1>{title}</h1>
          <span className="dash-product">{brand.product_name}</span>
          <div className="dash-header-fill" />
          <ThemeToggle />
          {meta.issuer ? (
            <button type="button" className="issuer-chip" title="Click to copy" aria-label={`Copy OIDC issuer ${meta.issuer}`} onClick={() => { void copyIssuer() }}>
              <span className="issuer-key">{copied ? 'Copied' : 'OIDC Issuer'}</span>
              <span className="mono issuer-val">{meta.issuer}</span>
            </button>
          ) : null}
          <Button href="/docs">API docs</Button>
        </Header>
        <Content className="dash-content">
          <Outlet />
        </Content>
      </Layout>
    </Layout>
  )
}
