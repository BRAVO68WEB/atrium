import { createContext, useContext, useEffect, useState } from 'react'
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom'
import { Button, ConfigProvider, Form, Input, Modal, Spin, Typography } from 'antd'
import { ApiError, Brand, Meta, Restart, api, login, logout, rememberCSRF } from './api'
import { ColorMode, applyBrand, atriumTheme, fallbackBrand, readColorMode, writeColorMode } from './brand'
import { Shell, ThemeToggle } from './shell'
import { Overview } from './pages/overview'
import { Applications, ApplicationDetail } from './pages/applications'
import { Resources, ResourceDetail, Scopes } from './pages/apis'
import { Users, UserDetail } from './pages/users'
import { Organizations, OrganizationDetail } from './pages/orgs'
import { Roles, RoleDetail } from './pages/roles'
import { SignInSettings } from './pages/signin'
import { Events } from './pages/events'
import { Settings } from './pages/settings'
import { Themes } from './pages/themes'
import { errText } from './widgets'

const MetaContext = createContext<Meta | null>(null)
const BrandContext = createContext<Brand>(fallbackBrand)
const RestartContext = createContext<(info: Restart) => void>(() => {})
const ColorModeContext = createContext<{ mode: ColorMode; toggle: () => void }>({ mode: 'light', toggle: () => {} })

export function useColorMode() {
  return useContext(ColorModeContext)
}

export function useBrand() {
  return useContext(BrandContext)
}

export function useMeta() {
  const meta = useContext(MetaContext)
  if (!meta) throw new Error('meta missing')
  return meta
}

export function useRestart() {
  return useContext(RestartContext)
}

export function App() {
  const [brand, setBrand] = useState<Brand | null>(null)
  const [mode, setMode] = useState<ColorMode>(readColorMode)
  const toggle = () => setMode((current) => {
    const next = current === 'dark' ? 'light' : 'dark'
    writeColorMode(next)
    return next
  })
  useEffect(() => {
    api<Brand>('/dashboard/brand').then(setBrand).catch(() => setBrand(fallbackBrand))
  }, [])
  useEffect(() => { if (brand) applyBrand(brand, mode) }, [brand, mode])
  if (!brand) {
    return <div style={{ height: '100%', display: 'grid', placeItems: 'center' }}><Spin /></div>
  }
  return (
    <ConfigProvider theme={atriumTheme(brand, mode)}>
      <BrandContext.Provider value={brand}>
        <ColorModeContext.Provider value={{ mode, toggle }}>
          <SessionApp />
        </ColorModeContext.Provider>
      </BrandContext.Provider>
    </ConfigProvider>
  )
}

function SessionApp() {
  const [meta, setMeta] = useState<Meta | null>(null)
  const [booting, setBooting] = useState(true)
  const [restart, setRestart] = useState<Restart | null>(null)

  useEffect(() => {
    api<Meta>('/dashboard/api/meta')
      .then((body) => {
        if (body.csrf) rememberCSRF(body.csrf)
        setMeta(body)
      })
      .catch(() => setMeta(null))
      .finally(() => setBooting(false))
  }, [])

  if (booting) {
    return <div style={{ height: '100%', display: 'grid', placeItems: 'center' }}><Spin /></div>
  }
  if (!meta) {
    return <Login onReady={setMeta} />
  }

  return (
    <MetaContext.Provider value={meta}>
      <RestartContext.Provider value={setRestart}>
        <BrowserRouter basename="/dashboard">
          <Routes>
            <Route element={<Shell onLogout={async () => { await logout().catch(() => undefined); setMeta(null) }} />}>
              <Route index element={<Overview />} />
              <Route path="applications" element={<Applications />} />
              <Route path="applications/:id" element={<ApplicationDetail />} />
              <Route path="resources" element={<Resources />} />
              <Route path="resources/detail" element={<ResourceDetail />} />
              <Route path="scopes" element={<Scopes />} />
              <Route path="users" element={<Users />} />
              <Route path="users/:id" element={<UserDetail />} />
              <Route path="organizations" element={<Organizations />} />
              <Route path="organizations/:id" element={<OrganizationDetail />} />
              <Route path="roles" element={<Roles />} />
              <Route path="roles/:id" element={<RoleDetail />} />
              <Route path="sign-in" element={<SignInSettings />} />
              <Route path="events" element={<Events />} />
              <Route path="settings" element={<Settings />} />
              <Route path="themes" element={<Themes />} />
              <Route path="*" element={<Navigate to="/" replace />} />
            </Route>
          </Routes>
        </BrowserRouter>
        <RestartModal info={restart} onClose={() => setRestart(null)} />
      </RestartContext.Provider>
    </MetaContext.Provider>
  )
}

function Login({ onReady }: { onReady: (meta: Meta) => void }) {
  const brand = useBrand()
  const [busy, setBusy] = useState(false)
  return (
    <div className="login-stage">
      <div className="login-card">
        <div className="login-tools"><ThemeToggle /></div>
        <div className="lockup">
          {brand.logo_url ? <img src={brand.logo_url} alt="" /> : null}
          <span className="product">{brand.product_name}</span>
        </div>
        <h1>Dashboard</h1>
        <p className="lede">Sign in with the management client id and secret.</p>
        <Form layout="vertical" onFinish={async (values: { client_id: string; client_secret: string }) => {
          setBusy(true)
          try {
            await login(values.client_id, values.client_secret)
            const body = await api<Meta>('/dashboard/api/meta')
            if (body.csrf) rememberCSRF(body.csrf)
            onReady(body)
          } catch (err) {
            Modal.error({ title: 'Sign-in failed', content: errText(err) })
          } finally {
            setBusy(false)
          }
        }}>
          <Form.Item name="client_id" label="Client ID" rules={[{ required: true }]}>
            <Input autoFocus autoComplete="username" />
          </Form.Item>
          <Form.Item name="client_secret" label="Client secret" rules={[{ required: true }]}>
            <Input.Password autoComplete="current-password" />
          </Form.Item>
          <Button type="primary" htmlType="submit" block loading={busy}>Sign in</Button>
        </Form>
      </div>
    </div>
  )
}

function RestartModal({ info, onClose }: { info: Restart | null; onClose: () => void }) {
  const [busy, setBusy] = useState(false)
  const [waiting, setWaiting] = useState(false)
  return (
    <Modal
      open={!!info}
      title="Restart required"
      onCancel={onClose}
      footer={[
        <Button key="later" onClick={onClose}>Later</Button>,
        info?.auto_restart ? <Button key="now" type="primary" loading={busy || waiting} onClick={async () => {
          setBusy(true)
          try {
            await api('/dashboard/api/restart', { method: 'POST', body: '{}' })
            setWaiting(true)
            for (let i = 0; i < 30; i++) {
              await new Promise((r) => setTimeout(r, 1000))
              try {
                const res = await fetch('/health')
                if (res.ok) {
                  window.location.assign('/dashboard')
                  return
                }
              } catch {
                /* process is down */
              }
            }
            Modal.warning({ title: 'Still restarting', content: 'Reload the page and sign in again.' })
          } catch (err) {
            if (err instanceof ApiError && err.status === 409) {
              Modal.info({ title: 'Restart the process', content: err.message })
            } else {
              Modal.error({ title: 'Restart failed', content: errText(err) })
            }
          } finally {
            setBusy(false)
          }
        }}>Restart container</Button> : null,
      ]}
    >
      <p>Saved <Typography.Text code>{info?.path}</Typography.Text>. The running process keeps the previous settings until it starts again.</p>
      {info?.in_docker
        ? <p>Restart now stops this process. Docker starts it again when the service uses <Typography.Text code>restart: unless-stopped</Typography.Text>. Sign in again after it comes back.</p>
        : <p>Restart the atrium process, or the container, to apply the file.</p>}
    </Modal>
  )
}
