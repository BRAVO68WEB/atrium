import { useEffect, useState } from 'react'
import { Typography } from 'antd'
import { api } from '../api'
import { PageHead, WindowSelect, errText } from '../widgets'
import { useMeta } from '../App'

type Day = { date: string; successes: number; failures: number }
type Address = { ip: string; attempts: number; successes: number; failures: number }
type Analytics = {
  attempts: number
  successes: number
  failures: number
  failure_rate: number
  unique_ips: number
  mfa_attempts: number
  by_day: Day[]
  by_ip: Address[]
}

export function Overview() {
  const meta = useMeta()
  const [window, setWindow] = useState('168h')
  const [stats, setStats] = useState<Analytics | null>(null)
  const [counts, setCounts] = useState({ users: 0, apps: 0, orgs: '—' })
  const [error, setError] = useState('')

  useEffect(() => {
    let stop = false
    setError('')
    Promise.all([
      api<Analytics>(`/dashboard/api/analytics/logins?window=${window}`),
      api<unknown[]>('/dashboard/api/users'),
      api<unknown[]>('/dashboard/api/clients'),
      meta.org_enabled ? api<unknown[]>('/dashboard/api/orgs') : Promise.resolve(null),
    ]).then(([report, users, clients, orgs]) => {
      if (stop) return
      setStats(report)
      setCounts({ users: users.length, apps: clients.length, orgs: orgs ? String(orgs.length) : '—' })
    }).catch((err) => { if (!stop) setError(errText(err)) })
    return () => { stop = true }
  }, [window, meta.org_enabled])

  const days = [...(stats?.by_day || [])].sort((a, b) => a.date.localeCompare(b.date))
  const addresses = [...(stats?.by_ip || [])].sort((a, b) => b.attempts - a.attempts).slice(0, 6)
  const rate = stats ? Math.round(stats.failure_rate * 1000) / 10 : 0

  return (
    <div className="console">
      <PageHead title="Overview" text="Attempts, failures, and the addresses reaching this issuer." extra={<WindowSelect value={window} onChange={setWindow} />} />
      {error && <Typography.Paragraph type="danger">{error}</Typography.Paragraph>}
      <div className="bento">
        <article className="tile tile-chart">
          <header>
            <h2>Sign-ins</h2>
            <p>{stats?.attempts ?? 0} attempts in this window</p>
          </header>
          <SignInChart days={days} />
          <div className="legend">
            <span><i className="swatch ok" /> Successes</span>
            <span><i className="swatch bad" /> Failures</span>
          </div>
        </article>
        <article className="tile tile-ring">
          <header>
            <h2>Failure rate</h2>
            <p>{stats?.failures ?? 0} failed of {stats?.attempts ?? 0}</p>
          </header>
          <FailureRing rate={rate} successes={stats?.successes ?? 0} failures={stats?.failures ?? 0} />
        </article>
        <article className="tile tile-num"><b>{counts.users}</b><span>Users</span></article>
        <article className="tile tile-num"><b>{counts.apps}</b><span>Applications</span></article>
        <article className="tile tile-num"><b>{counts.orgs}</b><span>Organizations</span></article>
        <article className="tile tile-num"><b>{stats?.unique_ips ?? 0}</b><span>Addresses</span></article>
        <article className="tile tile-ips">
          <header>
            <h2>Addresses</h2>
            <p>Most attempts in this window</p>
          </header>
          <AddressBars rows={addresses} />
        </article>
      </div>
    </div>
  )
}

function SignInChart({ days }: { days: Day[] }) {
  if (days.length === 0) return <p className="hint">No sign-ins in this window.</p>
  const width = 720
  const height = 280
  const pad = { l: 36, r: 12, t: 16, b: 32 }
  const innerW = width - pad.l - pad.r
  const innerH = height - pad.t - pad.b
  const peak = Math.max(1, ...days.map((day) => day.successes + day.failures))
  const group = innerW / days.length
  const bar = Math.min(48, group * 0.55)
  const ticks = [0, Math.ceil(peak / 2), peak]
  return (
    <svg className="chart" viewBox={`0 0 ${width} ${height}`} role="img" aria-label="Sign-ins by day">
      {ticks.map((tick) => {
        const y = pad.t + innerH - (tick / peak) * innerH
        return (
          <g key={tick}>
            <line x1={pad.l} x2={width - pad.r} y1={y} y2={y} className="chart-grid" />
            <text x={pad.l - 8} y={y + 4} textAnchor="end" className="chart-axis">{tick}</text>
          </g>
        )
      })}
      {days.map((day, index) => {
        const x = pad.l + index * group + (group - bar) / 2
        const ok = (day.successes / peak) * innerH
        const bad = (day.failures / peak) * innerH
        const base = pad.t + innerH
        return (
          <g key={day.date}>
            <rect x={x} y={base - bad} width={bar} height={Math.max(bad, 0)} className="bar-bad" rx="4" />
            <rect x={x} y={base - bad - ok} width={bar} height={Math.max(ok, 0)} className="bar-ok" rx="4" />
            <text x={x + bar / 2} y={height - 8} textAnchor="middle" className="chart-axis">{day.date.slice(5)}</text>
          </g>
        )
      })}
    </svg>
  )
}

function FailureRing({ rate, successes, failures }: { rate: number; successes: number; failures: number }) {
  const r = 78
  const c = 2 * Math.PI * r
  const total = successes + failures
  const failLen = total === 0 ? 0 : (failures / total) * c
  const okLen = total === 0 ? 0 : (successes / total) * c
  return (
    <div className="ring-wrap">
      <svg viewBox="0 0 200 200" className="ring" role="img" aria-label={`${rate}% failure rate`}>
        <circle cx="100" cy="100" r={r} className="ring-track" />
        <circle cx="100" cy="100" r={r} className="ring-ok" strokeDasharray={`${okLen} ${c - okLen}`} strokeDashoffset={c * 0.25} />
        <circle cx="100" cy="100" r={r} className="ring-bad" strokeDasharray={`${failLen} ${c - failLen}`} strokeDashoffset={c * 0.25 - okLen} />
      </svg>
      <div className="ring-label"><b>{rate}%</b><span>failed</span></div>
    </div>
  )
}

function AddressBars({ rows }: { rows: Address[] }) {
  if (rows.length === 0) return <p className="hint">No addresses in this window.</p>
  const peak = Math.max(1, ...rows.map((row) => row.attempts))
  return (
    <div className="addr-bars">
      {rows.map((row) => (
        <div key={row.ip} className="addr-row">
          <span className="mono">{row.ip}</span>
          <div className="addr-track" title={`${row.successes} succeeded, ${row.failures} failed`}>
            <div className="addr-ok" style={{ width: `${(row.successes / peak) * 100}%` }} />
            <div className="addr-bad" style={{ width: `${(row.failures / peak) * 100}%` }} />
          </div>
          <b>{row.attempts}</b>
        </div>
      ))}
    </div>
  )
}
