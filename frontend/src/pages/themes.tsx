import { useEffect, useState } from 'react'
import { Segmented, Select, Tag, Typography } from 'antd'
import { api } from '../api'
import { errText } from '../widgets'

type PageTheme = { name: string; label: string; variants: string[] }
type MailTheme = { name: string; label: string; subject: string; text: string; html: boolean; source: string }

export function Themes() {
  const [kind, setKind] = useState('Pages')
  const [pages, setPages] = useState<PageTheme[]>([])
  const [emails, setEmails] = useState<MailTheme[]>([])
  const [page, setPage] = useState('login')
  const [variant, setVariant] = useState('')
  const [mail, setMail] = useState('reset')
  const [error, setError] = useState('')

  useEffect(() => {
    api<{ pages: PageTheme[] }>('/dashboard/api/themes/pages').then((body) => {
      setPages(body.pages || [])
      if (body.pages?.length) setPage(body.pages[0].name)
    }).catch((err) => setError(errText(err)))
    api<{ emails: MailTheme[] }>('/dashboard/api/themes/email').then((body) => {
      setEmails(body.emails || [])
      if (body.emails?.length) setMail(body.emails.find((item) => item.name === 'reset')?.name || body.emails[0].name)
    }).catch((err) => setError(errText(err)))
  }, [])

  const currentPage = pages.find((item) => item.name === page)
  const currentMail = emails.find((item) => item.name === mail)
  const pageSrc = `/dashboard/preview/pages/${page}${variant ? `?variant=${encodeURIComponent(variant)}` : ''}`

  return (
    <div>
      <div className="dash-toolbar">
        <Segmented options={['Pages', 'Email']} value={kind} onChange={(value) => setKind(String(value))} />
        <Typography.Text type="secondary">Preview only. These themes are not edited here.</Typography.Text>
      </div>
      {error && <Typography.Paragraph type="danger" style={{ padding: 16 }}>{error}</Typography.Paragraph>}
      {kind === 'Pages' ? (
        <div className="explorer">
          <aside className="filter-col">
            {pages.map((item) => (
              <button key={item.name} className={item.name === page ? 'theme-link active' : 'theme-link'} onClick={() => { setPage(item.name); setVariant('') }}>
                {item.label}
              </button>
            ))}
          </aside>
          <div className="main">
            <div className="dash-toolbar">
              <Select
                style={{ width: 180 }}
                value={variant}
                onChange={setVariant}
                options={[{ value: '', label: 'Default' }, ...(currentPage?.variants || []).map((value) => ({ value, label: value }))]}
              />
              <Tag>{page}.html</Tag>
            </div>
            <iframe className="theme-frame" title={currentPage?.label || 'Page preview'} src={pageSrc} sandbox="allow-scripts allow-same-origin" />
          </div>
        </div>
      ) : (
        <div className="explorer">
          <aside className="filter-col">
            {emails.map((item) => (
              <button key={item.name} className={item.name === mail ? 'theme-link active' : 'theme-link'} onClick={() => setMail(item.name)}>
                {item.label}
              </button>
            ))}
          </aside>
          <div className="main page-pad">
            {currentMail && (
              <>
                <Typography.Title level={4} style={{ marginTop: 0 }}>{currentMail.subject}</Typography.Title>
                <Tag>{currentMail.source === 'file' ? 'File' : 'Built-in'}</Tag>
                {currentMail.html && <Tag>HTML</Tag>}
                <Typography.Paragraph type="secondary">{currentMail.name}.txt</Typography.Paragraph>
                <iframe className="theme-frame" title={currentMail.label} sandbox="" src={`/dashboard/preview/email/${currentMail.name}`} />
                <Typography.Title level={5}>Plain text</Typography.Title>
                <pre className="theme-text">{currentMail.text}</pre>
              </>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
