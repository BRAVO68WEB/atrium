import type { ReactNode } from 'react'
import { Button, Form, Input, Modal, Select, Switch, Typography, message } from 'antd'
import { WINDOWS } from './api'

export function confirmName(name: string, title: string) {
  return new Promise<boolean>((resolve) => {
    let typed = ''
    Modal.confirm({
      title,
      content: (
        <div>
          <p>Type <Typography.Text code>{name}</Typography.Text> to confirm.</p>
          <Input autoFocus onChange={(e) => { typed = e.target.value }} />
        </div>
      ),
      okText: 'Confirm',
      okButtonProps: { danger: true },
      onOk: () => {
        if (typed !== name) {
          message.error('The name did not match')
          return Promise.reject(new Error('mismatch'))
        }
        resolve(true)
      },
      onCancel: () => resolve(false),
    })
  })
}

export function showSecret(title: string, secret: string) {
  Modal.info({
    title,
    width: 560,
    content: (
      <div>
        <p>Copy this value now. It is not shown again.</p>
        <Input.TextArea value={secret} readOnly autoSize />
        <Button style={{ marginTop: 8 }} onClick={() => navigator.clipboard.writeText(secret)}>Copy</Button>
      </div>
    ),
  })
}

export function WindowSelect({ value, onChange }: { value: string; onChange: (value: string) => void }) {
  return <Select style={{ width: 180 }} value={value} options={WINDOWS} onChange={onChange} />
}

export function lines(value: string) {
  return value.split(/\r?\n/).map((line) => line.trim()).filter(Boolean)
}

export function joinLines(value?: string[]) {
  return (value || []).join('\n')
}

export function Stage({ kicker, title, text, extra }: { kicker: string; title: string; text: string; extra?: ReactNode }) {
  return (
    <section className="stage">
      <div className="stage-top">
        <div>
          <p className="kicker">{kicker}</p>
          <h2>{title}</h2>
          <p>{text}</p>
        </div>
        {extra ? <div className="stage-extra">{extra}</div> : null}
      </div>
    </section>
  )
}

export function errText(err: unknown) {
  return err instanceof Error ? err.message : 'Request failed'
}

export function Flag({ name, label, extra }: { name: string | (string | number)[]; label: string; extra?: string }) {
  return (
    <Form.Item className="flag-item" name={name} label={label} extra={extra} valuePropName="checked">
      <Switch checkedChildren="Enabled" unCheckedChildren="Off" />
    </Form.Item>
  )
}
