import { theme } from 'antd'
import type { ThemeConfig } from 'antd'
import type { Brand } from './api'

export const fallbackBrand: Brand = {
  product_name: 'Atrium',
  primary_color: '#445f88',
  background_color: '',
  text_color: '',
  logo_url: '',
  favicon_url: '',
  footer_text: '',
}

export type ColorMode = 'light' | 'dark'

const modeKey = 'atrium-dashboard-color-scheme'

function hexChannel(hex: string) {
  const raw = hex.replace('#', '')
  const full = raw.length === 3 ? raw.split('').map((part) => part + part).join('') : raw
  return [0, 2, 4].map((index) => Number.parseInt(full.slice(index, index + 2), 16))
}

function hexMix(base: string, toward: string, amount: number) {
  const from = hexChannel(base)
  const to = hexChannel(toward)
  const mixed = from.map((channel, index) => Math.round(channel * (1 - amount) + to[index] * amount))
  return `#${mixed.map((channel) => channel.toString(16).padStart(2, '0')).join('')}`
}

export function readColorMode(): ColorMode {
  try {
    return localStorage.getItem(modeKey) === 'dark' ? 'dark' : 'light'
  } catch {
    return 'light'
  }
}

export function writeColorMode(mode: ColorMode) {
  try {
    localStorage.setItem(modeKey, mode)
  } catch {
    /* storage can be blocked */
  }
}

export function applyBrand(brand: Brand, mode: ColorMode = 'light') {
  const root = document.documentElement
  const primary = brand.primary_color || fallbackBrand.primary_color
  const dark = mode === 'dark'
  const accent = dark ? hexMix(primary, '#ffffff', 0.55) : primary
  const ink = dark ? '#f4f4f5' : (brand.text_color || '#18181b')
  root.dataset.theme = mode
  root.style.setProperty('--brand-primary', accent)
  root.style.setProperty('--ink', ink)
  root.style.setProperty('--muted', dark ? '#a1a1aa' : '#3f3f46')
  root.style.setProperty('--line', dark ? '#343842' : '#e4e4e7')
  root.style.setProperty('--card', dark ? '#1e2128' : '#ffffff')
  root.style.setProperty('--page', dark ? '#14161c' : (brand.background_color || '#f4f4f5'))
  root.style.setProperty('--track', dark ? '#2a2d36' : '#f4f4f5')
  root.style.setProperty('--stage', `color-mix(in srgb, ${primary} 42%, #101218)`)
  document.title = brand.product_name || 'Atrium'
  let icon = document.querySelector<HTMLLinkElement>('link[rel="icon"]')
  if (!icon) {
    icon = document.createElement('link')
    icon.rel = 'icon'
    icon.type = 'image/png'
    document.head.appendChild(icon)
  }
  icon.href = brand.favicon_url || '/favicon.png'
}

export function atriumTheme(brand: Brand, mode: ColorMode = 'light'): ThemeConfig {
  const primary = brand.primary_color || fallbackBrand.primary_color
  const dark = mode === 'dark'
  const accent = dark ? hexMix(primary, '#ffffff', 0.55) : primary
  const card = dark ? '#1e2128' : '#ffffff'
  const page = dark ? '#14161c' : (brand.background_color || '#f4f4f5')
  const ink = dark ? '#f4f4f5' : (brand.text_color || '#18181b')
  const muted = dark ? '#a1a1aa' : '#3f3f46'
  const line = dark ? '#343842' : '#e4e4e7'
  const mix = dark ? card : 'white'
  return {
    algorithm: dark ? theme.darkAlgorithm : theme.defaultAlgorithm,
    token: {
      colorPrimary: accent,
      colorLink: accent,
      colorInfo: accent,
      colorSuccess: dark ? '#4ade80' : '#166534',
      colorError: dark ? '#fb7185' : '#9f1239',
      colorText: ink,
      colorTextSecondary: muted,
      colorBgLayout: page,
      colorBgContainer: card,
      colorBgElevated: dark ? '#262a33' : '#ffffff',
      colorBorder: line,
      colorBorderSecondary: line,
      fontSize: 15,
      borderRadius: 8,
      fontFamily: '"Segoe UI", "Helvetica Neue", sans-serif',
    },
    components: {
      Layout: {
        siderBg: card,
        headerBg: card,
        bodyBg: page,
        headerHeight: 56,
      },
      Menu: {
        itemBg: card,
        itemColor: muted,
        itemSelectedBg: `color-mix(in srgb, ${accent} 18%, ${mix})`,
        itemSelectedColor: accent,
        itemHoverBg: `color-mix(in srgb, ${accent} 10%, ${mix})`,
      },
      Table: {
        headerBg: dark ? '#262a33' : '#fafafa',
        headerColor: muted,
        borderColor: line,
        rowHoverBg: dark ? '#262a33' : '#f4f4f5',
        cellPaddingBlock: 10,
      },
      Button: { fontWeight: 600, primaryColor: dark ? '#14161c' : '#ffffff' },
    },
  }
}
