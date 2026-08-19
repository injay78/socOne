import {createContext, useContext} from 'react'

export interface Branding {
  product_name: string
  product_short_name: string
  logo_full: string
  logo_compact: string
  logo_mark: string
  logo_dark: string
  favicon: string
  login_background: string
  primary_color: string
  accent_color: string
}

/**
 * Neutral defaults render immediately so the shell never flashes one identity
 * and then swaps to another while the API call is in flight.
 */
export const NEUTRAL_BRANDING: Branding = {
  product_name: 'SOC Platform',
  product_short_name: 'SOC',
  logo_full: '',
  logo_compact: '',
  logo_mark: '',
  logo_dark: '',
  favicon: '/favicon.svg',
  login_background: '',
  primary_color: '#1677ff',
  accent_color: '#1677ff',
}

export const BrandingContext = createContext<{branding: Branding; reload: () => Promise<void>}>({
  branding: NEUTRAL_BRANDING,
  reload: async () => {},
})

export function useBranding() {
  return useContext(BrandingContext).branding
}

export function useBrandingReload() {
  return useContext(BrandingContext).reload
}
