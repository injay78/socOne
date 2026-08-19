import type {ThemeConfig} from 'antd'
import {theme} from 'antd'
import {fontFamilyMono, fontFamilySans} from './utils/typography'
import {NEUTRAL_BRANDING} from './brandingContext'

/**
 * The accent colour is deliberately NOT wired into any interactive token.
 *
 * In a SOC console orange is a severity colour: the SHB accent #F37022 sits
 * 1.13:1 from severity High (#fa541c) and 1.55:1 from Medium (#faad14), which
 * is indistinguishable at a glance. Using it for buttons or active states would
 * make ordinary controls read as warnings and blunt the severity scale.
 * It is exposed for brand marks only.
 *
 * White text on #F37022 measures 2.94:1 and fails WCAG AA, so the accent must
 * never carry white label text either.
 */
export function buildTheme(primaryColor?: string): ThemeConfig {
  return {
    algorithm: theme.darkAlgorithm,
    token: {
      colorPrimary: primaryColor || NEUTRAL_BRANDING.primary_color,
      fontFamily: fontFamilySans,
      fontFamilyCode: fontFamilyMono,
      fontSize: 14,
      lineHeight: 1.5715,
    },
  }
}

const themeConfig: ThemeConfig = buildTheme()

// Severity scale is untouched: it is the platform's shared vocabulary and must
// not shift because a deployment changed its brand colours.
export const severityColors: Record<string, string> = {
  Critical: '#ff4d4f',
  High: '#fa541c',
  Medium: '#faad14',
  Low: '#13c2c2',
  Info: '#1677ff',
  Informational: '#1677ff',
}

export const severityTagColors: Record<string, string> = {
  Critical: 'red',
  High: 'volcano',
  Medium: 'gold',
  Low: 'cyan',
  Info: 'blue',
  Informational: 'blue',
}

export default themeConfig
