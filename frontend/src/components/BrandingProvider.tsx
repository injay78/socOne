import {useCallback, useEffect, useMemo, useState} from 'react'
import client from '../api/client'
import {BrandingContext, NEUTRAL_BRANDING, type Branding} from '../brandingContext'

function applyFavicon(href: string) {
  if (!href) return
  const link = document.querySelector<HTMLLinkElement>("link[rel='icon']")
  if (link) link.href = href
}

export default function BrandingProvider({children}: {children: React.ReactNode}) {
  const [branding, setBranding] = useState<Branding>(NEUTRAL_BRANDING)

  const reload = useCallback(async () => {
    try {
      const {data} = await client.get<Branding>('/branding/')
      const merged = {...NEUTRAL_BRANDING, ...data}
      setBranding(merged)
      document.title = merged.product_name
      applyFavicon(merged.favicon)
    } catch {
      // Branding is cosmetic: a failure must never block the application.
      setBranding(NEUTRAL_BRANDING)
    }
  }, [])

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    reload()
  }, [reload])

  const value = useMemo(() => ({branding, reload}), [branding, reload])
  return <BrandingContext.Provider value={value}>{children}</BrandingContext.Provider>
}
