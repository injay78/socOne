import {App as AntApp, ConfigProvider} from 'antd'
import App from './App'
import AppMessageProvider from './components/AppMessageProvider'
import {useBranding} from './brandingContext'
import {buildTheme} from './theme'

export default function ThemedApp() {
  const branding = useBranding()
  return (
    <ConfigProvider theme={buildTheme(branding.primary_color)}>
      <AntApp>
        <AppMessageProvider />
        <App />
      </AntApp>
    </ConfigProvider>
  )
}
