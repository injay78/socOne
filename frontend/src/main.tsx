import React from 'react'
import ReactDOM from 'react-dom/client'
import {BrowserRouter} from 'react-router-dom'
import BrandingProvider from './components/BrandingProvider'
import ThemedApp from './ThemedApp'
import './index.css'

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <BrowserRouter>
      <BrandingProvider>
        <ThemedApp />
      </BrandingProvider>
    </BrowserRouter>
  </React.StrictMode>,
)
