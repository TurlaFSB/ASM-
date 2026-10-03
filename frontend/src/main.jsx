import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import './design.css'
import { initMotion } from './motion.js'
import App from './App.jsx'
import { applyTheme, watchSystemTheme } from './lib/theme.js'

applyTheme()
watchSystemTheme()
initMotion()

createRoot(document.getElementById('root')).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
