import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import Gardien from './Gardien.jsx'
import './styles.css'

// Coquille réduite du hub « Mes agents » : la barre du haut, puis la vue de
// l'agent. Dans le hub, la même vue est un onglet parmi les autres agents.
function App() {
  return (
    <div className="app">
      <header className="appbar">
        <div className="appbar-mark" aria-hidden="true">▣</div>
        <div className="appbar-heads">
          <h1 className="appbar-title">Gardien du VPS</h1>
          <p className="appbar-sub">OPS · LECTURE SEULE</p>
        </div>
        <div className="appbar-spacer" />
        <span className="appbar-dot" title="Agent actif" />
      </header>
      <main className="scroll">
        <Gardien />
      </main>
    </div>
  )
}

createRoot(document.getElementById('root')).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
