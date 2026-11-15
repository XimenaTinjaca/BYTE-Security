import { useState, useEffect, useCallback } from 'react'
import { api } from './api'
import StatusBar from './components/StatusBar'
import MetricCards from './components/MetricCards'
import SessionFeed from './components/SessionFeed'
import ThreatTable from './components/ThreatTable'
import CloudPanel from './components/CloudPanel'

const POLL_INTERVAL_MS = 5000

export default function App() {
  const [status, setStatus] = useState(null)
  const [stats, setStats] = useState(null)
  const [sessions, setSessions] = useState([])
  const [threats, setThreats] = useState([])
  const [quarantine, setQuarantine] = useState([])
  const [lastUpdate, setLastUpdate] = useState(null)
  const [error, setError] = useState(null)

  const refresh = useCallback(async () => {
    try {
      const [s, st, sess, th, q] = await Promise.all([
        api.status(),
        api.stats(),
        api.sessions(30),
        api.threats(),
        api.quarantine(),
      ])

      setStatus(s)
      setStats(st)
      setSessions(sess)
      setThreats(th)
      setQuarantine(q)
      setLastUpdate(new Date())
      setError(null)
    } catch (e) {
      setError(
        'No se puede conectar con el servidor. ¿Está ejecutándose Uvicorn en el puerto 8000?'
      )
    }
  }, [])

  // Carga inicial y actualización automática
  useEffect(() => {
    refresh()

    const id = setInterval(refresh, POLL_INTERVAL_MS)

    return () => clearInterval(id)
  }, [refresh])

  const handleRestore = async (sessionId) => {
    try {
      await api.restoreSession(sessionId)
      refresh()
    } catch (e) {
      alert(`Error al restaurar: ${e.message}`)
    }
  }

  return (
    <div className="app">

      {/* Encabezado e identidad de BYTE */}
      <header className="app-header">
        <div className="brand">
          <div className="brand-logo">
            <img
              src="/byte.png"
              alt="Byte, mascota de BYTE Security"
            />
          </div>

          <div className="brand-info">
            <h1>
              BYTE <span>Security</span>
            </h1>
            <p>Detección inteligente y recuperación de ransomware</p>
          </div>
        </div>

        <div className="header-meta">
          <div className="header-status">
            <span className={`header-dot ${error ? 'offline' : 'online'}`} />
            <span>
              {error ? 'Servidor desconectado' : 'Sistema de análisis'}
            </span>
          </div>

          {lastUpdate && (
            <div className="last-update">
              Última actualización: {lastUpdate.toLocaleTimeString('es-CO')}
            </div>
          )}
        </div>
      </header>

      {error && (
        <div className="error-banner">
          ⚠ {error}
        </div>
      )}

      <main className="app-main">

        <StatusBar status={status} error={error} />

        <MetricCards stats={stats} />

        <div className="grid-two">
          <SessionFeed
            sessions={sessions}
            onRestore={handleRestore}
          />

          <div className="right-col">
            <ThreatTable
              threats={threats}
              onRestore={handleRestore}
            />

            <CloudPanel quarantine={quarantine} />
          </div>
        </div>

      </main>
    </div>
  )
}
