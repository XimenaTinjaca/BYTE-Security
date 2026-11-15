
export default function StatusBar({ status, error }) {
  if (error) {
    return (
      <div className="status-bar">
        <div className="status-item">
          <div className="dot red" />
          <span>API desconectada</span>
        </div>
      </div>
    )
  }

  if (!status) {
    return (
      <div className="status-bar">
        <span style={{ color: 'var(--text-muted)', fontSize: 13 }}>
          Conectando con el servidor...
        </span>
      </div>
    )
  }

  return (
    <div className="status-bar">
      {/* Estado del modelo de Machine Learning */}
      <div className="status-item">
        <div className={`dot ${status.model_loaded ? 'green' : 'red'}`} />
        <span>
          {status.model_loaded
            ? `Modelo cargado (${status.model_name})`
            : 'Modelo no cargado — ejecuta train.py'}
        </span>
      </div>

      {/* Estado de la API */}
      <div className="status-item">
        <div className="dot green" />
        <span>API operativa</span>
      </div>

      {/* Amenazas detectadas que siguen activas */}
      <div className="status-item">
        <div className={`dot ${status.active_threats > 0 ? 'red' : 'green'}`} />
        <span>
          {status.active_threats > 0
            ? `${status.active_threats} amenaza${status.active_threats !== 1 ? 's' : ''} activa${status.active_threats !== 1 ? 's' : ''}`
            : 'Sin amenazas activas'}
        </span>
      </div>

      {/* Sesiones registradas durante la última hora */}
      <div className="status-item">
        <div className="dot yellow" />
        <span>
          {status.sessions_last_hour} {status.sessions_last_hour === 1 ? 'sesión' : 'sesiones'} en la última hora
        </span>
      </div>
    </div>
  )
}
