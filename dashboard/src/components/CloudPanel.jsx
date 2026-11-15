
export default function CloudPanel({ quarantine = [] }) {
  const total = quarantine.reduce(
    (sum, q) => sum + (q.quarantined_count || 0),
    0
  )

  return (
    <div className="card">
      <div className="card-header">
        <span>🛡️ Cuarentena local</span>

        <span className={`badge ${total > 0 ? 'warn' : 'benign'}`}>
          {total} archivo{total !== 1 ? 's' : ''} en cuarentena
        </span>
      </div>

      {quarantine.length === 0 ? (
        <div className="empty" style={{ padding: '16px' }}>
          No hay archivos registrados en cuarentena.
        </div>
      ) : (
        <div className="card-body" style={{ padding: '8px 16px' }}>
          {quarantine.map((q, i) => (
            <div key={q.session_id || i} className="quarantine-item">
              <div className="q-session">
                Sesión: {q.session_id} — {q.quarantined_count} archivo
                {q.quarantined_count !== 1 ? 's' : ''}
              </div>

              <div className="q-meta">
                Proceso: {q.process_name || '—'} &nbsp;|&nbsp;
                Riesgo: {Number(q.risk_score || 0).toFixed(0)}/100 &nbsp;|&nbsp;
                {q.quarantined_at
                  ? new Date(q.quarantined_at).toLocaleTimeString('es-CO')
                  : 'Fecha no disponible'}
              </div>
            </div>
          ))}

          <div
            style={{
              marginTop: 10,
              fontSize: 11,
              color: 'var(--text-muted)',
              fontStyle: 'italic',
            }}
          >
            Archivos gestionados por el módulo local de cuarentena del backend.
            Esta función no representa una conexión con un proveedor de almacenamiento en la nube.
          </div>
        </div>
      )}
    </div>
  )
}
