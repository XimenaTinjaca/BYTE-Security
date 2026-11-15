function fmt(dt) {
  if (!dt) return '—'
  return new Date(dt).toLocaleString('es-CO')
}

function getStatusLabel(status) {
  const labels = {
    active: 'Activa',
    recovered: 'Recuperada',
    recovery_partial: 'Recuperación parcial',
  }

  return labels[status] || status
}

export default function ThreatTable({ threats, onRestore }) {
  const active = threats.filter(t => t.status === 'active')

  return (
    <div className="card">
      <div className="card-header">
        <span>Historial de amenazas</span>

        <span className={`badge ${active.length > 0 ? 'ransom' : 'benign'}`}>
          {active.length} activas
        </span>
      </div>

      {threats.length === 0 ? (
        <div className="empty">
          No se han detectado amenazas.
        </div>
      ) : (
        <div className="scroll-body">
          {threats.map(t => (
            <div
              key={t.id}
              style={{
                padding: '10px 16px',
                borderBottom: '1px solid var(--border)',
                display: 'flex',
                flexDirection: 'column',
                gap: 4,
              }}
            >
              <div style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
              }}>
                <span style={{
                  fontFamily: 'var(--font)',
                  fontSize: 12,
                  color: 'var(--red)',
                }}>
                  {t.session_id}
                </span>

                <span className={`badge ${
                  t.status === 'recovered' ? 'benign'
                  : t.status === 'active' ? 'ransom'
                  : 'warn'
                }`}>
                  {getStatusLabel(t.status)}
                </span>
              </div>

              <div style={{
                display: 'flex',
                gap: 12,
                fontSize: 12,
                color: 'var(--text-muted)',
                flexWrap: 'wrap',
              }}>
                <span>Proceso: {t.process_name || '—'}</span>
                <span>Archivos: {t.files_affected}</span>

                <span style={{
                  color: t.risk_score >= 70
                    ? 'var(--red)'
                    : 'var(--yellow)',
                  fontWeight: 700,
                }}>
                  Riesgo: {Number(t.risk_score || 0).toFixed(0)}/100
                </span>
              </div>

              <div style={{
                fontSize: 11,
                color: 'var(--text-muted)',
              }}>
                {fmt(t.detected_at)}
              </div>

              {t.status === 'active' && (
                <button
                  className="btn btn-restore"
                  style={{ alignSelf: 'flex-start', marginTop: 4 }}
                  onClick={() => onRestore(t.session_id)}
                >
                  Restaurar archivos
                </button>
              )}

              {t.status === 'recovered' && (
                <button
                  className="btn btn-recovered"
                  style={{ alignSelf: 'flex-start', marginTop: 4 }}
                  disabled
                >
                  Recuperación completada
                </button>
              )}

              {t.status === 'recovery_partial' && (
                <span style={{ color: 'var(--yellow)', fontSize: 12 }}>
                  Recuperación incompleta
                </span>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
