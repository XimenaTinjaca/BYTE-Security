function RiskBar({ score }) {
  const color = score >= 70
    ? 'var(--red)'
    : score >= 40
      ? 'var(--yellow)'
      : 'var(--green)'

  return (
    <div className="risk-bar-wrap">
      <div className="risk-bar-track">
        <div
          className="risk-bar-fill"
          style={{ width: `${score}%`, background: color }}
        />
      </div>
    </div>
  )
}

export default function MetricCards({ stats }) {
  const s = stats || {}

  return (
    <div className="metric-cards">
      <div className="metric-card info">
        <div className="label">Total de sesiones</div>
        <div className="value">{s.total_sessions ?? '—'}</div>
        <div className="sub">Histórico completo</div>
      </div>

      <div className="metric-card threat">
        <div className="label">Amenazas detectadas</div>
        <div className="value">{s.total_threats ?? '—'}</div>
        <div className="sub">Patrones de ransomware</div>
      </div>

      <div className="metric-card safe">
        <div className="label">Sesiones seguras</div>
        <div className="value">{s.benign_sessions ?? '—'}</div>
        <div className="sub">Clasificadas como benignas</div>
      </div>

      <div className="metric-card warn">
        <div className="label">Riesgo promedio</div>
        <div className="value">
          {s.avg_risk_score != null ? s.avg_risk_score.toFixed(1) : '—'}
        </div>
        <div className="sub">En todas las sesiones</div>
        {s.avg_risk_score != null && <RiskBar score={s.avg_risk_score} />}
      </div>
    </div>
  )
}
