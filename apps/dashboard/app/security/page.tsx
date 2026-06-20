'use client'

import { useEffect, useState } from 'react'

// =====================================================================
// Types
// =====================================================================

interface RiskScore {
  pid: number
  agent_name: string
  total_score: number
  destination_score: number
  traffic_score: number
  time_score: number
  behavior_score: number
  reasons: string[]
  risk_level: string
}

interface AnomalyRecord {
  id: string
  pid: number
  agent_name: string
  anomaly_type: string
  severity: string
  description: string
  current_value: number
  baseline_value: number
  deviation: number
  detected_at: string
  resolved: boolean
}

interface OperationsData {
  total_agents: number
  total_anomalies: number
  unresolved_anomalies: number
  high_risk_agents: number
  critical_risk_agents: number
  learning_count: number
  established_count: number
  average_risk_score: number
  recent_anomalies: AnomalyRecord[]
  top_risk_agents: { pid: number; agent_name: string; total_score: number; risk_level: string }[]
}

interface TimelineEntry {
  id?: string
  event_type: string
  severity: string
  title?: string
  description?: string
  message?: string
  agent_name?: string
  pid?: number
  created_at: string
  detected_at?: string
}

interface CorrelationAlert {
  correlation_type: string
  description: string
  severity: string
  affected_agents: string[]
  detected_at: string
  average_score?: number
}

interface SecurityIncident {
  id: string
  pid: number
  agent_name: string
  incident_type: string
  severity: string
  description: string
  state: string
  detected_at: string
  deviation?: number
}

// =====================================================================
// Helpers
// =====================================================================

function getRiskColor(score: number) {
  if (score <= 20) return 'text-green-400'
  if (score <= 50) return 'text-yellow-400'
  if (score <= 80) return 'text-orange-400'
  return 'text-red-400'
}

function getRiskBg(level: string) {
  switch (level) {
    case 'Normal': return 'bg-green-900/50 text-green-300'
    case 'Suspicious': return 'bg-yellow-900/50 text-yellow-300'
    case 'HighRisk': return 'bg-orange-900/50 text-orange-300'
    case 'Critical': return 'bg-red-900/50 text-red-300'
    default: return 'bg-gray-800 text-gray-300'
  }
}

function getSeverityColor(severity: string) {
  switch (severity) {
    case 'Critical': return 'text-red-300 bg-red-900/50 border-red-800'
    case 'High': return 'text-orange-300 bg-orange-900/50 border-orange-800'
    case 'Medium': return 'text-yellow-300 bg-yellow-900/50 border-yellow-800'
    case 'Low': return 'text-blue-300 bg-blue-900/50 border-blue-800'
    default: return 'text-gray-300 bg-gray-800 border-gray-700'
  }
}

function getSeverityDot(severity: string) {
  switch (severity) {
    case 'Critical': return 'bg-red-500'
    case 'High': return 'bg-orange-500'
    case 'Medium': return 'bg-yellow-500'
    case 'Low': return 'bg-blue-500'
    default: return 'bg-gray-500'
  }
}

function formatTime(iso: string) {
  try {
    const d = new Date(iso)
    return d.toLocaleString()
  } catch {
    return iso
  }
}

function timeAgo(iso: string) {
  try {
    const d = new Date(iso)
    const now = new Date()
    const diff = now.getTime() - d.getTime()
    const mins = Math.floor(diff / 60000)
    if (mins < 1) return 'just now'
    if (mins < 60) return `${mins}m ago`
    const hours = Math.floor(mins / 60)
    if (hours < 24) return `${hours}h ago`
    const days = Math.floor(hours / 24)
    return `${days}d ago`
  } catch {
    return ''
  }
}

// =====================================================================
// Main Component
// =====================================================================

export default function SecurityDashboard() {
  const [riskScores, setRiskScores] = useState<RiskScore[]>([])
  const [anomalies, setAnomalies] = useState<AnomalyRecord[]>([])
  const [operations, setOperations] = useState<OperationsData | null>(null)
  const [timeline, setTimeline] = useState<TimelineEntry[]>([])
  const [correlations, setCorrelations] = useState<CorrelationAlert[]>([])
  const [incidents, setIncidents] = useState<SecurityIncident[]>([])
  const [selectedPid, setSelectedPid] = useState<number | null>(null)
  const [loading, setLoading] = useState(true)
  const [activeTab, setActiveTab] = useState<'ops' | 'overview' | 'anomalies' | 'timeline' | 'correlation' | 'details'>('ops')

  useEffect(() => {
    fetchAllData()
    const interval = setInterval(fetchAllData, 5000)
    return () => clearInterval(interval)
  }, [])

  async function fetchAllData() {
    try {
      const apiUrl = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3000'

      const [riskRes, anomalyRes, opsRes, timelineRes, correlationRes, incidentRes] = await Promise.all([
        fetch(`${apiUrl}/api/security/risk-scores`),
        fetch(`${apiUrl}/api/security/anomalies`),
        fetch(`${apiUrl}/api/security/operations`),
        fetch(`${apiUrl}/api/security/timeline`),
        fetch(`${apiUrl}/api/security/correlation`),
        fetch(`${apiUrl}/api/security/incidents`),
      ])

      if (riskRes.ok) {
        const data = await riskRes.json()
        setRiskScores(data.risk_scores || [])
      }
      if (anomalyRes.ok) {
        const data = await anomalyRes.json()
        setAnomalies(data.anomalies || [])
      }
      if (opsRes.ok) {
        const data = await opsRes.json()
        setOperations(data)
      }
      if (timelineRes.ok) {
        const data = await timelineRes.json()
        const entries = (data.timeline || []).map((e: any) => ({
          ...e,
          created_at: e.created_at || e.detected_at || new Date().toISOString(),
        }))
        setTimeline(entries.slice(0, 50))
      }
      if (correlationRes.ok) {
        const data = await correlationRes.json()
        setCorrelations(data.correlation_alerts || [])
      }
      if (incidentRes.ok) {
        const data = await incidentRes.json()
        setIncidents(data.incidents || [])
      }
    } catch (error) {
      console.error('Failed to fetch security data:', error)
    } finally {
      setLoading(false)
    }
  }

  const selectedAgent = selectedPid ? riskScores.find(r => r.pid === selectedPid) || null : null
  const selectedAnomalies = selectedPid ? anomalies.filter(a => a.pid === selectedPid) : anomalies
  const unresolvedAnomalies = anomalies.filter(a => !a.resolved)
  const criticalAnomalies = anomalies.filter(a => a.severity === 'Critical' && !a.resolved)
  const highRiskAgents = riskScores.filter(r => r.total_score > 50)

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-950">
        <div className="text-xl text-gray-400">Loading security data...</div>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-gray-950 text-gray-100">
      {/* Header */}
      <header className="bg-gray-900 border-b border-gray-800">
        <div className="max-w-7xl mx-auto px-4 py-4">
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-2xl font-bold text-white">Security Operations</h1>
              <p className="text-sm text-gray-400 mt-1">
                Runtime Security Control Loop — Detection & Correlation
              </p>
            </div>
            <div className="flex items-center gap-4">
              <a href="/" className="text-sm text-gray-400 hover:text-white transition-colors">Main Dashboard</a>
            </div>
          </div>
        </div>
      </header>

      {/* Alert banners */}
      <div className="max-w-7xl mx-auto px-4 py-4 space-y-2">
        {criticalAnomalies.length > 0 && (
          <div className="bg-red-900/50 border border-red-800 rounded-lg px-4 py-3 flex items-center gap-3">
            <span className="w-2 h-2 rounded-full bg-red-500 animate-pulse" />
            <span className="text-red-200 text-sm font-medium">
              {criticalAnomalies.length} critical unresolved {criticalAnomalies.length === 1 ? 'anomaly' : 'anomalies'}
            </span>
          </div>
        )}
        {highRiskAgents.length > 2 && (
          <div className="bg-orange-900/50 border border-orange-800 rounded-lg px-4 py-3 flex items-center gap-3">
            <span className="w-2 h-2 rounded-full bg-orange-500" />
            <span className="text-orange-200 text-sm font-medium">
              {highRiskAgents.length} agents with high or critical risk scores
            </span>
          </div>
        )}
      </div>

      {/* Tab navigation */}
      <div className="max-w-7xl mx-auto px-4 mb-6">
        <nav className="flex gap-1 border-b border-gray-800 overflow-x-auto">
          {[
            { id: 'ops' as const, label: 'Operations', count: undefined },
            { id: 'overview' as const, label: 'Agents', count: riskScores.length },
            { id: 'anomalies' as const, label: 'Anomalies', count: unresolvedAnomalies.length },
            { id: 'timeline' as const, label: 'Timeline', count: timeline.length },
            { id: 'correlation' as const, label: 'Correlation', count: correlations.length },
            { id: 'details' as const, label: 'Details' },
          ].map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`px-4 py-2.5 text-sm font-medium border-b-2 transition-colors whitespace-nowrap ${
                activeTab === tab.id
                  ? 'border-blue-500 text-blue-400'
                  : 'border-transparent text-gray-500 hover:text-gray-300 hover:border-gray-600'
              }`}
            >
              {tab.label}
              {tab.count !== undefined && (
                <span className={`ml-2 px-2 py-0.5 rounded-full text-xs ${
                  activeTab === tab.id ? 'bg-blue-900/50 text-blue-300' : 'bg-gray-800 text-gray-400'
                }`}>
                  {tab.count}
                </span>
              )}
            </button>
          ))}
        </nav>
      </div>

      {/* ================================================================ */}
      {/* OPERATIONS TAB — Security Ops Dashboard */}
      {/* ================================================================ */}
      {activeTab === 'ops' && (
        <main className="max-w-7xl mx-auto px-4 pb-8">
          {/* Key metrics */}
          <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-3 mb-6">
            <div className="bg-gray-900 rounded-lg border border-gray-800 p-3">
              <div className="text-xs text-gray-400 mb-1">Total Risk Score</div>
              <div className="text-xl font-bold text-white">
                {operations ? Math.round(operations.average_risk_score) : 0}
              </div>
            </div>
            <div className="bg-gray-900 rounded-lg border border-gray-800 p-3">
              <div className="text-xs text-gray-400 mb-1">Active Incidents</div>
              <div className={`text-xl font-bold ${incidents.length > 0 ? 'text-red-400' : 'text-green-400'}`}>
                {incidents.length}
              </div>
            </div>
            <div className="bg-gray-900 rounded-lg border border-gray-800 p-3">
              <div className="text-xs text-gray-400 mb-1">High Risk</div>
              <div className="text-xl font-bold text-orange-400">
                {operations?.high_risk_agents || 0}
              </div>
            </div>
            <div className="bg-gray-900 rounded-lg border border-gray-800 p-3">
              <div className="text-xs text-gray-400 mb-1">Critical Risk</div>
              <div className={`text-xl font-bold ${(operations?.critical_risk_agents || 0) > 0 ? 'text-red-400' : 'text-gray-400'}`}>
                {operations?.critical_risk_agents || 0}
              </div>
            </div>
            <div className="bg-gray-900 rounded-lg border border-gray-800 p-3">
              <div className="text-xs text-gray-400 mb-1">Learning</div>
              <div className="text-xl font-bold text-yellow-400">{operations?.learning_count || 0}</div>
            </div>
            <div className="bg-gray-900 rounded-lg border border-gray-800 p-3">
              <div className="text-xs text-gray-400 mb-1">Established</div>
              <div className="text-xl font-bold text-green-400">{operations?.established_count || 0}</div>
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
            {/* Top Risk Agents */}
            <div className="bg-gray-900 rounded-lg border border-gray-800">
              <div className="px-4 py-3 border-b border-gray-800">
                <h2 className="text-sm font-semibold text-white">Top Risk Agents</h2>
              </div>
              <div className="divide-y divide-gray-800">
                {(!operations?.top_risk_agents || operations.top_risk_agents.length === 0) ? (
                  <div className="px-4 py-6 text-center text-gray-500 text-sm">No agents tracked</div>
                ) : (
                  operations.top_risk_agents.map((agent) => (
                    <button
                      key={agent.pid}
                      onClick={() => { setSelectedPid(agent.pid); setActiveTab('details') }}
                      className="w-full px-4 py-2.5 flex items-center justify-between hover:bg-gray-800/50 transition-colors text-left"
                    >
                      <div className="flex items-center gap-2">
                        <div className={`w-1.5 h-1.5 rounded-full ${getSeverityDot(
                          agent.risk_level === 'Critical' ? 'Critical' :
                          agent.risk_level === 'HighRisk' ? 'High' :
                          agent.risk_level === 'Suspicious' ? 'Medium' : 'Low'
                        )}`} />
                        <span className="text-sm text-gray-200">{agent.agent_name}</span>
                      </div>
                      <span className={`text-sm font-bold ${getRiskColor(agent.total_score)}`}>
                        {agent.total_score}
                      </span>
                    </button>
                  ))
                )}
              </div>
            </div>

            {/* Recent Anomalies */}
            <div className="bg-gray-900 rounded-lg border border-gray-800">
              <div className="px-4 py-3 border-b border-gray-800">
                <h2 className="text-sm font-semibold text-white">Recent Anomalies</h2>
              </div>
              <div className="divide-y divide-gray-800">
                {(!operations?.recent_anomalies || operations.recent_anomalies.length === 0) ? (
                  <div className="px-4 py-6 text-center text-gray-500 text-sm">No anomalies detected</div>
                ) : (
                  operations.recent_anomalies.map((a: any, i: number) => (
                    <div key={i} className="px-4 py-2.5">
                      <div className="flex items-center gap-2 mb-0.5">
                        <span className={`text-xs px-1.5 py-0.5 rounded ${getSeverityColor(a.severity)}`}>
                          {a.severity}
                        </span>
                        <span className="text-xs text-gray-500">{a.agent_name}</span>
                      </div>
                      <p className="text-xs text-gray-400 truncate">{a.description}</p>
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>

          {/* Correlation Alerts Section */}
          {correlations.length > 0 && (
            <div className="bg-gray-900 rounded-lg border border-gray-800 mb-6">
              <div className="px-4 py-3 border-b border-gray-800">
                <h2 className="text-sm font-semibold text-white">
                  Correlation Alerts ({correlations.length})
                </h2>
              </div>
              <div className="divide-y divide-gray-800">
                {correlations.map((c, i) => (
                  <div key={i} className="px-4 py-3">
                    <div className="flex items-center gap-2 mb-1">
                      <span className={`text-xs px-1.5 py-0.5 rounded ${getSeverityColor(c.severity)}`}>
                        {c.severity}
                      </span>
                      <span className="text-xs text-gray-400">{c.correlation_type.replace(/([A-Z])/g, ' $1').trim()}</span>
                    </div>
                    <p className="text-sm text-gray-300">{c.description}</p>
                    <div className="flex flex-wrap gap-1 mt-1">
                      {c.affected_agents.map((name, j) => (
                        <span key={j} className="text-xs px-1.5 py-0.5 rounded bg-gray-800 text-gray-400">{name}</span>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Baseline Learning Status */}
          <div className="bg-gray-900 rounded-lg border border-gray-800">
            <div className="px-4 py-3 border-b border-gray-800">
              <h2 className="text-sm font-semibold text-white">Learning Status</h2>
            </div>
            <div className="p-4">
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm text-gray-400">Baseline Learning Progress</span>
                <span className="text-sm text-gray-300">
                  {operations?.established_count || 0} / {operations?.total_agents || 0} established
                </span>
              </div>
              <div className="w-full bg-gray-800 rounded-full h-2">
                <div
                  className="bg-blue-600 h-2 rounded-full transition-all duration-500"
                  style={{
                    width: `${(operations?.total_agents || 0) > 0
                      ? ((operations?.established_count || 0) / (operations?.total_agents || 1)) * 100
                      : 0}%`
                  }}
                />
              </div>
              <p className="text-xs text-gray-500 mt-2">
                {operations?.learning_count || 0} agent{(operations?.learning_count || 0) !== 1 ? 's' : ''} still learning — incidents suppressed during learning phase
              </p>
            </div>
          </div>
        </main>
      )}

      {/* ================================================================ */}
      {/* OVERVIEW TAB */}
      {/* ================================================================ */}
      {activeTab === 'overview' && (
        <main className="max-w-7xl mx-auto px-4 pb-8">
          {/* Stats cards */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
            <div className="bg-gray-900 rounded-lg border border-gray-800 p-4">
              <div className="text-sm text-gray-400 mb-1">Tracked Agents</div>
              <div className="text-2xl font-bold text-white">{riskScores.length}</div>
            </div>
            <div className="bg-gray-900 rounded-lg border border-gray-800 p-4">
              <div className="text-sm text-gray-400 mb-1">Unresolved Anomalies</div>
              <div className="text-2xl font-bold text-orange-400">{unresolvedAnomalies.length}</div>
            </div>
            <div className="bg-gray-900 rounded-lg border border-gray-800 p-4">
              <div className="text-sm text-gray-400 mb-1">High Risk Agents</div>
              <div className="text-2xl font-bold text-red-400">{highRiskAgents.length}</div>
            </div>
            <div className="bg-gray-900 rounded-lg border border-gray-800 p-4">
              <div className="text-sm text-gray-400 mb-1">Average Risk Score</div>
              <div className="text-2xl font-bold text-blue-400">
                {riskScores.length > 0
                  ? Math.round(riskScores.reduce((s, r) => s + r.total_score, 0) / riskScores.length)
                  : 0}
              </div>
            </div>
          </div>

          {/* Risk score list */}
          <div className="bg-gray-900 rounded-lg border border-gray-800">
            <div className="px-6 py-4 border-b border-gray-800">
              <h2 className="text-lg font-semibold text-white">Agent Risk Scores</h2>
            </div>
            <div className="divide-y divide-gray-800">
              {riskScores.length === 0 ? (
                <div className="px-6 py-8 text-center text-gray-500">
                  <p className="text-lg mb-2">No agents with security profiles</p>
                  <p className="text-sm">Agents will appear once discovered and generating network activity</p>
                </div>
              ) : (
                riskScores
                  .sort((a, b) => b.total_score - a.total_score)
                  .map((agent) => (
                    <button
                      key={agent.pid}
                      onClick={() => { setSelectedPid(agent.pid); setActiveTab('details') }}
                      className="w-full px-6 py-4 flex items-center justify-between hover:bg-gray-800/50 transition-colors text-left"
                    >
                      <div className="flex items-center gap-4">
                        <div className={`w-2 h-2 rounded-full ${getSeverityDot(
                          agent.risk_level === 'Normal' ? 'Low' :
                          agent.risk_level === 'Suspicious' ? 'Medium' :
                          agent.risk_level === 'HighRisk' ? 'High' : 'Critical'
                        )}`} />
                        <div>
                          <div className="font-medium text-white">{agent.agent_name}</div>
                          <div className="text-sm text-gray-400">PID: {agent.pid}</div>
                        </div>
                      </div>
                      <div className="flex items-center gap-3">
                        <div className="text-right">
                          <div className={`text-2xl font-bold ${getRiskColor(agent.total_score)}`}>
                            {agent.total_score}
                          </div>
                          <div className={`text-xs px-2 py-0.5 rounded-full ${getRiskBg(agent.risk_level)}`}>
                            {agent.risk_level === 'HighRisk' ? 'HIGH' : agent.risk_level.toUpperCase()}
                          </div>
                        </div>
                        <svg className="w-4 h-4 text-gray-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                        </svg>
                      </div>
                    </button>
                  ))
              )}
            </div>
          </div>
        </main>
      )}

      {/* ================================================================ */}
      {/* ANOMALIES TAB */}
      {/* ================================================================ */}
      {activeTab === 'anomalies' && (
        <main className="max-w-7xl mx-auto px-4 pb-8">
          <div className="bg-gray-900 rounded-lg border border-gray-800">
            <div className="px-6 py-4 border-b border-gray-800 flex items-center justify-between">
              <h2 className="text-lg font-semibold text-white">Security Anomalies</h2>
              <span className="text-xs text-gray-500">{unresolvedAnomalies.length} unresolved</span>
            </div>
            <div className="divide-y divide-gray-800">
              {anomalies.length === 0 ? (
                <div className="px-6 py-8 text-center text-gray-500">
                  <p className="text-lg mb-2">No anomalies detected</p>
                  <p className="text-sm">Anomalies appear when behavior deviates from learned baselines</p>
                </div>
              ) : (
                [...anomalies]
                  .sort((a, b) => new Date(b.detected_at).getTime() - new Date(a.detected_at).getTime())
                  .map((anomaly) => (
                    <div key={anomaly.id} className="px-6 py-4">
                      <div className="flex items-start justify-between">
                        <div className="flex-1">
                          <div className="flex items-center gap-2 mb-1">
                            <div className={`w-2 h-2 rounded-full ${getSeverityDot(anomaly.severity)}`} />
                            <span className={`text-xs font-medium px-2 py-0.5 rounded-full border ${getSeverityColor(anomaly.severity)}`}>
                              {anomaly.severity.toUpperCase()}
                            </span>
                            <span className="text-xs font-medium px-2 py-0.5 rounded-full bg-gray-800 text-gray-300">
                              {anomaly.anomaly_type.replace(/([A-Z])/g, ' $1').trim()}
                            </span>
                            {anomaly.resolved && <span className="text-xs text-green-400">Resolved</span>}
                          </div>
                          <h3 className="text-sm font-medium text-white">{anomaly.description}</h3>
                          <div className="mt-1 text-xs text-gray-400">
                            {anomaly.agent_name} | PID: {anomaly.pid} | Deviation: {anomaly.deviation.toFixed(1)}x
                          </div>
                          <div className="mt-0.5 text-xs text-gray-500">{formatTime(anomaly.detected_at)}</div>
                        </div>
                      </div>
                    </div>
                  ))
              )}
            </div>
          </div>
        </main>
      )}

      {/* ================================================================ */}
      {/* TIMELINE TAB */}
      {/* ================================================================ */}
      {activeTab === 'timeline' && (
        <main className="max-w-7xl mx-auto px-4 pb-8">
          <div className="bg-gray-900 rounded-lg border border-gray-800">
            <div className="px-6 py-4 border-b border-gray-800">
              <h2 className="text-lg font-semibold text-white">Security Timeline</h2>
              <p className="text-xs text-gray-500 mt-0.5">Chronological event history for investigations</p>
            </div>
            <div className="relative px-6 py-4">
              {timeline.length === 0 ? (
                <div className="text-center text-gray-500 py-8 text-sm">
                  No timeline events recorded yet
                </div>
              ) : (
                <div className="space-y-0">
                  {timeline.slice(0, 30).map((entry, i) => (
                    <div key={i} className="flex gap-3 py-2">
                      {/* Timeline line */}
                      <div className="flex flex-col items-center">
                        <div className={`w-2.5 h-2.5 rounded-full ${
                          entry.severity === 'critical' || entry.severity === 'Critical' ? 'bg-red-500' :
                          entry.severity === 'high' || entry.severity === 'High' ? 'bg-orange-500' :
                          entry.severity === 'warning' || entry.severity === 'Medium' ? 'bg-yellow-500' :
                          'bg-blue-500'
                        } ring-4 ring-gray-900`} />
                        {i < Math.min(timeline.length, 30) - 1 && (
                          <div className="w-px h-full min-h-[2rem] bg-gray-800" />
                        )}
                      </div>
                      {/* Content */}
                      <div className="flex-1 pb-3">
                        <div className="flex items-center gap-2">
                          <span className={`text-xs px-1.5 py-0.5 rounded ${
                            entry.severity === 'critical' || entry.severity === 'Critical' ? 'bg-red-900/50 text-red-300' :
                            entry.severity === 'high' || entry.severity === 'High' ? 'bg-orange-900/50 text-orange-300' :
                            'bg-blue-900/50 text-blue-300'
                          }`}>
                            {entry.event_type?.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase()) || 'Event'}
                          </span>
                          <span className="text-xs text-gray-500">{timeAgo(entry.created_at)}</span>
                        </div>
                        <p className="text-sm text-gray-300 mt-0.5">{entry.message || entry.description || entry.title || ''}</p>
                        {entry.agent_name && (
                          <p className="text-xs text-gray-500 mt-0.5">{entry.agent_name}</p>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </main>
      )}

      {/* ================================================================ */}
      {/* CORRELATION TAB */}
      {/* ================================================================ */}
      {activeTab === 'correlation' && (
        <main className="max-w-7xl mx-auto px-4 pb-8">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
            <div className="bg-gray-900 rounded-lg border border-gray-800 p-4">
              <div className="text-xs text-gray-400 mb-1">Total Agents</div>
              <div className="text-2xl font-bold text-white">{riskScores.length}</div>
            </div>
            <div className="bg-gray-900 rounded-lg border border-gray-800 p-4">
              <div className="text-xs text-gray-400 mb-1">High Risk Agents</div>
              <div className="text-2xl font-bold text-orange-400">{highRiskAgents.length}</div>
            </div>
          </div>

          {/* Risk Distribution */}
          <div className="bg-gray-900 rounded-lg border border-gray-800 mb-6">
            <div className="px-4 py-3 border-b border-gray-800">
              <h2 className="text-sm font-semibold text-white">Risk Distribution</h2>
            </div>
            <div className="p-4">
              <div className="grid grid-cols-4 gap-2">
                {[
                  { label: 'Normal', count: riskScores.filter(r => r.total_score <= 20).length, color: 'bg-green-600' },
                  { label: 'Suspicious', count: riskScores.filter(r => r.total_score > 20 && r.total_score <= 50).length, color: 'bg-yellow-600' },
                  { label: 'High', count: riskScores.filter(r => r.total_score > 50 && r.total_score <= 80).length, color: 'bg-orange-600' },
                  { label: 'Critical', count: riskScores.filter(r => r.total_score > 80).length, color: 'bg-red-600' },
                ].map(bucket => (
                  <div key={bucket.label} className="text-center">
                    <div className={`text-xl font-bold text-white`}>{bucket.count}</div>
                    <div className="text-xs text-gray-400">{bucket.label}</div>
                  </div>
                ))}
              </div>
              <div className="flex h-2 rounded-full overflow-hidden mt-3 bg-gray-800">
                {[
                  { count: riskScores.filter(r => r.total_score <= 20).length, color: 'bg-green-600' },
                  { count: riskScores.filter(r => r.total_score > 20 && r.total_score <= 50).length, color: 'bg-yellow-600' },
                  { count: riskScores.filter(r => r.total_score > 50 && r.total_score <= 80).length, color: 'bg-orange-600' },
                  { count: riskScores.filter(r => r.total_score > 80).length, color: 'bg-red-600' },
                ].map((bucket, i) => (
                  <div
                    key={i}
                    className={`${bucket.color} transition-all duration-500`}
                    style={{
                      width: `${riskScores.length > 0 ? (bucket.count / riskScores.length) * 100 : 0}%`
                    }}
                  />
                ))}
              </div>
            </div>
          </div>

          {/* Correlation Alerts */}
          <div className="bg-gray-900 rounded-lg border border-gray-800">
            <div className="px-4 py-3 border-b border-gray-800">
              <h2 className="text-sm font-semibold text-white">Cross-Agent Correlation Alerts</h2>
            </div>
            <div className="divide-y divide-gray-800">
              {correlations.length === 0 ? (
                <div className="px-4 py-8 text-center text-gray-500 text-sm">
                  No correlation alerts. With 2+ agents, cross-agent patterns will be detected automatically.
                </div>
              ) : (
                correlations.map((c, i) => (
                  <div key={i} className="px-4 py-3">
                    <div className="flex items-center gap-2 mb-1">
                      <span className={`text-xs px-1.5 py-0.5 rounded ${getSeverityColor(c.severity)}`}>
                        {c.severity}
                      </span>
                      <span className="text-xs font-medium text-gray-300">
                        {c.correlation_type.replace(/([A-Z])/g, ' $1').trim()}
                      </span>
                      <span className="text-xs text-gray-500 ml-auto">{timeAgo(c.detected_at)}</span>
                    </div>
                    <p className="text-sm text-gray-300">{c.description}</p>
                    <div className="flex flex-wrap gap-1 mt-1.5">
                      {c.affected_agents.map((name, j) => (
                        <button
                          key={j}
                          onClick={() => {
                            const agent = riskScores.find(r => r.agent_name === name)
                            if (agent) { setSelectedPid(agent.pid); setActiveTab('details') }
                          }}
                          className="text-xs px-2 py-0.5 rounded-full bg-gray-800 text-gray-400 hover:bg-gray-700 hover:text-white transition-colors"
                        >
                          {name}
                        </button>
                      ))}
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        </main>
      )}

      {/* ================================================================ */}
      {/* DETAILS TAB */}
      {/* ================================================================ */}
      {activeTab === 'details' && selectedPid && selectedAgent && (
        <main className="max-w-7xl mx-auto px-4 pb-8">
          {/* Agent header */}
          <div className="bg-gray-900 rounded-lg border border-gray-800 p-6 mb-6">
            <div className="flex items-center justify-between mb-4">
              <div>
                <h2 className="text-xl font-bold text-white">{selectedAgent.agent_name}</h2>
                <p className="text-sm text-gray-400">PID: {selectedAgent.pid}</p>
              </div>
              <div className="text-right">
                <div className={`text-3xl font-bold ${getRiskColor(selectedAgent.total_score)}`}>
                  {selectedAgent.total_score}
                </div>
                <div className={`text-xs px-2 py-0.5 rounded-full mt-1 ${getRiskBg(selectedAgent.risk_level)}`}>
                  {selectedAgent.risk_level === 'HighRisk' ? 'HIGH RISK' : selectedAgent.risk_level.toUpperCase()}
                </div>
              </div>
            </div>

            {/* Component scores */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-4">
              {[
                { label: 'Destination', score: selectedAgent.destination_score, color: 'text-blue-400' },
                { label: 'Traffic', score: selectedAgent.traffic_score, color: 'text-purple-400' },
                { label: 'Timing', score: selectedAgent.time_score, color: 'text-cyan-400' },
                { label: 'Behavior', score: selectedAgent.behavior_score, color: 'text-pink-400' },
              ].map(comp => (
                <div key={comp.label} className="bg-gray-800 rounded-lg p-3">
                  <div className="text-xs text-gray-400 mb-1">{comp.label}</div>
                  <div className={`text-lg font-bold ${comp.color}`}>{comp.score}</div>
                </div>
              ))}
            </div>

            {/* Risk Factors */}
            {selectedAgent.reasons.length > 0 && (
              <div>
                <h3 className="text-sm font-medium text-gray-400 mb-2">Risk Factors</h3>
                <ul className="space-y-1">
                  {selectedAgent.reasons.map((reason, i) => (
                    <li key={i} className="text-sm text-gray-300 flex items-center gap-2">
                      <span className="w-1.5 h-1.5 rounded-full bg-orange-500 flex-shrink-0" />
                      {reason}
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>

          {/* Timeline for this agent */}
          <div className="bg-gray-900 rounded-lg border border-gray-800 mb-6">
            <div className="px-6 py-4 border-b border-gray-800">
              <h2 className="text-lg font-semibold text-white">Agent Timeline</h2>
            </div>
            <div className="divide-y divide-gray-800">
              {selectedAnomalies.length === 0 ? (
                <div className="px-6 py-4 text-center text-gray-500 text-sm">No events for this agent</div>
              ) : (
                [...selectedAnomalies]
                  .sort((a, b) => new Date(b.detected_at).getTime() - new Date(a.detected_at).getTime())
                  .map((anomaly) => (
                    <div key={anomaly.id} className="px-6 py-3">
                      <div className="flex items-center gap-2 mb-1">
                        <span className={`text-xs px-2 py-0.5 rounded ${getSeverityColor(anomaly.severity)}`}>
                          {anomaly.severity}
                        </span>
                        <span className="text-xs text-gray-400">
                          {anomaly.anomaly_type.replace(/([A-Z])/g, ' $1').trim()}
                        </span>
                        <span className="text-xs text-gray-500 ml-auto">{formatTime(anomaly.detected_at)}</span>
                      </div>
                      <p className="text-sm text-gray-300">{anomaly.description}</p>
                    </div>
                  ))
              )}
            </div>
          </div>
        </main>
      )}

      {/* Empty state for agent details */}
      {activeTab === 'details' && !selectedPid && (
        <main className="max-w-7xl mx-auto px-4 pb-8">
          <div className="bg-gray-900 rounded-lg border border-gray-800 p-12 text-center">
            <svg className="w-16 h-16 mx-auto text-gray-700 mb-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
            </svg>
            <p className="text-gray-400 text-lg mb-2">Select an agent from the Overview tab</p>
            <p className="text-gray-600 text-sm">View detailed risk scores, anomalies, and security profiles</p>
          </div>
        </main>
      )}
    </div>
  )
}
