'use client'

import { useEffect, useState } from 'react'

// =====================================================================
// Types
// =====================================================================

interface DecisionRecord {
  id: string
  pid: number
  agent_name: string
  action: string
  reason: string
  rule: string
  confidence: number
  policy_name: string
  timestamp: string
  context: {
    risk_score: number
    risk_level: string
    anomaly_type?: string
    destination?: string
    process_name?: string
    file_path?: string
  }
}

interface ActionRecord {
  id: string
  pid: number
  agent_name: string
  action_type: string
  target: string
  result: string
  timestamp: string
  details: string
}

interface EnforcementIncident {
  id: string
  pid: number
  agent_name: string
  action_type: string
  action_target: string
  status: string
  created_at: string
  resolved_at?: string
  resolution?: string
}

interface EnforcementStats {
  blocked_destinations: number
  allowed_destinations: number
  flagged_processes: number
  file_violations: number
  total_incidents: number
  open_incidents: number
  total_actions: number
  total_decisions: number
  active_overrides: number
}

// =====================================================================
// Helpers
// =====================================================================

function actionColor(action: string) {
  switch (action) {
    case 'Block': return 'text-red-400 bg-red-900/50 border-red-800'
    case 'Flag': return 'text-yellow-300 bg-yellow-900/50 border-yellow-800'
    case 'Allow': return 'text-green-400 bg-green-900/50 border-green-800'
    case 'Restart': return 'text-purple-300 bg-purple-900/50 border-purple-800'
    case 'Escalate': return 'text-orange-300 bg-orange-900/50 border-orange-800'
    default: return 'text-gray-300 bg-gray-800 border-gray-700'
  }
}

function resultColor(result: string) {
  switch (result) {
    case 'Applied': return 'text-green-400'
    case 'Failed': return 'text-red-400'
    case 'Skipped': return 'text-gray-500'
    case 'Overridden': return 'text-yellow-400'
    default: return 'text-gray-500'
  }
}

function formatTime(iso: string) {
  try {
    return new Date(iso).toLocaleString()
  } catch { return iso }
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
  } catch { return '' }
}

// =====================================================================
// Main Component
// =====================================================================

export default function EnforcementDashboard() {
  const [decisions, setDecisions] = useState<DecisionRecord[]>([])
  const [actions, setActions] = useState<ActionRecord[]>([])
  const [incidents, setIncidents] = useState<EnforcementIncident[]>([])
  const [openIncidents, setOpenIncidents] = useState<EnforcementIncident[]>([])
  const [stats, setStats] = useState<EnforcementStats | null>(null)
  const [loading, setLoading] = useState(true)
  const [activeTab, setActiveTab] = useState<'overview' | 'decisions' | 'actions' | 'incidents' | 'lists'>('overview')

  useEffect(() => {
    fetchAllData()
    const interval = setInterval(fetchAllData, 5000)
    return () => clearInterval(interval)
  }, [])

  async function fetchAllData() {
    try {
      const apiUrl = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3000'

      const [decisionsRes, actionsRes, incidentsRes, statsRes, blockRes, allowRes, overridesRes] = await Promise.all([
        fetch(`${apiUrl}/api/enforcement/decisions`),
        fetch(`${apiUrl}/api/enforcement/actions`),
        fetch(`${apiUrl}/api/enforcement/incidents`),
        fetch(`${apiUrl}/api/enforcement/stats`),
        fetch(`${apiUrl}/api/enforcement/lists/block`),
        fetch(`${apiUrl}/api/enforcement/lists/allow`),
        fetch(`${apiUrl}/api/enforcement/overrides`),
      ])

      if (decisionsRes.ok) { const d = await decisionsRes.json(); setDecisions(d.decisions || []) }
      if (actionsRes.ok) { const d = await actionsRes.json(); setActions(d.actions || []) }
      if (incidentsRes.ok) { const d = await incidentsRes.json(); setOpenIncidents(d.open_incidents || []); setIncidents(d.all_incidents || []) }
      if (statsRes.ok) { const d = await statsRes.json(); setStats(d) }
    } catch (error) {
      console.error('Failed to fetch enforcement data:', error)
    } finally {
      setLoading(false)
    }
  }

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-950">
        <div className="text-xl text-gray-400">Loading enforcement data...</div>
      </div>
    )
  }

  const blockCount = stats?.blocked_destinations || 0
  const openIncidentCount = openIncidents.length
  const totalDecisions = decisions.length
  const flaggedProcs = stats?.flagged_processes || 0
  const fileViolations = stats?.file_violations || 0

  return (
    <div className="min-h-screen bg-gray-950 text-gray-100">
      {/* Header */}
      <header className="bg-gray-900 border-b border-gray-800">
        <div className="max-w-7xl mx-auto px-4 py-4">
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-2xl font-bold text-white">Runtime Enforcement</h1>
              <p className="text-sm text-gray-400 mt-1">
                Observe → Decide → Enforce → Audit
              </p>
            </div>
            <div className="flex items-center gap-4">
              <a href="/security" className="text-sm text-gray-400 hover:text-white transition-colors">Security Dashboard</a>
              <a href="/" className="text-sm text-gray-400 hover:text-white transition-colors">Main Dashboard</a>
            </div>
          </div>
        </div>
      </header>

      {/* Alert Banners */}
      <div className="max-w-7xl mx-auto px-4 py-4 space-y-2">
        {openIncidentCount > 0 && (
          <div className="bg-red-900/50 border border-red-800 rounded-lg px-4 py-3 flex items-center gap-3">
            <span className="w-2 h-2 rounded-full bg-red-500 animate-pulse" />
            <span className="text-red-200 text-sm font-medium">
              {openIncidentCount} open enforcement {openIncidentCount === 1 ? 'incident' : 'incidents'}
            </span>
          </div>
        )}
        {blockCount > 0 && (
          <div className="bg-orange-900/50 border border-orange-800 rounded-lg px-4 py-3 flex items-center gap-3">
            <span className="w-2 h-2 rounded-full bg-orange-500" />
            <span className="text-orange-200 text-sm font-medium">
              {blockCount} blocked destinations
            </span>
          </div>
        )}
      </div>

      {/* Tab Navigation */}
      <div className="max-w-7xl mx-auto px-4 mb-6">
        <nav className="flex gap-1 border-b border-gray-800 overflow-x-auto">
          {[
            { id: 'overview' as const, label: 'Overview' },
            { id: 'decisions' as const, label: 'Decisions', count: totalDecisions },
            { id: 'actions' as const, label: 'Actions', count: actions.length },
            { id: 'incidents' as const, label: 'Incidents', count: openIncidentCount },
            { id: 'lists' as const, label: 'Lists' },
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
      {/* OVERVIEW TAB */}
      {/* ================================================================ */}
      {activeTab === 'overview' && (
        <main className="max-w-7xl mx-auto px-4 pb-8">
          {/* Key Metrics */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
            <div className="bg-gray-900 rounded-lg border border-gray-800 p-4">
              <div className="text-xs text-gray-400 mb-1">Total Decisions</div>
              <div className="text-2xl font-bold text-white">{totalDecisions}</div>
            </div>
            <div className="bg-gray-900 rounded-lg border border-gray-800 p-4">
              <div className="text-xs text-gray-400 mb-1">Blocked Destinations</div>
              <div className={`text-2xl font-bold ${blockCount > 0 ? 'text-red-400' : 'text-green-400'}`}>
                {blockCount}
              </div>
            </div>
            <div className="bg-gray-900 rounded-lg border border-gray-800 p-4">
              <div className="text-xs text-gray-400 mb-1">Open Incidents</div>
              <div className={`text-2xl font-bold ${openIncidentCount > 0 ? 'text-red-400' : 'text-green-400'}`}>
                {openIncidentCount}
              </div>
            </div>
            <div className="bg-gray-900 rounded-lg border border-gray-800 p-4">
              <div className="text-xs text-gray-400 mb-1">Flagged Processes</div>
              <div className={`text-2xl font-bold ${flaggedProcs > 0 ? 'text-yellow-400' : 'text-gray-400'}`}>
                {flaggedProcs}
              </div>
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
            {/* Recent Decisions */}
            <div className="bg-gray-900 rounded-lg border border-gray-800">
              <div className="px-4 py-3 border-b border-gray-800">
                <h2 className="text-sm font-semibold text-white">Recent Decisions</h2>
              </div>
              <div className="divide-y divide-gray-800">
                {decisions.length === 0 ? (
                  <div className="px-4 py-6 text-center text-gray-500 text-sm">No decisions made</div>
                ) : (
                  decisions.slice(0, 10).map((d, i) => (
                    <div key={i} className="px-4 py-2.5">
                      <div className="flex items-center gap-2 mb-0.5">
                        <span className={`text-xs px-1.5 py-0.5 rounded border ${actionColor(d.action)}`}>
                          {d.action}
                        </span>
                        <span className="text-xs text-gray-500">{d.agent_name}</span>
                        <span className="text-xs text-gray-600 ml-auto">{timeAgo(d.timestamp)}</span>
                      </div>
                      <p className="text-xs text-gray-400 truncate">{d.reason}</p>
                      {d.context.destination && (
                        <span className="text-xs text-gray-500">{d.context.destination}</span>
                      )}
                    </div>
                  ))
                )}
              </div>
            </div>

            {/* Open Incidents */}
            <div className="bg-gray-900 rounded-lg border border-gray-800">
              <div className="px-4 py-3 border-b border-gray-800">
                <h2 className="text-sm font-semibold text-white">Open Incidents</h2>
              </div>
              <div className="divide-y divide-gray-800">
                {openIncidents.length === 0 ? (
                  <div className="px-4 py-6 text-center text-gray-500 text-sm">No open incidents</div>
                ) : (
                  openIncidents.slice(0, 10).map((inc, i) => (
                    <div key={i} className="px-4 py-2.5">
                      <div className="flex items-center gap-2 mb-0.5">
                        <span className={`text-xs px-1.5 py-0.5 rounded border ${actionColor(inc.action_type)}`}>
                          {inc.action_type}
                        </span>
                        <span className="text-xs text-gray-500">{inc.agent_name}</span>
                        <span className="text-xs text-gray-600 ml-auto">{timeAgo(inc.created_at)}</span>
                      </div>
                      <p className="text-xs text-gray-400">{inc.action_target}</p>
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>

          {/* Stats Grid */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <div className="bg-gray-900 rounded-lg border border-gray-800 p-3">
              <div className="text-xs text-gray-400">Flagged Processes</div>
              <div className="text-lg font-bold text-yellow-400">{flaggedProcs}</div>
            </div>
            <div className="bg-gray-900 rounded-lg border border-gray-800 p-3">
              <div className="text-xs text-gray-400">File Violations</div>
              <div className="text-lg font-bold text-yellow-400">{fileViolations}</div>
            </div>
            <div className="bg-gray-900 rounded-lg border border-gray-800 p-3">
              <div className="text-xs text-gray-400">Total Actions</div>
              <div className="text-lg font-bold text-white">{stats?.total_actions || 0}</div>
            </div>
            <div className="bg-gray-900 rounded-lg border border-gray-800 p-3">
              <div className="text-xs text-gray-400">Active Overrides</div>
              <div className="text-lg font-bold text-blue-400">{stats?.active_overrides || 0}</div>
            </div>
          </div>

          {/* Decision Distribution */}
          {decisions.length > 0 && (
            <div className="bg-gray-900 rounded-lg border border-gray-800 mt-6">
              <div className="px-4 py-3 border-b border-gray-800">
                <h2 className="text-sm font-semibold text-white">Decision Distribution</h2>
              </div>
              <div className="p-4">
                <div className="flex h-3 rounded-full overflow-hidden bg-gray-800">
                  {(['Block', 'Flag', 'Allow', 'Restart', 'Escalate'] as const).map(action => {
                    const count = decisions.filter(d => d.action === action).length
                    const pct = decisions.length > 0 ? (count / decisions.length) * 100 : 0
                    const colors: Record<string, string> = {
                      Block: 'bg-red-600',
                      Flag: 'bg-yellow-600',
                      Allow: 'bg-green-600',
                      Restart: 'bg-purple-600',
                      Escalate: 'bg-orange-600',
                    }
                    return count > 0 ? (
                      <div
                        key={action}
                        className={colors[action]}
                        style={{ width: `${pct}%` }}
                        title={`${action}: ${count} (${pct.toFixed(0)}%)`}
                      />
                    ) : null
                  })}
                </div>
                <div className="flex flex-wrap gap-3 mt-3 text-xs text-gray-400">
                  {(['Block', 'Flag', 'Allow', 'Restart', 'Escalate'] as const).map(action => {
                    const count = decisions.filter(d => d.action === action).length
                    return count > 0 ? (
                      <span key={action}>{action}: {count}</span>
                    ) : null
                  })}
                </div>
              </div>
            </div>
          )}
        </main>
      )}

      {/* ================================================================ */}
      {/* DECISIONS TAB */}
      {/* ================================================================ */}
      {activeTab === 'decisions' && (
        <main className="max-w-7xl mx-auto px-4 pb-8">
          <div className="bg-gray-900 rounded-lg border border-gray-800">
            <div className="px-6 py-4 border-b border-gray-800">
              <h2 className="text-lg font-semibold text-white">Enforcement Decisions</h2>
              <p className="text-xs text-gray-500 mt-0.5">Every decision includes reason, rule, confidence, and timestamp</p>
            </div>
            <div className="divide-y divide-gray-800">
              {decisions.length === 0 ? (
                <div className="px-6 py-8 text-center text-gray-500">No decisions recorded</div>
              ) : (
                [...decisions].reverse().map((d, i) => (
                  <div key={i} className="px-6 py-4">
                    <div className="flex items-start justify-between">
                      <div className="flex-1">
                        <div className="flex items-center gap-2 mb-1">
                          <span className={`text-xs font-medium px-2 py-0.5 rounded-full border ${actionColor(d.action)}`}>
                            {d.action}
                          </span>
                          <span className="text-xs text-gray-400">{d.agent_name}</span>
                          <span className="text-xs text-gray-500">
                            Rule: {d.rule}
                          </span>
                          <span className="text-xs text-gray-500 ml-auto">{formatTime(d.timestamp)}</span>
                        </div>
                        <p className="text-sm text-gray-300">{d.reason}</p>
                        <div className="flex gap-3 mt-1 text-xs text-gray-500">
                          <span>Confidence: {(d.confidence * 100).toFixed(0)}%</span>
                          <span>Policy: {d.policy_name} v{d.policy_version}</span>
                        </div>
                        {d.context.destination && (
                          <div className="mt-1 text-xs text-gray-400">
                            Destination: {d.context.destination}
                          </div>
                        )}
                        {d.context.anomaly_type && (
                          <div className="text-xs text-gray-400">
                            Anomaly: {d.context.anomaly_type}
                          </div>
                        )}
                        <div className="mt-1 text-xs text-gray-500">
                          Risk Score: {d.context.risk_score} ({d.context.risk_level})
                        </div>
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
      {/* ACTIONS TAB */}
      {/* ================================================================ */}
      {activeTab === 'actions' && (
        <main className="max-w-7xl mx-auto px-4 pb-8">
          <div className="bg-gray-900 rounded-lg border border-gray-800">
            <div className="px-6 py-4 border-b border-gray-800">
              <h2 className="text-lg font-semibold text-white">Enforcement Actions</h2>
            </div>
            <div className="divide-y divide-gray-800">
              {actions.length === 0 ? (
                <div className="px-6 py-8 text-center text-gray-500">No enforcement actions recorded</div>
              ) : (
                [...actions].reverse().map((a, i) => (
                  <div key={i} className="px-6 py-3">
                    <div className="flex items-center gap-2 mb-0.5">
                      <span className={`text-xs px-1.5 py-0.5 rounded border ${actionColor(a.action_type)}`}>
                        {a.action_type}
                      </span>
                      <span className={`text-xs font-medium ${resultColor(a.result)}`}>
                        {a.result}
                      </span>
                      <span className="text-xs text-gray-400">{a.agent_name}</span>
                      <span className="text-xs text-gray-500 ml-auto">{timeAgo(a.timestamp)}</span>
                    </div>
                    <p className="text-sm text-gray-300">
                      <span className="text-gray-500">Target:</span> {a.target}
                    </p>
                    <p className="text-xs text-gray-500">{a.details}</p>
                  </div>
                ))
              )}
            </div>
          </div>
        </main>
      )}

      {/* ================================================================ */}
      {/* INCIDENTS TAB */}
      {/* ================================================================ */}
      {activeTab === 'incidents' && (
        <main className="max-w-7xl mx-auto px-4 pb-8">
          <div className="bg-gray-900 rounded-lg border border-gray-800">
            <div className="px-6 py-4 border-b border-gray-800 flex items-center justify-between">
              <h2 className="text-lg font-semibold text-white">Enforcement Incidents</h2>
              <div className="flex items-center gap-2">
                <span className="text-xs text-red-400">{openIncidentCount} open</span>
                <span className="text-xs text-gray-500">|</span>
                <span className="text-xs text-gray-400">{incidents.length} total</span>
              </div>
            </div>
            <div className="divide-y divide-gray-800">
              {incidents.length === 0 && openIncidents.length === 0 ? (
                <div className="px-6 py-8 text-center text-gray-500">No enforcement incidents recorded</div>
              ) : (
                [...incidents, ...openIncidents.filter(oi => !incidents.find(i => i.id === oi.id))]
                  .filter((v, i, a) => a.findIndex(x => x.id === v.id) === i)
                  .sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime())
                  .map((inc, i) => (
                    <div key={i} className="px-6 py-4">
                      <div className="flex items-start justify-between">
                        <div className="flex-1">
                          <div className="flex items-center gap-2 mb-1">
                            <span className={`text-xs font-medium px-2 py-0.5 rounded-full border ${actionColor(inc.action_type)}`}>
                              {inc.action_type}
                            </span>
                            <span className={`text-xs px-1.5 py-0.5 rounded ${
                              inc.status === 'Open' ? 'bg-red-900/50 text-red-300' : 'bg-green-900/50 text-green-300'
                            }`}>
                              {inc.status}
                            </span>
                            <span className="text-xs text-gray-400">{inc.agent_name}</span>
                            <span className="text-xs text-gray-500 ml-auto">{formatTime(inc.created_at)}</span>
                          </div>
                          <p className="text-sm text-gray-300">Target: {inc.action_target}</p>
                          {inc.resolved_at && (
                            <p className="text-xs text-green-400 mt-0.5">
                              Resolved: {formatTime(inc.resolved_at)} — {inc.resolution || 'N/A'}
                            </p>
                          )}
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
      {/* LISTS TAB */}
      {/* ================================================================ */}
      {activeTab === 'lists' && (
        <main className="max-w-7xl mx-auto px-4 pb-8">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Block List */}
            <div className="bg-gray-900 rounded-lg border border-gray-800">
              <div className="px-4 py-3 border-b border-gray-800">
                <h2 className="text-sm font-semibold text-white">Block List</h2>
                <p className="text-xs text-gray-500 mt-0.5">{blockCount} destinations blocked</p>
              </div>
              <div className="divide-y divide-gray-800">
                {blockCount === 0 ? (
                  <div className="px-4 py-6 text-center text-gray-500 text-sm">No blocked destinations</div>
                ) : (
                  <div className="px-4 py-3">
                    <div className="flex items-center gap-2 py-1.5">
                      <span className="w-1.5 h-1.5 rounded-full bg-red-500 flex-shrink-0" />
                      <span className="text-sm text-gray-300">{blockCount} destination{blockCount !== 1 ? 's' : ''} blocked</span>
                    </div>
                  </div>
                )}
              </div>
            </div>

            {/* Allow List */}
            <div className="bg-gray-900 rounded-lg border border-gray-800">
              <div className="px-4 py-3 border-b border-gray-800">
                <h2 className="text-sm font-semibold text-white">Allow List</h2>
                <p className="text-xs text-gray-500 mt-0.5">{stats?.allowed_destinations || 9} allowed destinations</p>
              </div>
              <div className="divide-y divide-gray-800">
                <div className="px-4 py-3">
                  {['api.openai.com', 'api.anthropic.com', 'github.com', 'registry.npmjs.org', 'pypi.org', 'crates.io'].map((dest, i) => (
                    <div key={i} className="flex items-center gap-2 py-1.5">
                      <span className="w-1.5 h-1.5 rounded-full bg-green-500 flex-shrink-0" />
                      <span className="text-sm text-gray-300 font-mono">{dest}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>

          {/* Overrides Section */}
          <div className="bg-gray-900 rounded-lg border border-gray-800 mt-6">
            <div className="px-4 py-3 border-b border-gray-800">
              <h2 className="text-sm font-semibold text-white">Human Overrides</h2>
            </div>
            <div className="divide-y divide-gray-800">
              {(stats?.active_overrides || 0) === 0 ? (
                <div className="px-4 py-6 text-center text-gray-500 text-sm">No overrides recorded</div>
              ) : (
                <div className="px-4 py-3 text-sm text-gray-400">
                  Overrides allow manual approval, rejection, or temporary overrides of enforcement decisions.
                </div>
              )}
            </div>
          </div>
        </main>
      )}
    </div>
  )
}
