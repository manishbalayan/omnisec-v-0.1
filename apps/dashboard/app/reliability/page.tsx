'use client'

import { useEffect, useState } from 'react'

interface AgentStatus {
  name: string
  pid: number
  status: 'healthy' | 'warning' | 'failed' | 'hung' | 'recovering'
  cpu_percent: number
  memory_mb: number
  fd_count: number
  thread_count: number
}

interface Incident {
  id: string
  agent_name: string
  incident_type: string
  severity: string
  state: string
  title: string
  created_at: string
  resolved_at: string | null
  duration_ms: number | null
}

interface ReliabilityMetrics {
  agent_name: string
  mttr_ms: number
  mtbf_ms: number
  availability_percent: number
  total_incidents: number
}

interface DependencyHealth {
  name: string
  status: 'healthy' | 'degraded' | 'failed' | 'unknown'
  latency_ms: number | null
  uptime_percent: number
  last_check: string
}

export default function ReliabilityDashboard() {
  const [agents, setAgents] = useState<AgentStatus[]>([])
  const [incidents, setIncidents] = useState<Incident[]>([])
  const [metrics, setMetrics] = useState<ReliabilityMetrics[]>([])
  const [dependencies, setDependencies] = useState<DependencyHealth[]>([])
  const [loading, setLoading] = useState(true)
  const [lastUpdate, setLastUpdate] = useState<Date>(new Date())

  useEffect(() => {
    fetchData()
    const interval = setInterval(fetchData, 2000)
    return () => clearInterval(interval)
  }, [])

  async function fetchData() {
    try {
      const apiUrl = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3000'
      
      const [agentsRes, incidentsRes, metricsRes, depsRes] = await Promise.all([
        fetch(`${apiUrl}/api/agents`),
        fetch(`${apiUrl}/api/incidents`),
        fetch(`${apiUrl}/api/metrics/reliability`),
        fetch(`${apiUrl}/api/dependencies/health`)
      ])
      
      if (agentsRes.ok) {
        const data = await agentsRes.json()
        setAgents(data.agents || [])
      }
      if (incidentsRes.ok) {
        const data = await incidentsRes.json()
        setIncidents(data.incidents || [])
      }
      if (metricsRes.ok) {
        const data = await metricsRes.json()
        setMetrics(data.metrics || [])
      }
      if (depsRes.ok) {
        const data = await depsRes.json()
        setDependencies(data.dependencies || [])
      }
      
      setLastUpdate(new Date())
    } catch (error) {
      console.error('Failed to fetch data:', error)
    } finally {
      setLoading(false)
    }
  }

  function formatDuration(ms: number | null) {
    if (ms === null) return 'N/A'
    if (ms < 1000) return `${ms.toFixed(0)}ms`
    if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`
    if (ms < 3600000) return `${(ms / 60000).toFixed(1)}m`
    return `${(ms / 3600000).toFixed(1)}h`
  }

  function getStatusColor(status: string) {
    switch (status) {
      case 'healthy':
        return 'bg-green-100 text-green-800 border-green-200'
      case 'warning':
      case 'degraded':
        return 'bg-yellow-100 text-yellow-800 border-yellow-200'
      case 'failed':
      case 'hung':
        return 'bg-red-100 text-red-800 border-red-200'
      case 'recovering':
        return 'bg-blue-100 text-blue-800 border-blue-200'
      default:
        return 'bg-gray-100 text-gray-800 border-gray-200'
    }
  }

  function getSeverityColor(severity: string) {
    switch (severity) {
      case 'critical':
        return 'bg-red-500'
      case 'high':
        return 'bg-orange-500'
      case 'medium':
        return 'bg-yellow-500'
      case 'low':
        return 'bg-blue-500'
      default:
        return 'bg-gray-500'
    }
  }

  const healthyCount = agents.filter(a => a.status === 'healthy').length
  const warningCount = agents.filter(a => a.status === 'warning').length
  const failedCount = agents.filter(a => a.status === 'failed' || a.status === 'hung').length
  const openIncidents = incidents.filter(i => i.resolved_at === null).length
  const avgAvailability = metrics.length > 0
    ? metrics.reduce((sum, m) => sum + m.availability_percent, 0) / metrics.length
    : 100

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50">
        <div className="text-xl text-gray-600">Loading reliability data...</div>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-gray-50">
      <header className="bg-white shadow-sm border-b">
        <div className="max-w-7xl mx-auto px-4 py-4">
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-2xl font-bold text-gray-900">Reliability Dashboard</h1>
              <p className="mt-1 text-sm text-gray-500">
                Omnisec Reliability Engine
              </p>
            </div>
            <div className="text-right">
              <div className="text-sm text-gray-500">System Status</div>
              <div className={`text-lg font-bold ${openIncidents > 0 ? 'text-red-600' : 'text-green-600'}`}>
                {openIncidents > 0 ? 'DEGRADED' : 'HEALTHY'}
              </div>
            </div>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-4 py-6">
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4 mb-6">
          <div className="bg-white rounded-lg shadow p-4 border-l-4 border-green-500">
            <div className="text-sm text-gray-500">Healthy</div>
            <div className="text-2xl font-bold text-green-600">{healthyCount}</div>
          </div>
          <div className="bg-white rounded-lg shadow p-4 border-l-4 border-yellow-500">
            <div className="text-sm text-gray-500">Warning</div>
            <div className="text-2xl font-bold text-yellow-600">{warningCount}</div>
          </div>
          <div className="bg-white rounded-lg shadow p-4 border-l-4 border-red-500">
            <div className="text-sm text-gray-500">Failed/Hung</div>
            <div className="text-2xl font-bold text-red-600">{failedCount}</div>
          </div>
          <div className="bg-white rounded-lg shadow p-4 border-l-4 border-purple-500">
            <div className="text-sm text-gray-500">Open Incidents</div>
            <div className="text-2xl font-bold text-purple-600">{openIncidents}</div>
          </div>
          <div className="bg-white rounded-lg shadow p-4 border-l-4 border-blue-500">
            <div className="text-sm text-gray-500">Availability</div>
            <div className="text-2xl font-bold text-blue-600">{avgAvailability.toFixed(1)}%</div>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
          <div className="bg-white rounded-lg shadow">
            <div className="px-6 py-4 border-b border-gray-200">
              <h2 className="text-lg font-semibold text-gray-900">Agent Status</h2>
            </div>
            <div className="divide-y divide-gray-200 max-h-80 overflow-y-auto">
              {agents.length === 0 ? (
                <div className="px-6 py-4 text-center text-gray-500">No agents</div>
              ) : (
                agents.map((agent) => (
                  <div key={agent.pid} className="px-6 py-3 hover:bg-gray-50">
                    <div className="flex items-center justify-between">
                      <div>
                        <div className="font-medium text-gray-900">{agent.name}</div>
                        <div className="text-sm text-gray-500">PID: {agent.pid}</div>
                      </div>
                      <div className="text-right">
                        <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium border ${getStatusColor(agent.status)}`}>
                          {agent.status.toUpperCase()}
                        </span>
                        <div className="text-xs text-gray-500 mt-1">
                          CPU: {agent.cpu_percent.toFixed(1)}% | Mem: {agent.memory_mb.toFixed(0)}MB
                        </div>
                      </div>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>

          <div className="bg-white rounded-lg shadow">
            <div className="px-6 py-4 border-b border-gray-200">
              <h2 className="text-lg font-semibold text-gray-900">Dependency Health</h2>
            </div>
            <div className="divide-y divide-gray-200">
              {dependencies.length === 0 ? (
                <div className="px-6 py-4 text-center text-gray-500">No dependencies monitored</div>
              ) : (
                dependencies.map((dep) => (
                  <div key={dep.name} className="px-6 py-3">
                    <div className="flex items-center justify-between">
                      <div>
                        <div className="font-medium text-gray-900">{dep.name}</div>
                        <div className="text-xs text-gray-500">
                          Latency: {dep.latency_ms?.toFixed(1) || 'N/A'}ms
                        </div>
                      </div>
                      <div className="text-right">
                        <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium border ${getStatusColor(dep.status)}`}>
                          {dep.status.toUpperCase()}
                        </span>
                        <div className="text-xs text-gray-500 mt-1">
                          Uptime: {dep.uptime_percent.toFixed(1)}%
                        </div>
                      </div>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
          <div className="bg-white rounded-lg shadow">
            <div className="px-6 py-4 border-b border-gray-200">
              <h2 className="text-lg font-semibold text-gray-900">Reliability Metrics</h2>
            </div>
            <div className="p-6">
              {metrics.length === 0 ? (
                <div className="text-center text-gray-500">No metrics available</div>
              ) : (
                <div className="space-y-3">
                  {metrics.map((m) => (
                    <div key={m.agent_name} className="p-3 bg-gray-50 rounded-lg">
                      <div className="font-medium text-sm mb-2">{m.agent_name}</div>
                      <div className="grid grid-cols-2 gap-2 text-xs">
                        <div>
                          <span className="text-gray-500">MTTR: </span>
                          <span className="font-mono">{formatDuration(m.mttr_ms)}</span>
                        </div>
                        <div>
                          <span className="text-gray-500">MTBF: </span>
                          <span className="font-mono">{formatDuration(m.mtbf_ms)}</span>
                        </div>
                        <div>
                          <span className="text-gray-500">Availability: </span>
                          <span className="font-mono">{m.availability_percent.toFixed(1)}%</span>
                        </div>
                        <div>
                          <span className="text-gray-500">Incidents: </span>
                          <span className="font-mono">{m.total_incidents}</span>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>

          <div className="bg-white rounded-lg shadow">
            <div className="px-6 py-4 border-b border-gray-200">
              <h2 className="text-lg font-semibold text-gray-900">Recent Incidents</h2>
            </div>
            <div className="divide-y divide-gray-200 max-h-80 overflow-y-auto">
              {incidents.length === 0 ? (
                <div className="px-6 py-4 text-center text-gray-500">No incidents</div>
              ) : (
                incidents.slice(0, 20).map((incident) => (
                  <div key={incident.id} className="px-6 py-3">
                    <div className="flex items-start">
                      <div className={`w-2 h-2 rounded-full mt-2 mr-3 ${getSeverityColor(incident.severity)}`} />
                      <div className="flex-1">
                        <div className="flex items-center gap-2">
                          <span className="font-medium text-sm text-gray-900">{incident.title}</span>
                          <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${
                            incident.resolved_at ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'
                          }`}>
                            {incident.resolved_at ? 'RESOLVED' : incident.state}
                          </span>
                        </div>
                        <div className="text-xs text-gray-500 mt-1">
                          {incident.agent_name} | {incident.incident_type} | {new Date(incident.created_at).toLocaleString()}
                        </div>
                        {incident.duration_ms && (
                          <div className="text-xs text-gray-500">
                            Duration: {formatDuration(incident.duration_ms)}
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      </main>
    </div>
  )
}
