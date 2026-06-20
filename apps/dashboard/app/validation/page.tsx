'use client'

import { useEffect, useState } from 'react'

interface LatencyRecord {
  operation: string
  start_time: string
  end_time: string | null
  duration_ms: number | null
  success: boolean
  labels: Record<string, string>
}

interface MetricsSummary {
  operation: string
  count: number
  success_count: number
  failure_count: number
  min_latency_ms: number | null
  max_latency_ms: number | null
  avg_latency_ms: number | null
  p50_latency_ms: number | null
  p95_latency_ms: number | null
  p99_latency_ms: number | null
}

interface Event {
  id: string
  event_type: string
  severity: string
  message: string
  agent_id: string | null
  created_at: string
}

interface Agent {
  id: string
  name: string
  status: string
  pid: number
}

export default function ValidationPage() {
  const [metrics, setMetrics] = useState<MetricsSummary[]>([])
  const [events, setEvents] = useState<Event[]>([])
  const [agents, setAgents] = useState<Agent[]>([])
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
      
      const [eventsRes, agentsRes] = await Promise.all([
        fetch(`${apiUrl}/api/events`),
        fetch(`${apiUrl}/api/agents`)
      ])
      
      const eventsData = await eventsRes.json()
      const agentsData = await agentsRes.json()
      
      setEvents(eventsData.events || [])
      setAgents(agentsData.agents || [])
      setLastUpdate(new Date())
    } catch (error) {
      console.error('Failed to fetch data:', error)
    } finally {
      setLoading(false)
    }
  }

  function formatDuration(ms: number | null) {
    if (ms === null) return 'N/A'
    if (ms < 1) return '<1ms'
    if (ms < 1000) return `${ms.toFixed(1)}ms`
    return `${(ms / 1000).toFixed(2)}s`
  }

  function getSeverityColor(severity: string) {
    switch (severity) {
      case 'critical':
        return 'bg-red-100 text-red-800 border-red-200'
      case 'error':
        return 'bg-orange-100 text-orange-800 border-orange-200'
      case 'warning':
        return 'bg-yellow-100 text-yellow-800 border-yellow-200'
      default:
        return 'bg-blue-100 text-blue-800 border-blue-200'
    }
  }

  function getEventTypeIcon(type: string) {
    switch (type) {
      case 'agent_failed':
        return '🔴'
      case 'agent_restarted':
        return '🟢'
      case 'agent_discovered':
        return '🔍'
      case 'critical_alert':
        return '🚨'
      default:
        return '📋'
    }
  }

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50">
        <div className="text-xl text-gray-600">Loading validation data...</div>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-gray-50">
      <header className="bg-white shadow-sm border-b">
        <div className="max-w-7xl mx-auto px-4 py-4">
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-2xl font-bold text-gray-900">Omnisec Validation Dashboard</h1>
              <p className="mt-1 text-sm text-gray-500">
                Control Loop Testing & Metrics
              </p>
            </div>
            <div className="text-right">
              <div className="text-sm text-gray-500">Last Update</div>
              <div className="text-sm font-mono">{lastUpdate.toLocaleTimeString()}</div>
            </div>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-4 py-6">
        <div className="grid grid-cols-1 lg:grid-cols-4 gap-4 mb-6">
          <div className="bg-white rounded-lg shadow p-4 border-l-4 border-green-500">
            <div className="text-sm text-gray-500">Agents Running</div>
            <div className="text-2xl font-bold text-green-600">
              {agents.filter(a => a.status === 'running').length}
            </div>
          </div>
          <div className="bg-white rounded-lg shadow p-4 border-l-4 border-red-500">
            <div className="text-sm text-gray-500">Failed Agents</div>
            <div className="text-2xl font-bold text-red-600">
              {agents.filter(a => a.status === 'failed').length}
            </div>
          </div>
          <div className="bg-white rounded-lg shadow p-4 border-l-4 border-blue-500">
            <div className="text-sm text-gray-500">Total Events</div>
            <div className="text-2xl font-bold text-blue-600">{events.length}</div>
          </div>
          <div className="bg-white rounded-lg shadow p-4 border-l-4 border-purple-500">
            <div className="text-sm text-gray-500">Critical Alerts</div>
            <div className="text-2xl font-bold text-purple-600">
              {events.filter(e => e.severity === 'critical').length}
            </div>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
          <div className="bg-white rounded-lg shadow">
            <div className="px-6 py-4 border-b border-gray-200">
              <h2 className="text-lg font-semibold text-gray-900">Control Loop Status</h2>
            </div>
            <div className="p-6">
              <div className="space-y-4">
                <div className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                  <div className="flex items-center">
                    <div className="w-3 h-3 rounded-full bg-green-500 mr-3"></div>
                    <span className="font-medium">Failure Detection</span>
                  </div>
                  <span className="text-sm text-gray-500">Active</span>
                </div>
                <div className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                  <div className="flex items-center">
                    <div className="w-3 h-3 rounded-full bg-green-500 mr-3"></div>
                    <span className="font-medium">Event Propagation</span>
                  </div>
                  <span className="text-sm text-gray-500">Active</span>
                </div>
                <div className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                  <div className="flex items-center">
                    <div className="w-3 h-3 rounded-full bg-green-500 mr-3"></div>
                    <span className="font-medium">Restart Engine</span>
                  </div>
                  <span className="text-sm text-gray-500">Active</span>
                </div>
                <div className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                  <div className="flex items-center">
                    <div className="w-3 h-3 rounded-full bg-green-500 mr-3"></div>
                    <span className="font-medium">Alert Delivery</span>
                  </div>
                  <span className="text-sm text-gray-500">Active</span>
                </div>
              </div>
            </div>
          </div>

          <div className="bg-white rounded-lg shadow">
            <div className="px-6 py-4 border-b border-gray-200">
              <h2 className="text-lg font-semibold text-gray-900">Metrics Summary</h2>
            </div>
            <div className="p-6">
              {metrics.length === 0 ? (
                <div className="text-center text-gray-500 py-8">
                  No metrics recorded yet. Run chaos tests to generate metrics.
                </div>
              ) : (
                <div className="space-y-3">
                  {metrics.map((m) => (
                    <div key={m.operation} className="p-3 bg-gray-50 rounded-lg">
                      <div className="flex items-center justify-between mb-1">
                        <span className="font-medium text-sm">{m.operation}</span>
                        <span className="text-xs text-gray-500">{m.count} samples</span>
                      </div>
                      <div className="grid grid-cols-3 gap-2 text-xs">
                        <div>
                          <span className="text-gray-500">Avg: </span>
                          <span className="font-mono">{formatDuration(m.avg_latency_ms)}</span>
                        </div>
                        <div>
                          <span className="text-gray-500">P95: </span>
                          <span className="font-mono">{formatDuration(m.p95_latency_ms)}</span>
                        </div>
                        <div>
                          <span className="text-gray-500">P99: </span>
                          <span className="font-mono">{formatDuration(m.p99_latency_ms)}</span>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>

        <div className="bg-white rounded-lg shadow">
          <div className="px-6 py-4 border-b border-gray-200">
            <h2 className="text-lg font-semibold text-gray-900">Event Timeline</h2>
          </div>
          <div className="divide-y divide-gray-200 max-h-96 overflow-y-auto">
            {events.length === 0 ? (
              <div className="px-6 py-8 text-center text-gray-500">
                No events recorded
              </div>
            ) : (
              events.slice(0, 50).map((event) => (
                <div key={event.id} className="px-6 py-4 hover:bg-gray-50">
                  <div className="flex items-start">
                    <div className="mr-3 text-xl">
                      {getEventTypeIcon(event.event_type)}
                    </div>
                    <div className="flex-1">
                      <div className="flex items-center gap-2 mb-1">
                        <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border ${getSeverityColor(event.severity)}`}>
                          {event.severity}
                        </span>
                        <span className="text-xs text-gray-500">{event.event_type}</span>
                      </div>
                      <div className="text-sm text-gray-900">{event.message}</div>
                      <div className="text-xs text-gray-500 mt-1">
                        {new Date(event.created_at).toLocaleString()}
                      </div>
                    </div>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </main>
    </div>
  )
}
