'use client'

import { useEffect, useState } from 'react'

interface Agent {
  id: string
  name: string
  status: string
  pid: number
  cpu_usage: number
  memory_usage: number
}

interface Event {
  id: string
  event_type: string
  severity: string
  message: string
  created_at: string
}

export default function Home() {
  const [agents, setAgents] = useState<Agent[]>([])
  const [events, setEvents] = useState<Event[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    fetchData()
    const interval = setInterval(fetchData, 5000)
    return () => clearInterval(interval)
  }, [])

  async function fetchData() {
    try {
      const apiUrl = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3000'
      
      const [agentsRes, eventsRes] = await Promise.all([
        fetch(`${apiUrl}/api/agents`),
        fetch(`${apiUrl}/api/events`)
      ])
      
      const agentsData = await agentsRes.json()
      const eventsData = await eventsRes.json()
      
      setAgents(agentsData.agents || [])
      setEvents(eventsData.events || [])
    } catch (error) {
      console.error('Failed to fetch data:', error)
    } finally {
      setLoading(false)
    }
  }

  function getStatusColor(status: string) {
    switch (status) {
      case 'running':
        return 'bg-green-500'
      case 'failed':
        return 'bg-red-500'
      case 'stopped':
        return 'bg-yellow-500'
      default:
        return 'bg-gray-500'
    }
  }

  function getSeverityColor(severity: string) {
    switch (severity) {
      case 'critical':
        return 'text-red-600 bg-red-50'
      case 'error':
        return 'text-orange-600 bg-orange-50'
      case 'warning':
        return 'text-yellow-600 bg-yellow-50'
      default:
        return 'text-blue-600 bg-blue-50'
    }
  }

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-xl">Loading...</div>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-gray-50">
      <header className="bg-white shadow">
        <div className="max-w-7xl mx-auto px-4 py-6">
          <h1 className="text-3xl font-bold text-gray-900">Omnisec Dashboard</h1>
          <p className="mt-1 text-sm text-gray-500">
            Runtime Control Plane for Autonomous AI Agents
          </p>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-4 py-8">
        <div className="mb-6 flex justify-end gap-3">
          <a
            href="/reliability"
            className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-green-600 hover:bg-green-700"
          >
            Reliability Dashboard
          </a>
          <a
            href="/validation"
            className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-indigo-600 hover:bg-indigo-700"
          >
            Validation Dashboard
          </a>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
          <div className="bg-white rounded-lg shadow p-6">
            <h2 className="text-lg font-semibold text-gray-900">Total Agents</h2>
            <p className="mt-2 text-3xl font-bold text-blue-600">{agents.length}</p>
          </div>
          <div className="bg-white rounded-lg shadow p-6">
            <h2 className="text-lg font-semibold text-gray-900">Running</h2>
            <p className="mt-2 text-3xl font-bold text-green-600">
              {agents.filter(a => a.status === 'running').length}
            </p>
          </div>
          <div className="bg-white rounded-lg shadow p-6">
            <h2 className="text-lg font-semibold text-gray-900">Failed</h2>
            <p className="mt-2 text-3xl font-bold text-red-600">
              {agents.filter(a => a.status === 'failed').length}
            </p>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div className="bg-white rounded-lg shadow">
            <div className="px-6 py-4 border-b border-gray-200">
              <h2 className="text-lg font-semibold text-gray-900">Agents</h2>
            </div>
            <div className="divide-y divide-gray-200">
              {agents.length === 0 ? (
                <div className="px-6 py-4 text-center text-gray-500">
                  No agents discovered yet
                </div>
              ) : (
                agents.map((agent) => (
                  <div key={agent.id} className="px-6 py-4">
                    <div className="flex items-center justify-between">
                      <div>
                        <div className="flex items-center">
                          <div className={`w-2 h-2 rounded-full ${getStatusColor(agent.status)} mr-2`} />
                          <span className="font-medium text-gray-900">{agent.name}</span>
                        </div>
                        <div className="mt-1 text-sm text-gray-500">
                          PID: {agent.pid}
                        </div>
                      </div>
                      <div className="text-right text-sm">
                        <div>CPU: {agent.cpu_usage?.toFixed(1) || 0}%</div>
                        <div>Mem: {agent.memory_usage?.toFixed(1) || 0} MB</div>
                      </div>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>

          <div className="bg-white rounded-lg shadow">
            <div className="px-6 py-4 border-b border-gray-200">
              <h2 className="text-lg font-semibold text-gray-900">Recent Events</h2>
            </div>
            <div className="divide-y divide-gray-200">
              {events.length === 0 ? (
                <div className="px-6 py-4 text-center text-gray-500">
                  No events recorded
                </div>
              ) : (
                events.slice(0, 10).map((event) => (
                  <div key={event.id} className="px-6 py-4">
                    <div className="flex items-start justify-between">
                      <div className="flex-1">
                        <div className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getSeverityColor(event.severity)}`}>
                          {event.severity}
                        </div>
                        <div className="mt-1 text-sm text-gray-900">{event.message}</div>
                        <div className="mt-1 text-xs text-gray-500">
                          {new Date(event.created_at).toLocaleString()}
                        </div>
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
