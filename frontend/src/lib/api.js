const API_BASE = '/api/v1'

export async function fetchAlerts() {
  const res = await fetch(`${API_BASE}/alerts`)
  if (!res.ok) throw new Error('Failed to fetch alerts')
  return res.json()
}

export async function fetchStats() {
  const res = await fetch(`${API_BASE}/stats`)
  if (!res.ok) throw new Error('Failed to fetch stats')
  return res.json()
}

export async function fetchHealth() {
  const res = await fetch(`${API_BASE}/health`)
  if (!res.ok) throw new Error('API unavailable')
  return res.json()
}

export function connectAlertStream(onAlert) {
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
  const ws = new WebSocket(`${protocol}//${window.location.host}/ws/alerts`)
  ws.onmessage = (e) => {
    try { onAlert(JSON.parse(e.data)) } catch {}
  }
  ws.onerror = () => {}
  return ws
}