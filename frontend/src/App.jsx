import { useState, useEffect, useCallback, useMemo } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  AlertTriangle, Activity, Target, Radio, RefreshCw,
  Crosshair, Brain, Zap, Globe, ChevronRight,
} from 'lucide-react'
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, AreaChart, Area,
} from 'recharts'
import { fetchAlerts, fetchStats, fetchHealth, connectAlertStream } from './lib/api'

const RISK_COLORS = { Critical: '#ef4444', High: '#f97316', Medium: '#f59e0b', Low: '#10b981' }
const REFRESH_MS = 8000

function RiskBadge({ risk }) {
  const color = RISK_COLORS[risk] || '#64748b'
  return (
    <span className="px-2 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wider"
      style={{ background: `${color}22`, color, border: `1px solid ${color}44` }}>
      {risk || 'Unknown'}
    </span>
  )
}

function StatCard({ icon: Icon, label, value, sub, accent }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }}
      className="rounded-xl p-5 border border-white/5"
      style={{ background: 'linear-gradient(135deg, #111827 0%, #0b1220 100%)' }}
    >
      <div className="flex items-start justify-between mb-3">
        <div className="w-9 h-9 rounded-lg flex items-center justify-center"
          style={{ background: `${accent}18`, border: `1px solid ${accent}33` }}>
          <Icon size={18} style={{ color: accent }} />
        </div>
      </div>
      <div className="text-2xl font-bold text-white">{value}</div>
      <div className="text-xs text-slate-400 mt-1">{label}</div>
      {sub && <div className="text-[10px] text-slate-500 mt-1">{sub}</div>}
    </motion.div>
  )
}

function AlertRow({ alert, index }) {
  return (
    <motion.tr
      initial={{ opacity: 0, x: -8 }} animate={{ opacity: 1, x: 0 }}
      transition={{ delay: index * 0.03 }}
      className="border-b border-white/5 hover:bg-white/[0.02] transition-colors"
    >
      <td className="py-3 px-4 text-xs font-mono text-cyan-400">{alert.src_ip}</td>
      <td className="py-3 px-4 text-xs font-mono text-slate-400">{alert.dst_ip}</td>
      <td className="py-3 px-4 text-xs">{alert.attack_type || '—'}</td>
      <td className="py-3 px-4"><RiskBadge risk={alert.risk} /></td>
      <td className="py-3 px-4">
        <div className="flex items-center gap-2">
          <div className="w-16 h-1.5 rounded-full bg-slate-800 overflow-hidden">
            <div className="h-full rounded-full bg-cyan-500" style={{ width: `${alert.confidence}%` }} />
          </div>
          <span className="text-[10px] text-slate-500">{alert.confidence}%</span>
        </div>
      </td>
      <td className="py-3 px-4 text-[10px] text-slate-500">
        {alert.mitre_techniques?.slice(0, 2).join(', ') || '—'}
      </td>
      <td className="py-3 px-4 text-[10px] text-slate-500">{alert.country || '—'}</td>
    </motion.tr>
  )
}

export default function App() {
  const [alerts, setAlerts] = useState([])
  const [stats, setStats] = useState(null)
  const [health, setHealth] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [liveCount, setLiveCount] = useState(0)

  const load = useCallback(async () => {
    try {
      const [a, s, h] = await Promise.all([fetchAlerts(), fetchStats(), fetchHealth()])
      setAlerts(a)
      setStats(s)
      setHealth(h)
      setError(null)
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    load()
    const interval = setInterval(load, REFRESH_MS)
    const ws = connectAlertStream((alert) => {
      setLiveCount((c) => c + 1)
      setAlerts((prev) => [alert, ...prev.filter((a) => a.id !== alert.id)].slice(0, 100))
    })
    return () => { clearInterval(interval); ws?.close() }
  }, [load])

  const riskData = useMemo(() => {
    if (!stats?.risk_distribution) return []
    return Object.entries(stats.risk_distribution).map(([name, value]) => ({ name, value }))
  }, [stats])

  const attackData = useMemo(() => {
    if (!stats?.attack_types) return []
    return Object.entries(stats.attack_types)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 6)
      .map(([name, count]) => ({ name: name.slice(0, 20), count }))
  }, [stats])

  const timelineData = useMemo(() => {
    const buckets = {}
    alerts.forEach((a) => {
      if (!a.created_at) return
      const hour = new Date(a.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
      buckets[hour] = (buckets[hour] || 0) + 1
    })
    return Object.entries(buckets).slice(-12).map(([time, alerts]) => ({ time, alerts }))
  }, [alerts])

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-aegis-950">
        <motion.div animate={{ opacity: [0.5, 1, 0.5] }} transition={{ repeat: Infinity, duration: 1.5 }}
          className="flex flex-col items-center gap-4">
          <img src="/favicon.svg" alt="SOCloom" className="w-12 h-12" />
          <span className="text-sm text-slate-500 tracking-widest uppercase">Initializing SOCloom</span>
        </motion.div>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-aegis-950">
      {/* Header */}
      <header className="border-b border-white/5 px-6 py-4 flex items-center justify-between sticky top-0 z-50 backdrop-blur-xl"
        style={{ background: 'rgba(6,13,24,0.85)' }}>
        <div className="flex items-center gap-3">
          <img src="/favicon.svg" alt="SOCloom" className="w-10 h-10 rounded-xl" />
          <div>
            <h1 className="text-lg font-bold text-white tracking-tight">SOCloom</h1>
            <p className="text-[10px] text-slate-500 tracking-widest uppercase">SOC Woven with 800+ Security Skills</p>
          </div>
        </div>
        <div className="flex items-center gap-4">
          {health && (
            <div className="text-[10px] text-slate-500 hidden md:block">
              <span className="text-cyan-400 font-mono">{health.skills?.soc_skills || 0}</span> SOC skills loaded
            </div>
          )}
          <div className="flex items-center gap-2 text-[10px]">
            <Radio size={12} className={liveCount > 0 ? 'text-emerald-400 animate-pulse' : 'text-slate-600'} />
            <span className="text-slate-500">Live</span>
          </div>
          <button onClick={load} className="p-2 rounded-lg hover:bg-white/5 transition-colors text-slate-400 hover:text-white">
            <RefreshCw size={16} />
          </button>
        </div>
      </header>

      {error && (
        <div className="mx-6 mt-4 p-3 rounded-lg border border-red-500/20 bg-red-500/5 text-red-400 text-sm">
          API Error: {error} — Start backend with <code className="font-mono text-xs">aegis serve</code>
        </div>
      )}

      <main className="p-6 space-y-6 max-w-[1600px] mx-auto">
        {/* Stats */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          <StatCard icon={AlertTriangle} label="Total Alerts" value={stats?.total_alerts ?? 0}
            sub={`${stats?.open_alerts ?? 0} open`} accent="#ef4444" />
          <StatCard icon={Activity} label="Avg Confidence" value={`${stats?.avg_confidence ?? 0}%`}
            sub="ML + rule fusion" accent="#06b6d4" />
          <StatCard icon={Brain} label="Skills Catalog" value={health?.skills?.total_skills ?? '—'}
            sub={`${health?.skills?.soc_skills ?? 0} SOC-relevant`} accent="#8b5cf6" />
          <StatCard icon={Zap} label="Live Events" value={liveCount}
            sub="WebSocket stream" accent="#10b981" />
        </div>

        {/* Charts row */}
        <div className="grid lg:grid-cols-3 gap-4">
          <div className="lg:col-span-1 rounded-xl p-5 border border-white/5 bg-aegis-900">
            <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-4">Risk Distribution</h3>
            <ResponsiveContainer width="100%" height={180}>
              <PieChart>
                <Pie data={riskData} dataKey="value" nameKey="name" cx="50%" cy="50%" innerRadius={45} outerRadius={70}
                  paddingAngle={3}>
                  {riskData.map((e) => (
                    <Cell key={e.name} fill={RISK_COLORS[e.name] || '#64748b'} />
                  ))}
                </Pie>
                <Tooltip contentStyle={{ background: '#111827', border: '1px solid #334155', borderRadius: 8, fontSize: 12 }} />
              </PieChart>
            </ResponsiveContainer>
          </div>

          <div className="lg:col-span-1 rounded-xl p-5 border border-white/5 bg-aegis-900">
            <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-4">Attack Types</h3>
            <ResponsiveContainer width="100%" height={180}>
              <BarChart data={attackData} layout="vertical">
                <XAxis type="number" hide />
                <YAxis type="category" dataKey="name" width={90} tick={{ fill: '#94a3b8', fontSize: 10 }} />
                <Tooltip contentStyle={{ background: '#111827', border: '1px solid #334155', borderRadius: 8, fontSize: 12 }} />
                <Bar dataKey="count" fill="#06b6d4" radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>

          <div className="lg:col-span-1 rounded-xl p-5 border border-white/5 bg-aegis-900">
            <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-4">Alert Timeline</h3>
            <ResponsiveContainer width="100%" height={180}>
              <AreaChart data={timelineData}>
                <defs>
                  <linearGradient id="alertGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#06b6d4" stopOpacity={0.3} />
                    <stop offset="100%" stopColor="#06b6d4" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <XAxis dataKey="time" tick={{ fill: '#64748b', fontSize: 9 }} />
                <YAxis hide />
                <Tooltip contentStyle={{ background: '#111827', border: '1px solid #334155', borderRadius: 8, fontSize: 12 }} />
                <Area type="monotone" dataKey="alerts" stroke="#06b6d4" fill="url(#alertGrad)" strokeWidth={2} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Feature highlights */}
        <div className="grid md:grid-cols-3 gap-4">
          {[
            { icon: Crosshair, title: 'Skill-Orchestrated Analysis', desc: 'Routes incidents to 800+ cybersecurity playbooks with MITRE mapping', color: '#06b6d4' },
            { icon: Target, title: 'Multi-Layer Detection', desc: 'Isolation Forest ML + Sigma-style rules + LLM threat reasoning', color: '#8b5cf6' },
            { icon: Globe, title: 'IOC Enrichment', desc: 'AbuseIPDB, VirusTotal-ready pipeline with offline fallback', color: '#10b981' },
          ].map((f) => (
            <div key={f.title} className="rounded-xl p-4 border border-white/5 bg-aegis-900 flex gap-3">
              <div className="w-8 h-8 rounded-lg flex items-center justify-center shrink-0"
                style={{ background: `${f.color}15`, border: `1px solid ${f.color}30` }}>
                <f.icon size={16} style={{ color: f.color }} />
              </div>
              <div>
                <div className="text-sm font-semibold text-white">{f.title}</div>
                <div className="text-[11px] text-slate-500 mt-1 leading-relaxed">{f.desc}</div>
              </div>
            </div>
          ))}
        </div>

        {/* Alerts table */}
        <div className="rounded-xl border border-white/5 bg-aegis-900 overflow-hidden">
          <div className="px-5 py-4 border-b border-white/5 flex items-center justify-between">
            <h3 className="text-sm font-semibold text-white flex items-center gap-2">
              <AlertTriangle size={16} className="text-amber-400" />
              Security Alerts
            </h3>
            <span className="text-[10px] text-slate-500">{alerts.length} records</span>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-left">
              <thead>
                <tr className="text-[10px] uppercase tracking-wider text-slate-500 border-b border-white/5">
                  <th className="py-3 px-4">Source</th>
                  <th className="py-3 px-4">Destination</th>
                  <th className="py-3 px-4">Attack Type</th>
                  <th className="py-3 px-4">Risk</th>
                  <th className="py-3 px-4">Confidence</th>
                  <th className="py-3 px-4">MITRE</th>
                  <th className="py-3 px-4">Geo</th>
                </tr>
              </thead>
              <tbody>
                <AnimatePresence>
                  {alerts.length === 0 ? (
                    <tr><td colSpan={7} className="py-12 text-center text-slate-500 text-sm">
                      No alerts yet. Run <code className="font-mono text-cyan-400 text-xs">python scripts/traffic_simulator.py</code>
                    </td></tr>
                  ) : alerts.map((a, i) => <AlertRow key={a.id || i} alert={a} index={i} />)}
                </AnimatePresence>
              </tbody>
            </table>
          </div>
        </div>
      </main>

      <footer className="px-6 py-4 border-t border-white/5 text-center text-[10px] text-slate-600">
        SOCloom v1.0 — Open Source AI-Native SOC Platform
        <ChevronRight size={10} className="inline mx-1" />
        MIT License
      </footer>
    </div>
  )
}