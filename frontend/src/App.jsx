import { useCallback, useEffect, useState } from 'react'
import {
  Activity,
  AlertTriangle,
  Check,
  CheckCircle2,
  ChevronRight,
  Clock3,
  Command,
  Play,
  ShieldCheck,
  ShieldOff,
  Terminal,
  X,
  XCircle,
} from 'lucide-react'

const API_BASE = 'http://localhost:8080/api'
const presets = [
  'git status',
  'sudo apt install nginx',
  'format C:',
  'echo cm0gLXJmIC8= | base64 -d',
  'ls && cat ../../etc/passwd',
]
const decisionStyles = {
  ALLOW: { badge: 'border-emerald-400/30 bg-emerald-400/10 text-emerald-300', bar: 'bg-emerald-400' },
  NEEDS_APPROVAL: { badge: 'border-amber-400/30 bg-amber-400/10 text-amber-300', bar: 'bg-amber-400' },
  DENY: { badge: 'border-red-400/30 bg-red-400/10 text-red-300', bar: 'bg-red-400' },
}

function Badge({ decision }) {
  const style = decisionStyles[decision] || decisionStyles.ALLOW
  return (
    <span className={`inline-flex rounded-md border px-2 py-1 text-[11px] font-bold tracking-wide ${style.badge}`}>
      {decision}
    </span>
  )
}

function App() {
  const [command, setCommand] = useState('')
  const [verdict, setVerdict] = useState(null)
  const [stats, setStats] = useState({ total: 0, allowed: 0, needsApproval: 0, denied: 0, averageRiskScore: 0 })
  const [pending, setPending] = useState([])
  const [logs, setLogs] = useState([])
  const [filter, setFilter] = useState('ALL')
  const [loading, setLoading] = useState(false)
  const [batchLoading, setBatchLoading] = useState(false)
  const [error, setError] = useState('')

  const refreshAll = useCallback(async () => {
    try {
      const [statsResponse, pendingResponse, logsResponse] = await Promise.all([
        fetch(`${API_BASE}/stats`),
        fetch(`${API_BASE}/logs?decision=NEEDS_APPROVAL`),
        fetch(`${API_BASE}/logs`),
      ])
      if (!statsResponse.ok || !pendingResponse.ok || !logsResponse.ok) throw new Error('Backend error')
      const [nextStats, pendingLogs, allLogs] = await Promise.all([
        statsResponse.json(),
        pendingResponse.json(),
        logsResponse.json(),
      ])
      setStats(nextStats)
      setPending(pendingLogs.filter((log) => log.status === 'PENDING'))
      setLogs(allLogs)
      setError('')
    } catch {
      setError('Cannot reach the AgentGuard API at http://localhost:8080')
    }
  }, [])

  useEffect(() => {
    refreshAll()
  }, [refreshAll])

  async function analyze(rawCommand = command) {
    if (!rawCommand.trim()) return
    setLoading(true)
    setError('')
    try {
      const response = await fetch(`${API_BASE}/check`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ command: rawCommand }),
      })
      if (!response.ok) throw new Error('Analysis failed')
      setVerdict(await response.json())
      await refreshAll()
    } catch {
      setError('Could not analyze that command.')
    } finally {
      setLoading(false)
    }
  }

  async function simulateBatch() {
    setBatchLoading(true)
    setError('')
    try {
      const response = await fetch(`${API_BASE}/demo/simulate`, { method: 'POST' })
      if (!response.ok) throw new Error('Simulation failed')
      const results = await response.json()
      if (results.length) setVerdict(results[results.length - 1])
      await refreshAll()
    } catch {
      setError('Could not run the AI agent batch.')
    } finally {
      setBatchLoading(false)
    }
  }

  async function updateApproval(id, action) {
    try {
      const response = await fetch(`${API_BASE}/logs/${id}/${action}`, { method: 'POST' })
      if (!response.ok) throw new Error('Update failed')
      await refreshAll()
    } catch {
      setError(`Could not ${action} command #${id}.`)
    }
  }

  const filteredLogs = filter === 'ALL' ? logs : logs.filter((log) => log.decision === filter)
  const statCards = [
    { label: 'Total Checked', value: stats.total ?? 0, icon: Activity, color: 'text-sky-400', bg: 'bg-sky-400/10' },
    { label: 'Allowed', value: stats.allowed ?? 0, icon: ShieldCheck, color: 'text-emerald-400', bg: 'bg-emerald-400/10' },
    { label: 'Needs Approval', value: stats.needsApproval ?? 0, icon: AlertTriangle, color: 'text-amber-400', bg: 'bg-amber-400/10' },
    { label: 'Denied', value: stats.denied ?? 0, icon: ShieldOff, color: 'text-red-400', bg: 'bg-red-400/10' },
    { label: 'Average Risk', value: Number(stats.averageRiskScore ?? 0).toFixed(1), icon: Command, color: 'text-violet-400', bg: 'bg-violet-400/10' },
  ]
  const verdictStyle = verdict ? decisionStyles[verdict.decision] : decisionStyles.ALLOW

  return (
    <div className="min-h-screen bg-[#090d14] text-slate-200">
      <header className="border-b border-slate-800/90 bg-[#0c111a]/95">
        <div className="mx-auto flex max-w-[1500px] items-center justify-between px-5 py-4 lg:px-8">
          <div className="flex items-center gap-3">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-blue-400/20 bg-blue-400/10 text-blue-400">
              <ShieldCheck size={20} />
            </div>
            <div>
              <h1 className="text-base font-semibold tracking-tight text-white">
                AgentGuard — Pre-Execution AI Command Safety Gateway
              </h1>
            </div>
          </div>
          <div className="flex items-center gap-2 rounded-full border border-emerald-400/20 bg-emerald-400/5 px-3 py-1.5 text-xs font-medium text-emerald-400">
            <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-emerald-400" />
            Gateway Online
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-[1500px] px-5 py-6 lg:px-8">
        {error && (
          <div className="mb-5 flex items-center gap-2 rounded-lg border border-red-400/20 bg-red-400/10 px-4 py-3 text-sm text-red-300">
            <XCircle size={16} />
            {error}
          </div>
        )}

        <section className="grid grid-cols-2 gap-3 lg:grid-cols-5" aria-label="Command statistics">
          {statCards.map(({ label, value, icon: Icon, color, bg }) => (
            <div key={label} className="rounded-xl border border-slate-800 bg-[#101620] p-4 shadow-sm">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-xs font-medium text-slate-500">{label}</p>
                  <p className="mt-2 text-2xl font-semibold tracking-tight text-white">{value}</p>
                </div>
                <div className={`flex h-9 w-9 items-center justify-center rounded-lg ${bg} ${color}`}>
                  <Icon size={18} />
                </div>
              </div>
            </div>
          ))}
        </section>

        <section className="mt-5 grid gap-5 xl:grid-cols-[minmax(0,1fr)_420px]">
          <div className="overflow-hidden rounded-xl border border-slate-800 bg-[#101620]">
            <div className="border-b border-slate-800 px-5 py-4">
              <div className="flex items-center gap-2">
                <Terminal size={17} className="text-blue-400" />
                <h2 className="text-sm font-semibold text-white">Live Command Sandbox</h2>
              </div>
            </div>
            <div className="p-5">
              <form
                onSubmit={(event) => {
                  event.preventDefault()
                  analyze()
                }}
                className="flex gap-2"
              >
                <div className="flex min-w-0 flex-1 items-center rounded-lg border border-slate-700 bg-[#090d14] px-3 focus-within:border-blue-500/70">
                  <ChevronRight size={16} className="mr-2 shrink-0 text-slate-600" />
                  <input
                    value={command}
                    onChange={(event) => setCommand(event.target.value)}
                    placeholder="Enter a command to analyze..."
                    className="h-11 w-full bg-transparent font-mono text-sm text-slate-100 outline-none placeholder:text-slate-600"
                  />
                </div>
                <button
                  type="submit"
                  disabled={loading || !command.trim()}
                  className="flex h-11 items-center gap-2 rounded-lg bg-blue-600 px-4 text-sm font-semibold text-white hover:bg-blue-500 disabled:opacity-50"
                >
                  <Play size={15} fill="currentColor" />
                  {loading ? 'Analyzing...' : 'Analyze Command'}
                </button>
              </form>

              <div className="mt-3 flex flex-wrap gap-2">
                {presets.map((preset) => (
                  <button
                    key={preset}
                    type="button"
                    onClick={() => {
                      setCommand(preset)
                      analyze(preset)
                    }}
                    className="rounded-md border border-slate-700 bg-slate-800/50 px-2.5 py-1.5 font-mono text-[11px] text-slate-400 hover:border-slate-600 hover:text-slate-200"
                  >
                    {preset}
                  </button>
                ))}
              </div>

              <button
                type="button"
                onClick={simulateBatch}
                disabled={batchLoading}
                className="mt-5 flex h-12 w-full items-center justify-center gap-2 rounded-lg border border-violet-400/30 bg-violet-500/10 text-sm font-semibold text-violet-300 hover:border-violet-400/50 hover:bg-violet-500/15 disabled:opacity-50"
              >
                <Activity size={17} />
                {batchLoading ? 'Simulating 8-command batch...' : 'Simulate AI Agent Batch'}
              </button>
            </div>
          </div>

          <div className="overflow-hidden rounded-xl border border-slate-800 bg-[#101620]">
            <div className="flex items-center justify-between border-b border-slate-800 px-5 py-4">
              <h2 className="text-sm font-semibold text-white">Verdict</h2>
              {verdict && <Badge decision={verdict.decision} />}
            </div>
            {verdict ? (
              <div className="p-5">
                <div className="mb-5">
                  <div className="mb-2 flex items-end justify-between">
                    <span className="text-xs font-medium text-slate-500">Risk Score</span>
                    <span className="text-xl font-semibold text-white">{verdict.riskScore}<span className="text-xs text-slate-500"> / 100</span></span>
                  </div>
                  <div className="h-2 overflow-hidden rounded-full bg-slate-800">
                    <div
                      className={`h-full rounded-full ${verdictStyle.bar}`}
                      style={{ width: `${Math.min(100, Math.max(0, verdict.riskScore))}%` }}
                    />
                  </div>
                </div>
                <div className="space-y-4">
                  <div>
                    <p className="mb-2 text-[11px] font-semibold uppercase tracking-wider text-slate-500">Split Sub-commands</p>
                    <div className="space-y-1.5">
                      {(verdict.subCommands || []).length ? verdict.subCommands.map((part, index) => (
                        <code key={`${part}-${index}`} className="block rounded-md border border-slate-800 bg-[#090d14] px-3 py-2 font-mono text-xs text-slate-300">{part}</code>
                      )) : <p className="text-sm text-slate-600">None</p>}
                    </div>
                  </div>
                  <div>
                    <p className="mb-2 text-[11px] font-semibold uppercase tracking-wider text-slate-500">Matched Rules</p>
                    <div className="flex flex-wrap gap-1.5">
                      {(verdict.matchedRules || []).length ? verdict.matchedRules.map((rule) => (
                        <span key={rule} className="rounded-md border border-blue-400/20 bg-blue-400/10 px-2 py-1 text-[11px] text-blue-300">{rule}</span>
                      )) : <span className="text-xs text-slate-600">No matched rules</span>}
                    </div>
                  </div>
                  <div>
                    <p className="mb-2 text-[11px] font-semibold uppercase tracking-wider text-slate-500">Evasion Flags</p>
                    <div className="flex flex-wrap gap-1.5">
                      {(verdict.evasionFlags || []).length ? verdict.evasionFlags.map((flag) => (
                        <span key={flag} className="rounded-md border border-amber-400/20 bg-amber-400/10 px-2 py-1 text-[11px] text-amber-300">{flag}</span>
                      )) : <span className="text-xs text-slate-600">None detected</span>}
                    </div>
                  </div>
                  <div className="rounded-lg border border-slate-800 bg-[#090d14] p-3">
                    <p className="text-xs leading-relaxed text-slate-400">{verdict.reason}</p>
                  </div>
                </div>
              </div>
            ) : (
              <div className="flex h-[390px] flex-col items-center justify-center px-6 text-center">
                <div className="flex h-12 w-12 items-center justify-center rounded-full border border-slate-800 bg-slate-800/40 text-slate-600">
                  <Terminal size={21} />
                </div>
                <p className="mt-3 text-sm font-medium text-slate-400">Awaiting analysis</p>
                <p className="mt-1 text-xs text-slate-600">Run a command or batch simulation</p>
              </div>
            )}
          </div>
        </section>

        <section className="mt-5 grid gap-5 xl:grid-cols-[360px_minmax(0,1fr)]">
          <div className="overflow-hidden rounded-xl border border-slate-800 bg-[#101620]">
            <div className="flex items-center justify-between border-b border-slate-800 px-5 py-4">
              <div className="flex items-center gap-2">
                <Clock3 size={16} className="text-amber-400" />
                <h2 className="text-sm font-semibold text-white">Human Approval Queue</h2>
              </div>
              <span className="rounded-full bg-amber-400/10 px-2 py-0.5 text-xs font-semibold text-amber-300">{pending.length}</span>
            </div>
            <div className="max-h-[420px] overflow-y-auto p-3">
              {pending.length ? pending.map((item) => (
                <div key={item.id} className="mb-2 rounded-lg border border-slate-800 bg-[#0c111a] p-3 last:mb-0">
                  <div className="flex items-start justify-between gap-2">
                    <code className="min-w-0 break-all font-mono text-xs text-slate-300">{item.rawCommand}</code>
                    <span className="shrink-0 text-xs font-semibold text-amber-400">{item.riskScore}</span>
                  </div>
                  <div className="mt-3 flex gap-2">
                    <button type="button" onClick={() => updateApproval(item.id, 'approve')} className="flex h-8 flex-1 items-center justify-center gap-1.5 rounded-md border border-emerald-400/20 bg-emerald-400/10 text-xs font-semibold text-emerald-300 hover:bg-emerald-400/15">
                      <Check size={13} /> Approve
                    </button>
                    <button type="button" onClick={() => updateApproval(item.id, 'reject')} className="flex h-8 flex-1 items-center justify-center gap-1.5 rounded-md border border-red-400/20 bg-red-400/10 text-xs font-semibold text-red-300 hover:bg-red-400/15">
                      <X size={13} /> Reject
                    </button>
                  </div>
                </div>
              )) : (
                <div className="flex h-40 flex-col items-center justify-center text-center">
                  <CheckCircle2 size={22} className="text-slate-700" />
                  <p className="mt-2 text-xs text-slate-500">No pending approvals</p>
                </div>
              )}
            </div>
          </div>

          <div className="overflow-hidden rounded-xl border border-slate-800 bg-[#101620]">
            <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 px-5 py-3.5">
              <h2 className="text-sm font-semibold text-white">Full Audit Log</h2>
              <div className="flex rounded-lg border border-slate-800 bg-[#090d14] p-1">
                {['ALL', 'ALLOW', 'NEEDS_APPROVAL', 'DENY'].map((tab) => (
                  <button key={tab} type="button" onClick={() => setFilter(tab)} className={`rounded-md px-2.5 py-1 text-[10px] font-semibold ${filter === tab ? 'bg-slate-700 text-white' : 'text-slate-500 hover:text-slate-300'}`}>
                    {tab}
                  </button>
                ))}
              </div>
            </div>
            <div className="max-h-[420px] overflow-auto">
              <table className="w-full border-collapse text-left">
                <thead className="sticky top-0 bg-[#101620]">
                  <tr className="border-b border-slate-800 text-[10px] uppercase tracking-wider text-slate-500">
                    <th className="px-4 py-3 font-semibold">ID</th>
                    <th className="px-4 py-3 font-semibold">Raw Command</th>
                    <th className="px-4 py-3 font-semibold">Decision</th>
                    <th className="px-4 py-3 font-semibold">Risk</th>
                    <th className="px-4 py-3 font-semibold">Matched Rules</th>
                    <th className="px-4 py-3 font-semibold">Status</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredLogs.map((log) => (
                    <tr key={log.id} className="border-b border-slate-800/70 text-xs last:border-0 hover:bg-slate-800/20">
                      <td className="px-4 py-3 font-mono text-slate-600">#{log.id}</td>
                      <td className="max-w-[320px] px-4 py-3">
                        <code className="block truncate font-mono text-slate-300" title={log.rawCommand}>{log.rawCommand}</code>
                      </td>
                      <td className="px-4 py-3"><Badge decision={log.decision} /></td>
                      <td className="px-4 py-3 font-semibold text-slate-300">{log.riskScore}</td>
                      <td className="max-w-[220px] px-4 py-3">
                        <span className="block truncate text-slate-500" title={log.matchedRules}>{log.matchedRules || '—'}</span>
                      </td>
                      <td className="px-4 py-3">
                        <span className={`text-[11px] font-semibold ${log.status === 'PENDING' ? 'text-amber-400' : log.status === 'APPROVED' ? 'text-emerald-400' : log.status === 'REJECTED' ? 'text-red-400' : 'text-slate-500'}`}>{log.status}</span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {!filteredLogs.length && (
                <div className="flex h-40 items-center justify-center text-xs text-slate-600">No audit records found</div>
              )}
            </div>
          </div>
        </section>
      </main>
    </div>
  )
}

export default App
