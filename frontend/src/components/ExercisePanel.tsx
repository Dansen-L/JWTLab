import { useState, useEffect } from 'react'
import { motion, AnimatePresence, useReducedMotion } from 'framer-motion'
import JWTForge from './JWTForge'

interface Props {
  slug: string
  description: string
  defaultMutation?: string
  extraHeaderFields?: Record<string, unknown>
  verifyUrl?: string       // override default verify URL (e.g. ?mode=nosig)
  initialSecret?: string   // pre-fill the Forge secret field (e.g. cracked HMAC secret)
}

interface LogEntry {
  id: number
  method: string
  url: string
  status: number
  requestBody: string
  responseBody: string
  success: boolean
}

export default function ExercisePanel({ slug, description, defaultMutation, extraHeaderFields, verifyUrl, initialSecret }: Props) {
  const reduceMotion = useReducedMotion()
  const [patched, setPatched] = useState(false)
  const [patchedLoading, setPatchedLoading] = useState(false)
  const [log, setLog] = useState<LogEntry[]>([])
  const [firing, setFiring] = useState(false)
  const [received, setReceived] = useState(false)
  const [currentToken, setCurrentToken] = useState('')
  const [successFlash, setSuccessFlash] = useState(false)
  const [failFlash, setFailFlash] = useState(false)

  // Sync patched state from server on mount and when slug changes
  useEffect(() => {
    fetch('/api/v1/modules')
      .then(r => r.json())
      .then((mods: Array<{slug: string; patched: boolean}>) => {
        const m = mods.find(x => x.slug === slug)
        if (m) setPatched(m.patched)
      })
      .catch(() => {})
  }, [slug])

  // Mark module as in-progress when exercise mounts (if not already completed)
  useEffect(() => {
    const current = localStorage.getItem(`jwtlab.progress.${slug}`)
    if (current !== 'completed') {
      localStorage.setItem(`jwtlab.progress.${slug}`, 'in_progress')
      window.dispatchEvent(new Event('storage'))
    }
  }, [slug])

  // Load initial seed token
  useEffect(() => {
    fetch(`/api/v1/attack/${slug}/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'user', password: 'password' }),
    })
      .then(r => r.json())
      .then(d => d.token && setCurrentToken(d.token))
      .catch(() => {})
  }, [slug])

  const togglePatch = async () => {
    setPatchedLoading(true)
    try {
      const r = await fetch(`/api/v1/attack/${slug}/toggle-patch`, { method: 'POST' })
      const d = await r.json()
      setPatched(d.patched)
    } finally {
      setPatchedLoading(false)
    }
  }

  const fireToken = async (token: string) => {
    if (!token) return
    setFiring(true)
    const url = verifyUrl ?? `/api/v1/attack/${slug}/verify`
    const body = JSON.stringify({ token })

    try {
      const r = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body,
      })
      const data = await r.json()
      const entry: LogEntry = {
        id: Date.now(),
        method: 'POST',
        url,
        status: r.status,
        requestBody: body,
        responseBody: JSON.stringify(data, null, 2),
        success: r.ok,
      }
      setLog(prev => [entry, ...prev])

      if (r.ok) {
        setSuccessFlash(true)
        setTimeout(() => setSuccessFlash(false), 500)
        // Mark module complete in localStorage
        localStorage.setItem(`jwtlab.progress.${slug}`, 'completed')
        window.dispatchEvent(new Event('storage'))
      } else {
        setFailFlash(true)
        setTimeout(() => setFailFlash(false), 400)
      }
    } catch (err) {
      setLog(prev => [{
        id: Date.now(), method: 'POST', url, status: 0,
        requestBody: body, responseBody: `Network error: ${err}`, success: false,
      }, ...prev])
    } finally {
      setFiring(false)
      // Show response-direction arrow briefly after receipt
      setReceived(true)
      setTimeout(() => setReceived(false), 900)
    }
  }

  return (
    <section className="mb-6">
      <div className="flex items-center justify-between mb-3">
        <h2 className="font-display text-h3 text-text-primary">Interactive Exercise</h2>
        {/* VULNERABLE / PATCHED toggle */}
        <div className="flex items-center gap-3">
          {patched
            ? <span className="badge-patched">PATCHED</span>
            : <span className="badge-vulnerable">VULNERABLE</span>
          }
          <button
            onClick={togglePatch}
            disabled={patchedLoading}
            className="btn-secondary py-1 h-8 px-3 text-small"
          >
            {patchedLoading ? '…' : 'Toggle'}
          </button>
        </div>
      </div>

      <p className="text-text-muted text-small mb-4">{description}</p>

      {/* Split view: Forge (left) + Log (right) */}
      <div className="grid grid-cols-2 gap-4">
        {/* JWT Forge */}
        <div>
          <JWTForge
            initialToken={currentToken}
            onTokenChange={setCurrentToken}
            defaultMutation={defaultMutation}
            extraHeaderFields={extraHeaderFields}
            slug={slug}
            initialSecret={initialSecret}
          />
          <motion.button
            onClick={() => fireToken(currentToken)}
            disabled={firing || !currentToken}
            whileHover={{ scale: reduceMotion ? 1 : 1.02 }}
            whileTap={{ scale: reduceMotion ? 1 : 0.98 }}
            className="btn-primary w-full mt-3 disabled:opacity-50"
            aria-label="Fire token at vulnerable endpoint"
          >
            {firing ? 'Firing…' : '⚡ Fire Token'}
          </motion.button>

          {/* Traveling-dot arrows: client→server during request, server→client on response */}
          <div className="relative h-4 mt-2 overflow-hidden" aria-hidden="true">
            <AnimatePresence>
              {firing && (
                <motion.div
                  initial={{ left: '0%', opacity: 1 }}
                  animate={{ left: '100%', opacity: reduceMotion ? 1 : 0.6 }}
                  exit={{ opacity: 0 }}
                  transition={{ duration: reduceMotion ? 0 : 0.6, ease: 'linear', repeat: Infinity }}
                  className="absolute top-1 w-2 h-2 rounded-full bg-primary"
                  style={{ position: 'absolute' }}
                />
              )}
              {received && (
                <motion.div
                  initial={{ left: '100%', opacity: 1 }}
                  animate={{ left: '0%', opacity: reduceMotion ? 1 : 0.6 }}
                  exit={{ opacity: 0 }}
                  transition={{ duration: reduceMotion ? 0 : 0.6, ease: 'linear' }}
                  className="absolute top-1 w-2 h-2 rounded-full bg-accent"
                  style={{ position: 'absolute' }}
                />
              )}
            </AnimatePresence>
            {(firing || received) && (
              <div className={`absolute inset-y-2 left-0 right-0 border-t border-dashed ${received ? 'border-accent/40' : 'border-primary/40'}`} />
            )}
          </div>
        </div>

        {/* Request/Response log */}
        <div>
          <h3 className="font-display text-small text-text-muted mb-2 uppercase tracking-widest">
            Request / Response Log
          </h3>
          <AnimatePresence>
            {successFlash && (
              /* Radial burst from center — scale + radial glow */
              <motion.div
                initial={{ opacity: 0, scale: reduceMotion ? 1 : 0.7 }}
                animate={{ opacity: 1, scale: 1 }}
                exit={{ opacity: 0, scale: reduceMotion ? 1 : 1.1 }}
                transition={{ duration: reduceMotion ? 0 : 0.4, ease: [0.16, 1, 0.32, 1] }}
                className="bg-primary/20 border border-primary rounded-card p-3 mb-2 text-primary text-small font-medium"
                style={{ boxShadow: '0 0 24px rgba(0,229,160,0.35)' }}
              >
                ✓ SUCCESS
              </motion.div>
            )}
            {failFlash && (
              <motion.div
                initial={{ x: 0 }}
                animate={{ x: reduceMotion ? 0 : [-4, 4, -4, 4, 0] }}
                transition={{ duration: reduceMotion ? 0 : 0.3 }}
                className="bg-error/20 border border-error rounded-card p-3 mb-2 text-error text-small font-medium"
              >
                ✗ REJECTED
              </motion.div>
            )}
          </AnimatePresence>

          <div
            className="space-y-2 max-h-80 overflow-y-auto"
            tabIndex={0}
            role="log"
            aria-label="Request/Response log"
          >
            {log.length === 0 && (
              <div className="text-text-muted text-small italic">No requests fired yet.</div>
            )}
            {log.map(entry => (
              <motion.div
                key={entry.id}
                initial={{ opacity: 0, y: reduceMotion ? 0 : 4 }}
                animate={{ opacity: 1, y: 0 }}
                className={`rounded-card p-3 border ${
                  entry.success
                    ? 'bg-primary/5 border-primary/30'
                    : 'bg-error/5 border-error/30'
                }`}
              >
                <div className="flex items-center gap-2 mb-1">
                  <span className="font-mono text-small text-text-muted">{entry.method}</span>
                  <span className="font-mono text-small text-text-muted">{entry.url}</span>
                  <span className={`ml-auto font-mono text-small font-bold ${
                    entry.success ? 'text-primary' : 'text-error'
                  }`}>
                    HTTP {entry.status}
                  </span>
                </div>
                <pre className={`font-mono text-xs whitespace-pre-wrap max-h-24 overflow-y-auto ${
                  entry.success ? 'text-primary/80' : 'text-error/80'
                }`}>
                  {entry.responseBody}
                </pre>
              </motion.div>
            ))}
          </div>
        </div>
      </div>
    </section>
  )
}
