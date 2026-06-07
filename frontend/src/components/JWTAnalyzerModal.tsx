import { useState, useEffect, useRef, useCallback } from 'react'
import { motion, AnimatePresence, useReducedMotion } from 'framer-motion'
import CopyBlock from './CopyBlock'

// Sample JWT for the first-visit auto-play animation (HS256, role:user, iat set)
const SAMPLE_JWT = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyIiwicm9sZSI6InVzZXIiLCJpYXQiOjE3MDAwMDAwMDB9.WbzF4SoJH6Ld0gKHqajXO5jqY_lCVdxFu_8V0nqrfhA'

interface AnalysisResult {
  algorithm: string
  expired: boolean
  dangerousFields: string[]
  header: Record<string, unknown>
  payload: Record<string, unknown>
  signaturePresent: boolean
}

const DANGEROUS_FIELDS = new Set(['alg', 'kid', 'jku', 'x5u', 'jwk'])
const RFC_TOOLTIPS: Record<string, string> = {
  alg: 'RFC 7515 §4.1.1 — Algorithm header parameter. NEVER let the token header dictate which algorithm is used for verification.',
  kid: 'RFC 7515 §4.1.4 — Key ID. Used to look up signing keys; unsanitized use leads to SQL injection or path traversal.',
  jku: 'RFC 7515 §4.1.2 — JWK Set URL. Server may fetch this URL for verification keys — attacker-controlled URLs bypass key pinning.',
  x5u: 'RFC 7515 §4.1.5 — X.509 Certificate URL. Same SSRF risk as jku.',
  jwk: 'RFC 7515 §4.1.3 — JSON Web Key. Inline key in header — server trusting this allows key injection.',
  sub: 'RFC 7519 §4.1.2 — Subject. Principal that is the subject of the JWT.',
  exp: 'RFC 7519 §4.1.4 — Expiration Time. MUST be validated. Failure to check exp is a critical vulnerability.',
  iat: 'RFC 7519 §4.1.6 — Issued At. Identifies when the JWT was issued.',
  nbf: 'RFC 7519 §4.1.5 — Not Before. JWT must not be accepted before this time.',
  iss: 'RFC 7519 §4.1.1 — Issuer. Principal that issued the JWT.',
  aud: 'RFC 7519 §4.1.3 — Audience. Recipients the JWT is intended for.',
  typ: 'RFC 7515 §4.1.9 — Type. Media type of the JWT (typically "JWT").',
}

interface Props { onClose: () => void }

export default function JWTAnalyzerModal({ onClose }: Props) {
  const reduceMotion = useReducedMotion()
  const [rawToken, setRawToken] = useState('')
  const [analysis, setAnalysis] = useState<AnalysisResult | null>(null)
  const [verifySecret, setVerifySecret] = useState('')
  const [verifyAlg, setVerifyAlg] = useState('HS256')
  const [verifyResult, setVerifyResult] = useState<'pass' | 'fail' | null>(null)
  const [tooltip, setTooltip] = useState<string | null>(null)
  const [copiedJson, setCopiedJson] = useState(false)
  // auto-play: 'idle'=not started, 'playing'=animating, 'done'=finished/skipped
  const [autoPlay, setAutoPlay] = useState<'idle' | 'playing' | 'done'>('idle')
  const autoPlayTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const modalRef = useRef<HTMLDivElement>(null)
  const textareaRef = useRef<HTMLTextAreaElement>(null)
  // Store the element focused before modal opened, to return focus on close
  const returnFocusRef = useRef<HTMLElement | null>(null)

  // First-visit auto-play: seed sample JWT and play slow segment reveal
  useEffect(() => {
    const visited = localStorage.getItem('jwtlab.analyzer.visited')
    if (!visited) {
      // Delay start until modal entrance animation settles
      autoPlayTimerRef.current = setTimeout(() => setAutoPlay('playing'), 450)
    } else {
      setAutoPlay('done')
    }
    return () => { if (autoPlayTimerRef.current) clearTimeout(autoPlayTimerRef.current) }
  }, [])

  useEffect(() => {
    if (autoPlay === 'playing') {
      setRawToken(SAMPLE_JWT)
      // Auto-complete after ~3.5s
      autoPlayTimerRef.current = setTimeout(() => {
        setAutoPlay('done')
        localStorage.setItem('jwtlab.analyzer.visited', '1')
      }, 3500)
      return () => { if (autoPlayTimerRef.current) clearTimeout(autoPlayTimerRef.current) }
    }
  }, [autoPlay])

  const skipAutoPlay = useCallback(() => {
    if (autoPlayTimerRef.current) clearTimeout(autoPlayTimerRef.current)
    setAutoPlay('done')
    setRawToken(SAMPLE_JWT)
    localStorage.setItem('jwtlab.analyzer.visited', '1')
  }, [])

  useEffect(() => {
    if (autoPlay === 'done') textareaRef.current?.focus()
    const handleKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
    }
    document.addEventListener('keydown', handleKey)
    return () => document.removeEventListener('keydown', handleKey)
  }, [onClose, autoPlay])

  // Focus management: store trigger, focus first element, trap Tab within modal
  useEffect(() => {
    // Save the element that had focus before modal opened
    returnFocusRef.current = document.activeElement as HTMLElement | null

    // Focus into the modal (textarea or first focusable element)
    const focusable = 'a[href],button:not([disabled]),textarea,input,select,[tabindex]:not([tabindex="-1"])'
    const first = modalRef.current?.querySelector<HTMLElement>(focusable)
    first?.focus()

    const handleFocusTrap = (e: KeyboardEvent) => {
      if (e.key !== 'Tab' || !modalRef.current) return
      const elements = Array.from(modalRef.current.querySelectorAll<HTMLElement>(focusable))
      if (!elements.length) return
      const firstEl = elements[0]
      const lastEl = elements[elements.length - 1]
      if (e.shiftKey) {
        if (document.activeElement === firstEl) { e.preventDefault(); lastEl.focus() }
      } else {
        if (document.activeElement === lastEl) { e.preventDefault(); firstEl.focus() }
      }
    }
    document.addEventListener('keydown', handleFocusTrap)
    return () => {
      document.removeEventListener('keydown', handleFocusTrap)
      // Return focus to trigger element on unmount
      returnFocusRef.current?.focus()
    }
  }, [])

  useEffect(() => {
    if (!rawToken.trim()) { setAnalysis(null); return }
    fetch('/api/v1/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token: rawToken.trim() }),
    })
      .then(r => r.ok ? r.json() : null)
      .then(data => setAnalysis(data ?? null))
      .catch(() => setAnalysis(null))
  }, [rawToken])

  const isRsaAlg = verifyAlg.startsWith('RS')

  // Decode base64url with proper padding — returns Uint8Array with owned ArrayBuffer
  const b64urlDecode = (s: string): Uint8Array<ArrayBuffer> => {
    const b64 = s.replace(/-/g, '+').replace(/_/g, '/')
    const padded = b64 + '=='.slice(0, (4 - b64.length % 4) % 4)
    const binary = atob(padded)
    const bytes = new Uint8Array(binary.length)
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i)
    return bytes
  }

  // Strip PEM armor and decode to DER bytes — returns Uint8Array with owned ArrayBuffer
  const pemToDer = (pem: string): Uint8Array<ArrayBuffer> => {
    const b64 = pem
      .replace(/-----[A-Z ]+-----/g, '')
      .replace(/\s+/g, '')
    const binary = atob(b64)
    const bytes = new Uint8Array(binary.length)
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i)
    return bytes
  }

  const handleVerify = async () => {
    try {
      const parts = rawToken.trim().split('.')
      if (parts.length !== 3) { setVerifyResult('fail'); return }

      const sigBytes = b64urlDecode(parts[2])
      const msgBytes = new TextEncoder().encode(`${parts[0]}.${parts[1]}`)

      if (isRsaAlg) {
        // RS256 / RS384 / RS512 via SubtleCrypto RSASSA-PKCS1-v1_5
        const hashBits = verifyAlg.slice(2) // "256" | "384" | "512"
        const derBytes = pemToDer(verifySecret)
        const key = await crypto.subtle.importKey(
          'spki', derBytes,
          { name: 'RSASSA-PKCS1-v1_5', hash: `SHA-${hashBits}` },
          false, ['verify']
        )
        const valid = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, sigBytes, msgBytes)
        setVerifyResult(valid ? 'pass' : 'fail')
      } else {
        // HS256 / HS384 / HS512 via SubtleCrypto HMAC
        const enc = new TextEncoder()
        const key = await crypto.subtle.importKey(
          'raw', enc.encode(verifySecret),
          { name: 'HMAC', hash: `SHA-${verifyAlg.slice(2)}` },
          false, ['verify']
        )
        const valid = await crypto.subtle.verify('HMAC', key, sigBytes, msgBytes)
        setVerifyResult(valid ? 'pass' : 'fail')
      }
    } catch {
      setVerifyResult('fail')
    }
  }

  const copyJson = () => {
    if (!analysis) return
    navigator.clipboard.writeText(JSON.stringify({ header: analysis.header, payload: analysis.payload }, null, 2))
    setCopiedJson(true)
    setTimeout(() => setCopiedJson(false), 2000)
  }

  return (
    <AnimatePresence>
      <div
        className="fixed inset-0 z-[100] flex items-center justify-center bg-black/60 backdrop-blur-sm"
        onClick={e => e.target === e.currentTarget && onClose()}
        role="dialog"
        aria-modal="true"
        aria-label="JWT Analyzer"
      >
        <motion.div
          ref={modalRef}
          initial={{ opacity: 0, scale: reduceMotion ? 1 : 0.96, y: reduceMotion ? 0 : 8 }}
          animate={{ opacity: 1, scale: 1, y: 0 }}
          exit={{ opacity: 0, scale: reduceMotion ? 1 : 0.96, y: reduceMotion ? 0 : 8 }}
          transition={{ duration: reduceMotion ? 0 : 0.2 }}
          className="bg-surface border border-border rounded-card w-full max-w-4xl max-h-[90vh] overflow-y-auto m-4 shadow-2xl"
        >
          <div className="p-6">
            {/* Header */}
            <div className="flex items-center justify-between mb-4">
              <h2 className="font-display text-h2 text-text-primary">JWT Analyzer</h2>
              <button onClick={onClose} className="text-text-muted hover:text-text-primary transition-colors p-1" aria-label="Close">✕</button>
            </div>

            {/* Token input */}
            <textarea
              ref={textareaRef}
              value={rawToken}
              onChange={e => setRawToken(e.target.value)}
              placeholder="Paste a JWT here to decode…"
              className="input-field w-full h-24 resize-none font-mono text-small mb-4"
              aria-label="JWT token input"
            />

            {/* Token assembly animation: slow stagger on auto-play, fast on manual */}
            {rawToken.trim() && rawToken.trim().split('.').length !== 3 && (
              <div
                className="bg-error/20 border border-error rounded-card p-3 mb-4 text-error text-small font-medium"
                role="alert"
              >
                ✗ Invalid JWT — expected 3 dot-separated segments, got {rawToken.trim().split('.').length}
              </div>
            )}
            {rawToken.trim() && rawToken.trim().split('.').length === 3 && (
              <div className="mb-4">
                {autoPlay === 'playing' && (
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-xs text-text-muted/70 italic">Decoding token…</span>
                    <button
                      onClick={skipAutoPlay}
                      className="text-xs text-primary hover:text-primary/80 transition-colors px-2 py-0.5 border border-primary/30 rounded"
                      aria-label="Skip animation"
                    >
                      Skip →
                    </button>
                  </div>
                )}
                <div className="flex gap-1 font-mono text-xs break-all">
                  {rawToken.trim().split('.').map((seg, i) => (
                  <motion.span
                    key={`${rawToken.trim()}-${i}-${autoPlay}`}
                    initial={{ opacity: 0, y: reduceMotion ? 0 : (autoPlay === 'playing' ? 8 : 4) }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: reduceMotion ? 0 : (autoPlay === 'playing' ? 0.7 : 0.18), delay: reduceMotion ? 0 : i * 0.04, ease: 'easeOut' }}
                    className={[
                      'jwt-header-color',
                      'jwt-payload-color',
                      'jwt-sig-color',
                    ][i] ?? 'text-text-muted'}
                    style={autoPlay === 'playing' && !reduceMotion ? {
                      textShadow: i === 0 ? '0 0 12px rgba(91,188,255,0.6)'
                        : i === 1 ? '0 0 12px rgba(0,229,160,0.6)'
                        : '0 0 12px rgba(255,174,0,0.6)'
                    } : undefined}
                  >
                    {seg}
                    {i < 2 && <span className="text-text-muted">.</span>}
                  </motion.span>
                ))}
                </div>
              </div>
            )}

            {analysis && (
              <div>
                {/* Status bar */}
                <div className="flex items-center gap-3 mb-4">
                  <span className="text-small text-text-muted">Algorithm:</span>
                  <span className={`font-mono text-small ${analysis.algorithm.toLowerCase() === 'none' ? 'text-error' : 'text-primary'}`}>
                    {analysis.algorithm}
                  </span>
                  {analysis.expired && <span className="badge-vulnerable">[EXPIRED]</span>}
                  {!analysis.signaturePresent && <span className="badge-warning">No Signature</span>}
                  <button onClick={copyJson} className="ml-auto text-small text-text-muted hover:text-primary transition-colors">
                    {copiedJson ? '✓ Copied' : 'Copy JSON'}
                  </button>
                </div>

                {/* Three columns */}
                <div className="grid grid-cols-3 gap-4 mb-6">
                  {/* Header */}
                  <CopyBlock>
                    <div className="text-small font-medium jwt-header-color mb-2">Header</div>
                    {Object.entries(analysis.header).map(([k, v]) => (
                      <div key={k} className="flex items-start gap-1 mb-1 relative group">
                        {DANGEROUS_FIELDS.has(k) && (
                          <span
                            className="badge-warning cursor-help shrink-0"
                            onMouseEnter={() => setTooltip(RFC_TOOLTIPS[k] ?? `Custom claim — no standard RFC definition for "${k}"`)}
                            onMouseLeave={() => setTooltip(null)}
                          >
                            ⚠
                          </span>
                        )}
                        <span
                          className="text-text-muted text-small cursor-help"
                          onMouseEnter={() => setTooltip(RFC_TOOLTIPS[k] ?? `Custom claim — no standard RFC definition for "${k}"`)}
                          onMouseLeave={() => setTooltip(null)}
                        >
                          {k}:
                        </span>
                        <span className="text-jwt-header text-small break-all">{String(v)}</span>
                      </div>
                    ))}
                  </CopyBlock>

                  {/* Payload */}
                  <CopyBlock>
                    <div className="text-small font-medium jwt-payload-color mb-2">Payload</div>
                    {Object.entries(analysis.payload).map(([k, v]) => (
                      <div key={k} className="flex items-start gap-1 mb-1">
                        <span
                          className="text-text-muted text-small cursor-help"
                          onMouseEnter={() => setTooltip(RFC_TOOLTIPS[k] ?? `Custom claim — no standard RFC definition for "${k}"`)}
                          onMouseLeave={() => setTooltip(null)}
                        >
                          {k}:
                        </span>
                        <span className="text-jwt-payload text-small break-all">{String(v)}</span>
                      </div>
                    ))}
                  </CopyBlock>

                  {/* Signature */}
                  <CopyBlock>
                    <div className="text-small font-medium jwt-sig-color mb-2">Signature</div>
                    <span className={`text-small ${analysis.signaturePresent ? 'text-jwt-sig' : 'text-text-muted'}`}>
                      {analysis.signaturePresent ? 'Present ✓' : 'Absent —'}
                    </span>
                  </CopyBlock>
                </div>

                {/* Tooltip display */}
                {tooltip && (
                  <div className="bg-surface-alt border border-warning/30 rounded p-3 text-small text-text-muted mb-4">
                    {tooltip}
                  </div>
                )}

                {/* Signature verification */}
                <div className="border-t border-border pt-4">
                  <h3 className="font-display text-h3 text-text-primary mb-3">Verify Signature</h3>
                  <div className="flex gap-3 items-end flex-wrap">
                    <div className="flex-1 min-w-[90px]">
                      <label className="text-small text-text-muted block mb-1">Algorithm</label>
                      <select
                        value={verifyAlg}
                        onChange={e => { setVerifyAlg(e.target.value); setVerifyResult(null); setVerifySecret('') }}
                        className="input-field w-full"
                        aria-label="Signature verification algorithm"
                      >
                        {['HS256','HS384','HS512','RS256','RS384','RS512'].map(a => <option key={a}>{a}</option>)}
                      </select>
                    </div>
                    <div className="flex-[3]">
                      {isRsaAlg ? (
                        <>
                          <label className="text-small text-text-muted block mb-1">RSA Public Key (PEM)</label>
                          <textarea
                            value={verifySecret}
                            onChange={e => setVerifySecret(e.target.value)}
                            placeholder="-----BEGIN PUBLIC KEY-----&#10;…&#10;-----END PUBLIC KEY-----"
                            rows={4}
                            className="input-field w-full resize-none font-mono text-xs"
                            aria-label="RSA public key PEM"
                          />
                        </>
                      ) : (
                        <>
                          <label className="text-small text-text-muted block mb-1">HMAC Secret</label>
                          <input
                            type="text"
                            value={verifySecret}
                            onChange={e => setVerifySecret(e.target.value)}
                            placeholder="Enter HMAC secret…"
                            className="input-field w-full"
                            aria-label="HMAC secret for verification"
                          />
                        </>
                      )}
                    </div>
                    <button onClick={handleVerify} className="btn-primary self-end">Verify</button>
                  </div>
                  {verifyResult && (
                    <motion.div
                      initial={{ opacity: 0 }}
                      animate={{ opacity: 1 }}
                      className={`mt-3 text-small font-medium ${verifyResult === 'pass' ? 'text-primary' : 'text-error'}`}
                    >
                      {verifyResult === 'pass' ? '✓ PASS — Signature is valid' : '✗ FAIL — Signature does not match'}
                    </motion.div>
                  )}
                </div>
              </div>
            )}
          </div>
        </motion.div>
      </div>
    </AnimatePresence>
  )
}
