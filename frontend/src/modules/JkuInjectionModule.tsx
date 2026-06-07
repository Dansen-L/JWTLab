/**
 * Attack Module: jku / jwk Header Injection
 * Two attack paths:
 *   jku-fetch: server fetches JWKS from attacker-controlled URL (no domain allowlist)
 *   jwk-embed: server trusts inline JWK in token header
 */
import { useState, useEffect } from 'react'
import { motion, AnimatePresence, useReducedMotion } from 'framer-motion'
import ModuleLayout from '../components/ModuleLayout'
import AttackVisualizer from '../components/AttackVisualizer'
import ExercisePanel from '../components/ExercisePanel'

// ─── jku-fetch Attack Steps ─────────────────────────────────────────────────
const JKU_STEPS = [
  {
    title: 'Attacker Generates RSA Keypair',
    client: 'Generate 2048-bit RSA keypair:\n  GET /api/v1/attack/jku-injection/attacker-private-key\n\nResponse: {\n  "privateKeyPem": "-----BEGIN RSA PRIVATE KEY-----\\n...",\n  "suggestedJkuUrl": "http://localhost:8765/api/v1/attack/jku-injection/attacker-jwks"\n}',
    server: 'Server generates and stores a distinct attacker RSA keypair.\nThe suggestedJkuUrl points to the JWKS endpoint\nthat serves the attacker\'s public key.',
    description: 'The attacker generates or obtains an RSA keypair. In a real attack, they\'d host the JWKS at a URL they control. Here, the lab provides a /attacker-jwks endpoint.',
  },
  {
    title: 'Forge Token with jku Pointing to Attacker JWKS',
    client: 'header: {\n  "alg": "RS256",\n  "jku": "http://localhost:8765/api/v1/attack/jku-injection/attacker-jwks",\n  "kid": "attacker-key"\n}\npayload: {"sub":"user","role":"admin",...}\n\nSigned with: attacker\'s RSA private key',
    server: 'The server will fetch JWKS from the jku URL in the header.\nAttacker controls that URL → attacker controls the public key\nused for verification.',
    description: 'The attacker sets jku to their JWKS endpoint and signs the forged token with their RSA private key. When the server fetches the JWKS, it gets the attacker\'s public key.',
    highlight: true,
  },
  {
    title: 'Server Fetches Attacker JWKS (SSRF-adjacent)',
    client: 'POST /api/v1/attack/jku-injection/verify\n{"token": "<attacker-signed-RS256-token>"}',
    server: 'Server reads jku from token header.\nFetches: GET http://localhost:8765/api/v1/attack/jku-injection/attacker-jwks\n→ {"keys": [{"kty":"RSA","n":"...","e":"..."}]}\n\nVerifies token with attacker\'s public key — PASSES!\nHTTP 200 {"valid":true,"role":"admin"}',
    description: 'The server blindly fetches the JWKS from whatever URL the jku header specifies. It gets the attacker\'s public key, verifies the forged token (which was signed with the matching private key), and accepts it.',
    highlight: true,
  },
  {
    title: 'Patched: Domain Allowlist for jku',
    client: 'POST /api/v1/attack/jku-injection/verify\n{"token": "<attacker-jku-token>"}',
    server: 'Patched: jku domain checked against allowlist.\nAttacker domain not in allowlist.\n\nHTTP 401 {"valid":false,"message":"jku domain not in allowlist."}',
    description: 'The patched endpoint validates the jku URL against an allowlist of trusted domains before fetching. Attacker-controlled URLs are rejected before any SSRF-adjacent fetch occurs.',
  },
]

// ─── jwk-embed Attack Steps ────────────────────────────────────────────────
const JWK_STEPS = [
  {
    title: 'Attacker Generates Keypair and Builds JWK',
    client: 'Generate RSA keypair locally.\n\nConvert public key to JWK format:\n{\n  "kty": "RSA",\n  "n": "<base64url-encoded-modulus>",\n  "e": "AQAB",\n  "kid": "attacker-key"\n}',
    server: 'The JWK format embeds the full public key.\nAttacker prepares to inline this in the\ntoken header\'s jwk field.',
    description: 'The attacker generates an RSA keypair and converts the public key to JWK format. This will be embedded directly in the token header — no external URL fetch required.',
  },
  {
    title: 'Forge Token with Embedded jwk Header',
    client: 'header: {\n  "alg": "RS256",\n  "jwk": {"kty":"RSA","n":"...","e":"AQAB","kid":"attacker-key"}\n}\npayload: {"sub":"user","role":"admin",...}\n\nSigned with: attacker\'s RSA private key',
    server: 'The server trusts the inline jwk header field.\nIt uses that JWK to verify the token\'s signature.\nAttacker\'s public key is trusted — forged token passes.',
    description: 'The attacker embeds their public key directly in the token header using the jwk field, then signs with the matching private key. The token is self-verifying from the attacker\'s key.',
    highlight: true,
  },
  {
    title: 'Server Trusts Inline JWK (No Fetch Needed)',
    client: 'POST /api/v1/attack/jku-injection/verify\n{"token": "<jwk-embed-token>"}',
    server: 'Server reads jwk from token header.\nConstructs public key from embedded JWK.\n\nVerifies token with attacker-embedded key — PASSES!\nHTTP 200 {"valid":true,"role":"admin"}',
    description: 'The server trusts the inline jwk without any URL fetch. This is even simpler than the jku attack — no network infrastructure needed, just a crafted header.',
    highlight: true,
  },
  {
    title: 'Patched: Reject Inline jwk Header',
    client: 'POST /api/v1/attack/jku-injection/verify\n{"token": "<jwk-embed-token>"}',
    server: 'Patched: inline jwk header claims rejected.\n\nHTTP 401 {"valid":false,"message":"Inline jwk header not permitted."}',
    description: 'The patched endpoint unconditionally rejects tokens with a jwk header field. Keys must come from server-side configuration, not from user-supplied token headers.',
  },
]

const NARRATIVE = `
The JWT <code>jku</code> (JWK Set URL) and <code>jwk</code> (JSON Web Key) header claims were
designed to help servers discover verification keys. When a server trusts these claims from the
token itself, an attacker can direct it to use their own key.

<strong>Two attack paths:</strong>
<ul class="list-disc ml-4 mt-2 space-y-2">
  <li><strong>jku-fetch:</strong> The server fetches a JWKS from the URL in the jku header.
  An attacker sets jku to their own server, hosts their public key there, and signs the forged
  token with the matching private key. The server fetches the attacker's key and accepts the
  token. This is <span class="callout-term-danger">SSRF-adjacent</span> — the server makes an outbound HTTP request based on user input.</li>
  <li><strong>jwk-embed:</strong> The server reads the inline jwk header claim and uses that key
  for verification. The attacker embeds their own public key directly in the header and signs with
  the corresponding private key. No external URL required.</li>
</ul>

Both attacks exploit the same root cause: the server's <span class="callout-term">trust boundary</span> includes the token header,
not just the token payload.
`

const MITIGATION = `
**Fix:** Never accept key material from the token header.

\`\`\`python
# Vulnerable — fetches jku or trusts jwk from token header
def verify(token):
    header = jwt.get_unverified_header(token)
    if "jku" in header:
        keys = fetch_jwks(header["jku"])  # ← attacker controlled!
    elif "jwk" in header:
        key = load_jwk(header["jwk"])     # ← attacker controlled!
    return jwt.decode(token, key)

# Patched — keys come from server config only
def verify(token):
    header = jwt.get_unverified_header(token)
    if "jku" in header or "jwk" in header:
        raise ValueError("jku/jwk not permitted")
    return jwt.decode(token, server_public_key, algorithms=["RS256"])
\`\`\`

For jku specifically: validate the URL against an explicit allowlist of trusted domains
before fetching.
`

/**
 * SSRF-adjacent fetch arrow — animated connection from Server to Attacker JWKS endpoint.
 * Simulates the server making an outbound HTTP request to the attacker-controlled URL.
 */
function SsrfFetchArrow() {
  const [dotPos, setDotPos] = useState(0) // 0..100 percentage
  const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches

  useEffect(() => {
    // Skip animation entirely when the user prefers reduced motion
    if (prefersReducedMotion) return

    let frame: ReturnType<typeof requestAnimationFrame>
    let startTime: number | null = null
    const DURATION = 1200

    const animate = (ts: number) => {
      if (!startTime) startTime = ts
      const elapsed = ts - startTime
      const progress = Math.min(elapsed / DURATION, 1)
      setDotPos(progress * 100)
      if (progress < 1) {
        frame = requestAnimationFrame(animate)
      } else {
        // Restart after pause
        setTimeout(() => {
          setDotPos(0)
          startTime = null
          frame = requestAnimationFrame(animate)
        }, 600)
      }
    }
    frame = requestAnimationFrame(animate)
    return () => cancelAnimationFrame(frame)
  }, [prefersReducedMotion])

  return (
    <div className="mb-4 bg-surface-alt border border-border rounded-card p-4">
      <div className="text-small text-error font-medium mb-3">
        ⚠ SSRF-adjacent: Server fetches attacker-controlled URL
      </div>
      <div className="flex items-center gap-2 relative">
        {/* Server box */}
        <div className="rounded border border-border bg-surface px-3 py-2 text-small font-mono text-jwt-payload shrink-0">
          Server
        </div>
        {/* Animated fetch arrow */}
        <div className="flex-1 relative h-6 flex items-center">
          <div className="absolute inset-0 flex items-center">
            <div className="w-full border-t-2 border-dashed border-error/40" />
          </div>
          {/* Traveling dot */}
          <motion.div
            className="absolute w-3 h-3 rounded-full bg-error border border-error/60 z-10"
            style={{ left: `${dotPos}%`, top: '50%', transform: 'translateY(-50%)' }}
          />
          <div className="absolute right-0 text-error text-lg">→</div>
        </div>
        {/* Attacker JWKS box */}
        <div className="rounded border border-error/50 bg-error/10 px-3 py-2 text-small font-mono text-error shrink-0">
          Attacker JWKS
        </div>
      </div>
      <div className="text-xs text-text-muted mt-2">
        GET http://attacker.example/jwks → attacker&apos;s public key returned
      </div>
    </div>
  )
}

function JkuFetchTab() {
  const shouldReduceMotion = useReducedMotion()
  const [attackerKey, setAttackerKey] = useState<{privateKeyPem: string, suggestedJkuUrl: string} | null>(null)
  const [loading, setLoading] = useState(false)
  const [fetchError, setFetchError] = useState<string | null>(null)

  const fetchAttackerKey = async () => {
    setLoading(true)
    setFetchError(null)
    try {
      const r = await fetch('/api/v1/attack/jku-injection/attacker-private-key')
      if (!r.ok) { setFetchError(`Server error: ${r.status} ${r.statusText}`); return }
      const d = await r.json()
      setAttackerKey(d)
    } catch (e) {
      setFetchError(`Fetch failed: ${e}`)
    } finally {
      setLoading(false)
    }
  }

  // Extra header fields for the Forge: empty until key is fetched, then auto-populate jku + kid
  const extraHeaderFields: Record<string, unknown> = attackerKey
    ? { jku: attackerKey.suggestedJkuUrl, kid: 'attacker-key' }
    : {}

  return (
    <div className="space-y-4">
      <p className="text-text-muted text-small">
        Click "Fetch Attacker Key" to get the attacker RSA private key PEM and the
        <code className="px-1 bg-surface-alt rounded text-xs mx-1">suggestedJkuUrl</code>.
        The Forge will auto-populate the <code className="px-1 bg-surface-alt rounded text-xs">jku</code> header field.
        Paste the private key into the Forge secret field, switch to RS256, and fire.
      </p>

      <button
        onClick={fetchAttackerKey}
        disabled={loading}
        className="btn-secondary py-1.5 h-9 px-4 text-small"
        aria-label="Fetch attacker key from server"
      >
        {loading ? 'Fetching…' : '🔑 Fetch Attacker Key'}
      </button>

      {fetchError && (
        <div className="text-error text-small p-2 bg-error/10 border border-error/30 rounded">
          {fetchError}
        </div>
      )}

      {attackerKey && (
        <motion.div
          initial={{ opacity: 0, y: shouldReduceMotion ? 0 : 8 }}
          animate={{ opacity: 1, y: 0 }}
          className="space-y-3"
        >
          <div>
            <div className="text-small text-text-muted mb-1 font-medium">
              Suggested jku URL <span className="text-primary text-xs">(auto-populated in Forge below)</span>
            </div>
            <div className="code-block p-2 text-xs font-mono break-all text-primary">
              {attackerKey.suggestedJkuUrl}
            </div>
          </div>
          <div>
            <div className="text-small text-text-muted mb-1 font-medium">Attacker Private Key — paste into Forge secret</div>
            <pre className="code-block text-xs whitespace-pre-wrap max-h-40 overflow-y-auto">
              {attackerKey.privateKeyPem}
            </pre>
          </div>
        </motion.div>
      )}

      <ExercisePanel
        slug="jku-injection"
        description="Switch Forge to RS256. Click 'Fetch Attacker Key' above, then paste the private key into the Forge secret field. The jku header auto-populates after fetch. Click 'Fire Token' — the server will fetch your JWKS and accept the forged token."
        extraHeaderFields={extraHeaderFields}
      />
    </div>
  )
}

function JwkEmbedTab() {
  const shouldReduceMotion = useReducedMotion()
  const [jwks, setJwks] = useState<{keys: Array<Record<string, unknown>>} | null>(null)
  const [loading, setLoading] = useState(false)
  const [jwksError, setJwksError] = useState<string | null>(null)
  const [privateKeyPem, setPrivateKeyPem] = useState<string | null>(null)
  const [pkLoading, setPkLoading] = useState(false)
  const [pkError, setPkError] = useState<string | null>(null)

  const fetchJwks = async () => {
    setLoading(true)
    setJwksError(null)
    try {
      const r = await fetch('/api/v1/attack/jku-injection/attacker-jwks')
      if (!r.ok) { setJwksError(`Server error: ${r.status} ${r.statusText}`); return }
      const d = await r.json()
      setJwks(d)
    } catch (e) {
      setJwksError(`Fetch failed: ${e}`)
    } finally {
      setLoading(false)
    }
  }

  const fetchPrivateKey = async () => {
    setPkLoading(true)
    setPkError(null)
    try {
      const r = await fetch('/api/v1/attack/jku-injection/attacker-private-key')
      if (!r.ok) { setPkError(`Server error: ${r.status} ${r.statusText}`); return }
      const d = await r.json()
      setPrivateKeyPem(d.privateKeyPem ?? null)
    } catch (e) {
      setPkError(`Fetch failed: ${e}`)
    } finally {
      setPkLoading(false)
    }
  }

  // Embed the first JWK as the jwk header field; empty object until fetched
  const embeddedJwk = jwks?.keys?.[0]
  const extraHeaderFields: Record<string, unknown> = embeddedJwk ? { jwk: embeddedJwk } : {}

  return (
    <div className="space-y-4">
      <p className="text-text-muted text-small">
        Click "Embed JWK" to fetch the attacker JWKS and embed the first key directly in
        the token header as the <code className="px-1 bg-surface-alt rounded text-xs">jwk</code> field.
        Then click "Fetch Private Key" to get the corresponding private key for signing.
      </p>

      <div className="flex gap-2 flex-wrap">
        <button
          onClick={fetchJwks}
          disabled={loading}
          className="btn-secondary py-1.5 h-9 px-4 text-small"
          aria-label="Embed JWK in header"
        >
          {loading ? 'Fetching…' : '📎 Embed JWK'}
        </button>
        <button
          onClick={fetchPrivateKey}
          disabled={pkLoading}
          className="btn-secondary py-1.5 h-9 px-4 text-small"
          aria-label="Fetch attacker private key"
        >
          {pkLoading ? 'Fetching…' : '🔑 Fetch Private Key'}
        </button>
      </div>

      {jwksError && (
        <div className="text-error text-small p-2 bg-error/10 border border-error/30 rounded">
          {jwksError}
        </div>
      )}
      {pkError && (
        <div className="text-error text-small p-2 bg-error/10 border border-error/30 rounded">
          {pkError}
        </div>
      )}

      {jwks && (
        <motion.div
          initial={{ opacity: 0, y: shouldReduceMotion ? 0 : 8 }}
          animate={{ opacity: 1, y: 0 }}
        >
          <div className="text-small text-text-muted mb-1 font-medium">
            Attacker JWKS <span className="text-primary text-xs">(first key embedded as jwk header)</span>
          </div>
          <pre className="code-block text-xs whitespace-pre-wrap max-h-48 overflow-y-auto">
            {JSON.stringify(jwks, null, 2)}
          </pre>
        </motion.div>
      )}

      {privateKeyPem && (
        <motion.div
          initial={{ opacity: 0, y: shouldReduceMotion ? 0 : 8 }}
          animate={{ opacity: 1, y: 0 }}
        >
          <div className="text-small text-text-muted mb-1 font-medium">
            Attacker Private Key — paste into Forge secret field
          </div>
          <pre className="code-block text-xs whitespace-pre-wrap max-h-40 overflow-y-auto">
            {privateKeyPem}
          </pre>
        </motion.div>
      )}

      <ExercisePanel
        slug="jku-injection"
        description="Click 'Embed JWK' above to embed the attacker key in the Forge header. Switch Forge to RS256, paste the attacker private key into the key field. Click 'Fire Token' — the server reads the inline jwk and accepts the forged token."
        extraHeaderFields={extraHeaderFields}
      />
    </div>
  )
}

export default function JkuInjectionModule() {
  const [activeTab, setActiveTab] = useState<'jku-fetch' | 'jwk-embed'>('jku-fetch')

  return (
    <ModuleLayout
      slug="jku-injection"
      title="jku / jwk Header Injection"
      severity="Critical"
      cve={null}
      narrative={NARRATIVE}
      mitigation={MITIGATION}
    >
      {/* Sub-module tab selector */}
      <div className="flex gap-2 mb-6" role="tablist">
        <button
          onClick={() => setActiveTab('jku-fetch')}
          className={`px-4 py-2 rounded text-small font-medium transition-colors
            ${activeTab === 'jku-fetch' ? 'bg-primary text-surface border border-primary' : 'btn-secondary'}`}
          aria-selected={activeTab === 'jku-fetch'}
          role="tab"
        >
          jku injection
        </button>
        <button
          onClick={() => setActiveTab('jwk-embed')}
          className={`px-4 py-2 rounded text-small font-medium transition-colors
            ${activeTab === 'jwk-embed' ? 'bg-primary text-surface border border-primary' : 'btn-secondary'}`}
          aria-selected={activeTab === 'jwk-embed'}
          role="tab"
        >
          jwk embedding
        </button>
      </div>

      {activeTab === 'jku-fetch' ? (
        <>
          <AttackVisualizer steps={JKU_STEPS} />
          {/* SSRF-adjacent fetch arrow visualization */}
          <SsrfFetchArrow />
          <section className="mb-6">
            <h2 className="font-display text-h3 text-text-primary mb-3">jku-fetch Attack</h2>
            <JkuFetchTab />
          </section>
        </>
      ) : (
        <>
          <AttackVisualizer steps={JWK_STEPS} />
          <section className="mb-6">
            <h2 className="font-display text-h3 text-text-primary mb-3">jwk-embed Attack</h2>
            <JwkEmbedTab />
          </section>
        </>
      )}
    </ModuleLayout>
  )
}
