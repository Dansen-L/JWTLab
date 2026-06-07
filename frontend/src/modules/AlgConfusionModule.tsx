/**
 * Attack Module: Algorithm Confusion (RS256 → HS256)
 * CVE-2016-10555 — vulnerable libraries that accept alg from token header
 * allow an attacker to resign a token with the server's public key as the
 * HMAC secret, bypassing RS256 verification.
 */
import { useState } from 'react'
import { motion, useReducedMotion } from 'framer-motion'
import ModuleLayout from '../components/ModuleLayout'
import AttackVisualizer from '../components/AttackVisualizer'
import ExercisePanel from '../components/ExercisePanel'

const STEPS = [
  {
    title: 'Attacker Obtains RS256 Public Key',
    client: 'GET /.well-known/jwks.json\n(lab endpoint: /api/v1/attack/alg-confusion/public-key)\n\nResponse:\n{"publicKeyPem": "-----BEGIN PUBLIC KEY-----\\nMIIBIjANBgkqhkiG9w0B...\\n-----END PUBLIC KEY-----\\n"}',
    server: 'Public key is intentionally exposed\n(as is common — public keys are, by definition, public)\n\nKey size: 2048-bit RSA',
    description: 'The server\'s RS256 public key is retrieved. Public keys are often exposed in JWKS endpoints or documentation. This is not a vulnerability by itself.',
  },
  {
    title: 'Attacker Forges HS256 Token Signed with Public Key Bytes',
    client: 'Take public key PEM bytes as HMAC secret:\n\n  header: {"alg":"HS256","typ":"JWT"}\n  payload: {"sub":"user","role":"admin"}\n  signature: HMAC-SHA256(pubkey_bytes, header.payload)',
    server: 'Attacker re-encodes the token with alg=HS256\nand signs it using the public key bytes as the HMAC secret.\n\nThis produces a valid HMAC signature under HS256.',
    description: 'The attacker changes alg to "HS256" and signs the token using the RS256 public key bytes as the HMAC secret — a key the server already has!',
    highlight: true,
  },
  {
    title: 'Vulnerable Server Verifies HS256 with Public Key',
    client: 'POST /api/v1/attack/alg-confusion/verify\n{"token": "eyJhbGciOiJIUzI1NiJ9.<admin-payload>.<sig>"}',
    server: 'Vulnerable library sees alg=HS256 from token header.\nLooks up symmetric key: uses the stored public key bytes.\nHMAC verification succeeds — signature matches!\n\nHTTP 200: {"valid":true,"role":"admin"}',
    description: 'The vulnerable server trusts the alg field from the token header. It uses the same public key bytes (which the attacker also has) to verify the HS256 signature. It passes!',
    highlight: true,
  },
  {
    title: 'Patched: Algorithm Pinned Server-Side',
    client: 'POST /api/v1/attack/alg-confusion/verify\n{"token": "eyJhbGciOiJIUzI1NiJ9.<admin-payload>.<sig>"}',
    server: 'Patched server ignores token\'s alg header.\nForces algorithm = RS256 before verification.\n\nHTTP 401: {"valid":false,"message":"Algorithm not permitted."}',
    description: 'The patched endpoint pins the algorithm to RS256 explicitly, independent of what the token header claims. The attacker\'s HS256 token is rejected.',
  },
]

const NARRATIVE = `
<span class="callout-term-danger">Algorithm Confusion</span> (also called <span class="callout-term">Key Confusion</span>) exploits JWT libraries that derive the
verification algorithm from the token header rather than from server-side configuration.

The attack vector: RS256 uses two keys — a private key to sign, and a public key to verify.
If a vulnerable library sees <strong>alg=HS256</strong> in the header, it switches to symmetric
(HMAC) mode and uses whatever "key" is configured — which in an RS256 setup is the <em>public key</em>.

The attacker can obtain the public key (often published in a <span class="callout-term">JWKS endpoint</span>), use it as an
HMAC secret, and forge a perfectly valid HS256 signature. The server's own public key becomes
the attacker's signing key.

<strong>CVE-2016-10555</strong> documented this flaw in multiple popular JWT libraries.
`

const MITIGATION = `
**Fix:** Pin the algorithm explicitly at the verification call site — never read it from the token.

\`\`\`python
# Vulnerable: algorithm derived from header
jwt.decode(token, public_key, algorithms=jwt.get_unverified_header(token)["alg"])

# Patched: algorithm pinned server-side
jwt.decode(token, public_key, algorithms=["RS256"])  # ← explicit, from config
\`\`\`

Additionally, use separate key objects for signing and verification — some libraries detect
and reject algorithm mismatch automatically when key types differ.
`

interface AlgConfusionExercisePanelProps {
  slug: string
  onKeyFetched: (pem: string) => void
}

function AlgConfusionExercise({ slug: _slug, onKeyFetched }: AlgConfusionExercisePanelProps) {
  const [pubKey, setPubKey] = useState('')
  const [loading, setLoading] = useState(false)
  const [hexPreview, setHexPreview] = useState('')
  const reduceMotion = useReducedMotion()

  const fetchPublicKey = async () => {
    setLoading(true)
    try {
      const r = await fetch('/api/v1/attack/alg-confusion/public-key')
      const d = await r.json()
      const pem = d.publicKeyPem ?? ''
      setPubKey(pem)
      onKeyFetched(pem)
      // Build hex preview from PEM bytes (first 32 bytes)
      const lines = pem.replace(/-----[^-]+-----\n?/g, '').replace(/\n/g, '')
      const raw = atob(lines)
      const hex = Array.from(raw.slice(0, 32))
        .map(c => c.charCodeAt(0).toString(16).padStart(2, '0'))
        .join(' ')
      setHexPreview(hex + '…')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="space-y-4">
      <div>
        <button
          onClick={fetchPublicKey}
          disabled={loading}
          className="btn-secondary py-1.5 h-9 px-4 text-small"
          aria-label="Fetch public key from server"
        >
          {loading ? 'Fetching…' : '🔑 Fetch Public Key'}
        </button>
      </div>

      {pubKey && (
        <motion.div
          initial={{ opacity: 0, y: reduceMotion ? 0 : 8 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: reduceMotion ? 0 : 0.2 }}
          className="grid grid-cols-2 gap-4"
        >
          {/* PEM display */}
          <div>
            <div className="text-small text-text-muted mb-1 font-medium">PEM Format</div>
            <pre className="code-block text-xs whitespace-pre-wrap max-h-48 overflow-y-auto">
              {pubKey}
            </pre>
          </div>
          {/* Hex bytes display */}
          <div>
            <div className="text-small text-text-muted mb-1 font-medium">Raw Bytes (hex, first 32)</div>
            <pre className="code-block text-xs whitespace-pre-wrap font-mono break-all">
              {hexPreview}
            </pre>
            <div className="mt-2 p-2 bg-warning/10 border border-warning/30 rounded text-xs text-warning">
              ⚠ These bytes become the HMAC secret in algorithm confusion. The attacker
              uses this public key as the symmetric signing key.
            </div>
          </div>
        </motion.div>
      )}
    </div>
  )
}

export default function AlgConfusionModule() {
  const [fetchedPem, setFetchedPem] = useState('')

  return (
    <ModuleLayout
      slug="alg-confusion"
      title="Algorithm Confusion (RS256 → HS256)"
      severity="Critical"
      cve="CVE-2016-10555"
      narrative={NARRATIVE}
      mitigation={MITIGATION}
    >
      <AttackVisualizer steps={STEPS} />

      {/* Key inspection panel */}
      <section className="mb-6">
        <h2 className="font-display text-h3 text-text-primary mb-3">Public Key Inspector</h2>
        <p className="text-text-muted text-small mb-3">
          Fetch the server's RS256 public key. In a real attack, this is available via
          <code className="mx-1 px-1 bg-surface-alt rounded text-xs">/api/v1/attack/alg-confusion/public-key</code>
          or a JWKS endpoint. The attacker uses these exact bytes as the HMAC secret.
        </p>
        <AlgConfusionExercise slug="alg-confusion" onKeyFetched={setFetchedPem} />
      </section>

      <ExercisePanel
        slug="alg-confusion"
        description="Switch the Forge to HS256, paste the public key PEM bytes as the secret, and fire the token. The vulnerable endpoint will accept it because it uses the same public key bytes to verify."
        defaultMutation="flip-hs256-embedded"
        initialSecret={fetchedPem || undefined}
      />
    </ModuleLayout>
  )
}
