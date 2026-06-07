/**
 * Attack Module: Expired Token Extension (exp bypass)
 *
 * Two failure modes:
 *   Tab 1 (default): Signature IS checked, exp is NOT — re-sign expired token
 *   Tab 2 (mode=nosig): Neither signature NOR exp checked — modify claims freely
 *
 * Intentionally published secret: "expsecret"
 */
import { useState, useEffect } from 'react'
import { motion, AnimatePresence, useReducedMotion } from 'framer-motion'
import ModuleLayout from '../components/ModuleLayout'
import AttackVisualizer from '../components/AttackVisualizer'
import ExercisePanel from '../components/ExercisePanel'

// Tab 1: sig checked, exp NOT checked
const TAB1_STEPS = [
  {
    title: 'User Receives Short-lived Token',
    client: 'POST /api/v1/attack/exp-bypass/login\n{"username":"user","password":"password"}',
    server: 'HTTP 200\n{\n  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\n    eyJzdWIiOiJ1c2VyIiwiZXhwIjoxNzAwMDAwMDAwfQ.\n    <sig>"\n}\n// exp: 1700000000 (in the past)',
    description: 'The server issues a JWT with a short expiration. The HMAC secret "expsecret" is intentionally disclosed — this is the educational point: even knowing it, the server should reject expired tokens.',
  },
  {
    title: 'Token Expires',
    client: 'Time passes... token\'s exp timestamp is now in the past.\n\nAttacker knows secret: "expsecret" (intentionally published here).\n\nAttacker forges new token with exp in the future:\n  payload.exp = Date.now()/1000 + 3600',
    server: 'With "expsecret" the attacker can:\n  1. Decode the expired token\n  2. Modify exp to a future timestamp\n  3. Re-sign with the same secret\n\nThe server\'s vulnerability: it checks the\nsignature but NOT the exp claim.',
    description: 'The secret "expsecret" is intentionally disclosed. An attacker who knows this secret can re-sign any token with a modified expiry. The vulnerability is that signature verification alone is insufficient.',
    highlight: true,
  },
  {
    title: 'Attacker Fires Re-signed Expired→Valid Token',
    client: 'POST /api/v1/attack/exp-bypass/verify\n{"token": "<re-signed with future exp>"}',
    server: 'Vulnerable server checks: signature valid? YES.\nVulnerable server: skips exp check!\n\nHTTP 200 {"valid":true,"message":"Token accepted (signature verified; exp not checked — tab-1 mode)."}',
    description: 'The re-signed token passes because the server only checks the signature, not the expiration. An attacker who knows the secret can extend any token\'s lifetime indefinitely.',
    highlight: true,
  },
  {
    title: 'Patched: Verify Signature AND exp',
    client: 'POST /api/v1/attack/exp-bypass/verify\n{"token": "<expired token, valid sig>"}',
    server: 'Patched: verifies signature AND checks exp.\n\nHTTP 401 {"valid":false,"message":"Token expired."}\n\n// Even valid-sig expired tokens are rejected',
    description: 'The patched endpoint checks both the signature and the exp claim. An expired token is rejected regardless of signature validity.',
  },
]

// Tab 2: neither sig nor exp checked
const TAB2_STEPS = [
  {
    title: 'Attacker Obtains Any Valid Token',
    client: 'POST /api/v1/attack/exp-bypass/login\n{"username":"user","password":"password"}',
    server: 'HTTP 200 {"token": "<valid JWT signed with expsecret>"}\n\nKnown secret: expsecret',
    description: 'The attacker obtains any valid token. In tab-2 mode, they\'ll mutate the payload without re-signing — the server doesn\'t check the signature at all.',
  },
  {
    title: 'Mutate Claims Without Re-signing',
    client: 'Take any JWT.\nModify payload: role → admin, exp → past/future\n\nDO NOT re-sign — leave original signature or strip it.\n\n?mode=nosig endpoint skips ALL verification.',
    server: 'In tab-2 mode (POST /verify?mode=nosig):\n→ No signature check\n→ No exp check\n→ Accept any token with any claims',
    description: 'Tab-2 demonstrates the most severe failure: a server that performs no verification at all. The attacker can submit any base64url-encoded JSON payload and have it accepted.',
    highlight: true,
  },
  {
    title: 'Fire Mutated Token with ?mode=nosig',
    client: 'POST /api/v1/attack/exp-bypass/verify?mode=nosig\n{"token": "<mutated-unsigned-token>"}',
    server: 'HTTP 200 {"valid":true,"message":"Token accepted (no signature or exp check — tab-2 mode)."}\n\nAny payload, any signature, any exp — all accepted.',
    description: 'The ?mode=nosig endpoint accepts the mutated token unconditionally. This represents a critical misconfiguration where a server verifies neither signature nor expiry.',
    highlight: true,
  },
  {
    title: 'Patched: Enforces Signature + exp in All Modes',
    client: 'POST /api/v1/attack/exp-bypass/verify?mode=nosig\n{"token": "<mutated-token>"}',
    server: 'Patched: toggle-patch enables strict verification.\n\nHTTP 401 {"valid":false,"message":"Invalid signature."}\n\n// Patched mode ignores ?mode=nosig',
    description: 'The patched endpoint enforces strict verification regardless of query parameters. The mode=nosig bypass is disabled when the patch is active.',
  },
]

const NARRATIVE = `
JWT expiration (<code>exp</code>) is only one of several claims that must be verified.
Two distinct failure modes are demonstrated here:

<strong>Tab 1 — Signature checked, exp ignored:</strong>
The server verifies the HMAC signature but forgets to check whether the token has expired.
Since the secret is known ("expsecret" — intentionally disclosed for this exercise), an attacker
can re-sign any token with an arbitrary <code>exp</code>. A server that doesn't check exp accepts
both the original and the extended token.

<strong>Tab 2 — Neither checked:</strong>
The most catastrophic failure: the server performs no <span class="callout-term-danger">cryptographic verification</span> at all.
An attacker can submit any base64url payload with arbitrary claims and have it accepted.
This often happens when developers use <code>verify_signature=False</code> in production code
that was meant only for debugging.

Both modes share the root cause: <span class="callout-term-danger">partial JWT validation</span>.
`

const MITIGATION = `
**Fix:** Always verify BOTH signature AND exp. Most JWT libraries check both by default.

\`\`\`python
# Vulnerable — skips exp check
claims = jwt.decode(token, secret, algorithms=["HS256"], options={"verify_exp": False})

# Also vulnerable — skips signature entirely
claims = jwt.decode(token, options={"verify_signature": False}, algorithms=["none", "HS256"])

# Patched — default library behavior, no options override needed
claims = jwt.decode(token, secret, algorithms=["HS256"])
# ↑ This verifies signature AND checks exp by default
\`\`\`

**Key principle:** Never disable security checks in production code.
Use test-only flags like \`verify_signature=False\` only in unit tests, never in request handlers.

**Also validate nbf and iat:**
- \`nbf\` (Not Before): reject tokens presented before their valid window opens — prevents tokens from being used prematurely after theft
- \`iat\` (Issued At): flag tokens with an implausibly old issue time — signals replay of a long-stolen token

**Issue short-lived tokens:**
\`\`\`python
# Short-lived access token + refresh token pattern
access_token = jwt.encode(
    {"sub": user_id, "exp": now + 900},   # 15 minutes
    secret, algorithm="HS256"
)
# Refresh tokens live longer but can be revoked server-side
\`\`\`

A 15-minute window drastically limits what an attacker can do with a stolen token — even one
with a valid signature and future \`exp\`.
`

/**
 * Animated clock that jumps from "PAST" to year 2099 — exp bypass visualization.
 */
function ExpClockAnimation() {
  const [phase, setPhase] = useState<'past' | 'jumping' | 'future'>('past')
  const reduceMotion = useReducedMotion()

  useEffect(() => {
    const cycle = () => {
      setPhase('jumping')
      setTimeout(() => setPhase('future'), 400)
      setTimeout(() => {
        setPhase('past')
        setTimeout(cycle, 1200)
      }, 1600)
    }
    const t = setTimeout(cycle, 800)
    return () => clearTimeout(t)
  }, [])

  return (
    <div className="mb-6 flex items-center gap-6 bg-surface-alt border border-border rounded-card p-4">
      <div className="text-4xl select-none" aria-hidden="true">🕐</div>
      <div className="flex items-center gap-4">
        {/* exp:past */}
        <div className={`rounded px-3 py-1.5 border font-mono text-small transition-all ${
          phase === 'past' ? 'bg-error/20 border-error text-error' : 'bg-surface border-border text-text-muted opacity-50'
        }`}>
          exp: PAST (expired)
        </div>
        {/* Arrow with jumping animation */}
        <AnimatePresence>
          {phase === 'jumping' && (
            <motion.span
              initial={{ x: reduceMotion ? 0 : -8, opacity: 0 }}
              animate={{ x: 0, opacity: 1 }}
              exit={{ x: reduceMotion ? 0 : 8, opacity: 0 }}
              transition={{ duration: reduceMotion ? 0 : 0.2 }}
              className="text-primary text-lg font-bold"
              aria-hidden="true"
            >
              →
            </motion.span>
          )}
        </AnimatePresence>
        {phase !== 'jumping' && (
          <span className="text-text-muted">→</span>
        )}
        {/* exp:2099 */}
        <AnimatePresence mode="wait">
          {phase === 'future' ? (
            <motion.div
              key="future"
              initial={{ scale: reduceMotion ? 1 : 0.8, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: reduceMotion ? 1 : 0.8, opacity: 0 }}
              transition={{ duration: reduceMotion ? 0 : 0.22 }}
              className="rounded px-3 py-1.5 border bg-primary/20 border-primary text-primary font-mono text-small font-bold"
            >
              exp: 2099 ✓ accepted
            </motion.div>
          ) : (
            <motion.div
              key="waiting"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              className="rounded px-3 py-1.5 border border-border text-text-muted font-mono text-small opacity-50"
            >
              exp: 2099
            </motion.div>
          )}
        </AnimatePresence>
      </div>
      <div className="text-xs text-text-muted ml-auto">
        Attacker re-signs expired token with future exp
      </div>
    </div>
  )
}

export default function ExpBypassModule() {
  const [activeTab, setActiveTab] = useState<'tab1' | 'tab2'>('tab1')

  return (
    <ModuleLayout
      slug="exp-bypass"
      title="Expired Token Extension (exp bypass)"
      severity="High"
      cve={null}
      narrative={NARRATIVE}
      mitigation={MITIGATION}
    >
      {/* Intentionally published secret callout */}
      <div className="mb-4 p-3 bg-warning/10 border border-warning/30 rounded-card">
        <span className="text-warning text-small font-medium">Intentionally Published Secret: </span>
        <code className="font-mono text-warning bg-warning/10 px-1 rounded">expsecret</code>
        <span className="text-text-muted text-xs ml-2">— used for tab-1 re-signing exercise</span>
      </div>

      {/* Sub-module tab selector */}
      <div className="flex gap-2 mb-6" role="tablist">
        <button
          onClick={() => setActiveTab('tab1')}
          className={`px-4 py-2 rounded text-small font-medium transition-colors
            ${activeTab === 'tab1' ? 'bg-primary text-surface border border-primary' : 'btn-secondary'}`}
          aria-selected={activeTab === 'tab1'}
          role="tab"
        >
          Tab 1: sig checked, exp ignored
        </button>
        <button
          onClick={() => setActiveTab('tab2')}
          className={`px-4 py-2 rounded text-small font-medium transition-colors
            ${activeTab === 'tab2' ? 'bg-primary text-surface border border-primary' : 'btn-secondary'}`}
          aria-selected={activeTab === 'tab2'}
          role="tab"
        >
          Tab 2: no sig, no exp check
        </button>
      </div>

      {activeTab === 'tab1' ? (
        <>
          <AttackVisualizer steps={TAB1_STEPS} />
          {/* Clock animation — exp jump from past to 2099 */}
          <ExpClockAnimation />
          <ExercisePanel
            slug="exp-bypass"
            description="Tab 1: Use the 'Set exp to past' shortcut, then enter 'expsecret' as the HMAC secret and fire. The vulnerable endpoint accepts re-signed tokens regardless of expiry. The patched endpoint rejects them with 'Token expired.'"
            defaultMutation="set-exp-past"
          />
        </>
      ) : (
        <>
          <AttackVisualizer steps={TAB2_STEPS} />
          <ExercisePanel
            slug="exp-bypass"
            description="Tab 2: Click 'Set alg to none' to produce an unsigned token. Fire at POST /api/v1/attack/exp-bypass/verify?mode=nosig — the vulnerable endpoint accepts any token regardless of signature or expiry. Toggle patch to enable strict verification."
            defaultMutation="alg-none"
            verifyUrl="/api/v1/attack/exp-bypass/verify?mode=nosig"
          />
        </>
      )}
    </ModuleLayout>
  )
}
