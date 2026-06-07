/**
 * Attack Module: Weak HMAC Secret Brute-force
 * Demonstrates offline dictionary attacks against short/common HS256 secrets.
 */
import { useState, useEffect, useRef } from 'react'
import { motion, AnimatePresence, useReducedMotion } from 'framer-motion'
import ModuleLayout from '../components/ModuleLayout'
import AttackVisualizer from '../components/AttackVisualizer'
import ExercisePanel from '../components/ExercisePanel'

const WORDLIST_PREVIEW = [
  'password', 'admin', '123456', 'letmein', 'qwerty', 'dragon',
  'monkey', 'welcome', 'shadow', 'master', 'secret', '← cracked here',
]

const WORDLIST_LOOP = [
  'password', 'admin', '123456', 'letmein', 'qwerty',
  'dragon', 'monkey', 'welcome', 'shadow', 'master', 'secret',
]

/**
 * Animated wordlist loop — cycles through candidates, then flashes MATCH FOUND.
 * Runs automatically, looping continuously.
 */
function WordlistLoopAnimation() {
  const [currentIdx, setCurrentIdx] = useState(0)
  const [matched, setMatched] = useState(false)
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const reduceMotion = useReducedMotion()

  useEffect(() => {
    const run = () => {
      setCurrentIdx(i => {
        const next = (i + 1) % WORDLIST_LOOP.length
        if (next === WORDLIST_LOOP.length - 1) {
          // About to show 'secret' — will trigger match
          setMatched(false)
        }
        if (i === WORDLIST_LOOP.length - 1) {
          // Just showed 'secret', now show match
          setMatched(true)
          timerRef.current = setTimeout(() => {
            setMatched(false)
            setCurrentIdx(0)
          }, 900)
          return i
        }
        return next
      })
    }
    timerRef.current = setTimeout(run, 180)
    return () => { if (timerRef.current) clearTimeout(timerRef.current) }
  }, [currentIdx])

  const word = WORDLIST_LOOP[currentIdx]
  const isCracked = currentIdx === WORDLIST_LOOP.length - 1

  return (
    <div className="bg-surface-alt border border-border rounded-card p-4 mb-4">
      <div className="text-small text-text-muted mb-2 font-medium">
        Wordlist Attack Loop <span className="text-xs text-accent ml-2">(live)</span>
      </div>
      <div className="flex items-center gap-3">
        {/* Candidate word display */}
        <div className="font-mono text-sm w-32 text-right text-text-muted">
          Testing:
        </div>
        <AnimatePresence mode="wait">
          <motion.div
            key={`${currentIdx}-${word}`}
            initial={{ opacity: 0, y: reduceMotion ? 0 : -8 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: reduceMotion ? 0 : 8 }}
            transition={{ duration: reduceMotion ? 0 : 0.12 }}
            className={`font-mono text-sm px-3 py-1 rounded border w-28 text-center ${
              isCracked
                ? 'bg-primary/20 border-primary text-primary font-bold'
                : 'bg-surface border-border text-text-muted'
            }`}
          >
            {word}
          </motion.div>
        </AnimatePresence>
        {/* HMAC result */}
        <AnimatePresence>
          {isCracked || matched ? (
            <motion.div
              key="match"
              initial={{ opacity: 0, scale: reduceMotion ? 1 : 0.8 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0 }}
              transition={{ duration: reduceMotion ? 0 : 0.2 }}
              className="text-primary font-bold text-small"
            >
              ✓ MATCH FOUND!
            </motion.div>
          ) : (
            <motion.div
              key={`miss-${currentIdx}`}
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="text-error text-small"
            >
              ✗ sig mismatch
            </motion.div>
          )}
        </AnimatePresence>
      </div>
      <div className="text-xs text-text-muted mt-2">
        Candidate {currentIdx + 1} / {WORDLIST_LOOP.length} — cracked at "secret"
      </div>
    </div>
  )
}

const STEPS = [
  {
    title: 'Attacker Intercepts JWT',
    client: 'JWT captured from HTTP traffic:\neyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\n  .eyJzdWIiOiJ1c2VyIiwicm9sZSI6InVzZXIifQ\n  .wYAhBxfO5...',
    server: 'HS256 tokens are safe to share publicly —\nthe signature requires knowledge of the secret.\n\nBut if the secret is a dictionary word,\nan attacker can crack it offline.',
    description: 'A JWT signed with HS256 is captured. The header and payload are base64url-encoded (not encrypted), so the attacker can read the claims — but cannot forge without the secret.',
  },
  {
    title: 'Offline Dictionary Attack',
    client: 'For each word in wordlist:\n  candidate_sig = HMAC-SHA256(word, header.payload)\n  if candidate_sig == token_sig:\n    secret_found!\n    break',
    server: 'No network required — HMAC verification is\npure computation. Attacker can try millions of\ncandidates per second on a GPU.\n\nCommon secrets fall in milliseconds.',
    description: 'The attacker iterates through a wordlist, computing HMAC-SHA256 for each candidate and comparing against the token\'s signature. This is fast, offline, and undetectable.',
    highlight: true,
  },
  {
    title: 'Secret Found — Token Forged',
    client: 'Secret cracked: "secret"\n\nForge admin token:\n  header: {"alg":"HS256","typ":"JWT"}\n  payload: {"sub":"user","role":"admin","exp":...}\n  sig: HMAC-SHA256("secret", header.payload)',
    server: 'Attacker now holds a valid, properly-signed\nadmin token — indistinguishable from\na legitimately issued token.\n\nNo brute-force visible in server logs.',
    description: 'With the secret known, the attacker can forge any claims they want — including role:admin or any arbitrary user identity — and produce a cryptographically valid signature.',
    highlight: true,
  },
  {
    title: 'Patched: Strong Random Secret',
    client: 'POST /api/v1/attack/weak-secret/verify\n{"token": "<forged-admin-token>"}',
    server: 'A 256-bit random secret is computationally\ninfeasible to brute-force.\n\nForged token signature mismatch → HTTP 401\n{"valid":false,"message":"Signature verification failed"}',
    description: 'With a cryptographically random 256-bit secret (e.g., generated by python secrets.token_hex(32)), offline dictionary attacks are not viable in any realistic timeframe.',
  },
]

const NARRATIVE = `
<span class="callout-term">HMAC-based</span> JWT algorithms (HS256/HS384/HS512) are only as strong as the secret they use.
When that secret is a dictionary word, a short phrase, or any predictable value, an attacker
who obtains a token can mount an <span class="callout-term-danger">offline dictionary attack</span> — no server contact needed.

<strong>Entropy matters — time-to-crack vs. secret type:</strong>
<table class="entropy-chart text-xs mt-2 mb-3" style="border-collapse:collapse;width:100%" aria-label="Entropy chart: time to crack vs secret type">
<thead><tr style="border-bottom:1px solid #333">
  <th style="text-align:left;padding:4px 8px;color:#8B9EC7">Secret type</th>
  <th style="text-align:left;padding:4px 8px;color:#8B9EC7">Entropy</th>
  <th style="text-align:left;padding:4px 8px;color:#8B9EC7">Time to crack (GPU)</th>
  <th style="text-align:left;padding:4px 8px;color:#8B9EC7">Risk</th>
</tr></thead>
<tbody>
<tr>
  <td style="padding:4px 8px;color:#E3503E">Dictionary word (e.g. "secret")</td>
  <td style="padding:4px 8px;color:#E3503E">~17 bits</td>
  <td style="padding:4px 8px;color:#E3503E;font-weight:600">~0.1s</td>
  <td style="padding:4px 8px"><span style="background:#E3503E22;color:#E3503E;border:1px solid #E3503E44;padding:1px 6px;border-radius:4px;font-size:10px">CRITICAL</span></td>
</tr>
<tr>
  <td style="padding:4px 8px;color:#FFAE00">8-char random (e.g. "xK9mP2qL")</td>
  <td style="padding:4px 8px;color:#FFAE00">~48 bits</td>
  <td style="padding:4px 8px;color:#FFAE00;font-weight:600">~hours</td>
  <td style="padding:4px 8px"><span style="background:#FFAE0022;color:#FFAE00;border:1px solid #FFAE0044;padding:1px 6px;border-radius:4px;font-size:10px">HIGH</span></td>
</tr>
<tr>
  <td style="padding:4px 8px;color:#00E5A0">32-char random (secrets.token_hex(32))</td>
  <td style="padding:4px 8px;color:#00E5A0">256 bits</td>
  <td style="padding:4px 8px;color:#00E5A0;font-weight:600">infeasible</td>
  <td style="padding:4px 8px"><span style="background:#00E5A022;color:#00E5A0;border:1px solid #00E5A044;padding:1px 6px;border-radius:4px;font-size:10px">SAFE</span></td>
</tr>
</tbody>
</table>

OWASP JWT Security: use a minimum 256-bit (32-byte) random secret for HS256.
`

const MITIGATION = `
**Fix:** Generate secrets with a cryptographically secure random number generator.

\`\`\`python
import secrets
# Generates 256 bits of randomness — safe for HS256
JWT_SECRET = secrets.token_hex(32)  # 64 hex chars = 256 bits
\`\`\`

**Additional hardening:**
- Store secrets in environment variables or secrets managers (never hardcode)
- Rotate secrets periodically
- Consider RS256/RS512 (asymmetric) for multi-service architectures — no shared secret
- Rate-limit or monitor for repeated token submission attempts
`

interface CrackResult {
  found: boolean
  secret: string | null
  attempts: number
  elapsed_ms: number
}

interface WeakSecretExerciseProps {
  onCrackResult: (result: CrackResult) => void
}

function WeakSecretExercise({ onCrackResult }: WeakSecretExerciseProps) {
  const [crackResult, setCrackResult] = useState<CrackResult | null>(null)
  const [cracking, setCracking] = useState(false)
  const reduceMotion = useReducedMotion()

  const crackToken = async () => {
    setCracking(true)
    setCrackResult(null)
    try {
      const loginR = await fetch('/api/v1/attack/weak-secret/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: 'user', password: 'password' }),
      })
      const loginData = await loginR.json()
      const token = loginData.token

      const crackR = await fetch('/api/v1/crack', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token }),
      })
      const result = await crackR.json()
      setCrackResult(result)
      onCrackResult(result)
    } finally {
      setCracking(false)
    }
  }

  return (
    <div className="space-y-4">
      <div>
        <div className="text-small text-text-muted mb-1 font-medium">Built-in Wordlist (preview — 50+ words)</div>
        <div className="code-block p-3 max-h-24 overflow-y-auto">
          {WORDLIST_PREVIEW.map((w, i) => (
            <span
              key={i}
              className={`inline-block mr-2 mb-1 px-2 py-0.5 rounded text-xs font-mono
                ${w.includes('←') ? 'bg-primary/20 text-primary border border-primary/40' : 'bg-surface-alt text-text-muted'}`}
            >
              {w}
            </span>
          ))}
        </div>
        <p className="text-xs text-text-muted mt-1">50 common passwords; "secret" is at position 11</p>
      </div>

      <button
        onClick={crackToken}
        disabled={cracking}
        className="btn-secondary py-1.5 h-9 px-4 text-small"
        aria-label="Crack token using built-in wordlist"
      >
        {cracking ? 'Cracking…' : '🔓 Crack Token'}
      </button>

      {crackResult && (
        <motion.div
          initial={{ opacity: 0, y: reduceMotion ? 0 : 8 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: reduceMotion ? 0 : 0.2 }}
          className={`rounded-card p-4 border ${crackResult.found ? 'bg-primary/10 border-primary/40' : 'bg-error/10 border-error/40'}`}
        >
          {crackResult.found ? (
            <>
              <div className="font-medium text-primary mb-1">✓ Secret Cracked!</div>
              <div className="font-mono text-sm">
                Secret: <strong className="text-primary">{crackResult.secret}</strong>
              </div>
              <div className="text-xs text-text-muted mt-1">
                {crackResult.attempts} attempts in {crackResult.elapsed_ms}ms
              </div>
              <div className="mt-2 p-2 bg-warning/10 border border-warning/30 rounded text-xs text-warning">
                ✓ Forge secret auto-populated: <strong>{crackResult.secret}</strong>
                {' '}— forge an admin token in the Exercise Panel below!
              </div>
            </>
          ) : (
            <div className="text-error">Not found after {crackResult.attempts} attempts.</div>
          )}
        </motion.div>
      )}
    </div>
  )
}

export default function WeakSecretModule() {
  const [crackedSecret, setCrackedSecret] = useState<string | undefined>(undefined)

  const handleCrackResult = (result: CrackResult) => {
    if (result.found && result.secret) {
      setCrackedSecret(result.secret)
    }
  }

  return (
    <ModuleLayout
      slug="weak-secret"
      title="Weak Secret Brute-force"
      severity="High"
      cve={null}
      narrative={NARRATIVE}
      mitigation={MITIGATION}
    >
      <AttackVisualizer steps={STEPS} />

      {/* Animated wordlist loop visualization */}
      <WordlistLoopAnimation />

      <section className="mb-6">
        <h2 className="font-display text-h3 text-text-primary mb-3">Crack Token</h2>
        <p className="text-text-muted text-small mb-3">
          This endpoint uses <code className="px-1 bg-surface-alt rounded text-xs">secret</code> as
          its HMAC secret — a common password present in any dictionary. The built-in wordlist has
          at least 50 words with "secret" included.
          Click "Crack Token" to find it via{' '}
          <code className="px-1 bg-surface-alt rounded text-xs">POST /api/v1/crack</code>.
        </p>
        <WeakSecretExercise onCrackResult={handleCrackResult} />
      </section>

      <ExercisePanel
        slug="weak-secret"
        description="Forge an admin token: set role=admin in the payload. The Forge secret is pre-populated with the cracked value after cracking above. Fire at the vulnerable endpoint to get accepted."
        initialSecret={crackedSecret}
      />
    </ModuleLayout>
  )
}
