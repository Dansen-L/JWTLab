/**
 * Attack Module: alg=none Bypass
 * Spec: app_spec.txt §"Attack Module: alg=none"
 */
import ModuleLayout from '../components/ModuleLayout'
import AttackVisualizer from '../components/AttackVisualizer'
import ExercisePanel from '../components/ExercisePanel'

const STEPS = [
  {
    title: 'Legitimate HS256 Token Issued',
    client: 'POST /login\n{"username":"user","password":"password"}',
    server: 'HTTP 200\n{"token": "eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoidXNlciJ9.<sig>"}',
    description: 'The server issues a valid HS256-signed JWT to the authenticated user.',
  },
  {
    title: 'Attacker Decodes Header',
    client: 'Decode Base64url header:\n{"alg":"HS256","typ":"JWT"}',
    server: 'Attacker reads: alg = "HS256"',
    description: 'The attacker decodes the JWT header. The algorithm is set by the server but visible to anyone.',
  },
  {
    title: 'Attacker Changes alg to "none" and Promotes Role',
    client: 'New header: {"alg":"none","typ":"JWT"}\nPayload: {"role":"admin"}',
    server: 'Token assembled without signature:\neyJhbGciOiJub25lIn0.eyJyb2xlIjoiYWRtaW4ifQ.',
    description: 'The attacker re-encodes the header with alg=none, sets role to admin, and strips the signature (trailing dot).',
    highlight: true,
  },
  {
    title: 'Vulnerable Server Accepts Token',
    client: 'POST /verify\nAuthorization: Bearer eyJhbGciOiJub25lIn0...',
    server: 'HTTP 200\n{"valid":true,"role":"admin","message":"Token accepted"}',
    description: 'The vulnerable server trusts the algorithm claim from the header and skips verification — the attacker gains admin access.',
  },
]

const NARRATIVE = `
The "none" algorithm (<span class="callout-term">RFC 7518 §3.6</span>) signals that no signature is expected.
Historically, many JWT libraries accepted a token's own claim that no verification was needed —
the server would skip signature checking entirely if <span class="callout-term-danger">alg=none</span> appeared in the header.

<strong>CVE-2015-9235</strong> documented this in the popular node-jsonwebtoken library.
The root cause: the verification algorithm was selected from the token header rather than
pinned server-side — allowing any bearer to <span class="callout-term-danger">bypass authentication</span> with a crafted token.
`

const MITIGATION = `
**Fix:** Enforce a server-side algorithm allowlist before calling the JWT verifier.
Never use the token's own \`alg\` header to determine how to verify it.
\`\`\`python
# Patched: algorithm pinned at the library call site
jwt.decode(token, secret, algorithms=["HS256"])  # ← list is explicit, from config
\`\`\`
`

export default function AlgNoneModule() {
  return (
    <ModuleLayout
      slug="alg-none"
      title="alg=none Bypass"
      severity="Critical"
      cve="CVE-2015-9235"
      narrative={NARRATIVE}
      mitigation={MITIGATION}
    >
      <AttackVisualizer steps={STEPS} />
      <ExercisePanel
        slug="alg-none"
        description="Use the 'Set alg to none' shortcut to strip the signature and promote your role to admin."
      />
    </ModuleLayout>
  )
}
