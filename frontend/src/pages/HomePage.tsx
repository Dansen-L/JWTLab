import { motion, useReducedMotion } from 'framer-motion'
import { useNavigate } from 'react-router-dom'

const MODULES = [
  {
    slug: 'alg-none',
    title: 'alg=none Bypass',
    cve: 'CVE-2015-9235',
    description: 'Learn how the "none" algorithm allows signature bypass when a library trusts the token header.',
    severity: 'Critical',
  },
  {
    slug: 'alg-confusion',
    title: 'Algorithm Confusion',
    cve: 'CVE-2016-10555',
    description: 'RS256 → HS256 confusion: re-sign a token with the public key bytes as an HMAC secret.',
    severity: 'Critical',
  },
  {
    slug: 'weak-secret',
    title: 'Weak Secret Brute-force',
    cve: null,
    description: 'Dictionary-word HMAC secrets can be cracked offline from any exposed JWT.',
    severity: 'High',
  },
  {
    slug: 'kid-sqli',
    title: 'Key ID SQL Injection',
    cve: null,
    description: 'Unsanitized kid claims concatenated into SQL queries allow attackers to control key lookup.',
    severity: 'Critical',
  },
  {
    slug: 'jku-injection',
    title: 'jku / jwk Header Injection',
    cve: null,
    description: 'jku fetches attacker-controlled JWKS; jwk embeds attacker keys inline in the token header.',
    severity: 'Critical',
  },
  {
    slug: 'exp-bypass',
    title: 'exp Bypass',
    cve: null,
    description: 'Two failure modes: no signature check, or signature checked but exp claim ignored.',
    severity: 'High',
  },
]

const SEVERITY_COLOR: Record<string, string> = {
  Critical: 'text-error border-error/40 bg-error/10',
  High:     'text-warning border-warning/40 bg-warning/10',
}

export default function HomePage() {
  const navigate = useNavigate()
  const reduceMotion = useReducedMotion()

  return (
    <div>
      <motion.div
        initial={{ opacity: 0, y: reduceMotion ? 0 : 12 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: reduceMotion ? 0 : 0.32, ease: [0.16, 1, 0.32, 1] }}
      >
        <h1 className="font-display text-display text-primary mb-2">JWTLab</h1>
        <p className="text-text-muted text-body mb-8 max-w-xl">
          An interactive, animated sandbox for learning JSON Web Token attacks.
          Choose a module to begin — all are available from the start.
        </p>
      </motion.div>

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
        {MODULES.map((mod, i) => (
          <motion.div
            key={mod.slug}
            initial={{ opacity: 0, y: reduceMotion ? 0 : 12 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: reduceMotion ? 0 : 0.32, ease: [0.16, 1, 0.32, 1], delay: reduceMotion ? 0 : i * 0.04 }}
          >
            <button
              onClick={() => navigate(`/modules/${mod.slug}`)}
              className="card w-full text-left cursor-pointer group"
            >
              <div className="flex items-start justify-between gap-2 mb-2">
                <h3 className="font-display text-h3 text-text-primary">{mod.title}</h3>
                <div className="flex gap-2 shrink-0">
                  <span className={`rounded px-2 py-0.5 text-small border ${SEVERITY_COLOR[mod.severity]}`}>
                    {mod.severity}
                  </span>
                  {mod.cve && (
                    <span className="rounded px-2 py-0.5 text-small border border-accent/40 bg-accent/10 text-accent">
                      {mod.cve}
                    </span>
                  )}
                </div>
              </div>
              <p className="text-text-muted text-small">{mod.description}</p>
            </button>
          </motion.div>
        ))}
      </div>
    </div>
  )
}
