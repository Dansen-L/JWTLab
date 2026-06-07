import { ReactNode, useState, useEffect, useCallback } from 'react'
import { useNavigate, useLocation } from 'react-router-dom'
import { motion, useReducedMotion } from 'framer-motion'
import JWTAnalyzerModal from './JWTAnalyzerModal'

type Theme = 'dark' | 'light'

function applyTheme(theme: Theme) {
  const root = document.documentElement
  if (theme === 'light') {
    root.classList.add('theme-light')
    root.classList.remove('theme-dark')
  } else {
    root.classList.add('theme-dark')
    root.classList.remove('theme-light')
  }
  localStorage.setItem('jwtlab.theme', theme)
}

const MODULES = [
  { slug: 'alg-none',      title: 'alg=none Bypass',           cve: 'CVE-2015-9235', description: 'Signature bypass when a server trusts the token\'s own alg header.' },
  { slug: 'alg-confusion', title: 'Algorithm Confusion',        cve: 'CVE-2016-10555', description: 'RS256→HS256 confusion: re-sign with the public key as an HMAC secret.' },
  { slug: 'weak-secret',   title: 'Weak Secret Brute-force',    cve: null, description: 'Dictionary-word HMAC secrets can be cracked offline from any exposed JWT.' },
  { slug: 'kid-sqli',      title: 'Key ID SQL Injection',       cve: null, description: 'Unsanitized kid header concatenated into SQL enables attacker-controlled key lookup.' },
  { slug: 'jku-injection', title: 'jku / jwk Header Injection', cve: null, description: 'jku fetches attacker-controlled JWKS; jwk embeds attacker keys inline.' },
  { slug: 'exp-bypass',    title: 'exp Bypass',                 cve: null, description: 'Expired token accepted when server skips exp check or skips all verification.' },
]

interface Props { children: ReactNode }

export default function AppShell({ children }: Props) {
  const [analyzerOpen, setAnalyzerOpen] = useState(false)
  const [theme, setTheme] = useState<Theme>(() => {
    return (localStorage.getItem('jwtlab.theme') as Theme) ?? 'dark'
  })
  // Tick counter — incremented on every 'storage' event so module badges re-read localStorage
  const [_progressTick, setProgressTick] = useState(0)
  const navigate = useNavigate()
  const location = useLocation()
  const reduceMotion = useReducedMotion()

  // Apply theme on mount and when it changes
  useEffect(() => {
    applyTheme(theme)
  }, [theme])

  // Re-render badge state whenever ExercisePanel (or any code) writes to localStorage
  // and dispatches a 'storage' event. Without this, badges only update on navigation.
  useEffect(() => {
    const handler = () => setProgressTick(t => t + 1)
    window.addEventListener('storage', handler)
    return () => window.removeEventListener('storage', handler)
  }, [])

  const toggleTheme = useCallback(() => {
    setTheme(t => t === 'dark' ? 'light' : 'dark')
  }, [])

  // Global Ctrl+J keyboard shortcut — fires regardless of focused element
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.ctrlKey && e.key === 'j') {
        e.preventDefault()
        setAnalyzerOpen(true)
      }
    }
    document.addEventListener('keydown', handleKeyDown)
    return () => document.removeEventListener('keydown', handleKeyDown)
  }, [])

  const activeSlug = location.pathname.split('/modules/')[1] ?? ''

  return (
    <div className="flex flex-col min-h-screen">
      {/* ── Top bar ──────────────────────────────────────────────────────── */}
      <header className="h-12 flex items-center justify-between px-6 bg-surface border-b border-border fixed top-0 left-0 right-0 z-50">
        <a href="/" className="font-display font-bold text-primary text-lg tracking-wide">
          JWTLab
        </a>
        <button
          onClick={() => setAnalyzerOpen(true)}
          className="btn-secondary text-small py-1 h-8"
          aria-label="Open JWT Analyzer (Ctrl+J)"
        >
          JWT Analyzer
          <kbd className="ml-2 text-text-muted text-xs">Ctrl+J</kbd>
        </button>
        <div className="flex items-center gap-4">
          {/* Theme toggle button */}
          <button
            onClick={toggleTheme}
            className="btn-secondary py-1 h-8 px-3 text-small"
            aria-label={`Switch to ${theme === 'dark' ? 'light' : 'dark'} theme`}
            title={`Current theme: ${theme}`}
          >
            {theme === 'dark' ? '☀ Light' : '☾ Dark'}
          </button>
          <a
            href="https://github.com"
            target="_blank"
            rel="noopener noreferrer"
            className="text-text-muted hover:text-primary transition-colors text-small"
          >
            GitHub
          </a>
        </div>
      </header>

      <div className="flex flex-1 pt-12">
        {/* ── Left rail ──────────────────────────────────────────────────── */}
        <nav
          className="w-[220px] shrink-0 bg-surface border-r border-border fixed left-0 top-12 bottom-0 overflow-y-auto
                     lg:w-[220px] max-lg:w-14"
          aria-label="Learning path"
        >
          <div className="p-4 max-lg:p-2">
            <h2 className="text-text-muted text-small uppercase tracking-widest mb-3 max-lg:hidden">
              Attack Modules
            </h2>
            <ul className="space-y-1">
              {MODULES.map((mod, i) => {
                const isActive = activeSlug === mod.slug
                const completion = localStorage.getItem(`jwtlab.progress.${mod.slug}`) ?? 'available'
                return (
                  <li key={mod.slug}>
                    <button
                      onClick={() => navigate(`/modules/${mod.slug}`)}
                      className={`w-full text-left rounded px-3 py-2 text-small transition-colors
                        flex items-center gap-2
                        ${isActive
                          ? 'bg-primary/10 text-primary border-l-2 border-primary'
                          : 'text-text-muted hover:text-text-primary hover:bg-surface-alt'
                        }`}
                      aria-current={isActive ? 'page' : undefined}
                    >
                      {/* Completion badge */}
                      <span
                        className={`w-5 h-5 rounded-full border-2 flex items-center justify-center shrink-0
                          ${completion === 'completed'
                            ? 'bg-primary border-primary'
                            : completion === 'in_progress'
                            ? 'border-primary animate-pulse-ring'
                            : 'border-border'
                          }`}
                        aria-label={completion}
                      >
                        {completion === 'completed' && (
                          <svg width="10" height="8" viewBox="0 0 10 8" fill="none">
                            <path d="M1 4L3.5 6.5L9 1" stroke="#0A0C12" strokeWidth="2" strokeLinecap="round"/>
                          </svg>
                        )}
                        {completion !== 'completed' && (
                          <span className="text-xs text-text-muted">{i + 1}</span>
                        )}
                      </span>
                      <span className="max-lg:hidden truncate">{mod.title}</span>
                    </button>
                  </li>
                )
              })}
            </ul>

            {/* Attack taxonomy strip */}
            <div className="mt-8 pt-4 border-t border-border max-lg:hidden">
              <h3 className="text-text-muted text-small uppercase tracking-widest mb-2">Taxonomy</h3>
              <ul className="space-y-3">
                {MODULES.map(mod => (
                  <li key={mod.slug}>
                    <button
                      onClick={() => navigate(`/modules/${mod.slug}`)}
                      className="w-full text-left group"
                    >
                      <span className="text-small text-text-muted group-hover:text-text-primary transition-colors block">
                        {mod.title}
                      </span>
                      {mod.description && (
                        <span className="text-xs text-text-muted/60 leading-tight block mt-0.5">
                          {mod.description}
                        </span>
                      )}
                    </button>
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </nav>

        {/* ── Center content ────────────────────────────────────────────── */}
        <main
          className="flex-1 ml-[220px] max-lg:ml-14 px-12 py-12 max-w-[860px]"
          id="main-content"
        >
          <motion.div
            key={location.pathname}
            initial={{ opacity: 0, y: reduceMotion ? 0 : 12 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: reduceMotion ? 0 : 0.32, ease: [0.16, 1, 0.32, 1] }}
          >
            {children}
          </motion.div>
        </main>
      </div>

      {/* ── JWT Analyzer Modal ────────────────────────────────────────────── */}
      {analyzerOpen && <JWTAnalyzerModal onClose={() => setAnalyzerOpen(false)} />}
    </div>
  )
}
