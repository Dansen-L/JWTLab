import { ReactNode, useState, useEffect, useRef } from 'react'
import { motion, AnimatePresence, useReducedMotion } from 'framer-motion'
import ReactMarkdown from 'react-markdown'
import CopyBlock from './CopyBlock'

interface Props {
  slug: string
  title: string
  severity: string
  cve?: string | null
  narrative: string
  mitigation: string
  children: ReactNode
}

const SEVERITY_COLOR: Record<string, string> = {
  Critical: 'text-error border-error/40 bg-error/10',
  High:     'text-warning border-warning/40 bg-warning/10',
}

const SAMPLE_PARTS = [
  { label: 'Header', text: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9', color: 'text-jwt-header' },
  { label: 'Payload', text: 'eyJzdWIiOiJ1c2VyIiwicm9sZSI6InVzZXIifQ', color: 'text-jwt-payload' },
  { label: 'Signature', text: 'SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c', color: 'text-jwt-sig' },
]

export default function ModuleLayout({ slug, title, severity, cve, narrative, mitigation, children }: Props) {
  const storageKey = `jwtlab.started.${slug}`
  const [showIntro, setShowIntro] = useState(() => !localStorage.getItem(storageKey))
  const [narrativeCollapsed, setNarrativeCollapsed] = useState(true)
  const [introDone, setIntroDone] = useState(false)
  const reduceMotion = useReducedMotion()
  const introTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  // Auto-complete intro after 3s
  useEffect(() => {
    if (showIntro && !introDone) {
      introTimerRef.current = setTimeout(() => setIntroDone(true), 3000)
    }
    return () => { if (introTimerRef.current) clearTimeout(introTimerRef.current) }
  }, [showIntro, introDone])

  const skipIntro = () => {
    if (introTimerRef.current) clearTimeout(introTimerRef.current)
    setIntroDone(true)
  }

  const startModule = () => {
    setShowIntro(false)
    setNarrativeCollapsed(false)
    localStorage.setItem(storageKey, '1')
  }

  return (
    <div>
      {/* Module header */}
      <div className="flex flex-wrap items-start gap-3 mb-6">
        <h1 className="font-display text-display text-text-primary">{title}</h1>
        <div className="flex items-center gap-2 mt-1">
          <span className={`rounded px-2 py-0.5 text-small border ${SEVERITY_COLOR[severity] ?? ''}`}>
            {severity}
          </span>
          {cve && (
            <span className="rounded px-2 py-0.5 text-small border border-accent/40 bg-accent/10 text-accent">
              {cve}
            </span>
          )}
        </div>
      </div>

      {/* First-visit intro overlay: token assembly animation + Skip / Start Module */}
      <AnimatePresence>
        {showIntro && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: reduceMotion ? 0 : 0.2 }}
            className="mb-6 bg-surface-alt border border-border rounded-card p-6 text-center"
            aria-label="Module intro animation"
          >
            <p className="text-text-muted text-small mb-4">
              JWT Token Assembly
            </p>
            <div className="font-mono text-xs mb-4 flex flex-wrap items-center justify-center gap-0">
              {SAMPLE_PARTS.map((part, i) => (
                <motion.span
                  key={part.label}
                  className={part.color}
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  transition={{ duration: reduceMotion ? 0 : 0.6, delay: reduceMotion ? 0 : i * 0.9 }}
                  aria-label={part.label}
                >
                  {part.text}{i < SAMPLE_PARTS.length - 1 ? '.' : ''}
                </motion.span>
              ))}
            </div>

            {!introDone ? (
              <button
                onClick={skipIntro}
                className="btn-secondary py-1 h-8 px-4 text-small"
                aria-label="Skip animation"
              >
                Skip →
              </button>
            ) : (
              <motion.button
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                transition={{ duration: reduceMotion ? 0 : 0.2 }}
                onClick={startModule}
                className="btn-primary py-1 h-8 px-4 text-small"
                aria-label="Start Module"
              >
                Start Module
              </motion.button>
            )}
          </motion.div>
        )}
      </AnimatePresence>

      {/* Narrative — hidden until module is started */}
      {!showIntro && (
        <section className="mb-6">
          <div className="flex items-center justify-between mb-2">
            <h2 className="font-display text-h3 text-text-muted section-heading-bleed">Background</h2>
            <button
              onClick={() => setNarrativeCollapsed(c => !c)}
              className="text-small text-text-muted hover:text-primary transition-colors"
              aria-expanded={!narrativeCollapsed}
            >
              {narrativeCollapsed ? 'Expand ▾' : 'Collapse ▴'}
            </button>
          </div>
          {!narrativeCollapsed && (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              transition={{ duration: reduceMotion ? 0 : 0.2 }}
              className="narrative-body text-text-muted text-body leading-relaxed bg-surface-alt border border-border rounded-card p-4"
              dangerouslySetInnerHTML={{ __html: narrative.replace(/\n/g, '<br/>') }}
            />
          )}
        </section>
      )}

      {/* Children: AttackVisualizer + ExercisePanel */}
      {children}

      {/* Mitigation — rendered as Markdown */}
      <section className="mt-8">
        <h2 className="font-display text-h3 text-primary mb-3 section-heading-bleed">Mitigation</h2>
        <CopyBlock className="text-text-muted text-small mitigation-body">
          <ReactMarkdown
            components={{
              p: ({ children }) => <p className="mb-3 leading-relaxed">{children}</p>,
              strong: ({ children }) => <strong className="text-text-primary font-semibold">{children}</strong>,
              code: ({ children, className }) => {
                const isBlock = className?.startsWith('language-')
                return isBlock
                  ? <code className={`${className} block bg-surface rounded p-3 my-2 font-mono text-xs whitespace-pre-wrap text-accent`}>{children}</code>
                  : <code className="px-1 bg-surface rounded font-mono text-xs text-accent">{children}</code>
              },
              pre: ({ children }) => <pre className="my-2">{children}</pre>,
              ul: ({ children }) => <ul className="list-disc ml-4 space-y-1 mb-3">{children}</ul>,
              li: ({ children }) => <li className="text-text-muted">{children}</li>,
            }}
          >
            {mitigation}
          </ReactMarkdown>
        </CopyBlock>
      </section>
    </div>
  )
}
