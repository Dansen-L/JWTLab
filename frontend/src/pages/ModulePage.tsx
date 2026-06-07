import { useParams, useNavigate } from 'react-router-dom'
import { lazy, Suspense } from 'react'

// Lazy-load each module component
const AlgNoneModule       = lazy(() => import('../modules/AlgNoneModule'))
const AlgConfusionModule  = lazy(() => import('../modules/AlgConfusionModule'))
const WeakSecretModule    = lazy(() => import('../modules/WeakSecretModule'))
const KidSqliModule       = lazy(() => import('../modules/KidSqliModule'))
const JkuInjectionModule  = lazy(() => import('../modules/JkuInjectionModule'))
const ExpBypassModule     = lazy(() => import('../modules/ExpBypassModule'))

const MODULE_MAP: Record<string, React.LazyExoticComponent<() => JSX.Element>> = {
  'alg-none':       AlgNoneModule,
  'alg-confusion':  AlgConfusionModule,
  'weak-secret':    WeakSecretModule,
  'kid-sqli':       KidSqliModule,
  'jku-injection':  JkuInjectionModule,
  'exp-bypass':     ExpBypassModule,
}

const MODULE_ORDER = ['alg-none','alg-confusion','weak-secret','kid-sqli','jku-injection','exp-bypass']

export default function ModulePage() {
  const { moduleSlug } = useParams<{ moduleSlug: string }>()
  const navigate = useNavigate()
  const ModuleComponent = moduleSlug ? MODULE_MAP[moduleSlug] : null

  const currentIdx = MODULE_ORDER.indexOf(moduleSlug ?? '')
  const prevSlug = currentIdx > 0 ? MODULE_ORDER[currentIdx - 1] : null
  const nextSlug = currentIdx < MODULE_ORDER.length - 1 ? MODULE_ORDER[currentIdx + 1] : null

  if (!ModuleComponent) {
    return (
      <div className="flex flex-col items-center justify-center h-64 gap-4">
        <h2 className="font-display text-h2 text-error">Module not found</h2>
        <button onClick={() => navigate('/')} className="btn-primary">Back to Home</button>
      </div>
    )
  }

  return (
    <div>
      <Suspense fallback={<div className="text-text-muted">Loading module…</div>}>
        <ModuleComponent />
      </Suspense>

      {/* Module navigation */}
      <div className="flex justify-between items-center mt-12 pt-6 border-t border-border">
        {prevSlug ? (
          <button onClick={() => navigate(`/modules/${prevSlug}`)} className="btn-secondary">
            ← Previous Module
          </button>
        ) : <div />}
        {nextSlug ? (
          <button onClick={() => navigate(`/modules/${nextSlug}`)} className="btn-primary">
            Next Module →
          </button>
        ) : <div />}
      </div>
    </div>
  )
}
