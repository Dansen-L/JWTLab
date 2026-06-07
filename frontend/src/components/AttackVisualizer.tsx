import { useState } from 'react'
import { motion, AnimatePresence, useReducedMotion } from 'framer-motion'

interface Step {
  title: string
  client: string
  server: string
  description: string
  highlight?: boolean
}

interface Props {
  steps: Step[]
}

export default function AttackVisualizer({ steps }: Props) {
  const reduceMotion = useReducedMotion()
  const [currentStep, setCurrentStep] = useState(0)

  if (!steps.length) {
    return (
      <div className="bg-surface-alt border border-border rounded-card p-6 mb-6 h-[280px] flex items-center justify-center">
        <p className="text-text-muted">Attack visualizer coming soon.</p>
      </div>
    )
  }

  const step = steps[currentStep]
  const total = steps.length

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'ArrowRight' && currentStep < total - 1) setCurrentStep(c => c + 1)
    if (e.key === 'ArrowLeft' && currentStep > 0) setCurrentStep(c => c - 1)
  }

  return (
    <section
      className="mb-6"
      onKeyDown={handleKeyDown}
      tabIndex={0}
      aria-label="Attack step visualizer — use arrow keys to navigate steps"
      aria-keyshortcuts="ArrowLeft ArrowRight"
      role="region"
    >
      <h2 className="font-display text-h3 text-text-primary mb-3">Attack Flow</h2>

      {/* Fixed-height stage to prevent layout jank */}
      <div className="bg-surface-alt border border-border rounded-card overflow-hidden" style={{ height: '280px' }}>
        <AnimatePresence mode="wait">
          <motion.div
            key={currentStep}
            initial={{ opacity: 0, x: reduceMotion ? 0 : 20 }}
            animate={{ opacity: 1, x: 0 }}
            exit={{ opacity: 0, x: reduceMotion ? 0 : -20 }}
            transition={{ duration: reduceMotion ? 0 : 0.28, ease: [0.4, 0, 0.2, 1] }}
            className="h-full flex flex-col"
          >
            <div className="px-5 py-3 border-b border-border flex items-center gap-3">
              {/* Step indicator circles */}
              {steps.map((_, i) => (
                <button
                  key={i}
                  onClick={() => setCurrentStep(i)}
                  aria-label={`Step ${i + 1}`}
                  className={`transition-all
                    ${i < currentStep ? 'step-complete' : i === currentStep ? 'step-active' : 'step-pending'}
                  `}
                >
                  {i + 1}
                </button>
              ))}
              <span className="ml-2 text-text-primary font-medium text-small">{step.title}</span>
            </div>

            <div className="flex-1 grid grid-cols-2 gap-0 overflow-hidden">
              {/* Client panel */}
              <div className="p-4 border-r border-border">
                <div className="text-small font-medium text-jwt-header mb-2">Client</div>
                <pre className="text-small text-text-muted whitespace-pre-wrap font-mono overflow-y-auto max-h-32">
                  {step.client}
                </pre>
              </div>
              {/* Server panel */}
              <div className={`p-4 ${step.highlight ? 'bg-error/5' : ''}`}>
                <div className="text-small font-medium text-jwt-payload mb-2">Server</div>
                <pre className={`text-small whitespace-pre-wrap font-mono overflow-y-auto max-h-32
                  ${step.highlight ? 'text-error' : 'text-text-muted'}`}>
                  {step.server}
                </pre>
              </div>
            </div>
          </motion.div>
        </AnimatePresence>
      </div>

      {/* Description + navigation */}
      <div className="flex items-start justify-between gap-4 mt-3">
        <p className="text-text-muted text-small flex-1">{step.description}</p>
        <div className="flex items-center gap-2 shrink-0">
          <button
            onClick={() => setCurrentStep(c => Math.max(0, c - 1))}
            disabled={currentStep === 0}
            className="btn-secondary py-1 h-8 px-3 text-small disabled:opacity-30"
            aria-label="Previous step"
          >
            ←
          </button>
          <span className="text-small text-text-muted" aria-live="polite">{currentStep + 1} / {total}</span>
          <span className="text-xs text-text-muted/50 ml-1 select-none" aria-hidden="true">← →</span>
          <button
            onClick={() => setCurrentStep(c => Math.min(total - 1, c + 1))}
            disabled={currentStep === total - 1}
            className="btn-secondary py-1 h-8 px-3 text-small disabled:opacity-30"
            aria-label="Next step"
          >
            →
          </button>
        </div>
      </div>
    </section>
  )
}
