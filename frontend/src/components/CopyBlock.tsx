import { useRef, useState } from 'react'

interface CopyBlockProps extends React.HTMLAttributes<HTMLDivElement> {
  children: React.ReactNode
  tag?: 'div' | 'pre'
}

/**
 * Code block with a top-right copy-to-clipboard button.
 * Renders with `.code-block` styling per the design system spec.
 */
export default function CopyBlock({ children, className = '', tag: Tag = 'div', ...props }: CopyBlockProps) {
  const ref = useRef<HTMLDivElement>(null)
  const [copied, setCopied] = useState(false)

  const handleCopy = () => {
    const text = ref.current?.innerText ?? ''
    navigator.clipboard.writeText(text).catch(() => {})
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <div
      ref={ref}
      className={`code-block relative ${className}`}
      {...props}
    >
      {children}
      <button
        onClick={handleCopy}
        className="absolute top-1 right-1 text-xs px-1.5 py-0.5 rounded border border-border bg-surface text-text-muted hover:text-text-primary hover:border-primary/50 transition-colors opacity-60 hover:opacity-100 focus:opacity-100"
        aria-label="Copy code to clipboard"
        title="Copy to clipboard"
        type="button"
      >
        {copied ? '✓' : '⧉'}
      </button>
    </div>
  )
}
