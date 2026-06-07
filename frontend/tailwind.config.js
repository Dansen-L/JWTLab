/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        // JWTLab design system palette (app_spec.txt §design_system)
        background:   '#0A0C12',
        surface:      '#111520',
        'surface-alt':'#181E2C',
        border:       '#1E2A3E',
        primary:      '#00E5A0',
        accent:       '#7C5CFC',
        warning:      '#FFB800',
        error:        '#FF3B5C',
        'text-primary':'#E8EEF8',
        'text-muted': '#7A8BAA',
        'jwt-header': '#4FC3F7',
        'jwt-payload':'#A5D6A7',
        'jwt-sig':    '#CE93D8',
      },
      fontFamily: {
        display: ['"Space Grotesk"', 'sans-serif'],
        body:    ['"DM Sans"', 'sans-serif'],
        mono:    ['"JetBrains Mono"', 'monospace'],
      },
      fontSize: {
        'display': ['2.25rem', { lineHeight: '1.2', fontWeight: '700' }],
        'h2':      ['1.5rem',  { lineHeight: '1.3', fontWeight: '600' }],
        'h3':      ['1.125rem',{ lineHeight: '1.4', fontWeight: '500' }],
        'body':    ['0.9375rem',{ lineHeight: '1.65' }],
        'small':   ['0.8125rem',{ lineHeight: '1.5' }],
      },
      borderRadius: {
        card:   '12px',
        btn:    '8px',
        input:  '8px',
      },
      boxShadow: {
        'primary-glow': '0 0 0 2px rgba(0, 229, 160, 0.35)',
        'focus':        '0 0 0 2px #00E5A0',
      },
      animation: {
        'pulse-ring': 'pulse-ring 1.5s ease-in-out infinite',
        'fade-up':    'fade-up 320ms cubic-bezier(0.16, 1, 0.32, 1) forwards',
      },
      keyframes: {
        'pulse-ring': {
          '0%, 100%': { opacity: '1', transform: 'scale(1)' },
          '50%':      { opacity: '0.5', transform: 'scale(1.1)' },
        },
        'fade-up': {
          'from': { opacity: '0', transform: 'translateY(12px)' },
          'to':   { opacity: '1', transform: 'translateY(0)' },
        },
      },
    },
  },
  plugins: [],
}
