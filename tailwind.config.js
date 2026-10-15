/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        cyber: {
          bg: '#0B1020',
          panel: '#111827',
          card: '#131D31',
          border: '#1E293B',
          'border-light': '#334155',
          accent: '#22D3EE',
          'accent-glow': 'rgba(34, 211, 238, 0.15)',
          muted: '#94A3B8',
          text: '#F8FAFC',
          allowed: '#10B981',
          warning: '#F59E0B',
          blocked: '#EF4444'
        }
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'Fira Code', 'Consolas', 'monospace']
      },
      boxShadow: {
        'cyber-cyan': '0 0 15px -3px rgba(34, 211, 238, 0.25)',
        'cyber-card': '0 4px 20px -2px rgba(0, 0, 0, 0.5)'
      }
    },
  },
  plugins: [],
}
