/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'monospace'],
      },
      colors: {
        aegis: {
          950: '#060d18',
          900: '#0b1220',
          800: '#111827',
          700: '#1e293b',
          accent: '#06b6d4',
          danger: '#ef4444',
          warn: '#f59e0b',
          ok: '#10b981',
        },
      },
    },
  },
  plugins: [],
}