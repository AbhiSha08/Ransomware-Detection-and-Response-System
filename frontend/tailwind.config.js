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
        soc: {
          1000: '#000000',
          950:  '#000000', // Void black base
          900:  '#0A0A0A', // Panel base
          850:  '#0F0F0F', 
          800:  'rgba(255,255,255,0.05)', // Border
          700:  '#171717',
          600:  '#262626',
          500:  '#404040',
          400:  '#525252',
          300:  '#A3A3A3',
          200:  '#D4D4D4',
          100:  '#F5F5F5',

          nominal:       '#39ff14',
          'nominal-dim': '#1f8f0a',
          warning:       '#8b5cf6',
          'warning-dim': '#5b21b6',
          critical:       '#ef4444',
          'critical-dim': '#b91c1c',
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['IBM Plex Mono', 'Fira Code', 'monospace'],
      },
      fontSize: {
        '2xs': ['0.65rem', { lineHeight: '1rem' }],
      },
      backgroundImage: {
        'grid-dark': `linear-gradient(rgba(255, 255, 255, 0.02) 1px, transparent 1px),
                      linear-gradient(90deg, rgba(255, 255, 255, 0.02) 1px, transparent 1px)`,
      },
      backgroundSize: {
        'grid-dark': '40px 40px',
      },
      borderRadius: {
        'xl2': '1rem',
        'xl3': '1.25rem',
      },
      backdropBlur: {
        'xs': '2px',
        'glass': '12px',
      },
      keyframes: {
        'bar-fill': {
          '0%':   { transform: 'scaleX(0)', transformOrigin: 'left' },
          '100%': { transform: 'scaleX(1)', transformOrigin: 'left' },
        },
        'live-breathe': {
          '0%, 100%': { opacity: '1',   transform: 'scale(1)' },
          '50%':      { opacity: '0.5', transform: 'scale(0.75)' },
        },
      },
      animation: {
        'bar-fill':       'bar-fill 0.8s ease-out forwards',
        'live-breathe':   'live-breathe 2s ease-in-out infinite',
      },
    },
  },
  plugins: [],
}
