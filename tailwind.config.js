/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    './app/**/*.{ts,tsx}',
    './components/**/*.{ts,tsx}',
  ],
  theme: {
    extend: {
      keyframes: {
        'entropy-pulse': {
          '0%, 100%': {
            boxShadow: '0 0 0 0 rgba(244, 63, 94, 0.5)',
          },
          '50%': {
            boxShadow: '0 0 12px 2px rgba(244, 63, 94, 0.85)',
          },
        },
        'hud-pulse': {
          '0%, 100%': {
            opacity: '1',
            boxShadow: '0 0 0 0 rgba(52, 211, 153, 0.6)',
          },
          '50%': {
            opacity: '0.65',
            boxShadow: '0 0 8px 2px rgba(52, 211, 153, 0.55)',
          },
        },
      },
      animation: {
        'entropy-pulse': 'entropy-pulse 1.8s ease-in-out infinite',
        'hud-pulse': 'hud-pulse 2s ease-in-out infinite',
      },
    },
  },
  plugins: [],
};
