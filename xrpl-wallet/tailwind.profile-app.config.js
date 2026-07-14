/** @type {import('tailwindcss').Config} */
export default {
  content: ['./src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {},
  },
  // Full scoping (including preflight) is handled at the PostCSS level via
  // postcss-prefix-selector in vite.profile-app.config.ts, not here — an
  // earlier attempt disabled preflight entirely to avoid leaking into the
  // rest of NaluLF, but that also strips the box-sizing:border-box reset
  // several layout utilities assume, which broke click targets (an
  // invisible oversized element covered the onboarding checkboxes).
  // Prefixing every selector is more correct than disabling parts of Tailwind.
  plugins: [],
}
