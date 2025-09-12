/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  // Most configuration is now in CSS using @theme directive
  // This minimal config is kept for tool compatibility
  darkMode: 'class',
}