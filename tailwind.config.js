/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ["./index.html", "./src/**/*.{js,jsx}"],
  theme: {
    extend: {
      colors: {
        shadow: "#0B0F19",
        navy: "#111827",
        cyber: "#00BFFF",
        neon: "#00FF66",
        alert: "#FF3B30",
      },
    },
  },
  plugins: [],
};
