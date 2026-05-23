import type { Config } from "tailwindcss";

const config: Config = {
  content: ["./app/**/*.{ts,tsx}", "./components/**/*.{ts,tsx}"],
  theme: {
    extend: {
      fontFamily: {
        mono: ["ui-monospace", "SFMono-Regular", "Menlo", "monospace"],
      },
      colors: {
        ink: "#0a0e1a",
        panel: "#0f1626",
        edge: "#1e293b",
        local: "#10b981",
        cloud: "#3b82f6",
      },
      keyframes: {
        slidein: {
          "0%": { opacity: "0", transform: "translateY(6px)" },
          "100%": { opacity: "1", transform: "translateY(0)" },
        },
        pulseflow: {
          "0%,100%": { opacity: "0.3" },
          "50%": { opacity: "1" },
        },
      },
      animation: {
        slidein: "slidein 0.35s ease-out",
        pulseflow: "pulseflow 1.4s ease-in-out infinite",
      },
    },
  },
  plugins: [],
};

export default config;
