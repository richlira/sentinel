import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Sentinel — agentic privacy routing",
  description:
    "Sensitive data never leaves your hardware. A Managed Agent routes only sensitive spans to a local Gemma model.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body className="antialiased">{children}</body>
    </html>
  );
}
