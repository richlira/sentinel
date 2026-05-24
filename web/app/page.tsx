"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { API_BASE, fetchSynthetic, streamAnalyze, sendChat, type SentinelEvent } from "@/lib/sse";

type Mode = "localfirst" | "agent" | "local";
type ChatMsg = { role: "agent" | "user"; text: string };

type Span = {
  id: string;
  category: string;
  destination: string;
  preview: string;
  sha256: string;
  safe_derivative?: { display?: string; note?: string; valid_format?: boolean } | null;
  latency_ms?: number | null;
};

type Summary = {
  spans_total?: number;
  routed_local?: number;
  processed_cloud?: number;
  raw_sensitive_bytes_processed_in_cloud?: number;
  local_model?: string;
  local_endpoint_host?: string;
};

const CAT_COLOR: Record<string, string> = {
  pii: "text-rose-300 bg-rose-500/10 border-rose-500/30",
  financial: "text-amber-300 bg-amber-500/10 border-amber-500/30",
  medical: "text-violet-300 bg-violet-500/10 border-violet-500/30",
  non_sensitive: "text-slate-400 bg-slate-500/10 border-slate-500/20",
};

export default function Home() {
  const [doc, setDoc] = useState("");
  const [mode, setMode] = useState<Mode>("localfirst");
  const [running, setRunning] = useState(false);
  const [status, setStatus] = useState<"idle" | "classifying" | "routing" | "reviewing" | "done">("idle");
  const [spans, setSpans] = useState<Span[]>([]);
  const [summary, setSummary] = useState<Summary | null>(null);
  const [artifacts, setArtifacts] = useState<{ pdf?: string; audit_log?: string }>({});
  const [notice, setNotice] = useState<string | null>(null);
  const [routeMs, setRouteMs] = useState(0);
  const [messages, setMessages] = useState<ChatMsg[]>([]);
  const [interactionId, setInteractionId] = useState<string | null>(null);
  const [sessionId, setSessionId] = useState<string | null>(null);
  const [chatBusy, setChatBusy] = useState(false);
  const timer = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    fetchSynthetic().then((d) => setDoc(d.text)).catch(() => {});
    return () => { if (timer.current) clearInterval(timer.current); };
  }, []);

  const cloud = useMemo(() => spans.filter((s) => s.destination === "cloud-sandbox"), [spans]);
  const local = useMemo(() => spans.filter((s) => s.destination === "local-gemma"), [spans]);

  async function run() {
    setRunning(true);
    setStatus("classifying");
    setSpans([]);
    setSummary(null);
    setArtifacts({});
    setNotice(null);
    setRouteMs(0);
    setMessages([]);
    setInteractionId(null);
    setSessionId(null);

    try {
      await streamAnalyze({ mode }, async (e: SentinelEvent) => {
        switch (e.phase) {
          case "notice":
            setNotice(String(e.message));
            break;
          case "classify": {
            const ev = e as Record<string, unknown>;
            const span: Span = {
              id: String(ev.span_id ?? ev.id ?? ""),
              category: String(ev.category ?? ""),
              destination: String(ev.destination ?? "cloud-sandbox"),
              preview: String(ev.preview ?? ""),
              sha256: typeof ev.sha256 === "string" ? ev.sha256 : "",
            };
            setSpans((prev) => (prev.some((p) => p.id === span.id) ? prev : [...prev, span]));
            break;
          }
          case "route":
            if (e.status === "sending") {
              setStatus("routing");
              const t0 = Date.now();
              timer.current = setInterval(() => setRouteMs(Date.now() - t0), 100);
            } else if (e.status === "received") {
              if (timer.current) clearInterval(timer.current);
              setRouteMs(Number(e.latency_ms) || 0);
            }
            break;
          case "report": {
            setArtifacts({ pdf: String(e.pdf), audit_log: String(e.audit_log) });
            try {
              const res = await fetch(API_BASE + String(e.audit_log));
              const audit = await res.json();
              const byId = new Map<string, Span>(
                (audit.spans as Span[]).map((s) => [s.id, s]),
              );
              setSpans((prev) =>
                prev.map((s) => {
                  const full = byId.get(s.id);
                  return full ? { ...s, safe_derivative: full.safe_derivative, latency_ms: full.latency_ms } : s;
                }),
              );
            } catch { /* keep masked previews */ }
            break;
          }
          case "handoff":
            setStatus("reviewing");
            break;
          case "agent_message":
            setMessages((m) => [...m, { role: "agent", text: String(e.text) }]);
            break;
          case "done":
            setSummary(e.summary as Summary);
            if (e.interaction_id) setInteractionId(String(e.interaction_id));
            if (e.session_id) setSessionId(String(e.session_id));
            setStatus("done");
            break;
        }
      });
    } catch (err) {
      setNotice("Stream error: " + String(err));
    } finally {
      if (timer.current) clearInterval(timer.current);
      setRunning(false);
    }
  }

  async function sendChatTurn(text: string) {
    if (!interactionId) return;
    setMessages((m) => [...m, { role: "user", text }]);
    setChatBusy(true);
    try {
      const r = await sendChat(interactionId, text, sessionId ?? undefined);
      if (r.reply) setMessages((m) => [...m, { role: "agent", text: r.reply as string }]);
      if (r.interaction_id) setInteractionId(r.interaction_id);
    } catch (err) {
      setMessages((m) => [...m, { role: "agent", text: "Error: " + String(err) }]);
    } finally {
      setChatBusy(false);
    }
  }

  return (
    <main className="mx-auto max-w-7xl px-6 py-8">
      <Header mode={mode} setMode={setMode} running={running} onRun={run} status={status} />

      {notice && (
        <div className="mt-4 rounded-lg border border-amber-500/30 bg-amber-500/10 px-4 py-2 text-sm text-amber-200">
          {notice}
        </div>
      )}

      <StatusStrip status={status} routeMs={routeMs} localCount={local.length} mode={mode} />

      <div className="mt-6 grid grid-cols-1 gap-6 lg:grid-cols-[320px_1fr]">
        <DocPanel doc={doc} />
        {mode === "localfirst" ? (
          <div className="grid grid-cols-1 gap-5 md:grid-cols-2">
            <Column title="Local · DGX Spark" sub="redacted on-device · raw stays here"
                    accent="local" spans={local} busy={running && status === "classifying"} />
            <ChatPanel messages={messages} busy={chatBusy || status === "reviewing"}
                       canChat={!!interactionId && !running} onSend={sendChatTurn} />
          </div>
        ) : (
          <div className="grid grid-cols-1 gap-5 md:grid-cols-2">
            <Column title="Cloud Sandbox" sub="Managed Agent · non-sensitive" accent="cloud" spans={cloud} clear />
            <Column title="Local · DGX Spark" sub="Gemma · sensitive only" accent="local" spans={local} busy={status === "routing"} />
          </div>
        )}
      </div>

      {summary && <SummaryBar summary={summary} artifacts={artifacts} routeMs={routeMs} />}

      <footer className="mt-10 text-center text-xs text-slate-600">
        Synthetic data only. Built on Google Managed Agents — AGENTS.md · code_execution ·
        network allowlist header transform · file artifacts.
      </footer>
    </main>
  );
}

function Header({
  mode, setMode, running, onRun, status,
}: {
  mode: Mode;
  setMode: (m: Mode) => void;
  running: boolean;
  onRun: () => void;
  status: string;
}) {
  return (
    <header className="flex flex-col gap-4 border-b border-edge pb-6 sm:flex-row sm:items-center sm:justify-between">
      <div>
        <div className="flex items-center gap-2">
          <span className="text-2xl">🛡️</span>
          <h1 className="text-2xl font-semibold tracking-tight text-white">Sentinel</h1>
          <span className="rounded-full border border-edge px-2 py-0.5 text-[10px] uppercase tracking-wider text-slate-400">
            privacy routing
          </span>
        </div>
        <p className="mt-1 text-sm text-slate-400">
          Sensitive data never leaves your hardware. The cloud trusts the local model&apos;s
          answer without ever seeing the raw data.
        </p>
      </div>
      <div className="flex items-center gap-3">
        <div className="flex rounded-lg border border-edge bg-panel p-0.5 text-xs">
          {(["localfirst", "agent", "local"] as const).map((m) => (
            <button
              key={m}
              onClick={() => setMode(m)}
              disabled={running}
              className={`rounded-md px-3 py-1.5 transition ${
                mode === m ? "bg-slate-700 text-white" : "text-slate-400 hover:text-slate-200"
              }`}
            >
              {m === "localfirst" ? "Local-First" : m === "agent" ? "Cloud agent" : "Local"}
            </button>
          ))}
        </div>
        <button
          onClick={onRun}
          disabled={running}
          className="rounded-lg bg-emerald-500 px-5 py-2 text-sm font-semibold text-emerald-950 transition hover:bg-emerald-400 disabled:opacity-50"
        >
          {running ? "Analyzing…" : "Run analysis"}
        </button>
      </div>
    </header>
  );
}

function StatusStrip({ status, routeMs, localCount, mode }: { status: string; routeMs: number; localCount: number; mode: Mode }) {
  const label =
    status === "idle" ? "Ready" :
    status === "classifying" ? (mode === "localfirst" ? "Redacting on your hardware — raw never leaves…" : "Classifying spans in the cloud sandbox…") :
    status === "routing" ? `Routing ${localCount} sensitive spans to local Gemma — egress proxy injecting Authorization…` :
    status === "reviewing" ? "Managed Agent reviewing the redacted data + verifying fields via callback…" :
    "Complete — evidence generated.";
  const active = status === "routing" || status === "reviewing";
  return (
    <div className="mt-5 flex items-center gap-3 rounded-lg border border-edge bg-panel px-4 py-3 text-sm">
      <span className={`h-2.5 w-2.5 rounded-full ${active ? "animate-pulseflow bg-local" : status === "done" ? "bg-local" : "bg-slate-500"}`} />
      <span className="text-slate-300">{label}</span>
      {status === "routing" && (
        <span className="ml-auto font-mono text-xs text-slate-400">{(routeMs / 1000).toFixed(1)}s</span>
      )}
    </div>
  );
}

function DocPanel({ doc }: { doc: string }) {
  return (
    <aside className="rounded-xl border border-edge bg-panel p-4">
      <div className="mb-2 text-xs font-semibold uppercase tracking-wider text-slate-500">Input document</div>
      <pre className="max-h-[460px] overflow-auto whitespace-pre-wrap font-mono text-[11px] leading-relaxed text-slate-400">
        {doc || "Loading synthetic document…"}
      </pre>
    </aside>
  );
}

function ChatPanel({
  messages, busy, canChat, onSend,
}: {
  messages: ChatMsg[];
  busy: boolean;
  canChat: boolean;
  onSend: (text: string) => void;
}) {
  const [input, setInput] = useState("");
  return (
    <section className="flex flex-col rounded-xl border border-cloud/40 bg-panel p-4">
      <div className="mb-3 flex items-center gap-2">
        <span className="h-2 w-2 rounded-full bg-cloud" />
        <h2 className="text-sm font-semibold text-white">Managed Agent</h2>
        <span className="ml-auto text-[10px] uppercase tracking-wider text-slate-500">redacted data only</span>
      </div>
      <div className="flex min-h-[300px] flex-1 flex-col gap-3 overflow-auto">
        {messages.length === 0 && (
          <p className="py-10 text-center text-xs text-slate-600">
            The agent reviews the redacted document and verifies fields by calling back to your
            local model — then asks you a question.
          </p>
        )}
        {messages.map((m, i) => (
          <div key={i} className={`max-w-[92%] rounded-lg px-3 py-2 text-[12px] leading-relaxed ${
            m.role === "agent" ? "self-start border border-edge bg-ink/60 text-slate-200" : "self-end bg-cloud/20 text-slate-100"}`}>
            <div className="mb-0.5 text-[9px] uppercase tracking-wider text-slate-500">{m.role === "agent" ? "agent" : "you"}</div>
            <div className="whitespace-pre-wrap">{m.text}</div>
          </div>
        ))}
        {busy && <div className="self-start text-xs text-emerald-300/80"><span className="animate-pulseflow">● agent thinking…</span></div>}
      </div>
      <form
        className="mt-3 flex gap-2"
        onSubmit={(ev) => { ev.preventDefault(); if (input.trim() && canChat && !busy) { onSend(input.trim()); setInput(""); } }}
      >
        <input
          value={input}
          onChange={(e) => setInput(e.target.value)}
          disabled={!canChat || busy}
          placeholder={canChat ? "Ask the agent about the redacted data…" : "Run a Local-First analysis first"}
          className="flex-1 rounded-lg border border-edge bg-ink/60 px-3 py-2 text-sm text-slate-200 placeholder:text-slate-600 disabled:opacity-50"
        />
        <button
          type="submit"
          disabled={!canChat || busy}
          className="rounded-lg bg-cloud/80 px-4 py-2 text-sm font-medium text-white transition hover:bg-cloud disabled:opacity-50"
        >
          Send
        </button>
      </form>
    </section>
  );
}

function Column({
  title, sub, accent, spans, clear, busy,
}: {
  title: string;
  sub: string;
  accent: "cloud" | "local";
  spans: Span[];
  clear?: boolean;
  busy?: boolean;
}) {
  const ring = accent === "local" ? "border-local/40" : "border-cloud/40";
  const dot = accent === "local" ? "bg-local" : "bg-cloud";
  return (
    <section className={`rounded-xl border ${ring} bg-panel p-4`}>
      <div className="mb-3 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span className={`h-2 w-2 rounded-full ${dot}`} />
          <h2 className="text-sm font-semibold text-white">{title}</h2>
        </div>
        <span className="text-[10px] uppercase tracking-wider text-slate-500">{sub}</span>
      </div>
      {busy && (
        <div className="mb-3 flex items-center gap-2 rounded-md border border-local/30 bg-local/5 px-3 py-2 text-xs text-emerald-300">
          <span className="h-1.5 w-1.5 animate-pulseflow rounded-full bg-local" />
          Processing on local hardware…
        </div>
      )}
      <div className="flex flex-col gap-2">
        {spans.length === 0 && <p className="py-6 text-center text-xs text-slate-600">No spans yet</p>}
        {spans.map((s) => (
          <SpanCard key={s.id} span={s} clear={clear} />
        ))}
      </div>
    </section>
  );
}

function SpanCard({ span, clear }: { span: Span; clear?: boolean }) {
  const cat = CAT_COLOR[span.category] ?? CAT_COLOR.non_sensitive;
  const d = span.safe_derivative;
  return (
    <div className="animate-slidein rounded-lg border border-edge bg-ink/60 p-3">
      <div className="flex items-center justify-between">
        <span className={`rounded border px-1.5 py-0.5 text-[10px] font-medium uppercase ${cat}`}>
          {span.category.replace("_", " ")}
        </span>
        <span className="font-mono text-[9px] text-slate-600">{span.sha256 ? span.sha256.slice(0, 12) : ""}</span>
      </div>
      <p className={`mt-2 font-mono text-[11px] ${clear ? "text-slate-300" : "text-slate-400"}`}>
        {span.preview}
      </p>
      {d && (
        <div className="mt-2 flex flex-wrap items-center gap-2 border-t border-edge pt-2 text-[11px]">
          <span className="font-mono text-emerald-300">{d.display}</span>
          {d.valid_format && <span className="text-[9px] text-emerald-500">✓ valid</span>}
          {d.note && <span className="text-slate-500">· {d.note}</span>}
        </div>
      )}
    </div>
  );
}

function SummaryBar({
  summary, artifacts, routeMs,
}: {
  summary: Summary;
  artifacts: { pdf?: string; audit_log?: string };
  routeMs: number;
}) {
  return (
    <div className="mt-6 grid grid-cols-1 gap-4 rounded-xl border border-local/30 bg-gradient-to-br from-local/10 to-transparent p-5 sm:grid-cols-[auto_1fr_auto] sm:items-center">
      <div className="text-center sm:text-left">
        <div className="text-4xl font-bold text-local">{summary.raw_sensitive_bytes_processed_in_cloud ?? 0}</div>
        <div className="text-xs text-slate-400">raw sensitive bytes to cloud</div>
      </div>
      <div className="flex flex-wrap gap-x-8 gap-y-2 text-sm">
        <Stat label="Routed local" value={`${summary.routed_local ?? 0}`} accent="local" />
        <Stat label="Processed cloud" value={`${summary.processed_cloud ?? 0}`} accent="cloud" />
        <Stat label="Local latency" value={`${(routeMs / 1000).toFixed(1)}s`} />
        <Stat label="Local model" value={summary.local_model ?? "—"} />
      </div>
      <div className="flex gap-2">
        {artifacts.pdf && (
          <a href={API_BASE + artifacts.pdf} target="_blank" rel="noreferrer"
             className="rounded-lg bg-white/10 px-4 py-2 text-sm font-medium text-white hover:bg-white/20">
            ↓ PDF report
          </a>
        )}
        {artifacts.audit_log && (
          <a href={API_BASE + artifacts.audit_log} target="_blank" rel="noreferrer"
             className="rounded-lg border border-edge px-4 py-2 text-sm font-medium text-slate-300 hover:bg-white/5">
            ↓ audit-log.json
          </a>
        )}
      </div>
    </div>
  );
}

function Stat({ label, value, accent }: { label: string; value: string; accent?: "local" | "cloud" }) {
  const color = accent === "local" ? "text-local" : accent === "cloud" ? "text-cloud" : "text-white";
  return (
    <div>
      <div className={`font-semibold ${color}`}>{value}</div>
      <div className="text-xs text-slate-500">{label}</div>
    </div>
  );
}
