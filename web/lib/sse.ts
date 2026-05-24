export const API_BASE =
  process.env.NEXT_PUBLIC_API_BASE ?? "http://127.0.0.1:8000";

export type SentinelEvent = {
  phase: string;
  [key: string]: unknown;
};

/**
 * POST to /api/analyze and read the Server-Sent Events stream via fetch (EventSource
 * only supports GET, and we need multipart upload + POST). Calls onEvent per event.
 */
export async function streamAnalyze(
  opts: { mode: "localfirst" | "local" | "agent"; file?: File },
  onEvent: (e: SentinelEvent) => void,
  signal?: AbortSignal,
): Promise<void> {
  const form = new FormData();
  if (opts.file) form.append("file", opts.file);

  const res = await fetch(`${API_BASE}/api/analyze?mode=${opts.mode}`, {
    method: "POST",
    body: form,
    signal,
  });
  if (!res.body) throw new Error("no response stream");

  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });

    let idx;
    while ((idx = buffer.indexOf("\n\n")) !== -1) {
      const chunk = buffer.slice(0, idx);
      buffer = buffer.slice(idx + 2);
      const line = chunk.split("\n").find((l) => l.startsWith("data:"));
      if (!line) continue;
      try {
        onEvent(JSON.parse(line.slice(5).trim()));
      } catch {
        /* ignore malformed frames */
      }
    }
  }
}

export async function fetchSynthetic(): Promise<{ document: string; text: string }> {
  const res = await fetch(`${API_BASE}/api/synthetic`);
  return res.json();
}

/** Local-First multi-turn chat: continue the agent interaction over the redacted data. */
export async function sendChat(
  interactionId: string,
  message: string,
  sessionId?: string,
): Promise<{ reply?: string; interaction_id?: string; verifications?: unknown[]; error?: string }> {
  const res = await fetch(`${API_BASE}/api/chat`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ interaction_id: interactionId, message, session_id: sessionId }),
  });
  return res.json();
}
