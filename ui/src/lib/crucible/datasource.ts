import type { CrucibleEvent } from "./events";
import { replayReport } from "./replay";
import type { ValidationReport } from "./types";

export interface RunHandle {
  stop: () => void;
}

/** Options for a live validation driven from a raw ZAP report (API mode only). */
export interface ZapRunOptions {
  /** The raw ZAP JSON object (already parsed from the uploaded file). */
  zap: unknown;
  /** Target the validator attacks, e.g. "http://juiceshop:3000". */
  target: string;
  /** Where sandboxed attack containers run. */
  backend: "docker" | "local";
  /** Budget-gated adaptive retries (LLM diagnose → new tactic). */
  adaptive: boolean;
  /** Max attempts per finding before giving up (backend default 3). */
  maxAttempts?: number;
  /** Cap findings validated per vuln class (backend default 8). */
  maxPerClass?: number;
  /** Stream pacing multiplier passed to the backend. */
  speed?: number;
}

export interface DataSource {
  readonly kind: "mock" | "api";
  loadSampleReport: () => Promise<ValidationReport>;
  start: (
    report: ValidationReport,
    onEvent: (e: CrucibleEvent) => void,
    speed: number,
  ) => RunHandle;
  /**
   * Kick off a REAL validation from a raw ZAP report and stream the same
   * `CrucibleEvent` sequence. Only supported in API mode; the mock provider
   * reports back through `onError` so callers can surface a clear notice.
   */
  startZap: (
    opts: ZapRunOptions,
    onEvent: (e: CrucibleEvent) => void,
    onError: (message: string) => void,
  ) => RunHandle;
}

export const SAMPLE_URL = "/sample/validation_report.json";

/** Shown when live ZAP validation is attempted without a configured backend. */
export const ZAP_UNSUPPORTED_MESSAGE = "Live ZAP validation needs the backend — set VITE_API_BASE";

export async function fetchReport(url: string): Promise<ValidationReport> {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`Failed to load report (${res.status})`);
  return (await res.json()) as ValidationReport;
}

export const mockProvider: DataSource = {
  kind: "mock",
  loadSampleReport: () => fetchReport(SAMPLE_URL),
  start(report, onEvent, speed) {
    const signal = { cancelled: false };
    void replayReport(report, { onEvent, speed, signal });
    return {
      stop: () => {
        signal.cancelled = true;
      },
    };
  },
  startZap(_opts, _onEvent, onError) {
    // No backend to run a real validation against — surface a clear notice.
    onError(ZAP_UNSUPPORTED_MESSAGE);
    return { stop: () => {} };
  },
};

/**
 * Opens the SSE stream for an already-created run and forwards frames as
 * `CrucibleEvent`s. Shared by both the report-replay and live-ZAP paths.
 * Calls `onConnectError` only if the stream errors before any frame arrives
 * (i.e. it never connected) — a normal end-of-stream close is ignored.
 */
function subscribeStream(
  base: string,
  runId: string,
  onEvent: (e: CrucibleEvent) => void,
  signal: { cancelled: boolean },
  onConnectError?: (message: string) => void,
): EventSource {
  const source = new EventSource(`${base}/runs/${runId}/stream`);
  let gotFrame = false;
  source.onmessage = (msg) => {
    gotFrame = true;
    try {
      onEvent(JSON.parse(msg.data) as CrucibleEvent);
    } catch {
      /* ignore malformed frame */
    }
  };
  source.onerror = () => {
    source.close();
    if (!gotFrame && !signal.cancelled) {
      onConnectError?.("Lost the Crucible event stream before it started.");
    }
  };
  return source;
}

function createApiProvider(base: string): DataSource {
  return {
    kind: "api",
    loadSampleReport: () => fetchReport(SAMPLE_URL),
    start(report, onEvent, speed) {
      const signal = { cancelled: false };
      let source: EventSource | null = null;

      void (async () => {
        try {
          const res = await fetch(`${base}/runs`, {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({ report, speed }),
          });
          if (!res.ok) throw new Error(`POST /runs failed (${res.status})`);
          const { run_id: runId } = (await res.json()) as { run_id: string };
          if (signal.cancelled) return;
          source = subscribeStream(base, runId, onEvent, signal);
        } catch {
          // Live backend unavailable: degrade to the deterministic replay so
          // the console is never a dead screen.
          if (!signal.cancelled) void replayReport(report, { onEvent, speed, signal });
        }
      })();

      return {
        stop: () => {
          signal.cancelled = true;
          source?.close();
        },
      };
    },
    startZap(opts, onEvent, onError) {
      const signal = { cancelled: false };
      let source: EventSource | null = null;

      void (async () => {
        try {
          const res = await fetch(`${base}/runs`, {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({
              zap: opts.zap,
              target: opts.target,
              backend: opts.backend,
              adaptive: opts.adaptive,
              max_attempts: opts.maxAttempts ?? 3,
              max_per_class: opts.maxPerClass ?? 8,
              speed: opts.speed ?? 1,
            }),
          });
          if (!res.ok) throw new Error(`POST /runs failed (${res.status})`);
          const { run_id: runId } = (await res.json()) as { run_id: string };
          if (signal.cancelled) return;
          source = subscribeStream(base, runId, onEvent, signal, onError);
        } catch {
          // Unlike report replay there is nothing to fall back to, so tell the
          // caller the live run could not be started.
          if (!signal.cancelled) {
            onError(`Could not reach the Crucible backend at ${base}. Is crucible-api running?`);
          }
        }
      })();

      return {
        stop: () => {
          signal.cancelled = true;
          source?.close();
        },
      };
    },
  };
}

export function getDataSource(): DataSource {
  const base = import.meta.env["VITE_API_BASE"];
  return typeof base === "string" && base.length > 0 ? createApiProvider(base) : mockProvider;
}
