import type { CrucibleEvent } from "./events";
import type { RunTrace, ValidationReport, VerdictRecord } from "./types";

export interface ReplayOptions {
  speed?: number;
  onEvent: (event: CrucibleEvent) => void;
  signal?: { cancelled: boolean };
}

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

function pathFor(record: VerdictRecord): string {
  const proof = record.proof?.[0];
  if (proof?.request?.path) return proof.request.path;
  switch (record.vuln_class) {
    case "sqli":
      return "/rest/products/search";
    case "xss":
      return "/#/search";
    case "open_redirect":
      return "/redirect";
    case "acl_bypass":
      return "/ftp/quarantine";
    case "cors":
      return "/rest/user/whoami";
    case "file_disclosure":
      return "/ftp";
    default:
      return "/";
  }
}

/**
 * Replays a static validation report as the same event sequence the live
 * SSE API emits, so mock and API providers drive identical UI code.
 */
export async function replayReport(report: ValidationReport, opts: ReplayOptions) {
  const speed = opts.speed ?? 1;
  const wait = async (ms: number) => {
    await sleep(Math.max(4, ms / speed));
  };
  const cancelled = () => opts.signal?.cancelled === true;

  opts.onEvent({
    type: "run.start",
    run_id: `replay-${Date.now()}`,
    target: report.target,
    source: "zap",
    total: report.verdicts.length,
  });

  for (const record of report.verdicts) {
    if (cancelled()) return;
    opts.onEvent({
      type: "finding.start",
      finding_id: record.finding_id,
      vuln_class: record.vuln_class,
      name: record.name,
      severity: record.severity,
    });
    await wait(420);

    const path = pathFor(record);

    for (const entry of record.trace) {
      if (cancelled()) return;
      if (entry.kind === "diagnose") {
        await wait(700);
        opts.onEvent({
          type: "diagnose",
          finding_id: record.finding_id,
          attempt: entry.n,
          reasoning: entry.reasoning,
          hypotheses: entry.hypotheses,
          giveup: entry.giveup,
        });
        await wait(800);
        continue;
      }

      const run = entry as RunTrace;
      // Long adaptive sweeps are compressed so the canvas stays readable.
      const stepDelay = run.steps.length > 12 ? 60 : 320;
      for (const step of run.steps) {
        if (cancelled()) return;
        opts.onEvent({
          type: "step.sent",
          finding_id: record.finding_id,
          attempt: run.n,
          step_id: step.id,
          method: "GET",
          path,
          payload: step.payload,
          mode: run.mode,
        });
        await wait(stepDelay);
        const obs = run.observed[step.id] ?? { status: 0, len: 0 };
        opts.onEvent({
          type: "step.result",
          finding_id: record.finding_id,
          attempt: run.n,
          step_id: step.id,
          status: obs.status,
          body_len: obs.len,
          elapsed_ms: 40 + (step.id.length % 7) * 11,
        });
        await wait(stepDelay * 0.75);
      }

      if (run.verdict === "unresolved") {
        opts.onEvent({
          type: "oracle.interim",
          finding_id: record.finding_id,
          attempt: run.n,
          oracle: run.oracle,
          verdict: "unresolved",
        });
        await wait(700);
      }
    }

    if (cancelled()) return;
    await wait(420);
    opts.onEvent({
      type: "verdict",
      finding_id: record.finding_id,
      verdict: record.verdict,
      reason: record.reason,
      attempts: record.attempts,
      elapsed_s: record.elapsed_s,
      proof: record.proof ?? [],
    });
    await wait(520);
  }

  opts.onEvent({ type: "run.done", summary: report.summary });
}
