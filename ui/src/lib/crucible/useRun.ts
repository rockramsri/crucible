import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { toast } from "sonner";
import type { CrucibleEvent } from "./events";
import { getDataSource, type RunHandle, type ZapRunOptions } from "./datasource";
import {
  computeSummary,
  type Summary,
  type ValidationReport,
  type Verdict,
  type VerdictRecord,
  EMPTY_SUMMARY,
} from "./types";

export type NodeId = "planner" | "sandbox" | "target" | "oracle" | "gate" | "llm";

export interface LiveStep {
  stepId: string;
  attempt: number;
  payload: string;
  path: string;
  method: string;
  status?: number;
  bodyLen?: number;
  mode: "deterministic" | "adaptive";
}

export interface LiveAttempt {
  n: number;
  mode: "deterministic" | "adaptive";
  steps: LiveStep[];
  oracle?: string;
  verdict?: Verdict | "unresolved";
  diagnose?: { reasoning: string; cause: string; confidence: number; giveup: boolean };
}

export interface LiveFinding {
  id: string;
  name: string;
  vulnClass: VerdictRecord["vuln_class"];
  state: "queued" | "running" | "diagnosing" | "settled";
  verdict?: Verdict;
  reason?: string;
  attempts: number;
  elapsed_s: number;
  steps: LiveStep[];
  attemptList: LiveAttempt[];
  activeNode?: NodeId;
  activeAttempt: number;
  adaptive: boolean;
  unresolved: boolean;
}

export interface LogLine {
  id: number;
  ts: number;
  findingId?: string;
  tone: "info" | "progress" | "confirmed" | "fp" | "llm" | "warn";
  text: string;
}

export interface RunState {
  status: "idle" | "running" | "done";
  target: string;
  total: number;
  findings: Record<string, LiveFinding>;
  order: string[];
  logs: LogLine[];
  summary: Summary;
  settledCount: number;
}

const INITIAL: RunState = {
  status: "idle",
  target: "",
  total: 0,
  findings: {},
  order: [],
  logs: [],
  summary: EMPTY_SUMMARY,
  settledCount: 0,
};

let logSeq = 0;

function toneFor(verdict: Verdict): LogLine["tone"] {
  if (verdict === "confirmed") return "confirmed";
  if (verdict === "false_positive") return "fp";
  if (verdict === "skipped") return "info";
  return "warn";
}

function upsertAttempt(
  list: LiveAttempt[],
  n: number,
  patch: (a: LiveAttempt) => LiveAttempt,
): LiveAttempt[] {
  const idx = list.findIndex((a) => a.n === n);
  if (idx === -1) {
    return [...list, patch({ n, mode: "deterministic", steps: [] })].sort((a, b) => a.n - b.n);
  }
  return list.map((a) => (a.n === n ? patch(a) : a));
}

function reduce(state: RunState, e: CrucibleEvent): RunState {
  const pushLog = (line: Omit<LogLine, "id" | "ts">, s: RunState): RunState => ({
    ...s,
    logs: [...s.logs.slice(-400), { ...line, id: ++logSeq, ts: Date.now() }],
  });

  switch (e.type) {
    case "run.start":
      return pushLog(
        { tone: "info", text: `run started · ${e.total} findings · target ${e.target}` },
        { ...INITIAL, status: "running", target: e.target, total: e.total, settledCount: 0 },
      );

    case "finding.start": {
      const finding: LiveFinding = {
        id: e.finding_id,
        name: e.name,
        vulnClass: e.vuln_class,
        state: "running",
        attempts: 0,
        elapsed_s: 0,
        steps: [],
        attemptList: [],
        activeNode: "planner",
        activeAttempt: 1,
        adaptive: false,
        unresolved: false,
      };
      return pushLog(
        { tone: "info", findingId: e.finding_id, text: `${e.vuln_class} · ${e.name} · queued` },
        {
          ...state,
          findings: { ...state.findings, [e.finding_id]: finding },
          order: state.order.includes(e.finding_id) ? state.order : [...state.order, e.finding_id],
        },
      );
    }

    case "step.sent": {
      const f = state.findings[e.finding_id];
      if (!f) return state;
      const step: LiveStep = {
        stepId: e.step_id,
        attempt: e.attempt,
        payload: e.payload,
        path: e.path,
        method: e.method,
        mode: e.mode ?? "deterministic",
      };
      const attemptList = upsertAttempt(f.attemptList, e.attempt, (a) => ({
        ...a,
        mode: e.mode ?? a.mode,
        steps: [...a.steps, step],
      }));
      const next: LiveFinding = {
        ...f,
        state: "running",
        attempts: Math.max(f.attempts, e.attempt),
        activeNode: "target",
        activeAttempt: e.attempt,
        adaptive: f.adaptive || e.mode === "adaptive",
        steps: [...f.steps, step],
        attemptList,
      };
      return pushLog(
        {
          tone: e.mode === "adaptive" ? "llm" : "progress",
          findingId: e.finding_id,
          text: `run#${e.attempt} · ${f.vulnClass} · ${e.step_id} → ${e.method} ${e.path}`,
        },
        { ...state, findings: { ...state.findings, [e.finding_id]: next } },
      );
    }

    case "step.result": {
      const f = state.findings[e.finding_id];
      if (!f) return state;
      const patch = (s: LiveStep) =>
        s.stepId === e.step_id && s.attempt === e.attempt
          ? { ...s, status: e.status, bodyLen: e.body_len }
          : s;
      const steps = f.steps.map(patch);
      const attemptList = upsertAttempt(f.attemptList, e.attempt, (a) => ({
        ...a,
        steps: a.steps.map(patch),
      }));
      return pushLog(
        {
          tone: e.status >= 500 ? "warn" : "progress",
          findingId: e.finding_id,
          text: `run#${e.attempt} · ${f.vulnClass} · ${e.step_id} → ${e.status} · ${e.body_len}b`,
        },
        {
          ...state,
          findings: {
            ...state.findings,
            [e.finding_id]: {
              ...f,
              steps,
              attemptList,
              activeAttempt: e.attempt,
              activeNode: "oracle",
            },
          },
        },
      );
    }

    case "oracle.interim": {
      const f = state.findings[e.finding_id];
      if (!f) return state;
      const attemptList = upsertAttempt(f.attemptList, e.attempt, (a) => ({
        ...a,
        oracle: e.oracle,
        verdict: "unresolved" as const,
      }));
      return pushLog(
        {
          tone: "warn",
          findingId: e.finding_id,
          text: `${f.vulnClass} · run#${e.attempt} → UNRESOLVED · ${e.oracle}`,
        },
        {
          ...state,
          findings: {
            ...state.findings,
            [e.finding_id]: {
              ...f,
              unresolved: true,
              attemptList,
              activeAttempt: e.attempt,
              activeNode: "gate",
            },
          },
        },
      );
    }

    case "diagnose": {
      const f = state.findings[e.finding_id];
      if (!f) return state;
      const top = e.hypotheses[0];
      const skipAdaptive =
        Boolean(e.giveup) &&
        /adaptive did not run|LLM unavailable/.test(`${e.reasoning} ${top?.cause ?? ""}`);
      const attemptList = upsertAttempt(f.attemptList, e.attempt, (a) => ({
        ...a,
        diagnose: {
          reasoning: e.reasoning,
          cause: top?.cause ?? (skipAdaptive ? "adaptive did not run" : "new tactic"),
          confidence: top?.confidence ?? 0,
          giveup: e.giveup ?? false,
        },
      }));
      return pushLog(
        {
          tone: skipAdaptive ? "warn" : "llm",
          findingId: e.finding_id,
          text: skipAdaptive
            ? `${f.vulnClass} · ${top?.cause ?? e.reasoning}`
            : `${f.vulnClass} · budget gate open → LLM proposes: ${top?.cause ?? "new tactic"}`,
        },
        {
          ...state,
          findings: {
            ...state.findings,
            [e.finding_id]: {
              ...f,
              state: "diagnosing",
              attemptList,
              activeAttempt: e.attempt,
              activeNode: "llm",
              adaptive: f.adaptive || !skipAdaptive,
            },
          },
        },
      );
    }

    case "verdict": {
      const f = state.findings[e.finding_id];
      if (!f) return state;
      const lastN = f.attemptList.at(-1)?.n ?? 1;
      const attemptList = upsertAttempt(f.attemptList, lastN, (a) => {
        // An unresolved attempt already grew a budget-gate / LLM branch.
        // Overwriting it with the finding-level settle (inconclusive /
        // confirmed) made the canvas drop those nodes — "LLM graph appeared
        // then was destroyed". Keep the attempt's unresolved stamp; the
        // finding-level verdict still settles the scorecard.
        if (a.verdict === "unresolved") return a;
        return { ...a, verdict: e.verdict };
      });
      const last = attemptList.find((a) => a.n === lastN);
      const next: LiveFinding = {
        ...f,
        state: "settled",
        verdict: e.verdict,
        reason: e.reason,
        attempts: e.attempts,
        elapsed_s: e.elapsed_s,
        attemptList,
        activeAttempt: lastN,
        // Park on the LLM card when we diagnosed (or skipped adaptive)
        // without a retry lane; otherwise the oracle that stamped.
        activeNode: last?.verdict === "unresolved" || last?.diagnose ? "llm" : "oracle",
        unresolved: f.unresolved || last?.verdict === "unresolved",
        adaptive: f.adaptive,
      };
      const findings = { ...state.findings, [e.finding_id]: next };
      const settled = Object.values(findings).filter((x) => x.verdict) as LiveFinding[];
      const summary = computeSummary(
        settled.map((x) => ({ verdict: x.verdict! }) as VerdictRecord),
        state.total,
      );
      return pushLog(
        {
          tone: toneFor(e.verdict),
          findingId: e.finding_id,
          text: `${f.vulnClass} · oracle stamps ${e.verdict.toUpperCase()} · ${e.reason}`,
        },
        { ...state, findings, summary, settledCount: settled.length },
      );
    }

    case "run.done":
      return pushLog(
        {
          tone: "info",
          text: `run complete · measured FP-rate ${(e.summary.false_positive_rate * 100).toFixed(1)}%`,
        },
        { ...state, status: "done", summary: e.summary },
      );

    case "run.error":
      return pushLog(
        { tone: "warn", text: `run error · ${e.message}` },
        { ...state, status: "done" },
      );

    default:
      return state;
  }
}

export function useRun() {
  const [state, setState] = useState<RunState>(INITIAL);
  const [speed, setSpeed] = useState(1);
  const handleRef = useRef<RunHandle | null>(null);
  const source = useMemo(() => getDataSource(), []);

  // Single event sink for both report replay and live ZAP runs. Surfaces
  // backend-reported failures as a toast before folding them into the reducer.
  const dispatch = useCallback((event: CrucibleEvent) => {
    if (event.type === "run.error") toast.error(event.message);
    setState((s) => reduce(s, event));
  }, []);

  const start = useCallback(
    (report: ValidationReport, runSpeed = speed) => {
      handleRef.current?.stop();
      setState({
        ...INITIAL,
        status: "running",
        target: report.target,
        total: report.verdicts.length,
      });
      handleRef.current = source.start(report, dispatch, runSpeed);
    },
    [source, dispatch, speed],
  );

  // Live validation from a raw ZAP report (API mode). Drives the exact same
  // reducer/state as `start`, so the whole console lights up identically.
  const startZap = useCallback(
    (opts: ZapRunOptions) => {
      handleRef.current?.stop();
      setState({ ...INITIAL, status: "running", target: opts.target, total: 0 });
      handleRef.current = source.startZap(
        { ...opts, speed: opts.speed ?? speed },
        dispatch,
        (message) => {
          toast.error(message);
          handleRef.current = null;
          // If nothing streamed yet, drop back to the Start screen; if a run
          // was already in flight, settle it rather than wiping progress.
          setState((s) => (s.order.length === 0 ? INITIAL : { ...s, status: "done" }));
        },
      );
    },
    [source, dispatch, speed],
  );

  const stop = useCallback(() => {
    handleRef.current?.stop();
    handleRef.current = null;
    setState((s) => ({ ...s, status: "done" }));
  }, []);

  useEffect(() => () => handleRef.current?.stop(), []);

  return { state, start, startZap, stop, speed, setSpeed, sourceKind: source.kind, source };
}
