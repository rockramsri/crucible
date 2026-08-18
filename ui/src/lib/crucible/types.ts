export type VulnClass =
  | "sqli"
  | "xss"
  | "open_redirect"
  | "file_disclosure"
  | "acl_bypass"
  | "cors"
  | "unknown";

export type Verdict =
  | "confirmed"
  | "false_positive"
  | "agent_failure"
  | "inconclusive"
  | "skipped";

export type TraceVerdict = Verdict | "unresolved";

export interface Step {
  id: string;
  payload: string;
}

export interface Observation {
  status: number;
  len: number;
}

export interface RunTrace {
  n: number;
  kind: "run";
  mode: "deterministic" | "adaptive";
  steps: Step[];
  observed: Record<string, Observation>;
  oracle: string;
  verdict: TraceVerdict;
}

export interface Hypothesis {
  cause: string;
  confidence: number;
}

export interface DiagnoseTrace {
  n: number;
  kind: "diagnose";
  reasoning: string;
  hypotheses: Hypothesis[];
  giveup: boolean;
}

export type TraceEntry = RunTrace | DiagnoseTrace;

export interface ProofArtifact {
  step: string;
  request: {
    method: string;
    path: string;
    params?: Record<string, unknown> | null;
    json?: unknown;
    headers?: Record<string, string> | null;
  };
  response: {
    status: number;
    location?: string | null;
    body_snippet?: string | null;
  };
}

export interface VerdictRecord {
  finding_id: string;
  vuln_class: VulnClass;
  name: string;
  verdict: Verdict;
  reason: string;
  attempts: number;
  elapsed_s: number;
  proof: ProofArtifact[];
  trace: TraceEntry[];
  severity?: string | undefined;
}

export interface Summary {
  total: number;
  confirmed: number;
  false_positive: number;
  inconclusive: number;
  agent_failure: number;
  skipped: number;
  false_positive_rate: number;
}

export interface ValidationReport {
  generated: string;
  target: string;
  summary: Summary;
  verdicts: VerdictRecord[];
}

export const EMPTY_SUMMARY: Summary = {
  total: 0,
  confirmed: 0,
  false_positive: 0,
  inconclusive: 0,
  agent_failure: 0,
  skipped: 0,
  false_positive_rate: 0,
};

export function computeSummary(records: VerdictRecord[], total: number): Summary {
  const s: Summary = { ...EMPTY_SUMMARY, total };
  for (const r of records) s[r.verdict] += 1;
  const denom = s.confirmed + s.false_positive;
  s.false_positive_rate = denom > 0 ? s.false_positive / denom : 0;
  return s;
}
