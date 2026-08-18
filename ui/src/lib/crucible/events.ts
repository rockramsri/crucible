import type { Hypothesis, ProofArtifact, Summary, Verdict, VulnClass } from "./types";

export type CrucibleEvent =
  | { type: "run.start"; run_id: string; target: string; source: "zap"; total: number }
  | {
      type: "finding.start";
      finding_id: string;
      vuln_class: VulnClass;
      name: string;
      severity?: string | undefined;
    }
  | {
      type: "step.sent";
      finding_id: string;
      attempt: number;
      step_id: string;
      method: string;
      path: string;
      payload: string;
      mode?: "deterministic" | "adaptive" | undefined;
    }
  | {
      type: "step.result";
      finding_id: string;
      attempt: number;
      step_id: string;
      status: number;
      body_len: number;
      elapsed_ms: number;
    }
  | {
      type: "oracle.interim";
      finding_id: string;
      attempt: number;
      oracle: string;
      verdict: "unresolved";
    }
  | {
      type: "diagnose";
      finding_id: string;
      attempt: number;
      reasoning: string;
      hypotheses: Hypothesis[];
      giveup?: boolean | undefined;
    }
  | {
      type: "verdict";
      finding_id: string;
      verdict: Verdict;
      reason: string;
      attempts: number;
      elapsed_s: number;
      proof: ProofArtifact[];
    }
  | { type: "run.done"; summary: Summary }
  // Emitted by the live backend when a run throws (e.g. Docker/target
  // unreachable). Lets the UI stop cleanly instead of hanging on a dead stream.
  | { type: "run.error"; message: string };

export type EventHandler = (event: CrucibleEvent) => void;
