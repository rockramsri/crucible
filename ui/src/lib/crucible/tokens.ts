import {
  Database,
  Code2,
  ExternalLink,
  FileText,
  ShieldOff,
  Globe,
  HelpCircle,
  type LucideIcon,
} from "lucide-react";
import type { Verdict, VulnClass } from "./types";

export const VERDICT_COLOR: Record<Verdict | "unresolved" | "adaptive" | "running", string> = {
  confirmed: "var(--verdict-confirmed)",
  false_positive: "var(--verdict-fp)",
  inconclusive: "var(--verdict-inconclusive)",
  agent_failure: "var(--verdict-failure)",
  skipped: "var(--verdict-skipped)",
  unresolved: "var(--verdict-inconclusive)",
  adaptive: "var(--accent-llm)",
  running: "var(--accent-progress)",
};

export const VERDICT_LABEL: Record<Verdict | "unresolved", string> = {
  confirmed: "Confirmed",
  false_positive: "False positive",
  inconclusive: "Inconclusive",
  agent_failure: "Agent failure",
  skipped: "Skipped",
  unresolved: "Unresolved",
};

export const VULN_ICON: Record<VulnClass, LucideIcon> = {
  sqli: Database,
  xss: Code2,
  open_redirect: ExternalLink,
  file_disclosure: FileText,
  acl_bypass: ShieldOff,
  cors: Globe,
  unknown: HelpCircle,
};

export const VULN_LABEL: Record<VulnClass, string> = {
  sqli: "SQL injection",
  xss: "Cross-site scripting",
  open_redirect: "Open redirect",
  file_disclosure: "File disclosure",
  acl_bypass: "ACL bypass",
  cors: "CORS",
  unknown: "Unclassified",
};

export const VERDICT_ORDER: Verdict[] = [
  "confirmed",
  "false_positive",
  "inconclusive",
  "agent_failure",
  "skipped",
];
