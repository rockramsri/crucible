import { useMemo, useState } from "react";
import { motion } from "framer-motion";
import { Search } from "lucide-react";
import { cn } from "@/lib/utils";
import { VERDICT_COLOR, VERDICT_LABEL, VERDICT_ORDER, VULN_ICON, VULN_LABEL } from "@/lib/crucible/tokens";
import type { LiveFinding } from "@/lib/crucible/useRun";
import { VerdictPill } from "./VerdictPill";

interface Props {
  findings: LiveFinding[];
  selectedId: string | null;
  onSelect: (id: string) => void;
}

export function FindingsList({ findings, selectedId, onSelect }: Props) {
  const [query, setQuery] = useState("");
  const [verdictFilter, setVerdictFilter] = useState<string>("all");
  const [classFilter, setClassFilter] = useState<string>("all");

  const classes = useMemo(
    () => Array.from(new Set(findings.map((f) => f.vulnClass))),
    [findings],
  );

  const visible = findings.filter((f) => {
    if (verdictFilter !== "all" && f.verdict !== verdictFilter) return false;
    if (classFilter !== "all" && f.vulnClass !== classFilter) return false;
    if (query && !`${f.name} ${f.id} ${f.vulnClass}`.toLowerCase().includes(query.toLowerCase()))
      return false;
    return true;
  });

  return (
    <div className="flex h-full min-h-0 flex-col gap-3">
      <div className="clay-inset flex items-center gap-2 px-3 py-2">
        <Search className="size-4 text-faint" />
        <input
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Search findings"
          className="w-full bg-transparent text-sm outline-none placeholder:text-faint"
        />
      </div>

      <div className="flex flex-wrap gap-1.5">
        <Chip active={verdictFilter === "all"} onClick={() => setVerdictFilter("all")} label="All" />
        {VERDICT_ORDER.map((v) => (
          <Chip
            key={v}
            active={verdictFilter === v}
            onClick={() => setVerdictFilter(verdictFilter === v ? "all" : v)}
            label={VERDICT_LABEL[v]}
            color={VERDICT_COLOR[v]}
          />
        ))}
      </div>

      <div className="flex flex-wrap gap-1.5">
        <Chip active={classFilter === "all"} onClick={() => setClassFilter("all")} label="Any class" />
        {classes.map((c) => (
          <Chip
            key={c}
            active={classFilter === c}
            onClick={() => setClassFilter(classFilter === c ? "all" : c)}
            label={VULN_LABEL[c]}
          />
        ))}
      </div>

      <div className="min-h-0 flex-1 space-y-2 overflow-y-auto pr-1">
        {visible.map((f) => (
          <FindingCard
            key={f.id}
            finding={f}
            selected={f.id === selectedId}
            onSelect={() => onSelect(f.id)}
          />
        ))}
        {visible.length === 0 && (
          <p className="px-1 py-6 text-center text-xs text-faint">No findings match these filters.</p>
        )}
      </div>
    </div>
  );
}

function Chip({
  label,
  active,
  onClick,
  color,
}: {
  label: string;
  active: boolean;
  onClick: () => void;
  color?: string;
}) {
  return (
    <button
      onClick={onClick}
      className={cn(
        "rounded-full border px-2.5 py-1 text-[11px] transition-colors",
        active ? "border-transparent" : "border-border text-muted-foreground hover:text-foreground",
      )}
      style={
        active
          ? {
              color: color ?? "var(--foreground)",
              backgroundColor: `color-mix(in oklab, ${color ?? "var(--foreground)"} 14%, transparent)`,
            }
          : undefined
      }
    >
      {label}
    </button>
  );
}

function Sparkline({ finding }: { finding: LiveFinding }) {
  const steps = finding.steps.slice(-28);
  return (
    <div className="flex h-5 items-end gap-[2px]">
      {steps.map((s, i) => {
        const color =
          s.status === undefined
            ? VERDICT_COLOR.running
            : s.status >= 500
              ? VERDICT_COLOR.inconclusive
              : s.status >= 300 && s.status < 400
                ? VERDICT_COLOR.adaptive
                : VERDICT_COLOR.confirmed;
        const h = s.bodyLen ? Math.min(18, 4 + Math.log10(s.bodyLen + 1) * 4.5) : 4;
        return (
          <motion.span
            key={`${s.stepId}-${i}`}
            initial={{ height: 2, opacity: 0 }}
            animate={{ height: h, opacity: 0.9 }}
            className="w-[3px] rounded-sm"
            style={{ backgroundColor: color }}
          />
        );
      })}
      {steps.length === 0 && <span className="text-[10px] text-faint">no trace</span>}
    </div>
  );
}

function FindingCard({
  finding,
  selected,
  onSelect,
}: {
  finding: LiveFinding;
  selected: boolean;
  onSelect: () => void;
}) {
  const Icon = VULN_ICON[finding.vulnClass];
  const ring = finding.verdict ? VERDICT_COLOR[finding.verdict] : VERDICT_COLOR.running;

  return (
    <motion.button
      layout
      onClick={onSelect}
      initial={{ opacity: 0, y: 6 }}
      animate={{ opacity: 1, y: 0 }}
      className={cn(
        "clay-panel w-full px-3 py-3 text-left transition-shadow focus:ring-2 focus:ring-ring focus:outline-none",
        selected && "ring-2",
      )}
      style={{ boxShadow: selected ? `var(--clay-shadow), 0 0 0 1px ${ring}` : "var(--clay-shadow)" }}
    >
      <div className="flex items-start gap-2.5">
        <span
          className="mt-0.5 flex size-7 shrink-0 items-center justify-center rounded-lg"
          style={{ backgroundColor: `color-mix(in oklab, ${ring} 14%, transparent)`, color: ring }}
        >
          <Icon className="size-3.5" />
        </span>
        <div className="min-w-0 flex-1">
          <div className="flex items-center justify-between gap-2">
            <span className="truncate text-sm font-medium">{finding.name}</span>
            <VerdictPill verdict={finding.verdict} running={finding.state !== "settled"} />
          </div>
          <div className="mt-0.5 truncate font-mono text-[11px] text-faint">
            {finding.id} · {finding.steps[0]?.path ?? "—"}
          </div>
          <div className="mt-2 flex items-center justify-between gap-3">
            <Sparkline finding={finding} />
            <span className="shrink-0 font-mono text-[10px] text-faint">
              {finding.attempts} att · {finding.elapsed_s.toFixed(1)}s
            </span>
          </div>
        </div>
      </div>
    </motion.button>
  );
}
