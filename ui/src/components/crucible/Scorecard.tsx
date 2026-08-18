import { motion } from "framer-motion";
import { Activity, Gauge } from "lucide-react";
import { VERDICT_COLOR, VERDICT_LABEL, VERDICT_ORDER } from "@/lib/crucible/tokens";
import type { Summary } from "@/lib/crucible/types";

interface Props {
  summary: Summary;
  total: number;
  settled: number;
  target: string;
  status: "idle" | "running" | "done";
}

export function Scorecard({ summary, total, settled, target, status }: Props) {
  const pct = summary.false_positive_rate * 100;
  const progress = total > 0 ? (settled / total) * 100 : 0;

  return (
    <div className="clay-panel flex flex-wrap items-center gap-6 px-5 py-4">
      <div className="flex items-center gap-4">
        <div className="clay-inset flex size-14 items-center justify-center rounded-2xl">
          <Gauge className="size-6" style={{ color: VERDICT_COLOR.false_positive }} />
        </div>
        <div>
          <div className="text-[11px] tracking-[0.14em] text-faint uppercase">Measured FP-rate</div>
          <motion.div
            key={pct.toFixed(1)}
            initial={{ opacity: 0.4, y: 4 }}
            animate={{ opacity: 1, y: 0 }}
            className="font-mono text-4xl leading-none font-semibold"
            style={{ color: VERDICT_COLOR.false_positive }}
          >
            {pct.toFixed(1)}
            <span className="text-xl">%</span>
          </motion.div>
        </div>
      </div>

      <div className="hidden h-12 w-px bg-border md:block" />

      <div className="flex flex-wrap items-center gap-5">
        <Stat label="Findings" value={total} color="var(--foreground)" />
        {VERDICT_ORDER.map((v) => (
          <Stat key={v} label={VERDICT_LABEL[v]} value={summary[v]} color={VERDICT_COLOR[v]} />
        ))}
      </div>

      <div className="ml-auto min-w-56 flex-1">
        <div className="mb-2 flex items-center justify-between text-[11px] text-faint">
          <span className="inline-flex items-center gap-1.5 font-mono">
            <Activity className="size-3.5" />
            {target || "no target"}
          </span>
          <span className="font-mono">
            {settled}/{total} · {status}
          </span>
        </div>
        <div className="h-1.5 w-full overflow-hidden rounded-full bg-panel2">
          <motion.div
            className="h-full rounded-full"
            style={{ background: `linear-gradient(90deg, ${VERDICT_COLOR.running}, ${VERDICT_COLOR.adaptive})` }}
            animate={{ width: `${progress}%` }}
            transition={{ type: "spring", stiffness: 90, damping: 20 }}
          />
        </div>
      </div>
    </div>
  );
}

function Stat({ label, value, color }: { label: string; value: number; color: string }) {
  return (
    <div className="min-w-16">
      <div className="font-mono text-xl leading-none font-semibold" style={{ color }}>
        {value}
      </div>
      <div className="mt-1 text-[10px] tracking-[0.1em] text-faint uppercase">{label}</div>
    </div>
  );
}
