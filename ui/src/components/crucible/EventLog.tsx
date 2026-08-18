import { useEffect, useRef, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { ArrowDownToLine, Pause, Play, Terminal } from "lucide-react";
import { cn } from "@/lib/utils";
import { VERDICT_COLOR } from "@/lib/crucible/tokens";
import type { LogLine } from "@/lib/crucible/useRun";

const TONE: Record<LogLine["tone"], string> = {
  info: "var(--muted-foreground)",
  progress: VERDICT_COLOR.running,
  confirmed: VERDICT_COLOR.confirmed,
  fp: VERDICT_COLOR.false_positive,
  llm: VERDICT_COLOR.adaptive,
  warn: VERDICT_COLOR.inconclusive,
};

function stamp(ts: number) {
  const d = new Date(ts);
  return `${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}:${String(
    d.getSeconds(),
  ).padStart(2, "0")}`;
}

export function EventLog({
  logs,
  onSelect,
  variant = "panel",
}: {
  logs: LogLine[];
  onSelect?: (id: string) => void;
  variant?: "panel" | "ticker";
}) {
  const [paused, setPaused] = useState(false);
  const boxRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (paused || !boxRef.current) return;
    boxRef.current.scrollTop = boxRef.current.scrollHeight;
  }, [logs, paused]);

  if (variant === "ticker") {
    const recent = logs.slice(-2).reverse();
    return (
      <div className="clay-inset flex h-14 shrink-0 items-center gap-3 overflow-hidden px-3 py-2">
        <Terminal className="size-3.5 shrink-0 text-faint" />
        <div className="flex min-w-0 flex-1 flex-col justify-center gap-0.5">
          {recent.map((l, i) => (
            <motion.span
              key={l.id}
              initial={{ opacity: 0, y: -4 }}
              animate={{ opacity: i === 0 ? 1 : 0.3, y: 0 }}
              className="truncate font-mono text-[11px] leading-tight"
              style={{ color: TONE[l.tone] }}
            >
              <span className="text-faint">{stamp(l.ts)}</span> {l.text}
            </motion.span>
          ))}
          {recent.length === 0 && <span className="font-mono text-[11px] text-faint">awaiting run…</span>}
        </div>
      </div>
    );
  }

  return (
    <div className="clay-panel flex h-full min-h-0 flex-col">
      <div className="flex items-center gap-2 border-b border-border px-3 py-2">
        <Terminal className="size-3.5 text-faint" />
        <span className="text-[11px] tracking-[0.14em] text-faint uppercase">Event stream</span>
        <span className="ml-auto font-mono text-[10px] text-faint">{logs.length}</span>
        <button
          onClick={() => setPaused((p) => !p)}
          className="text-muted-foreground transition-colors hover:text-foreground"
          aria-label={paused ? "Resume autoscroll" : "Pause autoscroll"}
        >
          {paused ? <Play className="size-3.5" /> : <Pause className="size-3.5" />}
        </button>
        <button
          onClick={() => boxRef.current?.scrollTo({ top: boxRef.current.scrollHeight })}
          className="text-muted-foreground transition-colors hover:text-foreground"
          aria-label="Jump to latest"
        >
          <ArrowDownToLine className="size-3.5" />
        </button>
      </div>
      <div ref={boxRef} className="min-h-0 flex-1 space-y-0.5 overflow-y-auto px-3 py-2">
        <AnimatePresence initial={false}>
          {logs.map((l) => (
            <motion.button
              key={l.id}
              initial={{ opacity: 0, x: -8 }}
              animate={{ opacity: 1, x: 0 }}
              onClick={() => l.findingId && onSelect?.(l.findingId)}
              className={cn(
                "block w-full rounded px-1 py-0.5 text-left font-mono text-[11px] leading-snug",
                l.findingId && "hover:bg-panel2",
              )}
            >
              <span className="text-faint">{stamp(l.ts)}</span>{" "}
              <span style={{ color: TONE[l.tone] }}>{l.text}</span>
            </motion.button>
          ))}
        </AnimatePresence>
        {logs.length === 0 && (
          <p className="px-1 py-6 text-center font-mono text-[11px] text-faint">awaiting run…</p>
        )}
      </div>
    </div>
  );
}
