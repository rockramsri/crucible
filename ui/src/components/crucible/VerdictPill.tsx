import { cn } from "@/lib/utils";
import { VERDICT_COLOR, VERDICT_LABEL } from "@/lib/crucible/tokens";
import type { Verdict } from "@/lib/crucible/types";

interface Props {
  verdict?: Verdict | "unresolved" | undefined;
  running?: boolean;
  className?: string;
  size?: "sm" | "md";
}

export function VerdictPill({ verdict, running, className, size = "sm" }: Props) {
  const color = running && !verdict ? VERDICT_COLOR.running : verdict ? VERDICT_COLOR[verdict] : VERDICT_COLOR.skipped;
  const label = running && !verdict ? "Validating" : verdict ? VERDICT_LABEL[verdict] : "Queued";

  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-full border font-medium tracking-tight whitespace-nowrap",
        size === "sm" ? "px-2 py-0.5 text-[11px]" : "px-3 py-1 text-xs",
        className,
      )}
      style={{
        color,
        borderColor: `color-mix(in oklab, ${color} 40%, transparent)`,
        backgroundColor: `color-mix(in oklab, ${color} 12%, transparent)`,
      }}
    >
      <span
        className={cn("size-1.5 rounded-full", running && !verdict && "animate-pulse")}
        style={{ backgroundColor: color }}
      />
      {label}
    </span>
  );
}
