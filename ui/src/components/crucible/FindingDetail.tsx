import { motion, AnimatePresence } from "framer-motion";
import { Copy, X } from "lucide-react";
import { toast } from "sonner";
import { VERDICT_COLOR, VULN_ICON, VULN_LABEL } from "@/lib/crucible/tokens";
import type { LiveFinding } from "@/lib/crucible/useRun";
import { VerdictPill } from "./VerdictPill";

export function FindingDetail({
  finding,
  onClose,
}: {
  finding: LiveFinding | null;
  onClose: () => void;
}) {
  return (
    <AnimatePresence>
      {finding && (
        <>
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onClick={onClose}
            className="fixed inset-0 z-40 bg-black/50 backdrop-blur-[2px]"
          />
          <motion.aside
            initial={{ x: "100%" }}
            animate={{ x: 0 }}
            exit={{ x: "100%" }}
            transition={{ type: "spring", stiffness: 260, damping: 30 }}
            className="fixed top-0 right-0 z-50 flex h-full w-full max-w-xl flex-col border-l border-border bg-panel"
          >
            <Header finding={finding} onClose={onClose} />
            <div className="min-h-0 flex-1 space-y-5 overflow-y-auto px-5 py-4">
              <Section title="Verdict">
                <div className="clay-inset space-y-2 p-3">
                  <VerdictPill verdict={finding.verdict} running={finding.state !== "settled"} size="md" />
                  <p className="text-sm text-muted-foreground">{finding.reason ?? "Validation in progress."}</p>
                  <p className="font-mono text-[11px] text-faint">
                    {finding.attempts} attempts · {finding.elapsed_s.toFixed(1)}s ·{" "}
                    {finding.adaptive ? "adaptive replay" : "deterministic replay"}
                  </p>
                </div>
              </Section>

              <Section title={`Attempt trace (${finding.steps.length})`}>
                <div className="clay-inset divide-y divide-border">
                  {finding.steps.map((s, i) => (
                    <div key={`${s.stepId}-${i}`} className="grid grid-cols-[auto_1fr_auto] gap-3 px-3 py-2">
                      <span className="font-mono text-[11px] text-faint">#{i + 1}</span>
                      <div className="min-w-0">
                        <div className="truncate font-mono text-[11px]">
                          {s.method} {s.path}
                        </div>
                        <div className="truncate font-mono text-[11px] text-faint">{s.payload}</div>
                      </div>
                      <span
                        className="font-mono text-[11px]"
                        style={{
                          color:
                            s.status === undefined
                              ? VERDICT_COLOR.running
                              : s.status >= 500
                                ? VERDICT_COLOR.inconclusive
                                : VERDICT_COLOR.confirmed,
                        }}
                      >
                        {s.status ?? "…"}
                        {s.bodyLen !== undefined && (
                          <span className="ml-1 text-faint">{s.bodyLen}b</span>
                        )}
                      </span>
                    </div>
                  ))}
                  {finding.steps.length === 0 && (
                    <p className="px-3 py-4 text-center font-mono text-[11px] text-faint">
                      no requests issued
                    </p>
                  )}
                </div>
              </Section>

              <Section title="Reproduction">
                <Repro finding={finding} />
              </Section>
            </div>
          </motion.aside>
        </>
      )}
    </AnimatePresence>
  );
}

function Header({ finding, onClose }: { finding: LiveFinding; onClose: () => void }) {
  const Icon = VULN_ICON[finding.vulnClass];
  const color = finding.verdict ? VERDICT_COLOR[finding.verdict] : VERDICT_COLOR.running;
  return (
    <div className="flex items-start gap-3 border-b border-border px-5 py-4">
      <span
        className="flex size-9 items-center justify-center rounded-xl"
        style={{ backgroundColor: `color-mix(in oklab, ${color} 14%, transparent)`, color }}
      >
        <Icon className="size-4" />
      </span>
      <div className="min-w-0 flex-1">
        <h2 className="truncate text-base font-semibold">{finding.name}</h2>
        <p className="font-mono text-[11px] text-faint">
          {finding.id} · {VULN_LABEL[finding.vulnClass]}
        </p>
      </div>
      <button onClick={onClose} className="text-muted-foreground hover:text-foreground" aria-label="Close">
        <X className="size-4" />
      </button>
    </div>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section>
      <h3 className="mb-2 text-[11px] tracking-[0.14em] text-faint uppercase">{title}</h3>
      {children}
    </section>
  );
}

function Repro({ finding }: { finding: LiveFinding }) {
  const last = finding.steps[finding.steps.length - 1];
  const curl = last
    ? `curl -i -X ${last.method} 'http://localhost:3000${last.path}' \\\n  --data-urlencode "payload=${last.payload}"`
    : "# no successful request recorded";
  return (
    <div className="clay-inset relative p-3">
      <pre className="overflow-x-auto font-mono text-[11px] whitespace-pre-wrap text-muted-foreground">
        {curl}
      </pre>
      <button
        onClick={() => {
          void navigator.clipboard.writeText(curl);
          toast.success("Reproduction copied");
        }}
        className="absolute top-2 right-2 text-muted-foreground hover:text-foreground"
        aria-label="Copy reproduction"
      >
        <Copy className="size-3.5" />
      </button>
    </div>
  );
}
