import { useEffect, useMemo, useState } from "react";
import { createFileRoute } from "@tanstack/react-router";
import { Moon, Square, Sun } from "lucide-react";
import { Scorecard } from "@/components/crucible/Scorecard";
import { FindingsList } from "@/components/crucible/FindingsList";
import { LineageCanvas } from "@/components/crucible/LineageCanvas";
import { EventLog } from "@/components/crucible/EventLog";
import { FindingDetail } from "@/components/crucible/FindingDetail";
import { StartScreen } from "@/components/crucible/StartScreen";
import { useRun } from "@/lib/crucible/useRun";

const TITLE = "Crucible — Live Validation Lineage";
const DESC =
  "Watch an AI pentest-validation agent re-exploit every scanner finding in real time and stamp an honest verdict on a living lineage graph.";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: TITLE },
      { name: "description", content: DESC },
      { property: "og:title", content: TITLE },
      { property: "og:description", content: DESC },
      { property: "og:type", content: "website" },
      { property: "og:image", content: "/crucible-mark.png" },
      { name: "twitter:card", content: "summary_large_image" },
      { name: "twitter:image", content: "/crucible-mark.png" },
    ],
  }),
  component: CruciblePage,
});

function CruciblePage() {
  const { state, start, startZap, stop, sourceKind, source } = useRun();
  const [selected, setSelected] = useState<string | null>(null);
  const [detailOpen, setDetailOpen] = useState(false);
  const [clay, setClay] = useState(false);

  useEffect(() => {
    document.documentElement.classList.toggle("clay", clay);
  }, [clay]);

  const findings = useMemo(
    () => state.order.map((id) => state.findings[id]!).filter(Boolean),
    [state.order, state.findings],
  );

  // Follow the newest running finding until the user picks one.
  const [pinned, setPinned] = useState(false);
  useEffect(() => {
    if (pinned) return;
    const live = [...findings].reverse().find((f) => f.state !== "settled") ?? findings.at(-1);
    if (live) setSelected((cur) => (cur === live.id ? cur : live.id));
  }, [findings, pinned]);

  const active = selected ? (state.findings[selected] ?? null) : null;

  if (state.status === "idle") {
    return (
      <StartScreen
        onStart={(report, speed) => start(report, speed)}
        onStartZap={(opts) => startZap(opts)}
        sourceKind={sourceKind}
        loadSample={() => source.loadSampleReport()}
      />
    );
  }

  const pick = (id: string) => {
    setPinned(true);
    setSelected(id);
  };

  return (
    <main className="flex h-screen flex-col gap-3 overflow-hidden p-3">
      <header className="flex items-center gap-3">
        <h1 className="text-sm font-semibold tracking-tight">
          Crucible <span className="text-faint">· live validation lineage</span>
        </h1>
        <span className="clay-inset px-2 py-0.5 font-mono text-[10px] text-faint uppercase">
          {sourceKind}
        </span>
        <div className="ml-auto flex items-center gap-2">
          {state.status === "running" && (
            <button
              onClick={stop}
              className="clay-inset inline-flex items-center gap-1.5 px-3 py-1.5 text-xs hover:text-foreground"
            >
              <Square className="size-3" /> Stop
            </button>
          )}
          <button
            onClick={() => setClay((c) => !c)}
            className="clay-inset flex size-8 items-center justify-center text-muted-foreground hover:text-foreground"
            aria-label="Toggle theme"
          >
            {clay ? <Moon className="size-3.5" /> : <Sun className="size-3.5" />}
          </button>
        </div>
      </header>

      <Scorecard
        summary={state.summary}
        total={state.total}
        settled={state.settledCount}
        target={state.target}
        status={state.status}
      />

      <div className="grid min-h-0 flex-1 grid-cols-1 gap-3 lg:grid-cols-[320px_minmax(0,1fr)_340px]">
        <section className="min-h-0 lg:col-span-1">
          <FindingsList
            findings={findings}
            selectedId={selected}
            onSelect={(id) => {
              pick(id);
              setDetailOpen(true);
            }}
          />
        </section>
        <section className="min-h-0">
          <LineageCanvas finding={active} />
        </section>
        <section className="hidden min-h-0 lg:block">
          <EventLog logs={state.logs} onSelect={pick} />
        </section>
      </div>

      <EventLog logs={state.logs} variant="ticker" />

      <FindingDetail finding={detailOpen ? active : null} onClose={() => setDetailOpen(false)} />
    </main>
  );
}
