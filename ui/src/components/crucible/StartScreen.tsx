import { useRef, useState } from "react";
import { motion } from "framer-motion";
import {
  ChevronDown,
  FlaskConical,
  History,
  Info,
  Loader2,
  Play,
  Radar,
  Upload,
  Zap,
} from "lucide-react";
import { toast } from "sonner";
import { cn } from "@/lib/utils";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { ZAP_UNSUPPORTED_MESSAGE, type ZapRunOptions } from "@/lib/crucible/datasource";
import type { ValidationReport } from "@/lib/crucible/types";

interface Props {
  onStart: (report: ValidationReport, speed: number) => void;
  onStartZap: (opts: ZapRunOptions) => void;
  sourceKind: string;
  loadSample: () => Promise<ValidationReport>;
}

const SPEEDS = [
  { label: "0.5× presentation", value: 0.5 },
  { label: "1×", value: 1 },
  { label: "2×", value: 2 },
  { label: "Instant", value: 40 },
];

const JUICESHOP_ZAP_URL = "/sample/juiceshop_zap_full.json";
const DEFAULT_TARGET = "http://juiceshop:3000";

/** OWASP ZAP JSON reports always carry a top-level `site` array. */
function isZapReport(value: unknown): value is Record<string, unknown> {
  return (
    typeof value === "object" && value !== null && Array.isArray((value as { site?: unknown }).site)
  );
}

export function StartScreen({ onStart, onStartZap, sourceKind, loadSample }: Props) {
  const [speed, setSpeed] = useState(1);
  const [dragging, setDragging] = useState(false);
  const [busy, setBusy] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  // Live ZAP validation state (API mode only).
  const live = sourceKind === "api";
  const [target, setTarget] = useState(DEFAULT_TARGET);
  const [backend, setBackend] = useState<"docker" | "local">("docker");
  const [adaptive, setAdaptive] = useState(true);
  const [zapDragging, setZapDragging] = useState(false);
  const [zapBusy, setZapBusy] = useState(false);
  const zapInputRef = useRef<HTMLInputElement>(null);

  // In live mode the replay flow is demoted to a collapsed, click-to-open rail.
  const [replayOpen, setReplayOpen] = useState(false);

  const runSample = async () => {
    setBusy(true);
    try {
      onStart(await loadSample(), speed);
    } catch {
      toast.error("Could not load the sample report");
    } finally {
      setBusy(false);
    }
  };

  const readFile = async (file: File) => {
    try {
      const report = JSON.parse(await file.text()) as ValidationReport;
      if (!Array.isArray(report.verdicts)) throw new Error("bad shape");
      onStart(report, speed);
    } catch {
      toast.error("That file is not a validation_report.json");
    }
  };

  const launchZap = (zap: unknown) => {
    onStartZap({
      zap,
      target: target.trim() || DEFAULT_TARGET,
      backend,
      adaptive,
      speed,
    });
  };

  const readZapFile = async (file: File) => {
    setZapBusy(true);
    try {
      const parsed: unknown = JSON.parse(await file.text());
      if (!isZapReport(parsed)) throw new Error("bad shape");
      launchZap(parsed);
    } catch {
      toast.error("That file is not an OWASP ZAP JSON report (missing a 'site' array)");
    } finally {
      setZapBusy(false);
    }
  };

  const runJuiceShop = async () => {
    setZapBusy(true);
    try {
      const res = await fetch(JUICESHOP_ZAP_URL);
      if (!res.ok) throw new Error(`load failed (${res.status})`);
      const parsed: unknown = await res.json();
      if (!isZapReport(parsed)) throw new Error("bad shape");
      launchZap(parsed);
    } catch {
      toast.error("Could not load the bundled Juice Shop ZAP scan");
    } finally {
      setZapBusy(false);
    }
  };

  /**
   * Replay a recorded validation_report.json. Rendered as the full-width hero in
   * mock mode (`compact = false`) and as a slim disclosure body in live mode.
   */
  const renderReplay = (compact: boolean) => {
    if (compact) {
      return (
        <div className="border-t border-border px-4 pt-4 pb-4">
          <div
            onDragOver={(e) => {
              e.preventDefault();
              setDragging(true);
            }}
            onDragLeave={() => setDragging(false)}
            onDrop={(e) => {
              e.preventDefault();
              setDragging(false);
              const file = e.dataTransfer.files[0];
              if (file) void readFile(file);
            }}
            className={cn(
              "clay-inset flex flex-col items-center gap-2 px-4 py-6 text-center transition-colors",
              dragging && "border border-primary",
            )}
          >
            <Upload className="size-5 text-faint" />
            <p className="text-sm font-medium">Drop a validation_report.json</p>
            <p className="text-[11px] text-faint">or replay the Juice Shop benchmark</p>
            <input
              ref={inputRef}
              type="file"
              accept="application/json"
              className="hidden"
              onChange={(e) => {
                const file = e.target.files?.[0];
                if (file) void readFile(file);
              }}
            />
            <button
              onClick={() => inputRef.current?.click()}
              className="clay-inset px-3 py-1.5 text-xs font-medium transition-colors hover:text-primary"
            >
              Choose file
            </button>
          </div>
          <button
            onClick={() => void runSample()}
            disabled={busy}
            className="mt-3 inline-flex w-full items-center justify-center gap-2 rounded-lg bg-primary px-4 py-2 text-sm font-medium text-primary-foreground transition-opacity hover:opacity-90 disabled:opacity-50"
          >
            {busy ? <Loader2 className="size-3.5 animate-spin" /> : <Play className="size-3.5" />}
            Run sample validation
          </button>
        </div>
      );
    }

    return (
      <div
        onDragOver={(e) => {
          e.preventDefault();
          setDragging(true);
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={(e) => {
          e.preventDefault();
          setDragging(false);
          const file = e.dataTransfer.files[0];
          if (file) void readFile(file);
        }}
        className={cn(
          "clay-panel flex flex-col items-center gap-4 px-6 py-10 text-center transition-colors",
          dragging && "border-primary",
        )}
      >
        <Upload className="size-6 text-faint" />
        <div>
          <p className="text-sm font-medium">Drop a validation_report.json</p>
          <p className="mt-1 text-xs text-faint">or replay the OWASP Juice Shop benchmark</p>
        </div>
        <input
          ref={inputRef}
          type="file"
          accept="application/json"
          className="hidden"
          onChange={(e) => {
            const file = e.target.files?.[0];
            if (file) void readFile(file);
          }}
        />
        <div className="flex flex-wrap justify-center gap-2">
          <button
            onClick={() => inputRef.current?.click()}
            className="clay-inset px-4 py-2 text-sm font-medium transition-colors hover:text-primary"
          >
            Choose file
          </button>
          <button
            onClick={() => void runSample()}
            disabled={busy}
            className="inline-flex items-center gap-2 rounded-lg bg-primary px-4 py-2 text-sm font-medium text-primary-foreground transition-opacity hover:opacity-90 disabled:opacity-50"
          >
            {busy ? <Loader2 className="size-3.5 animate-spin" /> : <Play className="size-3.5" />}
            Run sample validation
          </button>
        </div>
      </div>
    );
  };

  /** Run a REAL validation from a raw ZAP report (interactive only in API mode). */
  const renderLiveCard = () => (
    <div className="clay-panel px-6 py-6">
      <div className="flex items-center gap-2">
        <Zap className="size-4 text-primary" />
        <h2 className="text-sm font-semibold">Run live from a ZAP report</h2>
        <span
          className={cn(
            "clay-inset ml-auto px-2 py-0.5 font-mono text-[10px] uppercase",
            live ? "text-verdict-confirmed" : "text-faint",
          )}
        >
          {live ? "live" : "backend required"}
        </span>
      </div>
      <p className="mt-1 text-xs text-faint">
        Re-exploit a raw OWASP ZAP scan against a live target and stream true verdicts as each
        finding is decided.
      </p>

      {!live ? (
        <div className="clay-inset mt-4 flex items-start gap-2 px-3 py-3 text-left">
          <Info className="mt-0.5 size-4 shrink-0 text-faint" />
          <p className="text-xs text-muted-foreground">
            {ZAP_UNSUPPORTED_MESSAGE}. Point the UI at a running{" "}
            <span className="font-mono">crucible-api</span> (set{" "}
            <span className="font-mono">VITE_API_BASE</span> in{" "}
            <span className="font-mono">.env</span>) to enable live runs.
          </p>
        </div>
      ) : (
        <>
          <div
            onDragOver={(e) => {
              e.preventDefault();
              setZapDragging(true);
            }}
            onDragLeave={() => setZapDragging(false)}
            onDrop={(e) => {
              e.preventDefault();
              setZapDragging(false);
              const file = e.dataTransfer.files[0];
              if (file) void readZapFile(file);
            }}
            className={cn(
              "clay-inset mt-4 flex flex-col items-center gap-2 px-4 py-6 text-center transition-colors",
              zapDragging && "border border-primary",
            )}
          >
            <Radar className="size-5 text-faint" />
            <p className="text-sm font-medium">Drop a ZAP JSON report</p>
            <input
              ref={zapInputRef}
              type="file"
              accept="application/json"
              className="hidden"
              onChange={(e) => {
                const file = e.target.files?.[0];
                if (file) void readZapFile(file);
              }}
            />
            <button
              onClick={() => zapInputRef.current?.click()}
              disabled={zapBusy}
              className="clay-inset px-3 py-1.5 text-xs font-medium transition-colors hover:text-primary disabled:opacity-50"
            >
              Choose ZAP file
            </button>
          </div>

          <div className="mt-4 grid gap-3 sm:grid-cols-2">
            <label className="flex flex-col gap-1.5">
              <span className="text-[11px] tracking-[0.12em] text-faint uppercase">Target</span>
              <input
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                placeholder={DEFAULT_TARGET}
                spellCheck={false}
                className="clay-inset w-full bg-transparent px-3 py-2 font-mono text-xs outline-none placeholder:text-faint focus:ring-1 focus:ring-ring"
              />
            </label>
            <label className="flex flex-col gap-1.5">
              <span className="text-[11px] tracking-[0.12em] text-faint uppercase">Backend</span>
              <Select value={backend} onValueChange={(v) => setBackend(v as "docker" | "local")}>
                <SelectTrigger className="clay-inset border-0 text-xs">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="docker">Docker (isolated containers)</SelectItem>
                  <SelectItem value="local">Local (host process)</SelectItem>
                </SelectContent>
              </Select>
            </label>
          </div>

          <label className="mt-3 flex cursor-pointer items-center justify-between gap-3">
            <span className="flex flex-col">
              <span className="text-xs font-medium">Adaptive retries</span>
              <span className="text-[11px] text-faint">
                Budget-gated LLM diagnosis proposes a new tactic when the oracle is unresolved.
              </span>
            </span>
            <Switch checked={adaptive} onCheckedChange={setAdaptive} />
          </label>

          <div className="mt-4 flex flex-wrap items-center gap-2">
            <button
              onClick={() => void runJuiceShop()}
              disabled={zapBusy}
              className="inline-flex items-center gap-2 rounded-lg bg-primary px-4 py-2 text-sm font-medium text-primary-foreground transition-opacity hover:opacity-90 disabled:opacity-50"
            >
              {zapBusy ? (
                <Loader2 className="size-3.5 animate-spin" />
              ) : (
                <Zap className="size-3.5" />
              )}
              Run Juice Shop scan (live)
            </button>
            <span className="font-mono text-[11px] text-faint">bundled ZAP full scan</span>
          </div>

          <div className="clay-inset mt-4 flex items-start gap-2 px-3 py-2.5">
            <Info className="mt-0.5 size-3.5 shrink-0 text-faint" />
            <p className="text-[11px] text-faint">
              Live mode needs Docker running and a reachable target at{" "}
              <span className="font-mono">{target.trim() || DEFAULT_TARGET}</span>. Crucible attacks
              the target — it does <span className="font-medium">not</span> start Juice Shop for
              you. Adaptive SQLi confirmation needs a non-empty{" "}
              <span className="font-mono">OPENAI_API_KEY</span> in the repo{" "}
              <span className="font-mono">.env</span> loaded by{" "}
              <span className="font-mono">crucible-api</span> (restart the API after editing).
              Docker backend uses the container name{" "}
              <span className="font-mono">http://juiceshop:3000</span>; Local backend uses{" "}
              <span className="font-mono">http://localhost:3000</span>.
            </p>
          </div>
        </>
      )}
    </div>
  );

  const speedControl = (
    <div className="mt-5 flex flex-wrap items-center justify-center gap-2">
      <span className="font-mono text-[11px] text-faint">speed</span>
      {SPEEDS.map((s) => (
        <button
          key={s.value}
          onClick={() => setSpeed(s.value)}
          className={cn(
            "rounded-full border px-2.5 py-1 font-mono text-[11px] transition-colors",
            speed === s.value
              ? "border-primary text-primary"
              : "border-border text-faint hover:text-foreground",
          )}
        >
          {s.label}
        </button>
      ))}
    </div>
  );

  return (
    <main className="dot-grid relative flex min-h-screen items-center justify-center px-6 py-16">
      <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_50%_20%,color-mix(in_oklab,var(--accent-progress)_12%,transparent),transparent_60%)]" />
      <motion.div
        initial={{ opacity: 0, y: 18 }}
        animate={{ opacity: 1, y: 0 }}
        className={cn("relative w-full", live ? "max-w-5xl" : "max-w-2xl")}
      >
        <div className="mb-8 text-center">
          <span className="clay-inset inline-flex items-center gap-2 px-3 py-1 font-mono text-[11px] text-faint">
            <span className="size-1.5 animate-pulse rounded-full bg-verdict-confirmed" />
            {sourceKind === "mock" ? "MOCK MODE · replaying a recorded run" : "LIVE API MODE"}
          </span>
          <div className="mt-5 flex items-center justify-center gap-3">
            <img
              src="/crucible-mark.png"
              alt=""
              width={44}
              height={44}
              className="size-11"
            />
            <h1 className="text-5xl font-semibold tracking-tight">Crucible</h1>
          </div>
          <p className="mx-auto mt-3 max-w-xl text-base text-muted-foreground">
            Live validation lineage. Watch an agent re-exploit every scanner finding and stamp an
            honest verdict — proof or false positive.
          </p>
        </div>

        {live ? (
          <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_22rem] lg:items-start">
            {renderLiveCard()}
            <Collapsible
              open={replayOpen}
              onOpenChange={setReplayOpen}
              className="clay-panel overflow-hidden"
            >
              <CollapsibleTrigger className="group flex w-full cursor-pointer items-center gap-3 px-4 py-4 text-left transition-colors hover:bg-panel2">
                <span className="clay-inset flex size-9 shrink-0 items-center justify-center">
                  <History className="size-4 text-faint" />
                </span>
                <span className="min-w-0 flex-1">
                  <span className="block text-sm font-medium">Replay a recorded run</span>
                  <span className="block text-[11px] text-faint">
                    Load a saved validation_report.json — demo
                  </span>
                </span>
                <ChevronDown className="size-4 shrink-0 text-faint transition-transform duration-200 group-data-[state=open]:rotate-180" />
              </CollapsibleTrigger>
              <CollapsibleContent className="overflow-hidden data-[state=closed]:animate-collapsible-up data-[state=open]:animate-collapsible-down">
                {renderReplay(true)}
              </CollapsibleContent>
            </Collapsible>
          </div>
        ) : (
          <div className="space-y-4">
            {renderReplay(false)}
            {renderLiveCard()}
          </div>
        )}

        {speedControl}

        <div className="mt-6 grid gap-3 sm:grid-cols-3">
          <Feature
            icon={Zap}
            title="Live lineage"
            body="Nodes appear, edges draw, packets fly per attempt."
          />
          <Feature
            icon={FlaskConical}
            title="Adaptive replay"
            body="Budget-gated LLM retries when the oracle is unresolved."
          />
          <Feature
            icon={Play}
            title="Honest verdicts"
            body="Deterministic oracles stamp confirmed or false positive."
          />
        </div>
      </motion.div>
    </main>
  );
}

function Feature({ icon: Icon, title, body }: { icon: typeof Zap; title: string; body: string }) {
  return (
    <div className="clay-inset p-3">
      <Icon className="size-4 text-primary" />
      <p className="mt-2 text-sm font-medium">{title}</p>
      <p className="mt-1 text-xs text-faint">{body}</p>
    </div>
  );
}
