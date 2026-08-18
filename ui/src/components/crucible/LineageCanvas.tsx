import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Bot, Box, Crosshair, Gavel, Maximize2, Minus, Plus, ShieldCheck, Cpu } from "lucide-react";
import type { LucideIcon } from "lucide-react";
import { VERDICT_COLOR, VERDICT_LABEL } from "@/lib/crucible/tokens";
import type { LiveAttempt, LiveFinding, NodeId } from "@/lib/crucible/useRun";

interface GNode {
  key: string;
  id: NodeId;
  attempt: number;
  label: string;
  sub: string;
  icon: LucideIcon;
  x: number;
  y: number;
}

interface GEdge {
  key: string;
  from: string;
  to: string;
  // "flow" = straight in-lane hop, "adaptive" = oracle→gate→llm reasoning,
  // "loop" = the budget-gate/LLM hand-off down into the next retry lane.
  kind: "flow" | "adaptive" | "loop";
}

const NODE_W = 152;
const NODE_H = 76;
// Vertical pitch between attempt lanes. Roomy enough that the loop-back
// connector gets its own clear horizontal channel in the gutter.
const ROW_H = 230;
// Push the whole graph down a touch so lane captions never clip off the top.
const TOP_PAD = 30;
// How far the LLM-diagnose node hangs below its lane baseline (into the gutter),
// so the retry hand-off leaves from the gutter, not from another card's row.
const LLM_DROP = 118;
const COL = { planner: 0, sandbox: 240, target: 480, oracle: 720, branch: 960 };
const CORNER_R = 18;

function buildGraph(finding: LiveFinding | null): { nodes: GNode[]; edges: GEdge[] } {
  const nodes: GNode[] = [];
  const edges: GEdge[] = [];
  if (!finding) return { nodes, edges };

  const attempts: LiveAttempt[] = finding.attemptList.length
    ? finding.attemptList
    : [{ n: 1, mode: "deterministic", steps: [] }];

  const laneY = (i: number) => TOP_PAD + i * ROW_H;

  nodes.push({
    key: "planner",
    id: "planner",
    attempt: 1,
    label: "Planner",
    sub: "host · trusted",
    icon: Cpu,
    x: COL.planner,
    y: laneY(0),
  });

  attempts.forEach((a, i) => {
    const y = laneY(i);
    const adaptive = a.mode === "adaptive";
    const done = a.steps.filter((s) => s.status !== undefined).length;
    nodes.push(
      {
        key: `sandbox-${a.n}`,
        id: "sandbox",
        attempt: a.n,
        label: adaptive ? `Sandbox · retry ${a.n - 1}` : "Sandbox",
        sub: adaptive ? "llm tactic · no egress" : "ephemeral · no egress",
        icon: Box,
        x: COL.sandbox,
        y,
      },
      {
        key: `target-${a.n}`,
        id: "target",
        attempt: a.n,
        label: "Target",
        sub: `${done}/${a.steps.length || "…"} probes`,
        icon: Crosshair,
        x: COL.target,
        y,
      },
      {
        key: `oracle-${a.n}`,
        id: "oracle",
        attempt: a.n,
        label: "Oracle",
        sub: a.oracle ?? "deterministic",
        icon: Gavel,
        x: COL.oracle,
        y,
      },
    );

    edges.push(
      {
        key: `e-p-${a.n}`,
        from: i === 0 ? "planner" : `llm-${attempts[i - 1]!.n}`,
        to: `sandbox-${a.n}`,
        kind: i === 0 ? "flow" : "loop",
      },
      { key: `e-st-${a.n}`, from: `sandbox-${a.n}`, to: `target-${a.n}`, kind: "flow" },
      { key: `e-to-${a.n}`, from: `target-${a.n}`, to: `oracle-${a.n}`, kind: "flow" },
    );

    // Keep gate + LLM for any attempt that went unresolved, diagnosed, or
    // handed off to a later retry lane — even after the finding settles
    // (inconclusive / confirmed). Destroying them on settle is what made
    // the live graph look like the LLM nodes "were suddenly destroyed".
    const hasNext = i < attempts.length - 1;
    if (showRetryBranch(a, finding, hasNext)) {
      nodes.push(
        {
          key: `gate-${a.n}`,
          id: "gate",
          attempt: a.n,
          label: "Budget gate",
          sub: gateSub(a, finding, hasNext),
          icon: ShieldCheck,
          x: COL.branch,
          y,
        },
        {
          key: `llm-${a.n}`,
          id: "llm",
          attempt: a.n,
          label: "LLM diagnose",
          sub: llmSub(a, finding, hasNext),
          icon: Bot,
          x: COL.branch,
          y: y + LLM_DROP,
        },
      );
      edges.push(
        { key: `e-og-${a.n}`, from: `oracle-${a.n}`, to: `gate-${a.n}`, kind: "adaptive" },
        { key: `e-gl-${a.n}`, from: `gate-${a.n}`, to: `llm-${a.n}`, kind: "adaptive" },
      );
    }
  });

  const present = new Set(nodes.map((n) => n.key));
  return { nodes, edges: edges.filter((e) => present.has(e.from) && present.has(e.to)) };
}

const truncate = (s: string, n: number) => (s.length > n ? `${s.slice(0, n - 1)}…` : s);

/** Gate + LLM stay on the canvas after settle if this attempt actually branched. */
function showRetryBranch(a: LiveAttempt, finding: LiveFinding, hasNext: boolean): boolean {
  if (a.diagnose) return true;
  if (a.verdict === "unresolved") return true;
  if (hasNext) return true;
  // A later retry that confirmed / FP must not grow its own empty LLM branch.
  if (a.verdict === "confirmed" || a.verdict === "false_positive" || a.verdict === "skipped") {
    return false;
  }
  // Settled inconclusive after oracle.interim, even if the attempt verdict
  // was later overwritten (legacy streams / race with the scorecard stamp).
  return Boolean(finding.unresolved && finding.state === "settled");
}

function gateSub(a: LiveAttempt, finding: LiveFinding, hasNext: boolean): string {
  if (hasNext) return `attempt ${a.n + 1} of 3`;
  if (finding.state === "settled") {
    if (a.diagnose?.giveup) return "give up · no retry";
    if (a.diagnose) return "no retry lane";
    return "LLM unavailable";
  }
  return `attempt ${a.n + 1} of 3`;
}

function llmSub(a: LiveAttempt, finding: LiveFinding, hasNext: boolean): string {
  if (a.diagnose?.giveup) return truncate(a.diagnose.cause || "LLM gave up", 28);
  if (a.diagnose) return truncate(a.diagnose.cause, 28);
  if (finding.state === "settled" && !hasNext) {
    return finding.adaptive ? "LLM unavailable" : "adaptive did not run";
  }
  return "awaiting gate";
}

export function LineageCanvas({ finding }: { finding: LiveFinding | null }) {
  const wrapRef = useRef<HTMLDivElement>(null);
  const [view, setView] = useState({ x: 0, y: 0, k: 0.85 });
  const dragRef = useRef<{ x: number; y: number; ox: number; oy: number } | null>(null);
  const manualRef = useRef(false);
  const [hover, setHover] = useState<string | null>(null);

  const { nodes, edges } = useMemo(() => buildGraph(finding), [finding]);

  const bounds = useMemo(() => {
    if (!nodes.length) return { w: 1100, h: 320 };
    // Pad right/bottom so the branch column, lane captions and the verdict
    // stamp that sits below the last lane all stay inside the fitted frame.
    return {
      w: Math.max(...nodes.map((n) => n.x)) + NODE_W + 48,
      h: Math.max(...nodes.map((n) => n.y)) + NODE_H + 108,
    };
  }, [nodes]);

  const activeKey = finding?.activeNode
    ? `${finding.activeNode}-${finding.activeAttempt}`
    : undefined;

  const fit = useCallback(() => {
    const el = wrapRef.current;
    const w = el?.clientWidth ?? 900;
    const h = el?.clientHeight ?? 480;
    const k = Math.min(1, Math.max(0.32, Math.min((w - 56) / bounds.w, (h - 72) / bounds.h)));
    manualRef.current = false;
    const next = { x: (w - bounds.w * k) / 2, y: (h - bounds.h * k) / 2, k };
    setView((v) => (v.x === next.x && v.y === next.y && v.k === next.k ? v : next));
  }, [bounds.w, bounds.h]);

  // Refit when the graph grows a new retry row or the panel resizes.
  useEffect(() => {
    if (!manualRef.current) fit();
    const el = wrapRef.current;
    if (!el || typeof ResizeObserver === "undefined") return;
    const ro = new ResizeObserver(() => {
      if (!manualRef.current) fit();
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, [fit]);

  useEffect(() => {
    manualRef.current = false;
  }, [finding?.id]);

  const byKey = (k: string) => nodes.find((n) => n.key === k);

  const nodeColor = (n: GNode): string => {
    if (!finding) return "var(--border)";
    if (n.id === "oracle") {
      const a = finding.attemptList.find((x) => x.n === n.attempt);
      if (a?.verdict && a.verdict !== "unresolved") return VERDICT_COLOR[a.verdict];
      if (a?.verdict === "unresolved") return VERDICT_COLOR.unresolved;
    }
    if (activeKey === n.key) return n.id === "llm" ? VERDICT_COLOR.adaptive : VERDICT_COLOR.running;
    if (n.id === "llm" || n.id === "gate") return VERDICT_COLOR.adaptive;
    return "var(--border)";
  };

  const activeEdgeKey = useMemo(() => {
    if (!finding || finding.state === "settled" || !finding.activeNode) return null;
    const n = finding.activeAttempt;
    switch (finding.activeNode) {
      case "sandbox":
      case "target":
        return `e-st-${n}`;
      case "oracle":
        return `e-to-${n}`;
      case "gate":
        return `e-og-${n}`;
      case "llm":
        return `e-gl-${n}`;
      default:
        return `e-p-${n}`;
    }
  }, [finding?.activeNode, finding?.activeAttempt, finding?.state]);

  const lastStepFor = (key: string) => {
    const n = byKey(key);
    if (!n || !finding) return null;
    const a = finding.attemptList.find((x) => x.n === n.attempt);
    return a?.steps[a.steps.length - 1] ?? null;
  };

  return (
    <div
      ref={wrapRef}
      className="clay-panel dot-grid relative h-full min-h-0 touch-none overflow-hidden"
      onPointerDown={(e) => {
        dragRef.current = { x: e.clientX, y: e.clientY, ox: view.x, oy: view.y };
        (e.target as HTMLElement).setPointerCapture?.(e.pointerId);
      }}
      onPointerMove={(e) => {
        const d = dragRef.current;
        if (!d) return;
        manualRef.current = true;
        setView((v) => ({ ...v, x: d.ox + (e.clientX - d.x), y: d.oy + (e.clientY - d.y) }));
      }}
      onPointerUp={() => (dragRef.current = null)}
      onWheel={(e) => {
        manualRef.current = true;
        setView((v) => ({ ...v, k: Math.min(2, Math.max(0.28, v.k - e.deltaY * 0.0012)) }));
      }}
    >
      <div className="pointer-events-none absolute top-4 left-4 z-10">
        <div className="text-[11px] tracking-[0.14em] text-faint uppercase">Attack lineage</div>
        <div className="mt-0.5 text-sm font-medium">
          {finding ? finding.name : "Select a finding"}
        </div>
        {finding && (
          <div className="mt-1 font-mono text-[10px] text-faint">
            {finding.attemptList.length || 1} run{(finding.attemptList.length || 1) > 1 ? "s" : ""}{" "}
            · {finding.steps.length} probes
          </div>
        )}
      </div>

      <div className="absolute top-4 right-4 z-10 flex gap-1.5">
        <CamButton
          onClick={() => {
            manualRef.current = true;
            setView((v) => ({ ...v, k: Math.min(2, v.k + 0.15) }));
          }}
          icon={Plus}
        />
        <CamButton
          onClick={() => {
            manualRef.current = true;
            setView((v) => ({ ...v, k: Math.max(0.28, v.k - 0.15) }));
          }}
          icon={Minus}
        />
        <CamButton onClick={fit} icon={Maximize2} />
      </div>

      <motion.div
        className="absolute top-0 left-0"
        style={{ width: bounds.w, height: bounds.h, transformOrigin: "0 0" }}
        animate={{ x: view.x, y: view.y, scale: view.k }}
        transition={{ type: "spring", stiffness: 90, damping: 20 }}
      >
        <svg className="absolute inset-0 h-full w-full overflow-visible">
          <defs>
            <linearGradient id="flow-grad" x1="0" y1="0" x2="1" y2="0">
              <stop offset="0%" stopColor={VERDICT_COLOR.running} stopOpacity="0.15" />
              <stop offset="100%" stopColor={VERDICT_COLOR.running} stopOpacity="0.95" />
            </linearGradient>
            {/* Small directional tips so each hop reads L→R (and the loop reads
                downward into the retry lane) even on the faint base line. */}
            <marker
              id="lineage-arrow-flow"
              viewBox="0 0 12 12"
              refX="10"
              refY="6"
              markerWidth="9"
              markerHeight="9"
              markerUnits="userSpaceOnUse"
              orient="auto"
            >
              <path d="M1 1 L11 6 L1 11 Z" fill={VERDICT_COLOR.running} />
            </marker>
            <marker
              id="lineage-arrow-adaptive"
              viewBox="0 0 12 12"
              refX="10"
              refY="6"
              markerWidth="9"
              markerHeight="9"
              markerUnits="userSpaceOnUse"
              orient="auto"
            >
              <path d="M1 1 L11 6 L1 11 Z" fill={VERDICT_COLOR.adaptive} />
            </marker>
          </defs>
          {edges.map((e) => {
            const a = byKey(e.from);
            const b = byKey(e.to);
            if (!a || !b) return null;
            const path = routeEdge(a, b, e.kind);
            const live = activeEdgeKey === e.key;
            const accent = e.kind === "flow" ? VERDICT_COLOR.running : VERDICT_COLOR.adaptive;
            const marker =
              e.kind === "flow" ? "url(#lineage-arrow-flow)" : "url(#lineage-arrow-adaptive)";
            return (
              <g key={e.key}>
                <motion.path
                  d={path}
                  fill="none"
                  stroke="var(--border)"
                  strokeWidth={1.4}
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  markerEnd={marker}
                  initial={{ pathLength: 0, opacity: 0 }}
                  animate={{ pathLength: 1, opacity: 0.6 }}
                  transition={{ duration: 1.1, ease: "easeInOut" }}
                />
                {live && (
                  <>
                    <motion.path
                      d={path}
                      fill="none"
                      stroke={accent}
                      strokeWidth={2.2}
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeDasharray="10 14"
                      initial={{ opacity: 0 }}
                      animate={{ opacity: 0.85, strokeDashoffset: [0, -48] }}
                      transition={{
                        strokeDashoffset: { repeat: Infinity, duration: 1.6, ease: "linear" },
                        opacity: { duration: 0.4 },
                      }}
                    />
                    {[0, 0.5].map((delay) => (
                      <circle key={delay} r={4.5} fill={accent} opacity={0.95}>
                        <animateMotion
                          dur="1.8s"
                          begin={`${delay * 1.8}s`}
                          repeatCount="indefinite"
                          path={path}
                        />
                      </circle>
                    ))}
                  </>
                )}
              </g>
            );
          })}
        </svg>

        <AnimatePresence>
          {nodes.map((n) => {
            const color = nodeColor(n);
            const Icon = n.icon;
            const isActive = activeKey === n.key && finding?.state !== "settled";
            const lastStep = hover === n.key ? lastStepFor(n.key) : null;
            return (
              <motion.div
                key={n.key}
                tabIndex={0}
                onFocus={() => setHover(n.key)}
                onBlur={() => setHover(null)}
                onMouseEnter={() => setHover(n.key)}
                onMouseLeave={() => setHover(null)}
                initial={{ opacity: 0, scale: 0.8, y: 14 }}
                animate={{ opacity: 1, scale: 1, y: 0 }}
                exit={{ opacity: 0, scale: 0.9 }}
                transition={{ type: "spring", stiffness: 160, damping: 20 }}
                className="clay-panel absolute flex cursor-default flex-col justify-center px-3 py-2 outline-none focus:ring-2 focus:ring-ring"
                style={{
                  left: n.x,
                  top: n.y,
                  width: NODE_W,
                  height: NODE_H,
                  boxShadow: `var(--clay-shadow), 0 0 0 2px color-mix(in oklab, ${color} 70%, transparent)`,
                }}
              >
                {isActive && (
                  <motion.span
                    className="pointer-events-none absolute -inset-1 rounded-[inherit]"
                    style={{
                      boxShadow: `0 0 0 2px color-mix(in oklab, ${color} 45%, transparent)`,
                    }}
                    animate={{ opacity: [0.6, 0, 0.6], scale: [1, 1.06, 1] }}
                    transition={{ repeat: Infinity, duration: 2 }}
                  />
                )}
                <div className="flex items-center gap-2">
                  <Icon className="size-4 shrink-0" style={{ color }} />
                  <span className="truncate text-sm font-medium">{n.label}</span>
                  {isActive && (
                    <motion.span
                      className="ml-auto size-1.5 shrink-0 rounded-full"
                      style={{ backgroundColor: color }}
                      animate={{ opacity: [1, 0.2, 1] }}
                      transition={{ repeat: Infinity, duration: 1.4 }}
                    />
                  )}
                </div>
                <div className="mt-1 truncate font-mono text-[10px] text-faint">{n.sub}</div>

                <AnimatePresence>
                  {lastStep && (
                    <motion.div
                      initial={{ opacity: 0, y: 6 }}
                      animate={{ opacity: 1, y: 0 }}
                      exit={{ opacity: 0, y: 4 }}
                      className="clay-inset absolute top-full left-0 z-20 mt-2 w-72 p-3"
                    >
                      <div className="text-[10px] tracking-[0.12em] text-faint uppercase">
                        run#{n.attempt} · last step · {lastStep.stepId}
                      </div>
                      <div className="mt-1 font-mono text-[11px] break-all text-foreground">
                        {lastStep.payload}
                      </div>
                      <div className="mt-2 font-mono text-[11px] text-muted-foreground">
                        {lastStep.method} {lastStep.path} → {lastStep.status ?? "…"}
                        {lastStep.bodyLen !== undefined ? ` · ${lastStep.bodyLen}b` : ""}
                      </div>
                    </motion.div>
                  )}
                </AnimatePresence>
              </motion.div>
            );
          })}
        </AnimatePresence>

        {/* Lane rails: attempt caption (far-left gutter) + interim stamp per run */}
        {(finding?.attemptList ?? []).map((a, i) => {
          const laneTop = TOP_PAD + i * ROW_H;
          const stamp = a.verdict;
          const color = stamp
            ? stamp === "unresolved"
              ? VERDICT_COLOR.unresolved
              : VERDICT_COLOR[stamp]
            : null;
          return (
            <div key={`rail-${a.n}`}>
              <div
                className="absolute font-mono text-[10px] tracking-[0.16em] text-faint uppercase"
                style={{ left: COL.planner + 2, top: laneTop - 20 }}
              >
                {a.n === 1 ? "run 1 · deterministic" : `retry ${a.n - 1} · ${a.mode}`}
              </div>
              <AnimatePresence>
                {color && (
                  <motion.div
                    key={`${a.n}-${stamp}`}
                    initial={{ opacity: 0, scale: 1.5, rotate: -10 }}
                    animate={{ opacity: 1, scale: 1, rotate: -6 }}
                    className="pointer-events-none absolute rounded-lg border-2 px-3 py-1 font-mono text-xs font-bold tracking-widest uppercase"
                    style={{
                      left: COL.oracle + 4,
                      top: laneTop + NODE_H + 12,
                      color,
                      borderColor: color,
                      backgroundColor: `color-mix(in oklab, ${color} 12%, transparent)`,
                    }}
                  >
                    {VERDICT_LABEL[stamp!]}
                  </motion.div>
                )}
              </AnimatePresence>
              {finding?.state === "settled" &&
                finding.verdict &&
                a.verdict === "unresolved" &&
                i === (finding.attemptList.length - 1) && (
                  <motion.div
                    initial={{ opacity: 0, scale: 1.4, rotate: 8 }}
                    animate={{ opacity: 1, scale: 1, rotate: 4 }}
                    className="pointer-events-none absolute rounded-lg border-2 px-3 py-1 font-mono text-xs font-bold tracking-widest uppercase"
                    style={{
                      left: COL.branch + 4,
                      top: laneTop + LLM_DROP + NODE_H + 12,
                      color: VERDICT_COLOR[finding.verdict],
                      borderColor: VERDICT_COLOR[finding.verdict],
                      backgroundColor: `color-mix(in oklab, ${VERDICT_COLOR[finding.verdict]} 12%, transparent)`,
                    }}
                  >
                    {VERDICT_LABEL[finding.verdict]}
                  </motion.div>
                )}
            </div>
          );
        })}
      </motion.div>
    </div>
  );
}

/**
 * Routes an edge between two node cards, always attaching to their rims (never
 * through them). Three shapes:
 *   - "loop": the budget-gate/LLM hand-off into the next retry lane. Leaves the
 *     LLM card's left rim, runs left through the clear gutter channel, then
 *     turns down into the retry Sandbox's top rim as a single rounded elbow.
 *   - vertical stack (gate → llm, same column): straight rim-to-rim drop.
 *   - default in-lane hop: right rim → left rim with a gentle S-curve.
 */
function routeEdge(a: GNode, b: GNode, kind: GEdge["kind"]): string {
  const A = { l: a.x, r: a.x + NODE_W, t: a.y, b: a.y + NODE_H, cy: a.y + NODE_H / 2 };
  const B = {
    l: b.x,
    r: b.x + NODE_W,
    t: b.y,
    cx: b.x + NODE_W / 2,
    cy: b.y + NODE_H / 2,
  };

  if (kind === "loop") {
    // Exit the LLM card's left rim, travel left along the gutter at that y,
    // then round the corner and drop straight into the Sandbox card's top rim.
    const sx = A.l;
    const sy = A.cy;
    const ex = B.cx;
    const ey = B.t;
    const r = Math.min(CORNER_R, Math.abs(ey - sy) / 2, Math.abs(sx - ex) / 2);
    // H stops `r` before the corner, Q rounds it, V finishes into the top rim.
    return `M ${sx} ${sy} H ${ex + r} Q ${ex} ${sy} ${ex} ${sy + r} V ${ey}`;
  }

  // Same-column vertical drop (budget gate → LLM diagnose).
  if (Math.abs(A.l - B.l) < 40 && B.t >= A.b - 1) {
    const x = a.x + NODE_W / 2;
    return `M ${x} ${A.b} V ${B.t}`;
  }

  // Default in-lane hop: right rim of A → left rim of B.
  const sx = A.r;
  const ex = B.l;
  const mx = (sx + ex) / 2;
  return `M ${sx} ${A.cy} C ${mx} ${A.cy}, ${mx} ${B.cy}, ${ex} ${B.cy}`;
}

function CamButton({ onClick, icon: Icon }: { onClick: () => void; icon: LucideIcon }) {
  return (
    <button
      onClick={onClick}
      className="clay-inset flex size-8 items-center justify-center text-muted-foreground transition-colors hover:text-foreground"
    >
      <Icon className="size-3.5" />
    </button>
  );
}
