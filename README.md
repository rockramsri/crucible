# Crucible

An agentic **validation layer** for web-app scanner output. It ingests a scan
report (OWASP ZAP today), then for each finding it **re-exploits the target in an
ephemeral, locked-down Docker sandbox** and returns an honest verdict —
`confirmed` / `false_positive` / `inconclusive` / `agent_failure` — with a
proof artifact and a measured **false-positive rate**.

Detection is what a scanner does. Crucible proves (or disproves) each finding.

## Safety / scope (non-negotiable)

- Only run this against **intentionally-vulnerable practice apps you host
  yourself** (OWASP Juice Shop, DVWA, or your own deliberately-vulnerable app).
- **Never** point it at real, production, or third-party systems you do not own.
- The sandbox that sends the attacks is **network-locked to the target and has no
  internet egress**; it holds no secrets and runs no LLM.

## How it works

```
ingest -> normalize -> plan (playbook) -> run in sandbox -> oracle -> report
```

- **Ingest** (`src/crucible/ingest/zap.py`): ZAP JSON → canonical `Finding`s, keeping only the
  target host (external CDN noise is dropped). New sources = new adapter.
- **Plan** (`src/crucible/playbooks/`): each vuln class has a deterministic playbook that turns
  a finding into a baseline/attack/control set of HTTP steps plus an oracle.
- **Sandbox** (`src/crucible/sandbox.py` + `runner/verify.py`): a dumb, hardened, no-internet
  container runs the steps and returns raw responses. It never decides anything.
- **Oracle** (in each playbook): deterministic Python decides the verdict. The LLM
  is never allowed to declare a true positive.
- **Refine** (`src/crucible/agent.py`, optional): if the oracle can't decide, an LLM
  may propose a better payload or classify the case — bounded by a per-finding
  budget. Disabled automatically if no matching API key is set.
- **Report** (`src/crucible/report.py`, `store.py`): JSON report + Markdown scorecard + an
  append-only SQLite audit log.

The LLM and the oracle run on the host; only `verify.py` runs inside the box.

## Layout

```
src/crucible/                 Python package
data/zap/juiceshop/           ZAP reports (input)
data/output/juiceshop/        validation report + LLM trace (output)
scripts/                      Juice Shop + ZAP helpers
```

## Install

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
cp .env.example .env          # then paste the matching provider key
```

## Usage

Scan Juice Shop (writes under `data/zap/juiceshop/`):

```bash
SCAN=baseline ./scripts/run_zap_juiceshop.sh   # ~1–2 min, passive
SCAN=full     ./scripts/run_zap_juiceshop.sh   # ~20–35 min, active
```

Validate a report (Juice Shop must still be on the `pentest` Docker network):

```bash
# Real sandbox: one hardened container per finding, over the private network.
python -m crucible.cli data/zap/juiceshop/juiceshop_zap_full.json \
    --target http://juiceshop:3000 --backend docker

# Dev / no-Docker fallback: run the same executor on the host.
python -m crucible.cli data/zap/juiceshop/juiceshop_zap_full.json \
    --target http://juiceshop:3000 --backend local --sandbox-base http://localhost:3000
```

After `pip install -e .` you can also run `crucible ...` instead of `python -m crucible.cli ...`.

Enable the optional LLM refine step by putting a key in `.env`:

```bash
# .env
ADAPTIVE_MODEL=openai:gpt-4.1
OPENAI_API_KEY=...
```

Current Gemini models refuse to generate SQLi payloads even for authorized testing,
so the adaptive layer defaults to OpenAI. Any pydantic-ai model string works
(`openai:gpt-4.1`, `anthropic:claude-...`, `google:gemini-3.6-flash`).

## Output

- Console: a scorecard (confirmed / false positives / FP-rate).
- `data/output/juiceshop/validation_report.json`: structured verdicts with proof.
- `data/output/juiceshop/llm_trace.jsonl`: per-iteration LLM/oracle trace.
- `data/output/juiceshop/runs.db`: local SQLite audit trail (gitignored).

### Benchmark (OWASP Juice Shop)

Same ZAP full-scan report, two runs (`--backend docker`) — the before/after that
shows the adaptive layer earning its keep:

- Deterministic only (no LLM): 2 confirmed, 23 false positives, **1 inconclusive**, 8 skipped.
- With the adaptive layer (`openai:gpt-4.1`): **3 confirmed**, 23 false positives, **0 inconclusive**, 8 skipped — **88.5%** false-positive rate.

The delta is the search SQLi. The deterministic generic UNION attempts return 500
(unresolved); the adaptive layer diagnoses "wrong breakout / column count",
requests a `sweep` tactic, the harness expands it to ~60 concrete probes, runs them
in one sandbox call, and the **deterministic oracle** confirms the one that returns
our injected marker. Zero hallucination — the LLM proposes the tactic, code does
the search, and the oracle (not the LLM) stamps the verdict.

Confirmed true positives carry proof artifacts (request/response); the 23 false
positives are correctly filtered (e.g. "backup files" that return the Angular app
shell, a `/%2e/` 403-"bypass" that doesn't retrieve the file, wildcard CORS).

## Extending

- **New scanner**: add an adapter under `src/crucible/ingest/` that returns `Finding`s.
- **New vuln class**: add a `VulnClass`, write a `playbooks/<class>.py` with
  `build_steps()` + `oracle()`, and register it in `playbooks/__init__.py`.

## Verdict taxonomy

- `confirmed` — oracle proved it, with an artifact.
- `false_positive` — target behaved safely / scanner artifact.
- `agent_failure` — our request/tooling broke (excluded from the FP-rate).
- `inconclusive` — budget exhausted / needs a human (excluded from the FP-rate).
- `skipped` — no playbook for that class yet.

## Create the GitHub repo

This folder is ready to become `crucible` on GitHub. From here:

```bash
git init
git add .
git commit -m "Initial commit: Crucible"
gh repo create crucible --public --source=. --remote=origin --push
```

`.env`, `.venv/`, `*.db`, and `PENTEST_PROJECT_CONTEXT.md` are gitignored. The Juice Shop ZAP scans and the sample validation output under `data/` are included on purpose.
