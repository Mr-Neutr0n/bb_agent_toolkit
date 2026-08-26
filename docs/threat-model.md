# Threat model and security design

BountyHarness runs security workflows against **live web and API targets** you are
authorized to test, and optionally sends evidence to model providers for triage.
This document describes trust boundaries, what data goes where, and how to deploy
it safely. It complements disclosure process in `SECURITY.md`.

> **One-line summary:** every `bb-run` is local and scope-gated, but some
> workflows actively test remote targets and some scripts send evidence to
> external model endpoints. Treat scope files, `.bb/` context, and provider keys
> as sensitive, and run hunters on isolated hosts.

## Components and data flow

| Component | Role | Trust level |
| --- | --- | --- |
| `bin/bb-*` | Thin harness (context, scope checks, workflow dispatch, tracing) | operator-controlled |
| `.claude/skills/*` | Fat skills: scripts + payloads + runbooks executed via `bb-run` | **executes against targets** |
| `.bb/` | RunContext (`context.env/json`), traces, cookies, tool locks | **sensitive local state** |
| `output/` / `evidence/` | Findings, requests, responses | **sensitive until disclosed** |
| `tools/registry` | Tool definitions, install receipts | trusted config |
| `program-memory` | Per-program knowledge persisted across engagements | sensitive |

Flow: `bb-init` -> writes `.bb/context.*` (TARGET, SCOPE_FILE, OUTDIR, RATE_LIMIT) ->
`bb-run <skill> <workflow>` loads context, checks scope file and safety tier, executes the
skill's command (often `curl`, `nuclei`, `subfinder`, or custom Python), writes under
`OUTDIR`, appends redacted trace to `.bb/traces/runs.jsonl` -> `reporting` packages.

Headless/autonomous path: `bb-hunt` bootstraps context from a URL then runs
`campaign` skill which sequences recon -> domain-model -> technique-kb -> planner -> vuln skills.

## Trust boundaries

### 1. Operator <-> harness and local filesystem

The harness has no authentication. Anyone with shell access can read `.bb/context.env`
(api keys in `AUTH_HEADER`, `COOKIE_JAR`), `output/` evidence, and `program-memory`
findings. **Boundary you enforce** via OS account isolation, encrypted disks, and not
sharing the working tree.

### 2. Harness <-> authorized target

This is the primary active boundary. Every intrusive or higher workflow is
expected to check `SCOPE_FILE` and `RATE_LIMIT` before sending traffic. Safety
tiers are:

- `passive` - no target traffic (e.g., CT log lookups)
- `active-safe` - low-volume, read-only probes
- `intrusive` - state-changing or high-volume probes, requires explicit scope
- `destructive-manual` - never automated, human confirmation required

A missing or empty scope file causes `bb-run` to warn and `bb-hunt` to cap its
ceiling to `active-safe` (see `campaign` skill). The `tools/circuit_breaker.py`
blocks repeated consecutive failures against the same target.

Target responses are **untrusted**: they may contain prompt-injection style
content, polyglot payloads, or deceptive headers. Skills that feed target content
to an LLM go through `agent-safety` checks.

### 3. Harness <-> model or provider endpoints

Some workflows ( `ai-llm`, `auto-research`, `vuln-intel` ) send evidence or prompts
to external model providers if you configure keys (`~/.secrets/*.env` mode 600).
This is a **data-egress boundary**. Know where evidence goes before enabling
those skills. The default local workflows (recon, sqli, xss, etc.) send nothing
externally except traffic to the target itself and to public data sources
(CT logs, DNS) when involved.

### 4. Host <-> secrets and evidence

Provider keys, session cookies, and pre-disclosure findings are the critical
assets. `.bb/` is gitignored and `gitleaks` is run pre-commit and in CI. Keep
`~/.secrets/*.env` at 600 and never inline credentials. Evidence directories are
never committed and should not be pasted into public issues.

## Assets to protect

- **Session material**: `COOKIE_JAR`, `AUTH_HEADER`, bearer tokens, `.bb/cookies.txt`
- **Provider keys**: `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `OPENROUTER_API_KEY` if used
- **Evidence**: `output/`, `evidence/`, `.bb/traces/` (full request/response, screenshots)
- **Program memory**: `.bb/program-memory/` or skill-local findings (pre-disclosure vulns)
- **Authorization scope files**: `engagements/*/scope/*` and any file referenced by `SCOPE_FILE`

## Key threats and mitigations

### 1. Out-of-scope or overly intrusive testing

Malicious or mistaken invocation could probe a host you are not authorized to test,
or run a destructive workflow against a live target.

- Design: every skill declares `safety_tier` in `skill.yaml`; `bb-run` warns when
  an intrusive workflow lacks a scope file; `bb-hunt` auto-caps without one;
  `scope-manager` can diff and validate scope files; `circuit_breaker` halts
  repeated failures.
- Operator: always run `bb-init` with an explicit `--scope-file` for intrusive
  testing; keep scope files versioned; review `planner` output before executing
  high-tier workflows; set `RATE_LIMIT` per program guidance.

### 2. Secret or evidence exfiltration

A skill bug, a malicious payload echo, or operator error could leak keys or
evidence via logs, traces, commits, or provider calls.

- Design: traces are redacted (`tools/run_trace.py`); `.bb/`, `output/`,
  `evidence/` are in `.gitignore`; `gitleaks` pre-commit hook and CI secret
  scans reject leaks; model-bound skills are opt-in.
- Operator: keep `~/.secrets/*.env` at 600; do not `cat` or paste `.bb/` into
  public channels; scope provider usage to `active-safe` findings only when
  sending evidence externally.

### 3. Untrusted target content

Target responses may attempt to influence an LLM-based triage step or hide
polyglots.

- Design: `agent-safety` skill guards LLM inputs; payloads treat target data as
  plain text; traces never store raw target responses with credentials inline.
- Operator: review `oob-infra` callbacks and `traffic-corpus` imports before
  feeding them to any LLM workflow.

### 4. Supply chain of the harness itself

Skills execute `curl`, `nuclei`, `subfinder`, and language runtimes installed
via `tools/registry` definitions.

- Design: registry pins install methods and `version/health` checks;
  `tools/capabilities.yaml` maps capabilities to tools; `THIRD_PARTY.md` files
  record provenance where third-party material is vendored.
- Operator: run `bin/bb-tools doctor` after install, keep the host updated, and
  review third-party skill payloads before use on sensitive programs.

### 5. Local privilege and host sharing

The harness itself does not require root and does not create nested containers
or dedicated Docker networks per scan.

- Design: no privilege escalation; files are written as the invoking user under
  `OUTDIR`.
- Operator: run hunters on a **dedicated VM or disposable worktree** when
  testing untrusted targets that may attempt to fingerprint or counter-scan.
  Do not colocate engine data with unrelated sensitive workloads.

## Secure deployment checklist

- [ ] Run on a **dedicated host or isolated worktree** per engagement
- [ ] Keep `bin/bb-init --scope-file <file>` explicit for any intrusive or
      authenticated workflow; validate with `scope-manager` where available
- [ ] Set `RATE_LIMIT` and `CONCURRENCY` from program guidance
- [ ] Keep `.bb/`, `output/`, `evidence/` private and gitignored; never commit them
- [ ] Store provider keys in `~/.secrets/*.env` at 600; do not inline them
- [ ] Put auth in front of any shared harness host you expose to a team
- [ ] Run `bin/bb-tools doctor` and `gitleaks detect --source . --no-git -v` before sharing evidence

## Out of scope

- Attacks requiring an already-compromised operator host or account
- Misconfigurations explicitly warned about here (e.g., running intrusive
  workflows without a scope file, sharing `output/` publicly)
- Security of third-party model providers or target infrastructure themselves

Vulnerabilities **in BountyHarness itself** are always in scope — report them via
`SECURITY.md`.
