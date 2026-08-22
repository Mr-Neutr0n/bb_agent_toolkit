# Autonomous Session Synthesis: Research to Roadmap

Date: 2026-08-22. This doc ties the session's three research threads to what
shipped and ranks what comes next.

## What Shipped This Session

| Commit | Deliverable | Source thread |
|---|---|---|
| a2e8595 | CI fix: 5 missing skills tracked (39 -> 44 upstream) | upstream CI |
| 5f7dd13 | Harness digest: agent topologies, patterns-to-adopt, gap map | sub-agent research |
| 8a8128d | Attack-pattern digest: 2025-2026 techniques, ranked ideas | attack-patterns research |
| cdf8acf | identity-domain skill (#45): 7 workflows, 98/100 quality | GOAD research |
| 7e1b827 | desync-matrix (http-protocol) + mcp-audit (ai-llm) | attack-patterns |
| f565298 | oauth-conformance workflow (auth) | attack-patterns |

Research sources preserved with URLs inside both digests under `docs/research/`.

## Key Strategic Findings

1. **The field's biggest failures are planning failures**, not tool failures.
   PentestGPT v2 taxonomy: repeated identical calls, drift, no pivots. Our
   planner + technique-kb are positioned to encode difficulty vectors and
   budget-aware pruning - nobody open-source does it well yet.

2. **Our differentiated assets match the field's uncovered gaps**:
   multi-persona authenticated testing (persona/cross-account), business-logic
   invariant checking, OOB correlation discipline. Lean into these; they are
   ahead of PentAGI/XBOW-class systems.

3. **Identity infrastructure on external scope is real bounty surface** and was
   completely uncovered before identity-domain landed. GOAD's no-creds phases
   translate almost 1:1 into passive/active-safe workflows.

4. **Desync research became corpus maintenance**: Kettle's $200k fortnight used
   trigger sweeps we now automate detection-only for. Weaponization stays
   human-gated by design.

5. **MCP integrity is an emerging reportable bug class**: rug-pull redefinitions,
   hidden-unicode description smuggling, anonymous listing. mcp-audit covers
   definitions; pair with mcp_fuzzer behavior tests.

## Ranked Next Steps

Quick wins (days):
1. Circuit breakers in bb-run trace layer: N consecutive 403/429 -> global
   backoff + shared per-target semaphore (harness digest pattern 3).
2. Campaign FSM persisted to .bb/campaign-state.json so bb-hunt resumes
   mid-phase (pattern 1).
3. Negative-result memory: program-memory records tested-and-clean endpoints;
   workflows check memory before firing (pattern 4).

Medium lifts (a week each):
4. Planner difficulty vectors: horizon estimate + historical success rate per
   technique from evaluation-harness data; bb-hunt timeboxes branches (pattern 2).
5. Hunt profiles fast|std|deep as policy knobs over wave width + verifier
   count (pattern 5).
6. Electron/deeplink audit skill: ASAR extraction, webPreferences audit,
   protocol-handler fuzzing. Underhunted vs one-click-RCE severity.
7. k8s-edge-sweep templates into cloud skill (ingress-nginx admission,
   Argo CD gRPC exposure).

Strategic bets:
8. Recon-to-exploit typed intermediate representation - structured handoff
   between recon outputs and vuln-skill inputs would lift end-to-end hit rates
   more than any single new technique (recon recall ~50% loss documented).
9. Disclosed-report RAG wired into impact-verifier for pre-submit duplicate
   detection against platform history.
10. Expose bb-run workflows as MCP tools so external agents can drive the
    governed pipeline (inverts our consumption of others' MCP servers).
11. Adversarial-environment awareness: honeypot/trap heuristics. Zero shipped
    mitigations anywhere; even a heuristic checklist would be first.

## Explicitly Not Ported (by design)

GOAD relay/coercion/delegation/ACL/trust phases: presuppose internal foothold,
generate blue-team noise (4624/4648 events), outside web-harness threat model.
OWA timed user enumeration ships as MANUAL gate only. Desync weaponization
stays behind verify workflow with human confirmation.
