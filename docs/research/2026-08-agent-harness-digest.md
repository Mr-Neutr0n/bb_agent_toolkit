# Research Digest: Agentic Pentest Harnesses (2025-2026)

Date: 2026-08-22. Scope: how the field builds AI-driven offensive-security harnesses,
what to copy into BountyHarness, what to avoid. Sources listed inline and at bottom.

## Framework Survey

| Framework | Topology | Notable capability | Copy | Avoid |
|---|---|---|---|---|
| PentAGI (vxcontrol) | Docker-isolated specialist workers (browser, Python, SQL, nmap) behind orchestrator; graph memory via Graphiti | Full-flow FSM, typed worker handoffs, memory taxonomy of tested-and-clean facts | Worker isolation, negative-result memory | Heavy infra for solo hunters |
| HackingBuddyGPT (ipa-lab) | Narrow autonomous loops (LLM + state + toolset), privesc/ssh focus | Small-loop determinism, published evals | Loop discipline: one goal per agent turn | Broad-scope claims |
| CAI (aliasrobotics) | Modular agents + MCP tools, benchmark-first | Trivy-bench style measurement culture | Per-skill precision/recall reporting | Trusting leaderboard numbers over real targets |
| MAPTA (arXiv 2508.20816) | Cost-metered micro-agents, threshold early-stop | $0.75 avg cost per API vuln attempt; honest zero-rate reporting | Cost telemetry + branch kill thresholds | Chasing 100% recall |
| XBOW | Closed harness, validator-gated submissions | Top-1 HackerOne US via deterministic validation before submit | Verify-before-report gate (we have impact-verifier; enforce harder) | Closed-source opacity |
| PentestGPT v2 failure study | N/A (failure taxonomy) | Type B failures: planning drift, repeated identical calls | Difficulty estimation, forced pivots, loop detection | Fully autonomous exploitation claims |
| ReactSwarm / pentest-agents brain.py | ReAct swarm, endpoint-tracking brain, auto-boost of paid technique classes | Per-target request semaphores, response tracking | Circuit breakers, per-tool-class locks | Unbounded concurrency |
| bountyhunter / claude-pentest / offensive-claude / bountyforge | Claude Code skill packs + modes | Mode profiles (fast/std/deep) as policy knobs | Profile-based hunt widths | Skill sprawl without validators |

## Patterns To Adopt (mapped to our harness)

1. Explicit campaign FSM persisted to `.bb/campaign-state.json` so `bb-hunt`
   resumes mid-phase instead of re-deciding (RECON, PLAN, EXECUTE, VERIFY, GRADE, REPORT).
2. Planner difficulty vectors: extend technique-kb entries with horizon estimate,
   evidence confidence needed, historical success rate from evaluation-harness.
   bb-hunt timeboxes or prunes branches exceeding remaining budget.
3. Circuit breakers in bb-run trace layer: N consecutive 403/429 triggers global
   backoff; shared per-target request semaphore across parallel workflows;
   per-category tool locks (nuclei and ffuf never simultaneous on one host).
4. Memory-first with negatives: program-memory records tested-and-clean endpoints
   and failed approaches; every workflow checks memory before firing, writes hits
   AND misses back after.
5. Hunt profiles: `--profile fast|std|deep` maps to surface promotion rules, wave
   width, verifier count. Early-stop when X tool calls yield no validated candidate.
6. Honest capability publication: plan output states expected per-vuln-class hit
   rates from evaluation-harness data instead of implying uniform coverage.

## Gaps Nobody Covers Well (opportunity map)

- Blind/timing exploitation judgment loops (MAPTA: 0% blind SQLi). OOB infra exists;
  differential-timing verdict automation is open territory.
- Authenticated multi-persona campaigns: persona + cross-account replay is ahead
  of the field here; lean into it.
- Business-logic invariant validation: barely explored anywhere; business-logic
  skill is differentiated.
- Adversarial-environment awareness (honeypot detection): zero shipped mitigations.
- Recon-to-exploit structured handoff: unstructured telemetry parsing causes ~50%
  recon recall loss; a typed intermediate representation between recon outputs and
  vuln-skill inputs would lift end-to-end numbers more than any agent tweak.
- Worker-layer safety enforcement: scope-enforcing hooks plus container egress
  policy would make this harness first among peers.
- Platform duplicate detection: disclosed-report RAG against own findings pre-submit.
- Multi-host chained campaigns with pivot tracking: untouched in open source.
- Real-target evaluation protocols (ethibench) instead of saturated CTF benchmarks.

## MCP Servers Worth Tracking

PortSwigger mcp-server (Burp control), raven-nest-mcp, mcp-security-hub,
mcpwner (AD-focused). Integration path: expose bb-run workflows as MCP tools so
external agents can drive the same governed pipeline.

## Key Sources

- github.com/vxcontrol/pentagi (docs/flow_execution.md)
- github.com/ipa-lab/hackingBuddyGPT, arxiv.org/abs/2310.11409
- github.com/aliasrobotics/cai, arxiv.org/abs/2504.06017
- arxiv.org/html/2508.20816v1 (MAPTA), xbow.com/blog/top-1-how-xbow-did-it
- arxiv.org/html/2602.17622v1 (PentestGPT v2 failure taxonomy)
- arxiv.org/html/2606.24496 (agentic red-team safety), arxiv.org/abs/2606.25332 (recon/exploit decoupling)
- github.com/BreachLine/reactswarm, github.com/H-mmer/pentest-agents
- github.com/drsharanthapa/bountyhunter, github.com/Stickman230/claude-pentest
- github.com/hypnguyen1209/offensive-claude, github.com/Gabson0x/bountyforge
- github.com/PortSwigger/mcp-server, github.com/FuzzingLabs/mcp-security-hub
