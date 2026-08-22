# Research Ingest: Fresh 2026 Agent & MCP Security (cluster: fresh-2026-agent-mcp)

- **Freshness window:** 2026-06-01 .. 2026-08-15 (ingest date: 2026-08-15)
- **Operator rule applied:** CURRENT = published 2026-06-01 or later; RECENT = 2026-01-01..2026-05-31; OUTDATED = 2025 or earlier.
- **Scope:** MCP security (attack classes new since the 2025 wave), AI agent security (prompt injection, tool/skill abuse, memory attacks), agent supply chains, and AI-driven security testing. All 28 sources below are **CURRENT** (June–August 2026). Pre-June items are listed under "CHECKED & SKIPPED" at the bottom, never as current technique.
- **Date verification:** every source date was confirmed from the page (publication date line, arXiv listing, or datatracker metadata). Where only month-level precision is available (arXiv ID encodes YYMM), the entry says so explicitly. No source is included with an unverified date; unverifiable candidates were dropped.

## FRESHNESS-TIER TABLE

| # | Source | Published | Tier | Date verified |
|---|---|---|---|---|
| 1 | PolicyLayer — The State of MCP Security (June + July audit) | 2026-06-01 / 2026-07-01 | CURRENT | yes (page) |
| 2 | CISA — MCP Security Design Considerations (CSI) | 2026-06-02 | CURRENT | yes (gov URL) |
| 3 | IETF — draft-mohiuddin-mcp-security-considerations-00 | 2026-06-01 | CURRENT | yes (datatracker) |
| 4 | Penaxtra — MCP Tool Poisoning and the RCE You Inherited | 2026-06-19 | CURRENT | yes (page) |
| 5 | CYFIRMA — Exploitation of MCP in Agentic AI Deployments | 2026-06-19 | CURRENT | yes (page) |
| 6 | mcp-witness — MCP-S-014 DNS rebinding vs mcp-server-fetch | 2026-06-02 | CURRENT | yes (finding file) |
| 7 | Practical DevSecOps — MCP Security Statistics 2026 | 2026-06-26 | CURRENT | yes (page meta) |
| 8 | Microsoft Tech Community — The state of MCP security in 2026 | 2026-06-26 | CURRENT | yes (page) |
| 9 | MCP-Guard (ACL 2026 Findings) | 2026-07 | CURRENT | yes (ACL anthology) |
| 10 | Trail of Bits — The sorry state of skill distribution | 2026-06-03 | CURRENT | yes (page) |
| 11 | CSA — AI Agent Skill Scanners: Bypassed Across the Board | 2026-06-10 | CURRENT | yes (page) |
| 12 | Palo Alto Networks — MCP Servers Are the New Unmanaged API | 2026-06-04 | CURRENT | yes (page meta) |
| 13 | Unit 42 — Trust No Skill: Integrity Verification | 2026-06-11 | CURRENT | yes (page) |
| 14 | Unit 42 — OpenClaw's Skill Marketplace & AI Supply Chain Threat | 2026-06-23 | CURRENT | yes (page) |
| 15 | Microsoft IR — Securing AI agents: reading to acting | 2026-06-30 | CURRENT | yes (page) |
| 16 | PortSwigger — Introducing Burp AT | 2026-07-27 | CURRENT | yes (page meta) |
| 17 | PortSwigger — From capable AI models to trusted security testing | 2026-07-30 | CURRENT | yes (page meta) |
| 18 | PortSwigger Research — Can AI do novel security research? (HTTP Terminator) | 2026-08-05 | CURRENT | yes (page meta) |
| 19 | arXiv — LoginTrap (2608.04741) | 2026-08-05 | CURRENT | yes (arXiv) |
| 20 | arXiv — ShareLock (2606.27027) | 2026-06 | CURRENT | month (arXiv ID) |
| 21 | arXiv — PlanFlip (2607.16199) | 2026-07 | CURRENT | month (arXiv ID) |
| 22 | arXiv — GhostWriter, "When Agents Remember Too Much" (2607.06595) | 2026-07-06 | CURRENT | yes (arXiv) |
| 23 | arXiv — MAFIA (2608.03844) | 2026-08 | CURRENT | month (arXiv ID) |
| 24 | arXiv — MOSAIC (2607.02857) | 2026-07 | CURRENT | month (arXiv ID) |
| 25 | arXiv — FARMA, Forged Reasoning Attacks (2607.05029) | 2026-07-06 | CURRENT | yes (arXiv) |
| 26 | arXiv — PI-Hunter (2606.12737) | 2026-06 | CURRENT | month (arXiv ID) |
| 27 | arXiv — Adversarial Attacks in Multi-Agent LLM Pipelines (2608.00718) | 2026-08 | CURRENT | month (arXiv ID) |
| — | arXiv — Hybrid Analysis for Secure MCP Tool Use (2607.25297) | 2026-07 | CURRENT | month (arXiv ID) |

Tier counts: **CURRENT 28 / RECENT 0 / OUTDATED 0** (slice is a fresh-hunt, not an audit; nothing older than the window was ingested).

## SOURCES

### MCP attack surface (CURRENT)

1. **The State of MCP Security** — PolicyLayer, 2026-06-01 (June audit, 2,031 servers) updated 2026-07-01 (July audit, 32,820 servers). [CURRENT]
   https://policylayer.com/research/state-of-mcp
   Classified 517,973 tools across 32,820 working servers from public registries into six risk categories. 28.1% of servers expose at least one destructive tool (delete/drop/force-push/cloud removal); 26.2% can execute arbitrary commands; 43.28% expose a destructive-or-execute tool. Stacking math: the probability a 5-server agent stack exposes at least one such tool passes 94.1% (99.7% at 10). "delete" is the single most common first verb in tool names (9,542 tools). The first ecosystem-wide, registry-scale quantification of MCP reach.

2. **Security Design Considerations for AI-Driven Automation (MCP CSI)** — CISA, 2026-06-02. [CURRENT]
   https://media.defense.gov/2026/Jun/02/2003943289/-1/-1/0/CSI_MCP_SECURITY.PDF
   Government guidance positioning MCP as a trust boundary in AI-driven automation: treats tool declarations as untrusted input, requires gateway-level policy enforcement, credential scoping, and least-privilege for agent tool access. Useful as an authoritative checklist source for `ai-llm`/`agent-safety` coverage mapping.

3. **draft-mohiuddin-mcp-security-considerations-00** — IETF (M. Mohiuddin), 2026-06-01. [CURRENT]
   https://datatracker.ietf.org/doc/draft-mohiuddin-mcp-security-considerations/00/
   First IETF-track security-considerations draft for MCP: threat model for MCP clients/servers, transport security (SSE/HTTP), authorization boundaries, and registry/supply-chain trust. Signals the protocol is moving toward formal security review; monitor revisions for normative security requirements.

4. **MCP Tool Poisoning, and the RCE You Inherited — Reading the June 2026 Disclosures** — Penaxtra, 2026-06-19. [CURRENT]
   https://penaxtra.com/blog/mcp-tool-poisoning-sdk-rce-2026
   Aggregates the June 2026 disclosure wave: on 2026-06-16 OX Security disclosed a command-execution default in Anthropic's official MCP SDKs (Python/TypeScript/Java/Rust), estimated up to 200,000 vulnerable instances riding 150M+ downloads and 7,000+ publicly reachable servers. Carries a stats table: 5.5% of public MCP servers carry poisoned tool metadata (Invariant Labs), 84.2% tool-poisoning success with auto-approval on, 82% of 2,614 MCP implementations have path-traversal-prone file ops and 34% command-injection-susceptible APIs (Endor Labs), 24,008 secrets found in public MCP configs (2,117 still valid, GitGuardian). Includes a June-2026-oriented remediation checklist (patch SDK, sweep downstream bundles).
   Note: the underlying Ox Security research ("Mother of All AI Supply Chains") first published 2026-04-15 (pre-window, see CHECKED & SKIPPED); the June 16 disclosure phase and its downstream CVE wave are what make this in-window. The CVE-2026-30xxx cluster (below) is the June 2026 advisory event.

5. **Exploitation of Model Context Protocol in Agentic AI Deployments** — CYFIRMA, 2026-06-19. [CURRENT]
   https://www.cyfirma.com/research/exploitation-of-model-context-protocol-in-agentic-ai-deployments/
   Threat-intel treatment of MCP as an architectural attack surface: agents as "non-human identities" (credentialed principals that accumulate permissions across every connected MCP server, with no lifecycle governance/offboarding/rotation in most deployments). ~9,400 MCP servers in public registries and 150M+ tooling downloads by mid-2026. Frames a single instruction-channel compromise as autonomous machine-speed action across every integration in one context window.

6. **MCP-S-014: mcp-server-fetch SSE DNS rebinding** — mcp-witness (D. Deslishant), 2026-06-02. [CURRENT]
   https://github.com/desledishant10/mcp-witness/blob/main/findings/2026-06-02-MCP-S-014-mcp-server-fetch-sse-dns-rebinding.md
   Concrete transport-level bug: DNS rebinding against the reference fetch MCP server over SSE lets a malicious page reach localhost-bound MCP endpoints and exfiltrate tool results. The mcp-witness scanner has found/disclosed 6 vulnerabilities with 1 upstream fix verified. Confirms that classic web bugs (DNS rebinding) port directly onto agent plumbing in 2026.

7. **MCP Security Statistics 2026: CVEs, Vulnerabilities & Trends** — Practical DevSecOps, 2026-06-26. [CURRENT]
   https://www.practical-devsecops.com/mcp-security-statistics-2026-report/
   Longitudinal CVE/statistics roundup for MCP (2025 wave vs. 2026): vulnerability counts, exploitability trends, and patch cadence across MCP servers, SDKs, and IDEs. Useful for severity baselines when triaging agent-infra findings.

8. **The state of MCP security in 2026** — Microsoft Security Community Blog, 2026-06-26. [CURRENT]
   https://techcommunity.microsoft.com/blog/microsoft-security-blog/the-state-of-mcp-security-in-2026/4531327
   Vendor checkpoint on where MCP risk sits in 2026: the latest MCP spec release candidate raises the security baseline — requests now carry what a gateway needs to inspect/enforce per call (no hidden session), tighter client-server identity checks, and a new "MCP Apps" capability whose interactive UI the host renders inside a sandbox. Explicitly warns "we reviewed MCP last year" is out of date. Maps risk to the OWASP Agentic Top 10.

9. **MCP-Guard: A Multi-Stage Defense-in-Depth Framework for Securing MCP** — Xing et al., ACL 2026 Findings (2026.findings-acl.240), July 2026. [CURRENT]
   https://aclanthology.org/2026.findings-acl.240/
   Three-stage MCP defense: lightweight static scanning → deep neural detector for semantic attacks (fine-tuned E5-based model, 96.01% adversarial-prompt accuracy) → LLM arbitrator synthesizing signals. Ships MCP-AttackBench, a 70,448-sample benchmark (GPT-4-augmented) simulating attack vectors that bypass conventional MCP defenses. First peer-reviewed benchmark for MCP-specific attack detection.

### AI agent security — supply chain & skills (CURRENT)

10. **The sorry state of skill distribution** — Samuel Judson / Trail of Bits, 2026-06-03. [CURRENT]
    https://blog.trailofbits.com/2026/06/03/the-sorry-state-of-skill-distribution/
    Bypassed all tested skill scanners — ClawHub's (VirusTotal Code Insight + GPT-5.5 guard model), Cisco's open-source skill-scanner, and all three skills.sh integrations (Gen Agent Trust Hub, Socket, Snyk) — with four low-effort skills (PoCs in trailofbits/overtly-malicious-skills): (1) ~100,000-newline padding truncates ClawHub's harness before the payload; (2) malicious logic in precompiled .pyc bytecode ignored by static analyzers (the xz-utils pattern); (3) SKILL.md indirection into a .docx/ZIP archive hiding a shell payload; (4) prompt injection dressed as corporate policy fooling LLM analyzers (Cisco's Claude Sonnet 4.6 judged it safe, LOW severity). Three of four took under an hour. Conclusion: "No amount of scanning or LLM analysis can reliably detect malicious content in agent skills" — treat public skill repositories as untrusted code.

11. **AI Agent Skill Scanners: Bypassed Across the Board** — Cloud Security Alliance, 2026-06-10. [CURRENT]
    https://labs.cloudsecurityalliance.org/research/csa-research-note-ai-agent-skill-scanner-bypass-20260610-csa/
    Independent analysis of the ToB findings plus a parallel DEV-community study of classical obfuscation (base85+XOR, UTF-8 affine transforms, multi-stream transposition) against the same scanners: Socket produced no Critical/High alerts even for unobfuscated baselines; Snyk downgraded findings under content splitting; only Gen kept Critical/High detection across conditions. Also covers NVIDIA's SkillSpector (open-sourced May 2026, 64 patterns/16 categories, ~87% claimed precision, but cannot analyze encrypted/binary code). Confirms scanner fragmentation: no single scanner covers all bypass classes.

12. **MCP Servers Are the New Unmanaged API. Start Treating Them That Way.** — Palo Alto Networks Blog, 2026-06-04. [CURRENT]
    https://www.paloaltonetworks.com/blog/cloud-security/mcp-servers-ai-attack-surface-security/
    Frames MCP servers as an unmanaged-API sprawl problem: no inventory, no versioning, no access control discipline. Argues for treating MCP endpoints as first-class API assets (discovery, classification, policy) — directly applicable to `recon`/`asset-graph` surface mapping for agentic targets.

13. **Trust No Skill: Integrity Verification for AI Agent Supply Chains** — Yuhao Wu, Tony Li, Hongliang Liu / Unit 42, 2026-06-11. [CURRENT]
    https://unit42.paloaltonetworks.com/ai-agent-supply-chain-risks/
    Introduces Behavioral Integrity Verification (BIV), an audit primitive that compares what a skill claims to do against what it does across three surfaces: metadata, executable code, and natural-language instructions. At registry scale, most skills deviate from declared behavior (mostly sloppy docs) but a dangerous slice carries multi-stage attack chains where individually benign-looking capabilities combine into credential theft, RCE, or silent exfiltration. Positions the skill ecosystem where mobile apps/browser extensions were a decade ago; recommends BIV-style checks before install, not after.

14. **OpenClaw's Skill Marketplace and the Emerging AI Supply Chain Threat** — Unit 42, 2026-06-23. [CURRENT]
    https://unit42.paloaltonetworks.com/openclaw-ai-supply-chain-risk/
    Found five malicious skills that evaded ClawHub's VirusTotal + ClawScan screening (Feb–May 2026 analysis): two macOS infostealers with C2 infrastructure, one evasion skill using file-size inflation to exceed scanner thresholds, and two **novel agentic threats** — "runtime agentic affiliate injection" (a skill that injects affiliate/promotional instructions into the agent's runtime at execution time) and "agentic front-running" (a skill that intercepts and races the agent's own pending actions). All five reported and taken down. The evasion technique independently confirms ToB's truncation finding (#10).

15. **Securing AI agents: When AI tools move from reading to acting** — Microsoft Incident Response, 2026-06-30. [CURRENT]
    https://www.microsoft.com/en-us/security/blog/2026/06/30/securing-ai-agents-ai-tools-move-from-reading-acting/
    Incident-response playbook for the poisoned-MCP-tool-metadata attack pattern (maps to OWASP ASI02 Tool Misuse / ASI04 Agentic Supply Chain). Key shift: "a prompt injection against an agent can trigger an action" — read-write agents change the impact profile. Cites IDC projection of 28.6M (2025) → 2.2B (2030) active enterprise agents. Detection/containment/prevention guidance using Microsoft security controls; first-party incident-response validation that MCP tool poisoning is being observed in enterprise environments, not just labs.

### AI agent security — memory, multi-agent, web/coding agents (CURRENT, arXiv)

16. **LoginTrap: Task-Agnostic Phishing-Style Indirect Prompt Injection against LLM-based Web Agents** — Guo et al. (Tongji), arXiv:2608.04741, 2026-08-05. [CURRENT]
    https://arxiv.org/abs/2608.04741v1
    Black-box, task-agnostic login-inducing attack: page-specific indirect injections (fuzzing-inspired generation) make login appear a plausible prerequisite, steering the agent to an attacker-controlled login page to steal credentials — 86% average end-to-end attack success across LLM backbones, effective across agent architectures and existing defenses. Identifies login inducement as a systematic authentication-boundary risk for web agents.

17. **ShareLock: A Stealthy Multi-Tool Threshold Poisoning Attack Against MCP** — Liu et al. (Shanghai Jiao Tong), arXiv:2606.27027, June 2026 (month-level from arXiv ID). [CURRENT]
    https://arxiv.org/abs/2606.27027v1
    First systematic treatment of multi-tool poisoning: distributes the malicious instruction across several MCP tools as Shamir-secret-share-like fragments (threshold scheme) so no single tool description looks malicious — defeats manual inspection and per-tool detectors while the assembled payload activates when the model reads enough fragments. Directly attacks the per-tool scanning assumption behind most 2025-2026 defenses.

18. **PlanFlip: Attacking Multi-Agent LLM Systems via Planning-Phase Prompt Injection** — Wang (Fudan), arXiv:2607.16199, July 2026. [CURRENT]
    https://arxiv.org/abs/2607.16199v1
    Four planning-phase injections (GoalSubstitution PF-1, PriorityInversion PF-2, ContextPollution PF-3, RoleConfusion PF-4) disguised as plausible tool outputs; a single injection into the Planner's context cascades to corrupt all downstream sub-task plans. Across nine frontier LLMs / 3,479 episodes: GPT-5 has the highest ASR (0.68) — capability amplifies vulnerability; and homogeneous pipelines show a "correlated-agent blind spot" where the same-backbone Critic reports alignment while plans are actually restructured (independent judges: −0.20 to −0.32 semantic deviation). Planner-vs-critic homophily is a new defense-bypass finding.

19. **When Agents Remember Too Much: Memory Poisoning Attacks on LLM Agents (GhostWriter)** — Torres, Shrestha, Misra (NMSU), arXiv:2607.06595, 2026-07-06. [CURRENT]
    https://arxiv.org/abs/2607.06595
    GhostWriter: two-phase attack (injection of a hidden payload via untrusted content; activation when poisoned memory is retrieved) against long-term memory in tool-using personal agents. Near-universal injection (~98%) with ~60% average activation against SOTA agents, exploiting the lack of security-focused memory governance. Proposes "Agentic Memory Sentry" (AMS) as defense. Memory poisoning is now demonstrated against production-grade personal agents with tools, not just chat models.

20. **MAFIA: Query-Only Memory Attacks via Probing and Factual Injection against Audited LLM Agents** — Chen et al. (HKUST), arXiv:2608.03844, August 2026. [CURRENT]
    https://arxiv.org/abs/2608.03844v1
    Extends query-only memory poisoning to two realistic settings where MINJA-style (2025) attacks fail: large benign memory pools (retrieval competition) and active input auditing. Placement strategy via memory probing + budget allocation/scheduling, and payloads wrapped in "compact factual cloaks" that preserve malicious effect while passing semantic similarity checks. Memory attacks now defeat retrieval-competition and audit defenses.

21. **MOSAIC: Knowledge-Guided CLI Command Composition Attack in LLM Coding Agents** — Wu et al. (Sun Yat-sen/PKU/HKUST), arXiv:2607.02857, July 2026. [CURRENT]
    https://arxiv.org/abs/2607.02857v1
    New exploit surface for coding agents: "CLI command-composition risk" (CCR) — individually benign CLI commands form a dangerous producer-consumer state relation across the command trace (one command writes OS state a later command reads), even when no single command contains malicious text. Attacks and defenses that only target the instruction layer miss this. Systematic, knowledge-guided enumeration replaces naive command generation.

22. **Your Agent's Memories Are Not Its Own: Forged Reasoning Attacks on LLM Agent Memory and Defenses (FARMA)** — Karamchandani et al. (Penn State), arXiv:2607.05029, 2026-07-06. [CURRENT]
    https://arxiv.org/abs/2607.05029
    "Forged Amplifying Rationale Memory Attack": poisons the agent's *reasoning history* (rationale/chain-of-thought records), not just stored facts — forged rationales amplify future decisions toward attacker goals. Distinct from fact-poisoning (MINJA/MAFIA): targets the evidence trail the agent (and auditors) trust when reconstructing why an action was taken.

23. **PI-Hunter: Automated Red-Teaming for Exposing and Localizing Prompt Injections** — He et al. (Google Cloud AI Research), arXiv:2606.12737, June 2026. [CURRENT]
    https://arxiv.org/abs/2606.12737v1
    Defense-side automation: existing red-teaming optimizes attack success only; PI-Hunter also *localizes* where the injection landed, so fixes target the actual vulnerable component (tool description vs memory vs retrieved content). Google-backed tooling for systematic injection auditing.

24. **Adversarial Attacks in Multi-Agent LLM Pipelines: Unveiling Structural Vulnerabilities in Agentic AI Architectures** — Bappy et al. (UMBC et al.), arXiv:2608.00718, August 2026. [CURRENT]
    https://arxiv.org/abs/2608.00718v1
    Single-agent-free security gap: in multi-agent pipelines, once one agent accepts adversarial content it is propagated as *trusted* input throughout the pipeline — intermediate outputs are the new injection channel. Structural, architecture-level vulnerability absent from single-agent settings.

25. **Hybrid Analysis for Secure MCP Tool Use in LLM Agents** — He et al. (Zhejiang Univ. / Alibaba), arXiv:2607.25297, July 2026. [CURRENT]
    https://arxiv.org/abs/2607.25297v1
    Defense for MCP tool misuse: prior work is static-only (inspecting prompts/generations); this combines static analysis with dynamic behavior verification of MCP tool invocations. Positions dynamic checking as the missing half of MCP tool-use defenses (aligns with BIV-style behavioral verification in #13).

### AI agent security — testing tooling (CURRENT)

26. **Introducing Burp AT: agentic AI, built on two decades of Burp Suite** — PortSwigger, 2026-07-27. [CURRENT]
    https://portswigger.net/blog/introducing-burp-at
    PortSwigger's entry into agentic security testing — an AI-driven assistant embedded in Burp. Product signal that the toolchain mainstream is moving toward agent-assisted testing; useful as context for how 2026 testing workflows are being reshaped (and what an "agent tester" can/can't be trusted for).

27. **From capable AI models to trusted security testing** — PortSwigger, 2026-07-30. [CURRENT]
    https://portswigger.net/blog/from-capable-ai-models-to-trusted-security-testing
    PortSwigger's framing of what it takes to make AI models *trusted* for security testing (verification, traceability, containment) — the trust-and-verification problem that separates "AI does research" demos from production testing. Complements the HTTP Terminator research below.

28. **Can AI do novel security research? Meet the HTTP Terminator** — James Kettle / PortSwigger Research, 2026-08-05 (companion blog 2026-08-12). [CURRENT]
    https://portswigger.net/research/can-ai-do-novel-security-research
    James Kettle's first substantial public result on AI performing *novel* security research: an agent that independently discovered and weaponized new HTTP-level attack techniques (HTTP Terminator), going beyond regurgitated CVEs. Bleeding-edge on two axes: (a) what autonomous agents can do to web targets (capability signal for what AI-driven attacks will look like), and (b) methodology for verifying agent-discovered findings (relevant to `impact-verifier` for AI-generated findings).

## CONCEPTS

### MCP attack surface, 2026 wave

- [technique] **Config-to-exec / MCP-by-design RCE (CVE-2026-30615/30617/30618/30623/30624/30625/33224/26015/40933).** Anthropic's official MCP SDKs (Python/TS/Java/Rust) accept `StdioServerParameters` command/args/cwd/env and pass them raw to process spawn; any user-controlled config channel (UI field, JSON config, marketplace package, transport-type substitution) becomes RCE. Anthropic's position: STDIO execution is "expected"/a secure default — no upstream fix, burden on operators (allowlist executables, schema-validate args, strip dangerous env vars, sandbox child processes). First disclosed April 2026 (OX Security, pre-window), June 16, 2026 disclosure wave per Penaxtra; the CVE-2026-30xxx cluster is the June 2026 advisory event. ~200k estimated instances, 150M+ downloads, 7k+ internet-reachable servers. (Penaxtra / CYFIRMA)
- [technique] **Transport-type substitution (CVE-2026-26015, DocsGPT).** An attacker who can POST an MCP server config can flip the declared transport from SSE/HTTP to STDIO and append an arbitrary command; the server executes it on connection. STDIO is enabled internally even where UIs only expose remote transports — hidden-STDIO hunting is a 2026 test step. (Penaxtra / OX disclosure via Penaxtra)
- [technique] **Zero-click prompt injection → local RCE in IDEs (CVE-2026-30615, Windsurf).** Windsurf modified MCP config files from page content without consent, chaining web-page prompt injection straight into local command execution. Test IDE MCP config handling for consentless writes — the "requires user consent" assumption that protects most IDEs is not universal. (Penaxtra / CSO coverage via Penaxtra)
- [technique] **Allowlist bypass via npx (CVE-2026-30625 Upsonic / CVE-2026-40933 Flowise).** Hardened MCP configs that allowlist `npx` inherit `npx -c` arbitrary-command execution. Any allowlist containing a package-runner binary is a bypass primitive. (Penaxtra)
- [technique] **DNS rebinding against MCP fetch servers (MCP-S-014).** Malicious web page rebinds a domain to 127.0.0.1 between resolution and connection, reaching localhost MCP endpoints over SSE and exfiltrating tool results. Classic web bug, freshly confirmed against reference MCP servers June 2026. (mcp-witness)
- [measurement] **Ecosystem-scale destructive-tool exposure.** 43.28% of MCP servers expose destructive-or-execute tools; the probability a 5-server agent stack hits one is 94.1%. Tool-permission audits are now a baseline requirement, not a nice-to-have. (PolicyLayer)
- [measurement] **Poisoned-metadata prevalence 2026.** 5.5% of public MCP servers carry poisoned tool metadata; 84.2% tool-poisoning success with auto-approval; 82% of implementations have path-traversal-prone file ops; 34% command-injection-susceptible APIs; 2,117 still-valid secrets in public MCP configs. (Penaxtra aggregation)
- [defense] **Gateway-inspectable MCP (spec RC).** New MCP release-candidate changes: requests carry everything a gateway needs to inspect/enforce per call, tighter client-server identity, "MCP Apps" UI rendered in a host sandbox. Re-audit with each spec revision — "we reviewed MCP last year" is explicitly stale. (Microsoft)
- [defense] **Three-stage MCP defense + benchmark.** Static scan → deep semantic detector (96.01%) → LLM arbitrator; MCP-AttackBench (70,448 samples) is the first shared benchmark for MCP attack detection. Use it as a test corpus for `ai-llm` workflows. (MCP-Guard, ACL 2026)
- [defense] **Hybrid static+dynamic MCP tool verification.** Static prompt/generation inspection alone misses runtime behavior; combine with dynamic verification of what tools actually do (parallels BIV). (Hybrid Analysis arXiv; Unit 42 BIV)

### Agent supply chain & skills (the June 2026 story)

- [technique] **Scanner-truncation evasion.** Prepending ~100k newlines pushes the payload past the scanner's size/context limit; VirusTotal Code Insight and a GPT-5.5 guard model both missed it. File-size inflation is also observed in the wild (Unit 42's OpenClaw finding). Test your own pipeline's truncation behavior before trusting scan results. (Trail of Bits / Unit 42)
- [technique] **Bytecode-as-payload (.pyc).** Ship benign-looking source + malicious precompiled bytecode; static analyzers and LLM analyzers skip binary artifacts. The xz-utils pattern, now in agent skills. (Trail of Bits)
- [technique] **Archive indirection.** SKILL.md points at a .docx (ZIP) containing the real instructions + shell payload; scanners only follow files explicitly referenced or known-executable types. (Trail of Bits)
- [technique] **LLM-scanner social engineering.** Malicious package-registry redirection framed as corporate policy text passes LLM-based risk analysis (Cisco's Sonnet 4.6: `is_safe: true`, LOW). LLM-as-judge scanning is vulnerable to persuasion, not just injection. (Trail of Bits)
- [technique] **Multi-tool threshold poisoning (ShareLock).** Malicious instruction split across multiple MCP tool descriptions via Shamir-style secret sharing; no single tool looks malicious, assembled payload activates across tools. Defeats per-tool detectors and manual review. (ShareLock arXiv)
- [technique] **Runtime agentic affiliate injection & agentic front-running.** Novel in-the-wild OpenClaw skill classes: injecting affiliate/promotional instructions into the agent's runtime at execution time, and racing/intercepting the agent's pending actions (front-running its decisions). "Agentic front-running" is a new behavioral class worth adding to `business-logic`/`ai-llm` technique lists. (Unit 42)
- [technique] **Behavioral-integrity gaps.** Skills routinely deviate from declared behavior across metadata/code/natural-language surfaces; multi-stage chains combine benign-looking capabilities into credential theft/RCE/exfiltration. Registry-scale auditing must compare claims vs. behavior, not just scan for malice. (Unit 42 BIV)
- [defense] **Scanner pessimism.** ToB: "No amount of scanning or LLM analysis can reliably detect malicious content in agent skills"; recommend curated marketplaces, pinning, version control, no auto-install, and treating public skill repos as untrusted code. CSA confirms fragmentation (Socket/Snyk miss classical obfuscation; only Gen held detection). (Trail of Bits / CSA)

### Memory attacks (2026 wave supersedes 2025 single-shot claims)

- [technique] **GhostWriter: hidden-payload memory injection + retrieval-time activation.** Injection via untrusted content with no privileged access; ~98% injection / ~60% activation against SOTA tool-using personal agents. Memory governance, not model hardening, is the gap. (GhostWriter arXiv)
- [technique] **Memory attacks that survive retrieval competition + auditing (MAFIA).** Probing-based placement and budgeted scheduling defeat large benign memory pools; "compact factual cloaks" keep malicious payloads semantically similar so they pass input auditing. The 2025 MINJA claim "query-only poisoning works" is now extended to realistic audited deployments — and old defenses (semantic filters) are explicitly bypassed. (MAFIA arXiv)
- [technique] **Forged reasoning (FARMA).** Poison the agent's stored rationale/chain-of-thought records rather than facts; future decisions amplify toward attacker goals while the agent's evidence trail (and auditors) look consistent. Distinct from fact-poisoning; targets explainability and audit tooling. (FARMA arXiv)
- [technique] **Login inducement for credential theft (LoginTrap).** Web agents can be steered into attacker-controlled login flows via page-specific injections — 86% end-to-end success; the authentication boundary of web agents is systematically untested. (LoginTrap arXiv)

### Multi-agent & pipeline attacks

- [technique] **Planning-phase injection with cascade amplification (PlanFlip).** One injection into the Planner corrupts all downstream sub-tasks (GoalSubstitution/PriorityInversion/ContextPollution/RoleConfusion); stronger models are more vulnerable (GPT-5 ASR 0.68); same-backbone Critic blind spot means homogeneous multi-agent pipelines self-approve corrupted plans. Test planners as a single point of failure, and vary backbone diversity. (PlanFlip arXiv)
- [technique] **Trusted-propagated adversarial output.** In multi-agent pipelines, once an agent accepts adversarial content it flows downstream as trusted input — intermediate outputs are an injection channel absent in single-agent systems. (Multi-agent arXiv)
- [technique] **CLI command-composition risk (CCR) in coding agents.** Individually benign commands form dangerous producer-consumer state relations across a command trace (MOSAIC). Instruction-layer scanning misses this; test coding agents for stateful command sequences, not just single-command injection. (MOSAIC arXiv)

### Agent-driven security testing (2026 direction)

- [methodology] **Automated red-teaming with localization (PI-Hunter).** Optimize for *where* the injection lands, not just whether it succeeds — fixes then target the actual vulnerable component. (PI-Hunter arXiv)
- [methodology] **AI-discovered novel attack techniques.** HTTP Terminator: an agent independently found and weaponized new HTTP-level techniques — evidence that agent-driven research is producing genuinely new attack classes, and that AI-generated findings need verification rigor (no trusting AI output without impact proof). (PortSwigger Research)
- [context] **Product shift: agentic testing tools.** Burp AT and "trusted security testing" framing signal that 2026 testing workflows increasingly pair agents with verification/containment layers. (PortSwigger)

## CHECKED & SKIPPED (pre-June 2026 — not ingested as sources)

Verified dates outside the freshness window; kept out per the freshness rule. Listed for provenance only, never as current technique:

- OX Security "Mother of All AI Supply Chains" MCP STDIO research — 2026-04-15 (pre-window; the June 16, 2026 disclosure wave and CVEs are covered via Penaxtra/CYFIRMA above). Also: CSA research note on the same topic (2026-04-20), CSO Online coverage (2026-04-17).
- Ox Security "MCP by Design" / "The Architectural Flaw at the Core of Anthropic's MCP" blog — 2026-04-15.
- Microsoft "Securing MCP: A Control Plane for Agent Tool Execution" — 2026-04-22.
- agentlair "State of MCP Security: Q1 2026" — 2026-04-30.
- Unit 42 "Navigating Security Tradeoffs of AI Agents" — 2026-03-18; "Fooling AI Agents: Web-Based Indirect Prompt Injection Observed in the Wild" — 2026-03-03; "Cracks in the Bedrock: Agent God Mode" — 2026-04-08; "Double Agents: GCP Vertex AI" — 2026-03-31.
- Trail of Bits "Jumping the line" (2025-04-21), "How MCP servers can steal your conversation history" (2025-04-23), "We built the security layer MCP always needed" (2025-07-28) — all 2025.
- Huntr blog "Hunting Vulnerabilities in Keras Model Deserialization" — 2025-06-19 (MFV content is the fresh-huntr-blog slice's domain; this post itself predates the window).
- arXiv 2604.05969 formal MCP security framework — April 2026.
- Coalition for Secure AI "Practical Guide to MCP Security" — 2026-01-20.
- Axels' Medium walkthroughs of PortSwigger Web LLM labs — 2026-05-04/05-18/05-26.

## HOW THIS CHANGES OUR HARNESS

- **`ai-llm` skill**: add a "June 2026 MCP disclosure" workflow — audit STDIO config channels (`StdioServerParameters` command/args/env reaching spawn), test transport-type substitution (SSE/HTTP → STDIO), hunt hidden-STDIO handlers, and check allowlists for package-runner binaries (`npx -c` bypass). All active-safe against your own infra.
- **`agent-safety` skill**: tool descriptions, skill manifests, memory records, *and stored reasoning histories* are untrusted model input (2026 additions: ShareLock multi-tool threshold splits, FARMA forged rationales, MAFIA audit-evading cloaks). Add skill-scanner-evasion awareness — never rely on a scanner alone; treat public skill repos as untrusted code (ToB).
- **`business-logic`**: register "agentic front-running" and "CLI command-composition risk" as new technique classes; planning-phase injection (PlanFlip) belongs in multi-agent targets.
- **`persona`/`cross-account`**: MAFIA/GhostWriter extend the MINJA cross-account memory-poisoning primitive to audited and retrieval-competitive deployments — test whether one persona's interactions poison shared memory *and* survive semantic filters.
- **`impact-verifier`**: AI-generated findings (HTTP Terminator direction) and config-to-exec bugs need verification of the *spawned side effect* (command executed even when SDK returns an error — the side effect precedes the error path); memory attacks need evidence of the poisoned record + retrieval, not just a prompt/response pair.
- **`technique-kb`/`planner`**: register the 2026 chains — config-channel→RCE, multi-tool threshold poisoning, login inducement for web agents, planning-phase cascade, transport-type substitution, hidden-STDIO, scanner-truncation/bytecode evasion — with preconditions (MCP server present, skill marketplace, shared memory, planner-based pipeline, web-agent deployment).
