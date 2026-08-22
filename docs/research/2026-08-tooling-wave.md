# Research Digest: Tooling Wave June-August 2026

Date: 2026-08-22. Two-month horizon scan requested after crt.name adoption.
Focus: what hunters/researchers shipped and discussed, what we adopted, what remains.

## What We Adopted This Session (commits 67ec4e3..94884a6)

| Adoption | Where | Source |
|---|---|---|
| crlf-desync probes (header injection -> desync, Range cache poisoning, status-line) | http-protocol | CRLF-Powered Desync Attacks + HTTP Terminator (Aug 2026 PortSwigger) |
| batch-confusion route confusion detection (wp2shell class, GET-only) | api | escape.tech wp2shell CVE-2026-63030 lineage |
| DOMPurify bypass classes payload pack (CVE-2026-49459 IN_PLACE clobber, PP gadget chain) | xss/payloads | Jun-Jul 2026 advisories |
| burp-mcp registry entry (proxy_driven_testing capability) | tools/registry | PortSwigger MCP server |
| trufflehog verified-mode entry | tools/registry | Aug 2026 TruffleHog talk |
| HackerOne IDV policy note on submission paths | reporting SKILL.md | H1 changelog Aug 5/14/17 |
| katana v1.7 -kb-secrets/-kb-endpoints with kb-event harvesting | recon js_recon | PD katana v1.7.0 |
| OSS hygiene: issue/PR templates, CoC, CHANGELOG, mermaid diagram, lint gates | repo root | best-practice comparison |

## Notable But Not Yet Adopted (tracked)

1. **HTTP Terminator micro-inspiration prompting**: fragment RFCs into small
   units before LLM hypothesis generation. Applies to technique-kb matching
   quality; needs an experiment harness run to justify integration.
2. **Shared-Parser Confusion** as standalone technique-kb category (Terminator).
   Requires reading the full paper before encoding detection heuristics.
3. **Cloudflare CT Monitoring + xReverseLabs daily dumps** as additional passive
   sources alongside crt.name. Both need API-shape evaluation.
4. **T3MP3ST multi-agent cells / CyberStrike signed skills**: agent-topology and
   skill-signing ideas; signing matters once third-party skill packs exist.
5. **certdrip-go WebSocket CT streamer**: real-time new-cert alerts; pairs with
   scope-manager guardrails for live asset watch.
6. **Firecrawl Developer Index**: semantic code/artifact search surface for
   osint/vuln-intel; evaluate Recall claims against our use cases.
7. **XBOW Mythos findings**: live-site access beats source access for real bugs;
   supports our browser-capture investment over static-analysis additions.
8. **Semgrep 14% TP reality check**: keeps human-in-the-loop framing correct.

## Key Strategic Reads

- Kettle's result (30k vectors, ~700 vulnerable systems) validates our
  expert-methodology-over-model-swap thesis: the ceiling comes from encoding
  technique knowledge, which is exactly what technique-kb + fat skills are.
- Scope enforcement became a product category (ThreatSwarm PreToolUse hooks,
  BurpMCP-Ultra gates): our bb-validate/circuit-breaker approach matches where
  the ecosystem landed; consider exposing scope checks as hooks too.
- Platforms formalizing AI-assisted submission policies (DEF CON panel + H1
  IDV) mean report provenance will matter: traces + artifact registry give us
  per-finding lineage most hunters lack.

## Sources

Primary URLs preserved inline above; see also:
- portswigger.net/research/can-ai-do-novel-security-research
- portswigger.net/research/crlf-powered-desync-attacks
- portswigger.net/research/css-the-bomb-inside-your-inbox
- github.com/projectdiscovery/katana/releases/tag/v1.7.0
- github.com/Cy-S3c/BurpMCP-Ultra
- zenity.io PleaseFix research
- blog.cloudflare.com/certificate-transparency-monitoring-ga
