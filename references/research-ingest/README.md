# Research Ingest Index

Last updated: 2026-08-15 · Freshness window: CURRENT = 2026-06-01+, RECENT = 2026-01-01..05-31,
OUTDATED = 2025 and earlier (legacy context only). Every source date is page-verified;
pre-June content is annotated `[superseded-risk]` where it may describe already-fixed issues.

## Corpus (9 topic files, 210 candidate records)

| File | Tier | Records | Core content |
|---|---|---|---|
| fresh-2026-agent-mcp.md | **CURRENT** | 33 | June-16 MCP SDK RCE wave (CVE-2026-30615/30623...), Trust-No-Skill, OpenClaw, ShareLock multi-tool poisoning, PlanFlip planning cascade, MAFIA/MOSAIC, CISA MCP CSI |
| fresh-2026-web-exploit.md | **CURRENT** | 19 | CRLF-powered desync + HTTP Terminator (dangling-byte RQP, Response Forking, Range Cache Poisoning, CVE-2026-63078), QUIC/H3 smuggling, nginx rift+PoolSlip RCE (CVE-2026-42945/9256), WP2Shell pre-auth RCE, Cloudflare path-normalization bypass |
| fresh-2026-huntr.md | **CURRENT** | 14 | Huntr 2.0 challenge-mode (AskNova/Inside Job), tool-call fast lane, token-golf/tokenizer forensics, 10× model-r/w multiplier, MFV program sunset watch |
| ai-ml-hunting-2025.md | recent/outdated | 27 | Keras config-as-code RCE (CVE-2025-1550 + gadget bypass), ModelScan evasion taxonomy, Hydra `_target_` metadata RCE (2026-01), MFV format value tiers |
| exploitdev-1day.md | recent/outdated | 24 | Patch→root-cause→variant loop, LLM patch-diff triage (OriginHQ/ReachForge 2026-06), escalation triad (write+read+render sink), K-REPRO kernel n-day |
| llm-agent-security.md | outdated | 22 | 2025 MCP/agent classes — ALL `[superseded-risk]`: re-verify against 2026 fixes before relying |
| web-modern-2025.md | recent/outdated | 28 | Parser Discrepancy Scan, desync trigger catalog, cache-deception checklist, OAuth 2.1 draft-15 |
| mlops-supplychain-2025.md | recent/outdated | 18 | Model artifacts = executable code, MLflow registry→RCE, typosquatting/token-leak heuristics |
| huntr-community.md | outdated+current | 25 | taiphung217 philosophy (target selection, 1-day variants, escalate-before-report, RCE-only), pre-2.0 economics = superseded, challenge-mode notes |

## Operating philosophy distilled (from huntr-community + fresh-2026-huntr)
1. **Target selection is the highest-leverage step** — pick hard, high-impact repos/programs; the
   payout gradient rewards RCE-class over bug-count.
2. **1-day variant hunting is the primary technique** — study prior reports on the same project,
   find siblings/variants elsewhere in the codebase (patch → root cause → sink rule).
3. **Escalate before reporting** — hold a traversal, chain write→render→RCE over days; report the
   chain, not the first hop.
4. **Manual + automated split** — doc-reading + logic analysis (manual); Joern/AFL++/LLM-triage
   (automated).
5. **Freshness is a weapon** — in the AI boom, June-2026 knowledge beats 2025 writeups; re-verify
   every 2025 CVE-class against current code before spending time on it.

## How this changes the harness (proposed follow-ups, NOT yet implemented)
- `ai-llm` skill: add MCP attack surface (config-to-exec, tool-description injection, sampling
  channel) from fresh-2026-agent-mcp — the 2025 injection playbook is stale.
- `http-protocol` skill: add HTTP Terminator/CRLF-desync trigger catalog (dangling-byte, RQP,
  Response Forking) from fresh-2026-web-exploit.
- New skill candidate: `model-format` hunting (config-as-code, metadata-RCE, scanner-evasion
  taxonomy) from ai-ml-hunting-2025 + mlops-supplychain.
- `technique-kb`: all 210 candidate records in `candidates/*.jsonl` are schema-ready for review
  and promotion (fields: title, source_url, source_date, concept_type, summary, applicable_skills,
  safety_tier, tags, confidence, freshness_tier).
- `vuln-intel`: CVE-2026-63078 missing from NVD — cite with care; MCP SDK CVE wave deserves a
  tracked cluster.

## Provenance
All content attributed (source_url + date per record). Corpus is local-only knowledge —
nothing here authorizes testing anything; safety tiers remain enforced by tools/safety_profiles.yaml.
LocalAI/MLflow/Dify/transformers findings from the hunt sessions remain in output/scratch/huntr-mfv/
and are marked NOT SUBMITTED per operator note.
