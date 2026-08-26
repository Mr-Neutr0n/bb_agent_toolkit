# Severity Ranker

## Overview
Re-rank findings by bounty impact using a composable markdown ranker, inspired by Kritt's severity rankers. A ranker is plain markdown describing your triage policy (Critical/High/Medium/Low/Informational). The `rank_findings` workflow applies it deterministically via keyword heuristics, or via LLM if `OPENAI_API_KEY` is set and `--llm` is passed.

## Quick Reference
- Payload: `.claude/skills/reporting/payloads/severity_ranker_default.md` (and any custom `*.md` you add)
- Command: see `skill.yaml` `rank-findings` workflow

## Workflow

```bash
# Heuristic ranking using default ranker
python3 .claude/skills/reporting/scripts/rank_findings.py \
  --findings output/acme/impact-verifier/verified.jsonl \
  --ranker .claude/skills/reporting/payloads/severity_ranker_default.md \
  --output output/acme/reports/ranked.jsonl

# Compose multiple rankers (concatenated in order)
python3 .claude/skills/reporting/scripts/rank_findings.py \
  --findings verified.jsonl \
  --ranker rankers/bug-bounty.md rankers/program-x.md \
  --output ranked.jsonl

# LLM-backed ranking (requires OPENAI_API_KEY)
python3 .claude/skills/reporting/scripts/rank_findings.py \
  --findings verified.jsonl --ranker ranker.md --llm --output ranked.jsonl

# Dry run preview
python3 .claude/skills/reporting/scripts/rank_findings.py \
  --findings verified.jsonl --ranker ranker.md --output /tmp/out.jsonl --dry-run
```

## Custom rankers
Create a markdown file with `## Critical`, `## High`, etc. sections. The heuristic
uses keyword lists derived from those headings; the LLM path uses the markdown verbatim
as system prompt. Keep it under a few hundred lines.

Example composite:
```bash
cat .claude/skills/reporting/payloads/severity_ranker_default.md my-program-ranker.md > /tmp/combined.md
```

## Evidence Required
- `ranked.jsonl` with `bounty_rank` and `bounty_rank_impact_level` per finding
- Original order preserved via stable sort; ranks are 1..N contiguous
