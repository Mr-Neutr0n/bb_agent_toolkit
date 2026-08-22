## Summary

<!-- What does this PR do? One or two sentences. -->

## Changes

-
-

## Checklist

- [ ] `make test` passes locally (YAML parse + py_compile for all 45 skills)
- [ ] `make validate` passes (skill quality validator)
- [ ] New/changed scripts pass `ruff check` and are invoked consistently with sibling scripts
- [ ] Bash changes pass `shellcheck bin/*`
- [ ] If adding a skill: SKILL.md, skill.yaml, >=3 scripts, >=1 runbook per workflow, >=2 payloads present
- [ ] Safety tier declared on skill and every intrusive workflow states its gate
- [ ] No secrets, cookies, tokens, or real target data anywhere in the diff
      (`make secrets` / gitleaks clean)
- [ ] Docs updated where behavior changed (SKILL.md, README catalog, AGENTS.md dispatch)

## Evidence (for new workflows)

<!-- Dry-run output or lab-target demonstration. Do NOT attach evidence from
     live bug bounty targets. Local fixtures only. -->
