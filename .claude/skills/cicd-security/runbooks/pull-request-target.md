# pull_request_target Misuse (Critical)

`pull_request_target` runs in the context of the BASE repo (has secrets) but can
be tricked into checking out and running attacker code.

## Vulnerable pattern

```yaml
on: pull_request_target

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
        with:
          ref: ${{ github.event.pull_request.head.sha }}  # ← attacker code!
      - run: npm test  # runs attacker's package.json scripts
```

## Why it's critical

- `pull_request_target` has access to secrets
- Checkout uses the PR's code
- Any `run:` step executes attacker-controlled code with access to all org secrets

## Detection

```bash
grep -rn 'pull_request_target' .github/workflows/
# Then check if the same job does a checkout of the PR head
grep -A 20 'pull_request_target' .github/workflows/*.yml | grep -E '(head\.sha|head_ref|checkout)'
```

## Validation before reporting

- Confirm the repo accepts PRs from forks (public repo)
- Confirm the workflow has access to secrets (not `secrets: inherit` restricted)
- Do NOT open a real PR against production without written program permission
