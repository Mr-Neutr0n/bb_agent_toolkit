# Self-Hosted Runner Poisoning + Supply Chain

## Why it matters

Public repos with self-hosted runners allow ANY fork to queue jobs on internal
machines.

## Detection

```bash
grep -rn 'self-hosted' .github/workflows/
# Combined with — does the repo accept PRs from forks?
grep -B5 'self-hosted' .github/workflows/*.yml | grep -E '(pull_request|push)'
```

## Exploit path

1. Fork public repo that uses self-hosted runners
2. Open PR with malicious workflow step
3. Job runs on internal self-hosted runner
4. Access internal network, read instance metadata, exfil secrets

## Dependency confusion / unpinned actions

```yaml
# VULNERABLE — could be hijacked if maintainer's account is compromised
uses: actions/checkout@v3

# SAFE — pinned to a specific commit SHA
uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
```

Dependency confusion attack:
1. Find `package.json` / `requirements.txt` referencing internal packages
2. Check if the internal package name is published on npm/PyPI
3. Publish a malicious package with a higher version number
4. Build server installs the public (malicious) one instead

## Chaining

- Chain A: IDOR on repo settings → read CI/CD config → workflow injection → org secret exfil
- Chain B: stored XSS on GitHub Enterprise → GITHUB_TOKEN theft → trigger malicious workflow → RCE on build infra
- Chain C: unpinned action → hijack action repo → next CI run pulls compromised action → backdoored releases
