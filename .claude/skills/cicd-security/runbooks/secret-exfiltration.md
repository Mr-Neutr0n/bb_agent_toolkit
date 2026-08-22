# Secret Exfiltration

## Secrets that appear in logs

```bash
grep -rn 'echo.*secrets\.' .github/workflows/
grep -rn 'cat.*secrets\.' .github/workflows/
grep -rn 'env.*secrets\.' .github/workflows/ | grep -v '^#'
```

## GITHUB_TOKEN abuse

The auto-generated `GITHUB_TOKEN` can be used to:
- Push code to branches
- Create releases
- Read all private repo content
- Approve PRs (if permissions allow)

```yaml
# Check for overly broad permissions
permissions:
  contents: write    # ← Can push/delete code
  packages: write    # ← Can push malicious packages
  pull-requests: write
```

## OIDC token theft / cloud credential abuse

```bash
grep -rn 'id-token.*write\|configure-aws-credentials\|google-github-actions\|azure/login' .github/workflows/
```

Overly broad AWS trust policy → any branch in the org can assume the role:

```json
{
  "Condition": {
    "StringEquals": {
      "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
      "token.actions.githubusercontent.com:sub": "repo:org/*:*"
    }
  }
}
```

Check: what role does the workflow assume? Is the trust policy scoped to a
specific branch? Can you trigger it from a fork or feature branch?
