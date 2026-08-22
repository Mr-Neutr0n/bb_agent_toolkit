# Chain Validity — Conditionally Valid Findings

Some findings are only reportable once a chain is proven end to end. Run:

```bash
python3 .claude/skills/triage-validation/scripts/chain_validity.py \
  --finding-dir "$FINDING_DIR" --output "$OUTDIR/triage/chain.md"
```

## The chain-required table

| Standalone Finding | Chain Required | Valid Result |
|---|---|---|
| Open redirect | + OAuth redirect_uri → auth code theft | ATO (Critical) |
| Clickjacking | + sensitive action + working PoC | Medium |
| CORS wildcard | + credentialed request exfils user PII | High |
| CSRF | + sensitive action (transfer funds, change email, delete account) | High |
| Rate limit bypass | + OTP/reset token brute force succeeds | Medium/High |
| SSRF DNS-only | + internal service access + data returned | Medium |
| Host header injection | + password reset email uses injected host | High |
| Prompt injection | + reads other user's data (IDOR) | High |
| S3 bucket listing | + JS bundles contain API keys or OAuth secrets | Medium/High |
| Self-XSS | + CSRF to trigger it on victim without their knowledge | Medium |
| Subdomain takeover | + OAuth redirect_uri registered at that subdomain | Critical |
| GraphQL introspection | + auth bypass mutation or IDOR on node() | High |

## Discipline

Build the chain first, prove it works end to end, THEN report. A chain report
must include the intermediate steps as evidence — a triager needs to walk the
chain from start to finish without filling gaps.
