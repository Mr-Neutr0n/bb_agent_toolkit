# Runbook: Bounty Estimation

## When
Run `reporting estimate-bounty` once a finding is verified and scored, to prioritize
which finding to write up first when you have several candidates.

```bash
bin/bb-run reporting estimate-bounty
```

Context variables:
- `SEVERITY`: critical | high | medium | low | info (or set `CVSS_SCORE` instead)
- `VULN_TYPE` or `IMPACT_CLASS`: e.g. rce, account_takeover, idor, xss_stored
- `PROGRAM_TIER`: top | established | standard | small | vdp
- `PLATFORM`: hackerone | bugcrowd | intigriti | yeswehack

## How the Estimate Works
1. Base range picked from severity (critical $3k-15k, high $1k-5k, ...).
2. Multiplied by vulnerability-class weight (RCE 2.5x, IDOR 1.4x, open redirect 0.3x ...).
3. Multiplied by program-tier weight (top programs ~2x, small ~0.5x, VDP = $0).

Example: critical + account_takeover + top program -> roughly $14k-$72k display range.

## Decision Use
- Two verified findings, limited time? Report the higher-band one first.
- Medium-severity finding on a top-tier program can outpay a high on a small program.
- VDP tier: skip estimation; there is no bounty, decide on disclosure value alone.

## Limits
Heuristic from public program-table patterns. Programs pay what their own table says.
Never quote this number to triage; use it privately for prioritization.
