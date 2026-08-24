# Runbook: Static PE Triage

## When
A bounty program ships Windows binaries: desktop clients, updaters, VPN agents,
anti-cheat tools, anything downloadable from their infrastructure.

```bash
BINARY_PATH=./downloads/target-client.exe bin/bb-run binary-analysis pe-triage
```

## What You Get
- Arch/subsystem/compile timestamp
- Section table with per-section entropy; packer verdict (UPX/VMP/Themida names
  or high-entropy executable sections)
- Watchlist import clusters: network / crypto / process-injection / anti-debug
- Embedded URLs and IPs (sample) that feed recon scope

## Reading the Verdict
- `likely_packed=true` -> plan an unpack step before deeper static work; use the
  dynamic session's pe-analysis/OEP tooling, re-run triage on the dumped image.
- `watchlist_import_hits.crypto` present -> license/update flows likely use it;
  those are prime breakpoints in the dynamic phase.
- Embedded URLs may reveal staging/internal hosts - cross-check against program
  scope and asset-graph before treating as findings.

## Batch Mode
Dropped several installers? `BINARIES_DIR=downloads/ bin/bb-run binary-analysis pe-triage-batch`
writes one JSONL line per PE with the same verdict fields.

## Never Here
No execution of the sample outside a disposable VM; no submitting the sample to
online multi-scanner services for bounty targets (leaks your research).
