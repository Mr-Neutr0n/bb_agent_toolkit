# Runbook: SPN OSINT

## When
After js-recon or any artifact collection. Service principals leak constantly into
client bundles via config objects, error templates, API docs, and source maps.

```bash
SPN_SCAN_PATH=$OUTDIR/recon/js/js_downloads bin/bb-run identity-domain spn-osint
```

Also useful against single URLs for Negotiate realm checks:
```bash
python3 .claude/skills/identity-domain/scripts/spn_osint.py header --url https://example.com
```

## What You Get
SPN-shaped strings (`MSSQLSvc/host:1433`, `HTTP/host`, `cifs/host`, ...) plus
Negotiate realm hints, deduplicated, file:line referenced.

## Chain Value
A leaked `MSSQLSvc/sql-prod.internal:1433` tells you: internal SQL naming scheme,
likely Kerberos-authenticated service accounts, and a target class for any future
authenticated-phase work. On its own: low info-leak finding. In a chain narrative:
strong supporting evidence.
