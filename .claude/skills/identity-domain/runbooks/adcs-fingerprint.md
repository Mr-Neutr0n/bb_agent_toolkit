# Runbook: ADCS Fingerprinting

## When
Scope includes hosts plausibly running Windows Certificate Services web roles:
VPN portals, PKI subdomains, admin-ish hostnames, anything serving `/certsrv`.

```bash
ADCS_HOST=pki.example.com bin/bb-run identity-domain adcs-fingerprint
```

## What You Get
Status of: `/certsrv/`, `/certsrv/mscep/`, `/_CES_Kerberos/service.svc`,
`/_CES_NTLM/service.svc`, `/CertEnroll/`, CEP policy endpoints, EST.
Auth scheme per endpoint; web_enrollment_exposed verdict.

## Why It Matters
Exposed IIS enrollment without EPA (KB5005413) is the classic ESC8 relay target.
You cannot verify EPA from outside, so frame reports as configuration findings:
"web enrollment reachable from internet; confirm EPA/channel-binding enforcement"
with the endpoint evidence attached. High-signal for security-conscious programs.

## Never Do Here
No enrollment attempts, no certificate requests, no credential submission.
Enumeration is GET/HEAD only.
