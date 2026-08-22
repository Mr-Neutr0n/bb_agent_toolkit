# Runbook: NTLM Recon

## When
Recon shows any host answering with `WWW-Authenticate: NTLM` or `Negotiate`.
Common on gateways, Exchange surfaces, ADFS, certsrv, legacy IIS.

```bash
HOSTS_FILE=$OUTDIR/recon/live/live_hosts.txt bin/bb-run identity-domain ntlm-recon
```

## What You Get
Per host: protocols offered, decoded Type 2 challenge:
- NetBIOS domain and host names
- DNS host/domain/forest via AV_PAIRs
- Challenge bytes and flags

## Reporting Angle
Internal naming disclosure on external scope is a low-to-medium info-leak finding.
It gets valuable when chained: domain name feeds targeted phishing impact analysis,
host FQDNs map internal topology, OS/build hints date unpatched estates.
Always pair with the raw response as evidence.

## False-Positive Discipline
CDNs and auth proxies terminate NTLM and return their own realm. Verify the
challenge decodes to plausible internal names before claiming target-side disclosure.
