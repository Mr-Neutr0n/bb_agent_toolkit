# Runbook: Entra Tenant Recon

## When
Target uses Microsoft identity (login.microsoftonline.com flows, outlook.com MX).

```bash
bin/bb-run identity-domain entra-recon   # uses $TARGET from context
```

## What You Get
- getuserrealm: managed vs federated, federation brand
- OIDC well-known: tenant GUID, issuer
- DKIM selector1/selector2 CNAMEs -> MOERA prefix leak (`<prefix>.mail.onmicrosoft.com`)
- Defender for Identity instance presence (`<domain>.atp.azure.com`)

## Rot Warning
Tenant enumeration tooling decays fast. GetFederationInformation domain listing
died Aug 2025; ACS `/metadata/json/1` died May 2026. This workflow encodes only
paths verified current at build time. Re-validate against Sprocket/TrustedSec
writeups before reporting anything timing-based.

## Reporting Angle
Tenant GUID + MOERA prefix disclosures are usually informational alone but are
the substrate for phishing-impact and tenant-recon chain reports. MDI presence
tells you the estate runs AD hybrid - useful context for the whole engagement.
