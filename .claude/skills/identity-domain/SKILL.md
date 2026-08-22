# Identity Domain Recon

## Overview
No-creds identity infrastructure discovery for externally-scoped targets. Translates
the safely-automatable slice of the GOAD methodology (recon, user-find, NTLM surface,
Exchange/ADFS/ADCS no-creds phases) into header-, DNS-, and XML-level workflows.
No relay, coercion, delegation abuse, or credential attacks - those require internal
foothold and stay out of this harness by design.

## Quick Reference
- **Skill**: identity-domain
- **Version**: 1.0.0
- **Bounded Context**: IdentityContext
- **Required tools**: `python3`, `dig`, `curl`
- **Risk tier**: passive to active-safe (one workflow is intrusive and manual-only)

## Workflow Selection

## Available Workflows

| Workflow | Purpose | Tier |
|---|---|---|
| `ntlm-recon` | Probe live hosts for NTLM/Negotiate; decode Type 2 challenge | active-safe |
| `adcs-fingerprint` | Enumerate certsrv/CES/mscep exposure | passive |
| `adfs-endpoints` | Fingerprint ADFS; parse FederationMetadata.xml | passive |
| `entra-recon` | Entra tenant metadata (federation, GUID, MOERA, MDI) | passive |
| `kerberos-userenum` | Governed AS-REQ username diff on scoped 88/tcp | active-safe |
| `owa-userenum` | Timed username validation; MANUAL gate only | intrusive |
| `spn-osint` | SPN and Negotiate realm leaks in JS bundles and headers | passive |

## Evidence Handling And Redaction

All collected headers, challenge bytes, metadata XML, and tenant lookups are
evidence and stay local-only under `$OUTDIR/identity/evidence/`. They are never
committed (gitignored). Redact internal hostnames and domain names from any text
that leaves the machine; sanitize reports to show the disclosure mechanism with
sample values masked. Authentication material is never stored: this skill sends no
credentials and captures none.

| Intent | Workflow | Tier |
|---|---|---|
| Find NTLM leaks + decode challenge | `ntlm-recon` | active-safe |
| Check certsrv/CES/mscep exposure | `adcs-fingerprint` | passive |
| Fingerprint ADFS, parse SAML metadata | `adfs-endpoints` | passive |
| Entra tenant metadata (federation, GUID, MOERA) | `entra-recon` | passive |
| Kerberos username diff on scoped 88/tcp | `kerberos-userenum` | active-safe |
| OWA timed username validation | `owa-userenum` | intrusive, MANUAL |
| SPN/Negotiate realm leak hunt in JS | `spn-osint` | passive |

## Dispatch Context
Use when recon surfaces any of: `/adfs`, `/certsrv`, `/EWS`, `/autodiscover`,
`WWW-Authenticate: NTLM|Negotiate`, Microsoft login flows on scope, or when
program scope includes VPN/gateway hosts that front AD estates.

## Evidence Required
- Raw request/response pairs per endpoint probed.
- Decoded Type 2 challenge fields (domain, host, DNS info) with raw header.
- FederationMetadata.xml artifact plus parsed fields.
- getuserrealm / OIDC well-known / DKIM responses proving tenant disclosure.
- For kerberos-userenum: the explicit port-88-in-scope acknowledgement in trace.

## References
- mayfly277 GOAD series (https://mayfly277.github.io/categories/goad/)
- KB5005413: NTLM relay mitigations for ADCS (EPA)
- m8sec NTLM info leak; Praetorian NTLMRecon
- dirkjanm.io: Entra actor tokens; ADCS attack surface extension
- Sprocket Security: tenant enumeration status (methods rot; verify before reporting)
- Technique mappings: see technique-kb entries tagged `identity` and `auth` for
  precondition/signal alignment.
