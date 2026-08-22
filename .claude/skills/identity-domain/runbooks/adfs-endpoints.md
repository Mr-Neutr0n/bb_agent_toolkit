# Runbook: ADFS Endpoints

## When
Login flows point at an ADFS farm or `/adfs` paths respond on scope.

```bash
ADFS_HOST=login.example.com bin/bb-run identity-domain adfs-endpoints
```

## What You Get
- Reachability of `/adfs/ls/`, idpinitiatedsignon, oauth2/authorize,
  WS-Trust usernamemixed endpoints
- Parsed FederationMetadata.xml: entityID, embedded signing certs count, endpoints

## Research Hooks
WS-Trust endpoints exposed externally enable SAML research chains
(signature wrapping, encryption-downgrade scenarios). Metadata cert lifetimes
and overlapping keys feed "Certified Pre-Owned" style analyses. IdP-initiated
SSO pages left open are a known relay-to-RP vector; note their presence.

## Report Framing
Facts first: endpoint inventory + metadata artifacts. Hypotheses clearly labeled.
ADFS version leaks (HTML comments, error pages) are low severity alone but
actionable context for defense teams.
