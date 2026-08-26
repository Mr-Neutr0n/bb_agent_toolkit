# Default severity ranker (Kritt-style composable markdown)

Use this as a starting ranker for `rank-findings`. Compose multiple rankers by
concatenating their markdown - the ranker text is used verbatim as ranking policy.

## Critical

- Reachable remote code execution, full account takeover without user interaction,
  authentication bypass to administrator, SSRF that reaches cloud instance metadata
- Any vulnerability where `exploitable=true` and `malicious_actor` can be external and unattended

## High

- SQL injection with data extraction, SSRF to internal services, stored XSS in a
  privileged context (admin, editor), insecure direct object reference exposing
  PII at scale, file upload that leads to remote code execution
- `exploitable=true` with authenticated attacker or high-value data at risk

## Medium

- Reflected cross-site scripting, cross-site request forgery on state-changing
  endpoints, CORS misconfiguration that leaks credentials, host header injection
  with cache poisoning impact, open redirect that chains to account effects
- `exploitable` may be true or false; reachability and user interaction required

## Low

- Clickjacking on non-sensitive pages, verbose error messages, missing security
  headers without a direct exploit, email enumeration
- Usually `exploitable=false` or informational

## Informational

- Best-practice deviations, theoretical vectors without a reachable trigger,
  headers missing but no sensitive action affected

## Ranking rules

1. Demote theoretical findings (no reachable trigger flow) one level.
2. Promote any finding where `trigger_flow` shows an external actor reaching a
   privileged action without authentication.
3. Preserve the order inside each bucket by CVSS score if present.
