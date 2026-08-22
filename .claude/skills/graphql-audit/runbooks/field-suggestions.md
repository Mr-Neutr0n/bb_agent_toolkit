# Field Suggestions — Schema Recovery Without Introspection

GraphQL engines return helpful "Did you mean X?" errors on typos. This leaks
field names even when introspection is disabled.

## Manual probe

```bash
# Typo on a known field to trigger suggestions
curl -s -X POST https://target.com/graphql \
  -H 'Content-Type: application/json' \
  -d '{"query":"{ usr { id } }"}' | grep -i "suggest\|did you mean\|Cannot query"
```

## Clairvoyance (automated)

```bash
clairvoyance -u https://target.com/graphql -o schema.json

# With auth
clairvoyance -u https://target.com/graphql \
  -H "Authorization: Bearer TOKEN" -o schema.json

# Seed with known type names (speeds up discovery significantly)
clairvoyance -u https://target.com/graphql \
  --input-document schema_partial.json -o schema_full.json
```

**What clairvoyance recovers:** type names, field names, argument names —
~80% of introspection output even when blocked.

## Chain

Field suggestions → discover hidden field → IDOR (High). See `05-chaining.md`.
