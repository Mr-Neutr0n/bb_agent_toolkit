# Runbook: Kerberos User Enumeration

## When
Program scope explicitly includes a KDC host on 88/tcp. Rare but real on
infrastructure-heavy programs.

```bash
KDC_HOST=dc.example.com USERS_FILE=./users.txt PORT88_IN_SCOPE=1 \
  bin/bb-run identity-domain kerberos-userenum
```

## Gate Discipline
The script refuses to run without `--port88-in-scope`. That flag is an explicit
acknowledgement: confirm with `bin/bb-run scope-manager validate-url` first and
keep the validation trace as evidence.

## Mechanics
AS-REQ username diff only. No passwords sent, no lockout risk by design.
Requires `kerbrute` binary (see tools registry); the wrapper refuses to hand-roll
raw Kerberos traffic.

## Rate Plan
Defaults to $RATE_LIMIT from context. Keep at or below 5/s even when allowed more;
the goal is enumeration proof, not volume.
