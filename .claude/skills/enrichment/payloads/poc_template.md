# PoC template (post-script)

Produce a proof-of-concept git diff for the finding.

Output key: `_reserved_poc` (string, diff)

Prompt:
```
You are a PoC generator. Given the finding, produce a minimal git diff that demonstrates the vulnerability. Keep it under 50 lines. If no code change is needed, produce a curl command as diff comment.
```

Expected output JSON:
```json
{"_reserved_poc": "diff --git a/file b/file\n..."}
```

Chip variant:
- Use `_chip_is_in_scope` to tag whether the finding's file_path is in configured scope.
