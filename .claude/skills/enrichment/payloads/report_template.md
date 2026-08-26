# Report template (post-script)

Produce a markdown vulnerability report for the finding.

Output key: `_reserved_report` (string, markdown)

Prompt:
```
You are a security report writer. Given the finding context, write a concise markdown report with:
- Title, severity, file_path:line
- Summary and trigger_flow
- Malicious input example (as code block)
- Impact and actor

Keep it under 500 lines. Use plain text for attacker-controlled fields.
```

Expected output JSON:
```json
{"_reserved_report": "# Report: ..."}
```
