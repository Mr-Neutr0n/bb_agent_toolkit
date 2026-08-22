# Check Never-Submit — Always-Rejected List Walkthrough

Run `bin/bb-run triage-validation check-never-submit` with `FINDING_DIR` set, or:

```bash
python3 .claude/skills/triage-validation/scripts/never_submit_check.py \
  --finding-dir "$FINDING_DIR" --output "$OUTDIR/triage/never_submit.md"
```

## Procedure

1. The script matches the finding text (description, request, response, notes)
   against 24 never-submit rules and 8 N/A kill signals.
2. Every matched rule is a reason to kill the finding — unless the conditionally
   valid table lists a chain that turns it into a reportable bug.
3. If the only matches are on the "theoretical language" list, rewrite the
   description to be concrete: "An attacker can [exact action] by [exact method]".
4. Kill-signal matches → classify as `[INFORMATIONAL]` and move on.

## Decision rule

If your finding matches a kill signal → classify as `[INFORMATIONAL]`, do not
run `/validate`, move on. Submitting these destroys your validity ratio.
