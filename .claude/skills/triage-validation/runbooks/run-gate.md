# Run Gate — 7-Question Gate Walkthrough

Run `bin/bb-run triage-validation run-gate` with `FINDING_DIR` set to the finding
directory, or execute the script directly:

```bash
python3 .claude/skills/triage-validation/scripts/triage_gate.py \
  --finding-dir "$FINDING_DIR" --output "$OUTDIR/triage/gate_result.md"
```

## Procedure

1. Read the finding description and the raw request/response evidence first.
2. Fill in the 7-Question Gate table — one FAIL means the finding is dead.
   Do not "fix" a FAIL with softer wording; kill or downgrade honestly.
3. For authenticated findings, answer the identity check questions. Blank
   answers auto-fail on auth-related findings.
4. Work the 4 gates in order. Gate 2 (dedup) is where most duplicates die.
5. Write the verdict line: `SUBMIT` / `KILL` / `CHAIN REQUIRED`.

## Kill Fast Rules

1. **5-minute rule**: If you can't fill in Q1's template in 5 minutes → move on.
2. **Precondition count**: More than 2 preconditions simultaneously required → kill it.
3. **Impact test**: "What does attacker walk away with?" — nothing tangible → kill it.
4. **Admin bypass**: "Admin can do X" is NEVER a bug → kill it immediately.
5. **Design doc test**: Documented behavior → kill it immediately.
6. **Rabbit hole signal**: 30+ min on Q6 with no reproducible PoC → kill it.

## Anti-patterns that lose money

- Writing a report before confirming the bug exists (most common)
- Submitting theoretical impact without proof
- Chaining A+B into one report when they're separate bugs (two payouts)
- Overclaiming severity — triagers trust you less next time
- Under-describing impact — triager doesn't understand why it matters
