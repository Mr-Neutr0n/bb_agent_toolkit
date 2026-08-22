# Runbook: OWA User Enumeration (MANUAL ONLY)

## Status
This workflow is intrusive-tier and ships as a MANUAL gate on purpose. Running it
writes `$OUTDIR/identity/owa_userenum.MANUAL.md` and stops. It never sends traffic
automatically.

## If A Human Approves The Test
1. Confirm in writing that username enumeration is in program scope (many explicitly exclude it).
2. Harvest candidates passively first: JS bundles, LinkedIn patterns, CT logs, spn-osint output.
3. Use timed-response or error-delta methods at <= 1 request per candidate per hour window.
4. Abort permanently if ANY lockout warning, CAPTCHA shift, or 429 appears.
5. Evidence: raw paired requests/responses with timestamps for every probe.

## Why Manual
Timing attacks against production auth endpoints are the classic blue-team noise
generator and the easiest way to lose program access. The value of a valid-username
list rarely justifies the risk. Prefer reporting the *existence* of the oracle
(demonstrated on your own test accounts) instead of harvesting real users.
