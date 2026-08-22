#!/usr/bin/env python3
"""never_submit_check.py — Match a finding against the NEVER SUBMIT list and N/A kill signals.

Each rule has a keyword signature. A match means: kill the finding, or build the
chain from the conditionally-valid table before reporting. Output is markdown.

Usage:
  python3 never_submit_check.py --finding-dir findings/<name>
  python3 never_submit_check.py --finding-dir findings/<name> --output out/never_submit.md
  python3 never_submit_check.py --help
"""

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

# (rule id, keyword signature, why it N/As, chain required to be valid)
NEVER_SUBMIT = [
    ("NS-01", ["missing csp", "missing hsts", "no csp", "no hsts"], "Missing security headers are accepted risk on nearly every program", "None"),
    ("NS-02", ["missing spf", "missing dkim", "missing dmarc"], "Email header disclosure without abuse chain", "None"),
    ("NS-03", ["graphql introspection"], "Introspection alone has no impact without an auth bypass or IDOR", "GraphQL introspection + auth bypass mutation or IDOR on node()"),
    ("NS-04", ["banner disclosure", "version disclosure", "server header"], "Version disclosure without a working CVE exploit", "Working CVE PoC against the live service"),
    ("NS-05", ["clickjacking"], "Clickjacking on non-sensitive pages is out of scope", "Sensitive action + working PoC"),
    ("NS-06", ["tabnabbing"], "Informational at best", "None"),
    ("NS-07", ["csv injection"], "No actual code execution shown", "Actual formula execution on the victim's machine"),
    ("NS-08", ["cors wildcard", "access-control-allow-origin: *"], "Wildcard blocks credentialed exfiltration", "Credentialed request exfils user PII"),
    ("NS-09", ["logout csrf"], "Lowest-priority CSRF class, consistently N/A", "None"),
    ("NS-10", ["self-xss"], "Only exploits own account", "CSRF to trigger it on a victim without their knowledge"),
    ("NS-11", ["open redirect"], "Redirect is informational without a token theft chain", "OAuth redirect_uri → auth code theft"),
    ("NS-12", ["oauth client_secret", "client secret in"], "Known and expected in mobile apps", "None"),
    ("NS-13", ["dns callback", "dns only", "interactsh"], "SSRF DNS-only callback shows no internal access", "Internal service access with data returned"),
    ("NS-14", ["host header injection"], "No impact alone", "Password reset email uses the injected host"),
    ("NS-15", ["rate limit", "no rate limit", "missing rate limit"], "Rate limit on non-critical forms is consistently N/A", "OTP/reset token brute force succeeds"),
    ("NS-16", ["session not invalidated", "session not invalidated on logout"], "Known limitation, rarely paid", "None"),
    ("NS-17", ["concurrent sessions"], "Expected behavior on most platforms", "None"),
    ("NS-18", ["internal ip"], "Internal IP in an error message is informational", "None"),
    ("NS-19", ["mixed content"], "Browser-level informational", "None"),
    ("NS-20", ["weak ciphers", "ssl cipher"], "TLS hardening gap, rarely paid standalone", "None"),
    ("NS-21", ["httponly", "secure flag", "cookie flags"], "Missing cookie flags alone is not a finding", "None"),
    ("NS-22", ["broken external links"], "Not a vulnerability", "None"),
    ("NS-23", ["autocomplete", "password autocomplete"], "Best-practice gap, not a vulnerability", "None"),
    ("NS-24", ["pre-account takeover", "pre-ato"], "Very specific conditions required, usually N/A", "Victim-side condition proven end to end"),
]

KILL_SIGNALS = [
    ("KS-01", "Reflected XSS with CSP present", ["content-security-policy", "csp present"]),
    ("KS-02", "IDOR — own data only", ["own account", "own user", "self id", "own data"]),
    ("KS-03", "SQLi — error message only", ["sql error", "db error", "error message"]),
    ("KS-04", "Nuclei info template match", ["nuclei", "info template"]),
    ("KS-05", "MFA rate limit without lockout", ["mfa rate limit", "otp rate limit"]),
    ("KS-06", "Auth bypass requiring admin precondition", ["admin can", "requires admin"]),
    ("KS-07", "XSS via alert(document.domain)", ["alert(document.domain)", "alert(1)"]),
    ("KS-08", "SAML metadata exposure", ["saml metadata"]),
]

COMMON = [
    ("missing ", "says a thing is missing — check the never-submit list first"),
    ("disclosure", "disclosure without proven impact is informational"),
    ("could potentially", "theoretical language — prove it or kill it"),
    ("may allow", "theoretical language — prove it or kill it"),
]


def _load_text(finding_dir: Path) -> str:
    parts = []
    for name in ("description.txt", "request.txt", "response.txt", "notes.md", "README.md"):
        p = finding_dir / name
        if p.exists():
            parts.append(p.read_text(errors="replace"))
    jl = finding_dir / "findings.jsonl"
    if jl.exists():
        for line in jl.read_text(errors="replace").splitlines()[:20]:
            try:
                rec = json.loads(line)
                parts.append(json.dumps(rec))
            except Exception:
                pass
    return "\n".join(parts)


def main() -> int:
    ap = argparse.ArgumentParser(description="Check a finding against the never-submit list and N/A kill signals.")
    ap.add_argument("--finding-dir", required=True, help="Directory with description/request/response files")
    ap.add_argument("--output", default="-", help="Output markdown path (default: stdout)")
    args = ap.parse_args()

    finding_dir = Path(args.finding_dir)
    if not finding_dir.is_dir():
        print(f"ERROR: finding dir not found: {finding_dir}", file=sys.stderr)
        return 2
    text = _load_text(finding_dir).lower()

    ns_hits = [r for r in NEVER_SUBMIT if any(sig in text for sig in r[1])]
    ks_hits = [r for r in KILL_SIGNALS if any(sig in text for sig in r[2])]
    common_hits = [c for c in COMMON if c[0] in text]

    lines = []
    lines.append("# Never-Submit Check")
    lines.append("")
    lines.append(f"- Generated: {datetime.now(timezone.utc).isoformat()}")
    lines.append(f"- Finding dir: `{finding_dir}`")
    lines.append("")
    lines.append("## NEVER SUBMIT List Matches")
    lines.append("")
    if ns_hits:
        lines.append("| Rule | Why it N/As | Chain required |")
        lines.append("|------|-------------|----------------|")
        for rid, sig, why, chain in ns_hits:
            lines.append(f"| {rid} ({', '.join(sig)}) | {why} | {chain} |")
        lines.append("")
        lines.append("**Decision: KILL, or build the chain first.**")
    else:
        lines.append("_No never-submit rule matched._")
    lines.append("")
    lines.append("## N/A Kill Signals")
    lines.append("")
    if ks_hits:
        for kid, name, _ in ks_hits:
            lines.append(f"- **{kid}**: {name} — if you see this, stop")
        lines.append("")
        lines.append("Classify as `[INFORMATIONAL]`, do not run `/validate`, move on.")
    else:
        lines.append("_No kill signal matched._")
    lines.append("")
    lines.append("## Theoretical Language Check")
    lines.append("")
    if common_hits:
        for word, note in common_hits:
            lines.append(f"- Found `{word}` → {note}")
    else:
        lines.append("_No theoretical language detected._")
    lines.append("")
    report = "\n".join(lines)

    if args.output == "-":
        print(report)
    else:
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(report)
        print(f"Never-submit report written to {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
