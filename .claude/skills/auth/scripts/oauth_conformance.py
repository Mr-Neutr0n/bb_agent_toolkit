#!/usr/bin/env python3
"""OAuth/OIDC conformance auditor - deterministic checks the redirect matrix does not cover.

Subcommands:
    wellknown      Fetch and grade .well-known/openid-configuration for risky config
    authorize      Error-differential probes: PKCE enforcement, state handling,
                   response_type=none token leakage
    endsession     Open-redirect hygiene on end_session_endpoint
    deviceflow     Device-flow availability + scope audit from discovery doc
    noauth-checklist  Emit guided manual test plan for the nOAuth account-merge pattern

All network probes are unauthenticated GETs or error-path POSTs. No credentials,
no code redemption, nothing state-changing.

Usage:
    oauth_conformance.py wellknown --issuer https://accounts.example.com --output wk.json
    oauth_conformance.py authorize --issuer https://accounts.example.com --client-id CLIENT --redirect-uri https://app.example.com/cb
    oauth_conformance.py endsession --discovery discovery.json --output es.json
    oauth_conformance.py deviceflow --discovery discovery.json --client-id CLIENT
    oauth_conformance.py noauth-checklist --provider "ExampleID" --output checklist.md
"""

import argparse
import base64
import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

RATE_LIMIT = float(__import__("os").environ.get("RATE_LIMIT", "5"))
UA = "Mozilla/5.0 (Security Research; BountyHarness)"

RISKY_WELLKNOWN = [
    ("id_token_signing_alg_values_supported", ["none"],
     "issuer advertises 'none' signing algorithm"),
    ("claims_parameter_supported", [True],
     "claims parameter enabled - enables claim-based injection surfaces if not filtered"),
    ("request_parameter_supported", [True],
     "request objects accepted - check for unsigned request_uri support (JAR bypass)"),
    ("token_endpoint_auth_methods_supported", ["none"],
     "token endpoint accepts client auth 'none' - public clients only should use this"),
    ("response_modes_supported", ["fragment", "form_post", "query"],
     "query response mode enabled - codes/tokens can leak via Referer and logs"),
]


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def log(msg: str) -> None:
    print(f"[{now_iso()}] {msg}", file=sys.stderr)


def throttle() -> None:
    time.sleep(1.0 / max(RATE_LIMIT, 0.1))


def http_get(url: str, timeout: int = 12) -> tuple[int, str, str]:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            final = resp.geturl()
            return resp.status, resp.read(500_000).decode("utf-8", errors="replace"), final
    except urllib.error.HTTPError as e:
        return e.code, "", url
    except Exception as e:
        return 0, str(e), url


def fetch_discovery(issuer: str) -> dict | None:
    issuer = issuer.rstrip("/")
    for suffix in ("/.well-known/openid-configuration",
                   "/.well-known/oauth-authorization-server"):
        throttle()
        status, body, _ = http_get(f"{issuer}{suffix}")
        if status == 200 and body.startswith("{"):
            try:
                return json.loads(body)
            except json.JSONDecodeError:
                pass
    # RFC 8414 insertion form: /.well-known/openid-configuration/<path>
    p = urllib.parse.urlparse(issuer)
    if p.path:
        throttle()
        status, body, _ = http_get(f"{p.scheme}://{p.netloc}/.well-known/openid-configuration{p.path}")
        if status == 200 and body.startswith("{"):
            try:
                return json.loads(body)
            except json.JSONDecodeError:
                pass
    return None


def cmd_wellknown(args) -> dict:
    doc = fetch_discovery(args.issuer)
    if not doc:
        out = {"status": "no_discovery", "issuer": args.issuer,
               "note": "No discovery document found; provider may be non-conformant or issuer path differs."}
    else:
        findings = []
        for field, bad_vals, why in RISKY_WELLKNOWN:
            val = doc.get(field)
            if val is None:
                continue
            if isinstance(val, list):
                overlap = [v for v in bad_vals if v in val]
                if field == "response_modes_supported":
                    if "query" in val:
                        findings.append({"field": field, "value": val, "why": why, "severity": "low"})
                elif overlap:
                    findings.append({"field": field, "value": val, "why": why, "severity": "medium"})
            elif val in bad_vals:
                findings.append({"field": field, "value": val, "why": why, "severity": "medium"})
        missing = [f for f in ("authorization_endpoint", "token_endpoint", "issuer", "jwks_uri")
                   if f not in doc]
        if missing:
            findings.append({"field": "<missing>", "value": missing,
                             "why": "required fields absent from discovery", "severity": "info"})
        out = {"status": "graded", "issuer": args.issuer, "checked_at": now_iso(),
               "findings_count": len(findings), "findings": findings,
               "endpoints": {k: doc.get(k) for k in
                             ("authorization_endpoint", "token_endpoint", "userinfo_endpoint",
                              "end_session_endpoint", "device_authorization_endpoint", "jwks_uri")}}
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output).write_text(json.dumps(out, indent=2))
    return out


def cmd_authorize(args) -> dict:
    doc = fetch_discovery(args.issuer)
    auth_ep = (doc or {}).get("authorization_endpoint")
    results: list[dict] = []
    if not auth_ep:
        results.append({"probe": "discovery", "result": "skipped",
                        "detail": "authorization_endpoint unknown"})
    else:
        base_params = {
            "client_id": args.client_id,
            "redirect_uri": args.redirect_uri,
            "response_type": "code",
        }
        probes = [
            ("pkce-not-enforced", {"code_challenge_method_missing": True}),
            ("state-optional", {}),
            ("response-type-none-leak", {"response_type_override": "none"}),
        ]
        for name, _cfg in probes:
            params = dict(base_params)
            if name == "response-type-none-leak":
                params["response_type"] = "none"
            if name != "pkce-not-enforced" or True:
                params.setdefault("scope", "openid")
            qs = urllib.parse.urlencode(params)
            url = f"{auth_ep}?{qs}"
            throttle()
            status, body, final_url = http_get(url)
            entry = {"probe": name, "status": status}
            low = body.lower()
            if name == "pkce-not-enforced":
                if "code_challenge" in low and ("required" in low or "missing" in low):
                    entry["result"] = "pkce-enforced"
                elif status in (302, 303) or "error=" not in low:
                    entry["result"] = "inconclusive-no-pkce-error"
                    entry["note"] = "server did not complain about missing PKCE; verify interactively"
                else:
                    entry["result"] = "pkce-error-present"
            elif name == "state-optional":
                if "invalid_state" in low or "state required" in low:
                    entry["result"] = "state-required"
                else:
                    entry["result"] = "state-not-validated-at-authorize"
                    entry["note"] = "CSRF protection depends on client-side handling; flag as weak"
            else:  # response_type=none
                if "unsupported_response_type" in low:
                    entry["result"] = "none-rejected"
                elif status in (302, 303):
                    entry["result"] = "none-accepted"
                    entry["note"] = "response_type=none allowed; check it cannot be combined with scope grants"
                else:
                    entry["result"] = f"http-{status}"
            results.append(entry)

    out = {"status": "probed", "issuer": args.issuer, "checked_at": now_iso(), "results": results}
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output).write_text(json.dumps(out, indent=2))
    return out


def cmd_endsession(args) -> dict:
    doc_path = Path(args.discovery)
    doc = json.loads(doc_path.read_text()) if doc_path.exists() else fetch_discovery(args.issuer or "")
    ep = (doc or {}).get("end_session_endpoint")
    findings: list[dict] = []
    if not ep:
        findings.append({"severity": "info",
                         "detail": "no end_session_endpoint advertised"})
    else:
        evil = "https://example.com/logout-callback"
        for variant in (evil, f"https://example.com@evil.example/", "//evil.example/logout"):
            throttle()
            url = f"{ep}?post_logout_redirect_uri={urllib.parse.quote(variant, safe='')}&id_token_hint=x"
            status, _, final_url = http_get(url)
            landed = urllib.parse.urlparse(final_url or "")
            open_redir = any(h in (final_url or "") for h in ("example.com", "evil"))
            findings.append({
                "variant": variant[:60], "status": status, "final_url": (final_url or "")[:120],
                "open_redirect_candidate": bool(open_redir and "evil" in final_url),
            })
    out = {"status": "checked", "checked_at": now_iso(),
           "endpoint": ep or None, "results": findings}
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output).write_text(json.dumps(out, indent=2))
    return out


def cmd_deviceflow(args) -> dict:
    doc = fetch_discovery(args.issuer)
    ep = (doc or {}).get("device_authorization_endpoint")
    result: dict = {"status": "checked", "issuer": args.issuer, "device_authorization_endpoint": ep}
    if not ep:
        result["note"] = "device flow not offered"
    else:
        # unauthenticated probe: expect 400 invalid_client rather than 200 with user_code
        throttle()
        req = urllib.request.Request(
            ep,
            data=urllib.parse.urlencode({"client_id": args.client_id or "unknown-client"}).encode(),
            headers={"User-Agent": UA, "Content-Type": "application/x-www-form-urlencoded"},
            method="POST")
        try:
            with urllib.request.urlopen(req, timeout=12) as resp:
                body = resp.read(100_000).decode("utf-8", errors="replace")
                result["unauth_status"] = resp.status
                parsed = {}
                try:
                    parsed = json.loads(body)
                except json.JSONDecodeError:
                    pass
                if parsed.get("device_code") or parsed.get("user_code"):
                    result["finding"] = "device flow initiates WITHOUT client authentication"
                    result["severity"] = "medium"
                else:
                    result["finding"] = "device flow responded but did not issue codes to unknown client"
        except urllib.error.HTTPError as e:
            result["unauth_status"] = e.code
            err_body = ""
            try:
                err_body = e.read(20_000).decode("utf-8", errors="replace")
            except Exception:
                pass
            if "unauthorized_client" in err_body or "invalid_client" in err_body:
                result["finding"] = "unknown client rejected (expected)"
            else:
                result["finding"] = f"error body review needed: {err_body[:120]}"
        except Exception as e:
            result["error"] = str(e)[:120]
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output).write_text(json.dumps(result, indent=2))
    return result


def cmd_noauth_checklist(args) -> dict:
    lines = [
        f"# nOAuth Manual Test Plan - {args.provider}",
        "",
        "Automated portion ends here; the account-merge pattern needs two real tenants.",
        "",
        "## Prerequisites",
        "1. Attacker tenant on the SAME IdP family as victim domain (e.g., free Entra tenant).",
        "2. Victim email address you control a forwarding alias for, OR written consent",
        "   from a colleague whose account you will use. Never touch third-party accounts.",
        "",
        "## Steps",
        "1. On the target app, start 'Sign in with {provider}' using the VICTIM email",
        "   but authenticate through the ATTACKER tenant (tenant picker confusion).",
        "2. Observe whether the app links the attacker-controlled identity to the",
        "   pre-existing victim account keyed by email.",
        "3. If linked: document full chain - signup flow, tenant selection screen,",
        "   ID token claims (email_verified value!), app account page showing merge.",
        "4. Check id_token: is `email_verified` false/absent while the app treats the",
        "   address as verified? That mismatch is the reportable defect.",
        "",
        "## Evidence To Capture",
        "- Full request/response of the linking call",
        "- Decoded ID token (mask signatures)",
        "- Screenshot of merged account state",
        "",
        "## Severity Framing",
        "Account takeover of any pre-existing account whose email is guessable.",
        "Typically critical when passwordless login exists.",
        "",
        f"_Generated {now_iso()} by oauth_conformance.py_",
    ]
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output).write_text("\n".join(lines))
    return {"status": "checklist_written", "output": args.output}


def main():
    parser = argparse.ArgumentParser(description="OAuth/OIDC conformance auditor")
    sub = parser.add_subparsers(dest="command")

    w = sub.add_parser("wellknown")
    w.add_argument("--issuer", required=True)
    w.add_argument("--output", required=True)

    a = sub.add_parser("authorize")
    a.add_argument("--issuer", required=True)
    a.add_argument("--client-id", required=True)
    a.add_argument("--redirect-uri", required=True)
    a.add_argument("--output", required=True)

    e = sub.add_parser("endsession")
    e.add_argument("--discovery", default=None, help="Path to previously saved discovery JSON")
    e.add_argument("--issuer", default=None)
    e.add_argument("--output", required=True)

    d = sub.add_parser("deviceflow")
    d.add_argument("--issuer", required=True)
    d.add_argument("--client-id", default="")
    d.add_argument("--output", required=True)

    n = sub.add_parser("noauth-checklist")
    n.add_argument("--provider", required=True)
    n.add_argument("--output", required=True)

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)

    fn = {"wellknown": cmd_wellknown, "authorize": cmd_authorize,
          "endsession": cmd_endsession, "deviceflow": cmd_deviceflow,
          "noauth-checklist": cmd_noauth_checklist}
    print(json.dumps(fn[args.command](args), indent=2))


if __name__ == "__main__":
    main()
