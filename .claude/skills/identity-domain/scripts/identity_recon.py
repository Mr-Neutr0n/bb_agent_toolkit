#!/usr/bin/env python3
"""Identity-domain recon engine — no-creds identity infrastructure discovery on external scope.

Covers the safely-automatable slice of AD/Entra attack methodology (GOAD parts 1, 2,
4, Exchange-1 translated to external web scope): NTLM challenge parsing, ADCS web
enrollment fingerprinting, ADFS/SAML endpoint analysis, Entra tenant metadata.
Header/DNS/XML level only. No coercion, no relay, no credential attacks.

Subcommands:
    ntlm-recon          Probe hosts for WWW-Authenticate: NTLM and decode Type 2 challenge
    adcs-fingerprint    Enumerate certsrv/CES/mscep endpoints, note EPA absence
    adfs-endpoints      Fingerprint ADFS paths and parse SAML FederationMetadata
    entra-recon         getuserrealm + OIDC well-known + DKIM MOERA + MDI checks

Usage:
    identity_recon.py ntlm-recon --hosts-file live.txt --output out.json
    identity_recon.py adcs-fingerprint --host vpn.example.com --output out.json
    identity_recon.py adfs-endpoints --host login.example.com --output out.json
    identity_recon.py entra-recon --domain example.com --output out.json
"""

import argparse
import base64
import json
import socket
import ssl
import struct
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

RATE_LIMIT = float(__import__("os").environ.get("RATE_LIMIT", "5"))
TIMEOUT = 10

UA = "Mozilla/5.0 (Security Research; BountyHarness)"


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def log(msg: str) -> None:
    print(f"[{now_iso()}] {msg}", file=sys.stderr)


def throttle() -> None:
    time.sleep(1.0 / max(RATE_LIMIT, 0.1))


def http(url: str, method: str = "GET", headers: dict | None = None) -> dict:
    """Header-level HTTP fetch returning status + headers (+ body only for XML/JSON)."""
    req = urllib.request.Request(url, headers={"User-Agent": UA, **(headers or {})}, method=method)
    result = {"url": url, "method": method, "status": 0, "headers": {}, "body_snippet": ""}
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            result["status"] = resp.status
            result["headers"] = {k.lower(): v for k, v in resp.headers.items()}
            ctype = resp.headers.get("Content-Type", "")
            if any(t in ctype for t in ("xml", "json")):
                body = resp.read(65536)
                try:
                    result["body_snippet"] = body.decode("utf-8", errors="replace")
                except Exception:
                    pass
    except urllib.error.HTTPError as e:
        result["status"] = e.code
        result["headers"] = {k.lower(): v for k, v in e.headers.items()} if e.headers else {}
        ctype = (e.headers or {}).get("Content-Type", "")
        if e.code in (401, 403) and "ntlm" in str((e.headers or {}).get("WWW-Authenticate", "")).lower():
            pass
        elif any(t in ctype for t in ("xml", "json")):
            try:
                result["body_snippet"] = e.read(65536).decode("utf-8", errors="replace")
            except Exception:
                pass
    except Exception as e:
        result["error"] = str(e)[:120]
    return result


# ── NTLM Type 2 parsing ──

NULL_NEGOTIATE = base64.b64encode(
    b"NTLMSSP\x00" + struct.pack("<I", 1) + struct.pack("<I", 0x200B2006) + b"\x00" * 16
).decode()


def parse_ntlm_type2(challenge_b64: str) -> dict:
    info: dict = {"raw": challenge_b64[:64] + "..."}
    try:
        blob = base64.b64decode(challenge_b64)
        if blob[:8] != b"NTLMSSP\x00" or struct.unpack("<I", blob[8:12])[0] != 2:
            info["error"] = "not a Type 2 message"
            return info
        dom_len, _, dom_off = struct.unpack("<HHI", blob[12:20])
        flags = struct.unpack("<I", blob[20:24])[0]
        info["challenge_hex"] = blob[24:32].hex()
        info["flags_hex"] = f"{flags:08x}"
        if dom_len:
            raw = blob[dom_off : dom_off + dom_len]
            info["netbios_domain"] = raw.decode("utf-16-le", errors="replace").strip("\x00")
        # Target info AV_PAIRs at offset 40 when present
        if len(blob) > 40:
            ti_len, _, ti_off = struct.unpack("<HHI", blob[40:48])
            av = {}
            pos = ti_off
            end = ti_off + ti_len
            while pos + 4 <= min(end, len(blob)):
                av_id, av_len = struct.unpack("<HH", blob[pos : pos + 4])
                val = blob[pos + 4 : pos + 4 + av_len]
                if av_id == 0:
                    break
                key = {1: "netbios_host", 2: "netbios_domain", 3: "dns_host", 4: "dns_domain",
                       5: "dns_tree", 7: "timestamp"}.get(av_id, f"av_{av_id}")
                if av_id == 7:
                    import datetime as _dt
                    try:
                        secs = struct.unpack("<Q", val)[0]
                        av[key] = (_dt.datetime(1601, 1, 1) + _dt.timedelta(microseconds=secs / 10)).isoformat()
                    except Exception:
                        av[key] = val.hex()
                else:
                    av[key] = val.decode("utf-16-le", errors="replace")
                pos += 4 + av_len
            if av:
                info["target_info"] = av
    except Exception as e:
        info["error"] = str(e)[:120]
    return info


NTLM_PROBE_PATHS = [
    "/", "/rpc", "/EWS/", "/autodiscover/autodiscover.xml", "/adfs/ls/",
    "/certsrv/", "/owa/", "/Microsoft-Server-ActiveSync",
]


def ntlm_recon(hosts: list[str], output_path: str) -> dict:
    findings = []
    for host in hosts:
        host = host.strip().rstrip("/")
        if not host:
            continue
        if not host.startswith(("http://", "https://")):
            host = f"https://{host}"
        for path in NTLM_PROBE_PATHS:
            throttle()
            r = http(f"{host}{path}", headers={"Authorization": f"NTLM {NULL_NEGOTIATE}"})
            www_auth = r.get("headers", {}).get("www-authenticate", "")
            if "ntlm" in www_auth.lower() or "negotiate" in www_auth.lower():
                entry = {
                    "url": r["url"], "status": r["status"],
                    "protocols": [p.split()[0].lower() for p in www_auth.split(",") if p.strip()],
                }
                for part in www_auth.split(","):
                    part = part.strip()
                    if part.lower().startswith("ntlm ") and len(part) > 30:
                        entry["type2"] = parse_ntlm_type2(part[5:].strip())
                        break
                findings.append(entry)
                log(f"NTLM found: {r['url']} -> {entry.get('type2', {}).get('netbios_domain', 'n/a')}")
                break  # first hit per host is enough for the summary line
    out = {"checked_at": now_iso(), "count": len(findings), "findings": findings}
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    Path(output_path).write_text(json.dumps(out, indent=2))
    return out


# ── ADCS fingerprinting ──

ADCS_PATHS = [
    "/certsrv/", "/certsrv/mscep/", "/certsrv/mscep/mscep.dll",
    "/_CES_Kerberos/service.svc", "/_CES_Kerberos/password",
    "/_CES_NTLM/service.svc", "/CertEnroll/",
    "/ADPolicyProvider_CEP_CertificateService.svc",
    "/.well-known/est/simpleenroll",
]


def adcs_fingerprint(host: str, output_path: str) -> dict:
    if not host.startswith(("http://", "https://")):
        host = f"https://{host}"
    endpoints = []
    for path in ADCS_PATHS:
        throttle()
        r = http(f"{host}{path}")
        auth = r.get("headers", {}).get("www-authenticate", "")
        entry = {
            "path": path, "status": r["status"],
            "auth": auth[:120] if auth else None,
            "server": r.get("headers", {}).get("server"),
        }
        if r["status"] not in (404, 0):
            entry["note"] = "endpoint exists"
            if "ntlm" in auth.lower() or "negotiate" in auth.lower():
                entry["auth_scheme"] = "windows-integrated"
            endpoints.append(entry)
    has_enrollment = any(e["status"] in (200, 401, 403) for e in endpoints)
    out = {
        "checked_at": now_iso(), "host": host,
        "web_enrollment_exposed": has_enrollment,
        "epa_channel_binding_note": (
            "KB5005413: exposed IIS-based enrollment without EPA is relay-prone; "
            "EPA enforcement cannot be verified externally - flag as config finding."
        ),
        "endpoints": endpoints,
    }
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    Path(output_path).write_text(json.dumps(out, indent=2))
    return {"web_enrollment_exposed": has_enrollment, "endpoint_count": len(endpoints), "output": output_path}


# ── ADFS / SAML ──

ADFS_PATHS = [
    "/adfs/ls/", "/adfs/ls/idpinitiatedsignon.aspx",
    "/adfs/oauth2/authorize", "/adfs/services/trust/2005/usernamemixed",
    "/FederationMetadata/2007-06/FederationMetadata.xml",
]


def adfs_endpoints(host: str, output_path: str) -> dict:
    if not host.startswith(("http://", "https://")):
        host = f"https://{host}"
    results = []
    metadata = {}
    for path in ADFS_PATHS:
        throttle()
        r = http(f"{host}{path}")
        entry = {"path": path, "status": r["status"]}
        if r["status"] in (200, 302, 401):
            server_hdr = r.get("headers", {}).get("server", "")
            if server_hdr:
                entry["server"] = server_hdr
        if path.endswith(".xml") and r["body_snippet"]:
            xml = r["body_snippet"]
            for tag in ("entityID", "Location"):
                import re
                m = re.search(rf'{tag}="([^"]+)"', xml)
                if m:
                    metadata[tag] = m.group(1)
            certs = xml.count("X509Certificate")
            if certs:
                metadata["x509_certs_embedded"] = certs
            metadata["metadata_fetched"] = True
            entry["parsed"] = True
        results.append(entry)
    present = [e for e in results if e["status"] in (200, 302, 401)]
    out = {
        "checked_at": now_iso(), "host": host,
        "adfs_detected": bool(present),
        "metadata": metadata,
        "endpoints": results,
    }
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    Path(output_path).write_text(json.dumps(out, indent=2))
    return {"adfs_detected": out["adfs_detected"], "output": output_path}


# ── Entra tenant recon ──


def dns_lookup(name: str) -> list[str]:
    try:
        import subprocess
        r = subprocess.run(["dig", "+short", name], capture_output=True, text=True, timeout=8)
        return [l.strip() for l in r.stdout.splitlines() if l.strip()]
    except Exception:
        return []


def entra_recon(domain: str, output_path: str) -> dict:
    out: dict = {"checked_at": now_iso(), "domain": domain}
    # getuserrealm - federation status
    throttle()
    r = http(f"https://login.microsoftonline.com/getuserrealm.svc?xml=1&email=test@{domain}")
    if r.get("body_snippet"):
        import re
        xml = r["body_snippet"]
        ns = re.search(r"<NameServerType>([^<]+)</NameServerType>", xml)
        fst = re.search(r"<FederationGlobalVersion>([^<]*)</FederationGlobalVersion>", xml)
        fed = re.search(r'FederationBrandName="([^"]*)"', xml)
        out["name_server_type"] = ns.group(1) if ns else None
        out["is_federated"] = (ns.group(1).lower() == "federated") if ns else False
        if fst:
            out["federation_global_version"] = fst.group(1)
        brand = re.search(r"<FederationBrandName>([^<]+)</FederationBrandName>", xml)
        if brand:
            out["federation_brand"] = brand.group(1)
        del fed
    # OIDC well-known -> tenant GUID + issuer
    throttle()
    r = http(f"https://login.microsoftonline.com/{domain}/v2.0/.well-known/openid-configuration")
    if r.get("body_snippet"):
        try:
            cfg = json.loads(r["body_snippet"])
            issuer = cfg.get("issuer", "")
            out["oidc_tenant_id"] = issuer.split("/")[3] if issuer.count("/") >= 3 else None
            out["oidc_issuer"] = issuer
        except json.JSONDecodeError:
            pass
    # DKIM selectors -> MOERA prefix leak
    for sel in ("selector1", "selector2"):
        recs = dns_lookup(f"{sel}._domainkey.{domain}")
        for rec in recs:
            if "protection.outlook.com" in rec or ".onmicrosoft." in rec:
                moera = rec.split(".")[0] if ".onmicrosoft." in rec else None
                if moera:
                    out[f"{sel}_moera_prefix"] = moera
                break
    # Defender for Identity instance
    mdi = dns_lookup(f"{domain.rstrip('.')}.atp.azure.com")
    out["mdi_instance_present"] = bool([r for r in mdi if "atp.azure.com" in r])
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    Path(output_path).write_text(json.dumps(out, indent=2))
    return out


def main() -> None:
    parser = argparse.ArgumentParser(description="Identity-domain recon engine (no-creds, header-level)")
    sub = parser.add_subparsers(dest="command")

    p1 = sub.add_parser("ntlm-recon")
    p1.add_argument("--hosts-file", required=True)
    p1.add_argument("--output", required=True)

    p2 = sub.add_parser("adcs-fingerprint")
    p2.add_argument("--host", required=True)
    p2.add_argument("--output", required=True)

    p3 = sub.add_parser("adfs-endpoints")
    p3.add_argument("--host", required=True)
    p3.add_argument("--output", required=True)

    p4 = sub.add_parser("entra-recon")
    p4.add_argument("--domain", required=True)
    p4.add_argument("--output", required=True)

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.command == "ntlm-recon":
        hosts = Path(args.hosts_file).read_text().splitlines()
        out = ntlm_recon(hosts, args.output)
        print(json.dumps({"count": out["count"], "output": args.output}))
    elif args.command == "adcs-fingerprint":
        print(json.dumps(adcs_fingerprint(args.host, args.output)))
    elif args.command == "adfs-endpoints":
        print(json.dumps(adfs_endpoints(args.host, args.output)))
    elif args.command == "entra-recon":
        print(json.dumps(entra_recon(args.domain, args.output)))


if __name__ == "__main__":
    main()
