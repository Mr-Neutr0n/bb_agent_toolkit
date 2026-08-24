# Changelog

All notable changes to this project are documented here.
Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning follows [SemVer](https://semver.org/) at the toolkit level.

## [3.1.0] - 2026-08-22

### Added
- `identity-domain` skill (#45): no-creds identity infra recon - NTLM Type 2
  decoding, ADCS web enrollment fingerprinting, ADFS/SAML metadata parsing,
  Entra tenant recon (getuserrealm/OIDC/DKIM-MOERA/MDI), governed Kerberos
  user enum with explicit scope ack, SPN OSINT.
- `crlf-desync` workflow (http-protocol): header-value CRLF injection,
  Range cache poisoning, status-line injection probes (Aug 2026 research).
- `batch-confusion` workflow (api): REST batch endpoint discovery + route
  confusion detection (wp2shell class, GET-only sub-requests).
- `oauth-conformance` workflow (auth): discovery grading, PKCE/state
  differentials, end-session redirects, device-flow audit, nOAuth checklist.
- `mcp-audit` workflow (ai-llm): MCP tool-definition rug-pull diffing,
  hidden-unicode description smuggling scans, STDIO config audit.
- Circuit breaker in bb-run: per-target cooldown after consecutive failures.
- Campaign FSM state file (.bb/campaigns/<id>/state.json) for external tools.
- Negative-result memory: program-memory `tested_clean` category with expiry.
- ct-index-enum workflow (recon): crt.name CT-index enumeration with
  first-seen dates and new-asset flagging.
- Tool registry: burp-mcp, trufflehog, crt.name entries.

### Added
- `binary-analysis` skill (#46): static PE triage (stdlib) + MCP-driven x64dbg dynamic sessions for desktop-app bounty surface.

### Changed
- bb-run UX: --help/--version, `list` commands for skills and workflows.
- Traces now record tools_required from skill.yaml.
- README accuracy pass: 45-skill catalog, badges, quick start.

### Fixed
- CI now enforces ruff + shellcheck; all binaries clean.
- Stale skill catalogs across README/AGENTS.md (39 -> 45).

## [3.0.0] - 2026-05-07

### Added
- Deterministic audit framework: validate_skills.py subcommands with JSON
  output, schema validation, safety-tier checks, release gate.
- Workflow tracing (.bb/traces/runs.jsonl + SQLite).
- Artifact registry with stable bb:// URIs.
- YAML playbooks with DAG validation and safe runner.
- Gated browser capture (Playwright, three-plane model).
- Program memory governance (corrections, decay, isolation).
- Provider adapters for five agent platforms.
- vuln-intel (#37) and scope-manager (#38) skills.
- oob-infra auto-setup/auto-cleanup/quick-poll workflows.
- Reporting quality gate and bounty estimator; CVSS 4.0 calculator and
  impact narrative generator in impact-verifier.

## [2.x] - earlier

See git history (initial open-source releases, DDD skill wave).
