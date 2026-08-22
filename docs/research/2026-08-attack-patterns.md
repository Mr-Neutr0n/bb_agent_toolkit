# Research Digest: New Attack Patterns (late 2025 - Aug 2026)

Date: 2026-08-22. Focus: bounty-relevant techniques, automation feasibility,
and concrete skill/workflow ideas for BountyHarness. Companion to the harness digest.

## Web / HTTP Protocol

- Desync trigger classes are now corpus maintenance, not research: obfuscated `Expect`
  0.CL, TE.TE chunk extensions, multipart/byteranges CL.0, dangling-byte request
  queue poisoning confirmation. Kettle's Aug 2025 bug-hunting marathon reported
  $200k in two weeks from exactly these shapes. [AUTO detect / HYBRID weaponize]
- Browser-powered desync and web cache deception variants: delimiter/extension
  matrices tested with two accounts; CDN header-count truncation (>100 headers);
  framework internal-cache probes (`__nextDataReq`, `_payload.json`,
  `x-now-route-matches`). Multiple five-figure payouts documented. [AUTO]
- DOM clobbering as CSP-escape primitive: gadget detection at confirmed HTML
  injection points matched against whitelisted-CDN gadget databases; 497 gadgets /
  19 CVEs catalogued publicly. [HYBRID]

## AI / LLM-Specific (paid findings)

- Highest-paying LLM chains end in conventional bug classes (SSRF, ATO, credential
  theft). Framing matters as much as discovery.
- Indirect prompt injection via crawlable content with OOB exfil markers;
  prompt-preloading URL parameters on chat surfaces. Google-tier $20k+. Needs LLM
  loop for payload iteration; delivery fully scripted.
- MCP server attacks: tool-definition rug-pulls (hash diff across sessions), hidden
  unicode instructions in tool descriptions, anonymous remote tool listing, STDIO
  launch configs matching SDK command-injection defaults. [AUTO scans / LLM impact]
- Scanner-evasion via injection into the scanning agent itself (Shai-Hulud pattern):
  any harness LLM loop reading target content needs canary-based self-protection.

## Identity / Cloud / CI-CD

- OAuth conformance testing is deterministic and underhunted: nOAuth account-merge
  pattern, authorize-endpoint open redirects, device-flow scope audits, PKCE/state/
  nonce validation gaps. [AUTO]
- CI/CD moved to critical tier: `pull_request_target` with fork-reachable cache
  writes, SHA-unpinned actions, orphan-commit workflow reachability, OIDC scope
  creep on public org repos are default audit surface now. [AUTO]
- Supply-chain provenance: phantom versions, published-version-without-tag mismatch,
  anomalous upload User-Agents for targets publishing packages. VDP-friendly. [AUTO]
- Kubernetes edge: exposed ingress-nginx admission controllers (CVE-2025-1974
  family), Argo CD repo-server gRPC reachability, EOL controller fingerprints. [AUTO]
- Entra tenant recon rots fast: GetFederationInformation domain enum died Aug 2025,
  ACS metadata May 2026. Remaining unauthenticated paths: getuserrealm, OIDC
  well-known, DKIM selector MOERA CNAMEs, MDI instance checks. Encode current-state
  checks, never hardcoded endpoints.
- Identity-infra on external scope is a real gap class: NTLM challenge info leaks,
  OWA/EWS/Autodiscover NTLM endpoints, ADCS web enrollment exposure (/certsrv,
  mscep, CES endpoints) without EPA, ADFS endpoint fingerprinting, SAML metadata
  analysis, Kerberos user enumeration where 88/tcp is scoped. See identity-domain skill.
- Desktop Electron apps sit inside normal web program scope and are systematically
  under-tested vs one-click-RCE severity: ASAR extraction, webPreferences audit
  (the recurring fatal profile: nodeIntegration:true + contextIsolation:false +
  stripped security headers), protocol-handler enumeration, deeplink reflection
  fuzzing, `shell.openExternal(file://)` passthrough. [AUTO recon/fuzz / HYBRID chains]

## Ranked Skill/Workflow Ideas (bounty relevance x automation feasibility)

1. desync-matrix sweep -> http-protocol [AUTO detect]
2. gha-workflow-audit -> cicd-security [AUTO]
3. cache-discrepancy matrix -> cors-csrf/http-protocol [AUTO]
4. mcp-audit (tool rug-pull diffing) -> ai-llm [AUTO + LLM]
5. electron-deeplink audit -> new surface [AUTO recon / HYBRID]
6. agent-inject-harness with OOB canaries -> ai-llm + oob-infra [LLM core]
7. oauth-conformance suite -> auth [AUTO]
8. k8s-edge-sweep templates -> cloud/recon [AUTO]
9. clobber-csp-chain finder -> xss [HYBRID]
10. provenance-audit -> vuln-intel/osint [AUTO]
11. xsleak-probe matrix -> modern-browser [AUTO]
12. scanner-poison-guard canaries -> agent-safety [AUTO + LLM]

## Sources (selection)

- PortSwigger HTTP-desync research series and Kettle marathon writeups (portswigger.net/research)
- CherryHQ cherry-studio GHSA-p6vw-w3p8-4g72; AFFiNE GHSA-67vm-2mcj-8965; SiYuan GHSA-6gx2-8gcr-x83f
- flatt.tech "Escaping Electron Isolation With Obsolete Feature" (RyotaK Chatwork chain)
- Electron platform GHSAs: mwmh-mq4g-g6gr, p2rr-rvmm-c5fp; deepstrike.io Electron pentest guide
- Sprocket Security tenant-enumeration status; TrustedSec Azure time-based enumeration
- dirkjanm.io Entra actor-token and Intune ADCS posts; KB5005413 NTLM relay mitigation
