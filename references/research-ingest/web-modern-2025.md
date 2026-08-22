# web-modern-2025 — Modern Web Appsec (race conditions, OAuth/PKCE/DCR, cache attacks, prototype pollution, WAF bypass, XS-Leaks, PortSwigger Research)

Cluster: web-modern-2025. Ingestion date: 2026-08-15. Audit date: 2026-08-15 (research-freshness audit pass).
Freshness window (operator rule): CURRENT = published 2026-06-01 or later; RECENT = 2026-01-01..2026-05-31; OUTDATED = 2025 or earlier (legacy context only, never treated as current technique). All notes are normalized, attributed, and tagged
`[technique]` / `[methodology]` / `[philosophy]` / `[tool]`. Original ingest tags (`[fresh]` / `[legacy-context]`) are kept for attribution; the FRESHNESS-TIER table below is the authoritative tier.

## FRESHNESS-TIER (audited 2026-08-15)

| # | Source | Pub date (verified) | Tier |
|---|---|---|---|
| 1 | HTTP/1.1 must die: the desync endgame (PortSwigger) | 2025-08-06 | OUTDATED |
| 2 | CRLF-Powered Desync Attacks: Beheading HTTP Streams (PortSwigger/TurtleSec) | 2026-08-05 ✓ | CURRENT |
| 3 | Can AI do novel security research? Meet the HTTP Terminator (PortSwigger) | 2026-08-05 ✓ (upd. 2026-08-12) | CURRENT |
| 4 | Pipelining vs request smuggling triage (PortSwigger) | 2025-08-19 | OUTDATED |
| 5 | Repeater Strike: manual testing, amplified (PortSwigger) | 2025-07-15 | OUTDATED |
| 6 | Gotta cache 'em all (PortSwigger) | 2024-08-08 | OUTDATED |
| 7 | Single-packet attack (PortSwigger) | 2023-10-18 | OUTDATED |
| 8 | Server-side prototype pollution (PortSwigger) | 2023-02-15 | OUTDATED |
| 9 | WAFFLED (arXiv:2503.10846) | 2025-03 | OUTDATED |
| 10 | HTTP Request Synchronization Defeats Discrepancy Attacks (arXiv:2510.09952) | 2025-10 | OUTDATED |
| 11 | When Prototypes Betray You — ProbeTheProto + GALA (JHU) | 2025-03-17 | OUTDATED |
| 12 | Audience Injection Attacks (IACR ePrint 2025/629) | 2025-04-07 (rev. 2025-12-02; IEEE S&P 2026) | OUTDATED |
| 13 | OAuth 2.1 draft-ietf-oauth-v2-1-13 | 2025-05-28 | OUTDATED (current draft: -15, 2026-03-02) |
| 14 | Forbid PKCE plain mode — oauth-v2-1 issue #236 | 2025-09-15 | OUTDATED |
| 15 | OAuth code injection / BFF / DCR analysis (Anador) | 2025-04-12 | OUTDATED |
| 16 | Web Cache Deception guide (Payload Playground) | 2026-04-10 ✓ | RECENT |
| 17 | Cache Deception + CSPT → ATO (zere.es) | 2025-08-17 | OUTDATED |
| 18 | Race Condition 101 (Kerolos Ayman) | 2025-06-24 | OUTDATED |
| 19 | Race Conditions in APIs (BIPI) | 2025 (undated) | OUTDATED — date unverified |
| 20 | ChatGPT ATO — Wildcard Web Cache Deception | 2024-02-04 | OUTDATED |
| 21 | CVE-2025-5266 (Firefox XS-Leaks) | 2025-06 | OUTDATED |
| 22 | SoK: XS-Leaks (AsiaCCS 2022) | 2022 | OUTDATED |

Totals: CURRENT 2 · RECENT 1 · OUTDATED 19. Dates verified at audit for the tier-moving sources (PortSwigger 2026-08-05 posts, Payload Playground, OAuth draft status); remaining dates carried from ingest with spot checks. **Cluster gap**: no 2026-06+ source covers race conditions, OAuth, prototype pollution, or XS-Leaks — those sections are OUTDATED-tier and need re-verification from the June–August 2026 window (see fresh-2026-web-exploit.md ingest).

## SOURCES

### PortSwigger Research (core of the cluster)

1. **HTTP/1.1 must die: the desync endgame** — James Kettle, PortSwigger Research, 2025-08-06 (Black Hat USA / DEF CON 33). [OUTDATED] (kept as canonical desync baseline; extended by #2/#3)
   https://portswigger.net/research/http1-must-die
   New desync classes (0.CL via obfuscated `Expect`, TE.TE), Expect-based desyncs (GitLab, Netlify, Akamai), Parser
   Discrepancy Scan methodology, HTTP Request Smuggler 3.0, $200k+ bounties in two weeks, 24M+ websites exposed via CDN core infrastructure.
2. **CRLF-Powered Desync Attacks: Beheading HTTP Streams** — Tom "t0xodile" Stacey et al., PortSwigger Research, 2026-08-05 (DEF CON 34). [CURRENT — date verified]
   https://portswigger.net/research/crlf-powered-desync-attacks
   Header injection → request splitting → RQP; Nginx `proxy_pass $uri` CRLF normalization; desync inside CDN infrastructure; CRLF-powered CL.TE; desync worm concept; AI-generated scanners (github.com/t0xodile/crlf-powered-desync-scanner).
3. **Can AI do novel security research? Meet the HTTP Terminator** — James Kettle, PortSwigger Research, 2026-08-05 (Black Hat USA 2026 / DEF CON 34). [CURRENT — date verified; paper updated 2026-08-12; open-sourced: github.com/PortSwigger/http-terminator]
   https://portswigger.net/research/can-ai-do-novel-security-research
   Autonomous research factory: 138 RFCs → 15,000 micro-inspiration fragments → 30,000 desync vectors; novel triggers
   (`Transfer-Encoding: gzip`, `Content-Type: multipart/byteranges` CL.0, `Early-Data`, dual matching Content-Length);
   dangling-byte technique for RQP; **Response Forking** (new desync class, unproven); **Shared-Parser Confusion**;
   status-line injection; Range Cache Poisoning; protocol-ruler technique; CVE-2026-63078 (Apache Traffic Server); blueprint for AI research loops.
4. **Beware the false false-positive: how to distinguish HTTP pipelining from request smuggling** — PortSwigger Research, 2025-08-19. [OUTDATED by date; triage methodology is still current practice]
   https://portswigger.net/research/how-to-distinguish-http-pipelining-from-request-smuggling
   Triage methodology separating connection-reuse/pipelining artifacts from genuine desyncs; test script for Repeater.
5. **Repeater Strike: manual testing, amplified** — PortSwigger Research, 2025-07-15. [OUTDATED by date; variant-amplification pattern absorbed into the 2026 HTTP Terminator cascade]
   https://portswigger.net/research/repeater-strike-manual-testing-amplified
   AI generates regex "strike rules" from a Repeater request/response pair, scans proxy history for IDOR/related variants (~61 tokens per rule). Predecessors: Shadow Repeater (2025-02-20), Document My Pentest (2025-04-23).
6. **Gotta cache 'em all: bending the rules of web cache exploitation** — PortSwigger Research, 2024-08-08. [OUTDATED — legacy baseline for cache work]
   https://portswigger.net/research/gotta-cache-em-all
   URL-parser discrepancies between origin and CDN proxies → arbitrary cache poisoning/deception; cache key as fingerprint; path confusion taxonomy. Still the baseline for 2025 cache work.
7. **The single-packet attack: making remote race-conditions 'local'** — PortSwigger Research, 2023-10-18. [OUTDATED — legacy; still the canonical race methodology used in every 2025 case study found]
   https://portswigger.net/research/the-single-packet-attack-making-remote-race-conditions-local
   (with **Smashing the state machine** whitepaper, 2023-08-09). HTTP/2 single-packet technique, sub-states, limit-overrun; still the canonical race methodology used in every 2025 case study found.
8. **Server-side prototype pollution: black-box detection without the DoS** — PortSwigger Research, 2023-02-15. [OUTDATED — legacy; detection baseline, now mirrored in OWASP WSTG (current)]
   https://portswigger.net/research/server-side-prototype-pollution
   Non-destructive probes: `json spaces`, status override, exposedHeaders, OPTIONS, reflection, OAST; Burp extension. Still the detection baseline, now mirrored in OWASP WSTG (current).

### Academic / fresh 2025–2026 research

9. **WAFFLED: Exploiting Parsing Discrepancies to Bypass Web Application Firewalls** — Akhavani et al., arXiv:2503.10846, 2025-03. [OUTDATED — 2025 WAF state; no 2026 re-verification in corpus]
   https://arxiv.org/html/2503.10846
   1,207 confirmed bypasses across AWS WAF, Azure WAF, GCP Cloud Armor, Cloudflare, ModSecurity via fuzzing non-malicious components (headers, body segments) with `application/json`, `multipart/form-data`, `application/xml`; >90% of sites accept `application/x-www-form-urlencoded` and `multipart/form-data` interchangeably; HTTP-Normalizer defense proxy.
10. **HTTP Request Synchronization Defeats Discrepancy Attacks** — Topcuoglu et al., arXiv:2510.09952, 2025-10. [OUTDATED — 2025; best discrepancy-attack catalog, defense-oriented]
    https://arxiv.org/html/2510.09952
    Defense research but the best current catalog of discrepancy attack classes (cache poisoning, smuggling, path/hostname confusion) and why per-vendor patches fail; proposes propagating per-request processing history.
11. **When Prototypes Betray You (ProbeTheProto + GALA)** — Kang, Li, Cao, Johns Hopkins dissertation, 2025-03-17. [OUTDATED — 2025 measurement; largest client-side PP dataset to date]
    https://jscholarship.library.jhu.edu/items/38a5960a-98f5-4c85-a844-717e79ebf33a
    Large-scale measurement: 2,917 zero-day client-side prototype pollution vulns on 2,738/1M real websites (10 in top-1,000); 48 → XSS, 736 → cookie manipulation, 830 → URL manipulation; GALA gadget mining (133 zero-day gadgets; Vue CVE-2024-6783, Meta bounty).
12. **Audience Injection Attacks** — Hosseyni, Küsters, Würtele, IACR ePrint 2025/629 (2025-04-07, rev. 2025-12-02; IEEE S&P 2026). [OUTDATED by pub date; attack class remains unpatched-by-default across many ASes — re-verify adoption of `aud` enforcement in 2026]
    https://eprint.iacr.org/2025/629
    New attack class on audience handling in signature-based client authentication across OAuth 2.0, OIDC, FAPI, CIBA, Device Grant, PAR, revocation/introspection; leads to impersonation/ATO; fixes coordinated across a dozen standards.
13. **OAuth 2.1 Authorization Framework, draft-ietf-oauth-v2-1-13** — IETF, 2025-05-28. [OUTDATED — draft-13; current draft is -15 (last updated 2026-03-02, IESG submission milestone Dec 2026); re-read -15 before relying on checklist details]
    https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/13/
    PKCE mandatory, exact redirect-URI string matching, implicit/ROPC removed, refresh tokens for public clients sender-constrained or one-time-use, DCR interplay. RFC 9700 (OAuth 2.0 Security BCP, 2024-12) is the [legacy-context] companion.
14. **Consideration to forbid PKCE plain mode in OAuth 2.1** — oauth-wg/oauth-v2-1 issue #236, 2025-09-15. [OUTDATED — consensus discussion; verify whether plain-mode removal actually landed in draft-15/final RFC]
    https://github.com/oauth-wg/oauth-v2-1/issues/236
    PKCE `plain` mode = unverifiable downgrade vector (A4 attacker rewrites `code_challenge_method`); consensus at IETF 125 to drop it; MCP spec inherits the bad language.
15. **Attacks via a New OAuth flow, Authorization Code Injection, and Whether HttpOnly, PKCE, and BFF Can Help** — Anador, 2025-04-12. [OUTDATED — 2025]
    https://dev.to/anador/attacks-via-a-new-oauth-flow-authorization-code-injection-and-whether-httponly-pkce-and-bff-can-1i2c
    Silent-iframe code injection against BFF/confidential clients; PKCE verifier placed in HttpOnly pre-auth session cookie; what PKCE/BFF do and don't stop; form-post response mode + DCR `javascript:` redirect URI → AS-side XSS.

### Community / case-study sources

16. **Web Cache Deception: Path Confusion, Delimiters, and Static-Extension Tricks** — Payload Playground, 2026-04-10. [RECENT — date verified]
    https://payloadplayground.com/blog/web-cache-deception-guide
    Four WCD discrepancy classes, delimiter fuzz list, two-account confirmation methodology, safe cache-buster hygiene, defense checklist (cache by Content-Type not extension, never cache Set-Cookie, strict Vary).
17. **Cache Deception + CSPT: Turning Non Impactful Findings into Account Takeover** — Jorge Cerezo Dacosta, 2025-08-17. [OUTDATED — 2025; chaining template still valid]
    https://zere.es/posts/cache-deception-cspt-account-takeover/
    Chain: CSPT lets victim's browser send authenticated request (custom `X-Auth-Token`) to a cacheable path → CDN caches token JSON → unauthenticated fetch = ATO. Great chaining template for "unexploitable" singles.
18. **Race Condition 101: real bug bounty scenario** — Kerolos Ayman, 2025-06-24. [OUTDATED — 2025; low depth; evidence of current practice]
    https://keroayman77.medium.com/race-condition-101-...  — unique-name validation race broken with 11 parallel Repeater requests.
19. **Race Conditions in APIs: Single-Packet Attacks and Idempotency** — BIPI, 2025 (undated). [OUTDATED — date unverified]
    https://bipi.in/blog/race-conditions-in-apis — TOCTOU targets checklist (vouchers, refunds, MFA enroll, withdrawals, promo signup), 20-copy parallel replay, `SELECT FOR UPDATE`/idempotency-key/atomic-UPDATE fixes, detection via duplicate transaction alerts.
20. **ChatGPT Account Takeover — Wildcard Web Cache Deception** — Harel, 2024-02-04. [OUTDATED — 2024; canonical modern WCD example]
    https://nokline.github.io/bugbounty/2024/02/04/ChatGPT-ATO.html — wildcard cache rule (`/share/*`) + `%2F..%2F` normalization mismatch → cached auth tokens. Canonical modern WCD example.
21. **CVE-2025-5266** (Firefox < 139 / ESR < 128.11, fixed 2025-06). [OUTDATED — fixed 2025-06; proof the class was live in 2025 browsers; re-derive channel inventory for 2026 browsers]
    https://nvd.nist.gov/vuln/detail/CVE-2025-5266 — cross-origin `<script>` load/error events leak information enabling XS-Leaks; proof the class is still live in 2025 browsers.
22. **SoK: Exploring Current and Future Research Directions on XS-Leaks** — Van Goethem et al., AsiaCCS 2022. [OUTDATED — 2022 SoK; framework still the analytical baseline]
    https://lirias.kuleuven.be/retrieve/680065 — formal model (state transfer → component state → retrieval), defense analysis: no single defense covers all; SameSite + COOP + site isolation is the minimal best set. MDN XS-Leaks guide (current living doc) is the practical checklist: https://developer.mozilla.org/en-US/docs/Web/Security/Attacks/XS-Leaks

## CONCEPTS

### Race conditions (2025–2026 state)

- [technique] Single-packet attack: complete 20–30 HTTP/2 requests with one TCP packet (withhold END_STREAM/final byte, Nagle-batch the final frames after a 100ms wait + ping warm-up). Eliminates network jitter → remote races behave like local. Burp Repeater "Send group in parallel" / Turbo Intruder `engine=Engine.BURP2, concurrentConnections=1` + `gate`/`openGate`. [legacy-context 2023; unchanged standard in 2025]
- [technique] HTTP/3 supports the single-packet attack in principle (UDP datagram ~1500B), not worth building; HTTP/1.1 pipelining is sequential (head-of-line blocking) — use parallel connections + last-byte sync instead. WebSocket races are under-tooled; RFC 8441 (WS over H2 streams) would enable full-power single-packet races.
- [methodology] Race discovery loop (Smashing the state machine): (1) benchmark baseline behavior with sequential requests; (2) pick high-value multi-step endpoints (email change, invite, coupon, password reset); (3) probe with 20–30 concurrent copies, look for any anomaly (duplicate success, different error text, second-order state change); (4) minimize to 2 requests to prove the exploit. "Spotting anomalies is the single most important skill."
- [technique] Multi-endpoint races: when requests must land at different times, abuse server "leaky bucket" rate-limits — flood dummy requests to force a server-side delay and make the single-packet attack viable for delayed execution.
- [methodology] 2025 practice checklist for API races: voucher redemption, refund issuance, withdrawal (100% balance), MFA enroll-vs-disable half-states, promo signup credits, unique-name/unique-key validation (3/11 successes → reportable). Fixes to check for when triaging: `SELECT ... FOR UPDATE`, idempotency keys (Stripe pattern), atomic `UPDATE ... WHERE balance >= X`, Redis SET NX mutex, act-then-check with unique constraints. [superseded-risk: checklist is 2025 practice with no 2026-06+ confirmation in cluster — re-verify target list against fresh 2026 race research]

### HTTP desync / smuggling (2025–2026 state — biggest movement in the cluster)

- [methodology] Parser Discrepancy Scan (HTTP Request Smuggler 3.0): stop sending canned CL.TE/TE.CL probes; instead detect inconsistent parsing of HTTP headers across the proxy chain, then confirm leads manually. "This strategy creates an avalanche of desync research leads" and bypasses the wave of superficial blocklist mitigations from 2019–2024.
- [technique] 0.CL desync via `Expect: 100-continue`: obfuscated `Expect :\t100-continue` variants hit GitLab; vanilla `Expect` hit Netlify CDN; obfuscated hit Akamai. Expect handling = early-response gadget.
- [technique] `Transfer-Encoding: gzip` (RFC 9112 §6.1 "HTTP/1.0 + TE = faulty framing") as a CL.0 trigger on multiple stacks (F5 Big-IP case → RQP at an airport).
- [technique] `Content-Type: multipart/byteranges; boundary=BOUND` as a CL.0 desync trigger (RFC 2616 §19.2 — a response-only content type misapplied to requests); worked on multiple server implementations, 200+ websites, incl. an American bank. Never considered Content-Type a desync vector before.
- [technique] Dual matching Content-Length headers: some servers (Citrix NetScaler case) treat the request as CL:0 even when both CLs match and are valid → framing confusion; exploit found via the "clean request gets two responses" anomaly rule.
- [technique] CRLF-powered desyncs (2026): Nginx `proxy_pass $uri` normalizes the path and decodes `%0d%0a` → request-header injection → request splitting → RQP, no RFC-breaking mutated headers needed. Insertion points beyond the path: custom upstream headers, session cookies (payment provider case: credit card + PII exfil from a K8s cluster). CRLF-injected `Transfer-Encoding` → CL.TE desync. Escalation ladder: header injection → splitting → RQP → "desync worm" (self-propagating ATO). [CURRENT — 2026-08-05]
- [technique] RQP weaponization: dangling-byte technique (smuggled request missing its final byte) removes the stacked-response race, forcing the back-end to generate the second response only when the victim's request arrives — made RQP reliable on every method-agnostic back-end tested. [CURRENT — 2026-08-05]
- [concept/methodology] Shared-Parser Confusion: servers share request/response parsing code, so response-processing features (multipart/byteranges, Set-Cookie in requests) can be hit from requests — a new cross-server attack class expected to yield many attacks; closest prior art is Orange Tsai's Apache "Confusion Attacks". [CURRENT — 2026-08-05; unproven breadth, treat as lead]
- [concept] Response Forking: "one request → two responses" primitive (HTTP/0.9-style second response) as a potential new desync class independent of length disagreement; unproven in the wild (hypothetical). [CURRENT by source; still unproven]
- [technique] Range Cache Poisoning: `Range` responses served without a 206 status can be cached; multi-range (`bytes=364-382, 1-2`) + front-end reassembly or context-aware escaping as the exploitation route.
- [methodology] Triage discipline: pipelining/keep-alive behavior looks like smuggling — use connection-reuse fingerprinting (test script in the 2025-08-19 post) before reporting; client-side (browser-powered) desyncs can't use header obfuscation.
- [tool] HTTP Request Smuggler 3.0 (parser discrepancy scan + new vectors), HTTP Hacker (stream-level view), Turbo Intruder with MCP interface, crlf-powered-desync-scanner (BulkScan-based), PortSwigger/http-terminator (AGPL, 2026-08-03 — seeker/flamer/validator/investigator stages).
- [philosophy] Desyncs are a protocol-design flaw, not a per-implementation bug: upstream HTTP/1.1 must be treated as hostile; "the request is a lie" (stream of bytes); assume any HTTP/1.1 hop in the chain is exploitable; allow-list methods and body-carrying methods on both front-end and back-end.

### Cache poisoning / deception (2025–2026 state)

- [technique] WCD discrepancy classes: (1) path confusion — appended segments/`;foo.css`/`..%2F` forms the origin routes to a dynamic handler while the cache keys the `.css` suffix; (2) delimiter discrepancies — `;`, `?`, encoded newline as path terminators (Tomcat matrix params `;jsessionid=`); (3) static-extension/directory blanket rules — fuzz a wide extension list (`.css .js .jpg .png .gif .ico .svg .woff .map .txt .pdf`) and `/static/`-style prefixes with origin-side normalization. Probe cache and origin separately; confirm via `cf-cache-status: HIT` / `x-cache` / `Age`. [RECENT — 2026-04-10]
- [technique] Wildcard cache rules + encoded traversal: rules like `/share/*` cache everything; `%2F..%2F` (CDN doesn't decode, origin does) maps any sensitive API endpoint into a cacheable path → cached auth tokens (ChatGPT ATO case). Always probe cache-rule prefixes with encoded traversal.
- [methodology] Safe WCD confirmation: two accounts you control; cache your own response; re-request unauthenticated and check you receive account A's data; unique cache-buster query (`?wcd=`) while mapping, drop only for final proof. Never deliberately cache a live victim's data.
- [technique] Cache-key parser fuzzing (Gotta cache 'em all): the cache key is a fingerprint of request attributes (path, query, headers, body); any parser discrepancy between CDN and origin that makes two semantically different requests collide on one key enables poisoning or deception — fuzz URL parsing (encoding, normalization, fragment handling) across the proxy.
- [methodology] Chaining: an individually unexploitable cache deception (auth required via header the browser can't send) becomes ATO when combined with a client-side path traversal that makes the victim's own browser issue the authenticated request to the cacheable path. Always ask "what else can make this request?"
- [philosophy] "Cache and origin are two systems that rarely agree" — hunt the seam, not the layers; WCD is the sibling of cache poisoning (key vs origin behavior), and the same delimiters power smuggling.

### Prototype pollution (2025 state)

- [technique] Client-side PP is now a measured epidemic, not a rarity: 2,917 zero-day sources across 2,738/1M sites (ProbeTheProto, 2025); sources = query/hash/URL-driven recursive merges; gadgets turn sources into DOM XSS (48 verified), cookie manipulation (736), URL manipulation (830). Top-1000 sites included. [superseded-risk: measurement is 2025; prevalence/impact re-check needed for 2026]
- [methodology] Gadget mining (GALA): don't stop at the source; systematically hunt gadgets by borrowing defined property values from benign sites and injecting them into undefined lookups at vulnerable sites — 133 zero-day gadgets (Vue CVE-2024-6783). Practical takeaway: after confirming a source, grep the page's third-party libs for config/options/sink properties read off `this.*`/`config.*` without own-property definitions.
- [technique] Server-side detection stays black-box: `json spaces` pretty-print probe (Express), status-code override, `Access-Control-Expose-Headers` override, OPTIONS/HEAD exclusion, reflection of `__proto__`, non-reflected property test, OAST via `--inspect`/child-process sinks. `--disable-proto=delete` is defense-in-depth only (constructor.prototype remains).
- [technique] Filter-bypass encodings: `constructor[prototype][x]=y`, nested `__pro__proto__to__[x]=y`, dot/square-bracket JSON syntax in query params — survives single-pass `__proto__` strips.
- [tool] DOM Invader (source + gadget scan), ppmap/ppfuzz, PortSwigger server-side PP scanner extension, OWASP WSTG latest "Testing for Prototype Pollution" as the checklist.

### OAuth 2.1 / PKCE / DCR (2025–2026 state)

- [methodology] OAuth 2.1 audit checklist (draft-13, 2025): PKCE required for all auth-code clients (server MUST enforce verifier iff challenge present); exact redirect-URI string matching (path included; loopback port-only exception); implicit & ROPC absent; bearer tokens not in query strings; public-client refresh tokens sender-constrained or single-use; DCR per RFC 7591/7592. RFC 9700 (2024) is the normative BCP. [superseded-risk: checklist is draft-13-based (2025-05-28); current draft is -15 (2026-03-02) — re-read before use; core requirements (PKCE-for-all, exact redirect) unchanged to date]
- [technique] PKCE downgrade: attacker strips `code_challenge` (or rewrites method to `plain`) from the authorization request when the AS only enforces PKCE conditionally → stolen-code redemption works. Test: does the AS reject token requests with a `code_verifier` when no challenge was in the auth request? Is `plain` accepted (it must not be, per IETF 125 consensus)? [superseded-risk: `plain`-drop was consensus-in-progress (2025-09); verify final draft-15 language]
- [technique] Audience injection (2025): signature-based client auth (`private_key_jwt` and friends) must be bound to the correct audience per endpoint; when audience validation is missing/loose across multiple endpoints (auth, token, revocation, introspection, PAR), attackers can redirect/impersonate across the ecosystem — test by replaying a signed client assertion against sibling endpoints and checking audience acceptance.
- [technique] DCR abuse: register clients with `javascript:` / pseudo-protocol redirect URIs under form-post response mode → XSS on the authorization server itself; open-ecosystem DCR + client redirect matching enables mix-up; per-AS distinct redirect URIs can be circumvented by registering a new client with the honest AS using the attacker-assigned URI.
- [methodology] Code-injection/BFF testing: silent-iframe authorization flows against BFFs — BFF + PKCE stops code redemption without client credentials, but attacker JS on the app origin can still run a fresh silent flow (fresh tokens); PKCE does not stop injection when attacker can modify the victim's `code_challenge`; server-side verifier in an HttpOnly pre-auth session cookie is the robust pattern to look for (and to test against).

### WAF bypass (2025–2026 state)

- [technique] Parsing-differential WAF bypass (WAFFLED, 2025): fuzz *non-malicious* components — header names/values, body segments — under `application/json`, `multipart/form-data`, `application/xml`; 1,207 bypasses across AWS, Azure, Cloud Armor, Cloudflare, ModSecurity. The enabling fact: >90% of sites accept form-urlencoded and multipart interchangeably — craft the payload in the body representation the WAF doesn't parse. [superseded-risk: 2025-03 measurements; WAF vendors have updated since — re-verify bypasses on current 2026 configs before relying]
- [methodology] Differential testing loop: for each content-type, send benign-but-suspicious structures (duplicate fields, unusual field order, parameter pollution) and compare WAF verdict vs origin handling; normalize-anywhere defenses (HTTP-Normalizer) kill whole classes, per-vendor regex patches do not.

### XS-Leaks / browser-edge (2025–2026 state)

- [technique] XS-Leak channels still shipping in 2025 browsers: CVE-2025-5266 — cross-origin `<script>` load/error events leaked response state (fixed Firefox 139/ESR 128.11, 2025-06). Classic channels remain: error-event oracles, frame counting via window refs, CSP-based redirect detection, network timing (performance.now / cross-window), cache state, focus/blur navigation. [superseded-risk: channel inventory is 2025-browser-specific; must be re-derived per 2026 browser version]
- [methodology] Systematic leak hunting: model = attacker transfers app state into a component's state (cache, connection pool, DOM, server rate-limiter), then retrieves the difference; test each inclusion method × detectable-difference pair (AutoLeak ran 151,776 test cases; S&P'23 framework found 280 observation channels incl. "fixed" leaks).
- [philosophy] Defense matrix (current): SameSite cookies + COOP + site isolation is the minimal best set; Fetch-Metadata isolation (Sec-Fetch-Dest) + framing protection as fallback; there is no single complete defense — cross-window attacks resist even COOP. Practical target-side checks: missing `frame-ancestors`/COOP/CORP, Lax-only SameSite, stateful endpoints that reflect session state cross-site.

### AI-augmented methodology (PortSwigger 2025–2026)

- [methodology] Variant amplification (Repeater Strike, 2025): one confirmed IDOR → AI generates regex strike rules from the request/response pair → sweep proxy history for sibling endpoints; ~61 tokens per rule, zero tokens at scan time. Same pattern as "1-day variant hunting": turn one finding into a class. [superseded-risk: superseded-in-part by the HTTP Terminator cascade (2026-08) as the canonical AI-research workflow; still the cheapest per-finding amplification]
- [methodology] AI research factory (HTTP Terminator, 2026): evaluation-first design (black-box trigger → victim-response contamination test, no expectations about the poisoned response), micro-inspiration (1–3 sentence fragments from RFCs; avoid full-context prompts that cause over-anchoring), cascade (feed every proven hypothesis back as inspiration; ask "how can I detect similar behavior elsewhere?" and "does the origin of that behavior enable other attacks?"), deterministic code over AI for validation (split templates: agent proves trigger/payload, code evaluates success). [CURRENT — 2026-08-05; open-sourced]
- [tool] Protocol ruler technique: use the back-end's header-length limit as a ruler to measure front-end input transformations (value-rewriting, header dropping, Unicode/mojibake transforms) — now shipped in Param Miner.

## OUTDATED-OR-SUPERSEDED

Re-tiering note: with the 2026-06-01 CURRENT cutoff, 19 of 22 sources are OUTDATED-tier. Items below flag what is functionally dead vs merely old. None of these are treated as current technique without a 2026 re-verification.

- **Race conditions** [OUTDATED-CONTEXT]: pre-2023 lore said races were only reliably testable with last-byte sync and near-local targets; single-packet attack (2023) is now the default, ~4–10x tighter (1ms vs 4ms median spread), and 2025 writeups (unique-name races, API TOCTOU) use it as standard. HTTP/1.1 pipelining as a race technique is dead (head-of-line blocking). "Limit-overrun" thinking is now framed as a special case of sub-state discovery ("everything is multi-step"). [superseded-risk: all sources ≤2025 — the single-packet default itself needs 2026 confirmation]
- **Request smuggling** [OUTDATED-CONTEXT]: 2019-era CL.TE/TE.CL payload-blocklists are obsolete — vendors patched the known strings, and 2025–2026 research (Expect/0.CL, TE.TE, dual-CL, multipart/byteranges, CRLF splitting) walks straight through them; the effective method is now primitive/parser-discrepancy detection, not known-payload probes. Smuggling-as-rare is dead: it's a protocol flaw ("HTTP/1.1 must die"), and RQP weaponization (dangling-byte) is now practical where it was considered unreliable. NOTE: this whole area is refreshed by the CURRENT-tier 2026-08-05 CRLF-desync + HTTP Terminator posts — use those as the current baseline and treat 2025 posts as their prehistory.
- **Cache attacks** [OUTDATED-CONTEXT]: extension-only WCD checklists (`.css`/`.js` appended) still work but miss the modern variants: delimiter/matrix-param confusion, wildcard cache-rule + encoded traversal, `Range`-without-206 cache poisoning, parser-mismatch key collisions. "Cache-Control on origin is respected" is false — CDNs override for static-looking paths. (Latest in-cluster source: 2026-04-10, RECENT.)
- **Prototype pollution** [OUTDATED-CONTEXT]: treated as exotic/server-side-only in pre-2023 material; 2025 measurements show client-side sources on ~0.3% of all websites (incl. top-1000); detection moved from manual payloads to DOM Invader gadget scans and large-scale taint tracking; `__proto__`-only payloads fail against modern strips (constructor/prototype, nested encodings). [superseded-risk: 2025 measurement — 2026 prevalence unverified]
- **OAuth** [OUTDATED-CONTEXT]: pre-2024 guidance ("PKCE only for native apps", state-for-CSRF is enough, redirect prefix matching OK) is superseded by OAuth 2.1/RFC 9700 (PKCE for all clients, exact redirect matching, PAR, DCR hardening, `iss` for mix-up, S256-only after IETF 125). Audience validation for signed client assertions is a newly mandatory check (audience injection). [superseded-risk: cluster's checklist is draft-13 (2025-05-28); current draft -15 (2026-03-02) — re-read for final details]
- **WAF evasion** [OUTDATED-CONTEXT]: signature mutation (case swaps, comment obfuscation) is largely moot against modern WAFs; the 2025 frontier is structural parsing differentials (content-type interchangeability, header/body placement), which scale across vendors. [superseded-risk: WAFFLED is 2025-03; re-verify bypass set against 2026 WAF configs]
- **XS-Leaks** [OUTDATED-CONTEXT]: several classic channels (connection-pool timing without keying, some error-event leaks) were fixed or partitioned; but new ones keep shipping (2025 Firefox CVE), so the old "list of 10 techniques" must be re-derived per browser version; systematic channel-discovery frameworks replace hand-rolled PoCs. [superseded-risk: all sources ≤2025; no 2026 XS-Leak research in cluster]
- **Manual variant hunting** [OUTDATED-CONTEXT]: pure-manual "one finding = one report" is being augmented by AI-assisted variant amplification (Shadow Repeater/Repeater Strike 2025) and fully autonomous research factories (HTTP Terminator 2026) — hunting windows for novel classes are shrinking. [CURRENT direction per 2026-08-05 posts]

## HOW THIS CHANGES OUR HARNESS

1. **`http-protocol` skill**: replace/expand canned smuggling probes with the Parser Discrepancy Scan approach; add the 2025–2026 trigger catalog (Expect/0.CL, TE.TE, `Transfer-Encoding: gzip`, `multipart/byteranges` CL.0, dual matching CL, CRLF injection → splitting → RQP, dangling-byte RQP, Range cache poisoning) with safety tiers (probes active-safe; RQP exploitation intrusive). Add pipelining-vs-smuggling triage to `impact-verifier` to cut false positives.
2. **`race-condition` skill**: codify single-packet attack defaults (BURP2 engine, gate/openGate, 20–30 copies) and the benchmark→probe→minimize methodology; add the 2025 API target checklist (vouchers/refunds/MFA/withdrawals/signup) and rate-limit-abuse delay trick; add fix-pattern triage (SELECT FOR UPDATE, idempotency keys) to distinguish reportable vs already-hardened. [superseded-risk: checklist needs 2026 re-verification]
3. **`recon` / `http-protocol`**: add a cache-deception checklist workflow (extension + delimiter fuzz lists, cache-status header read, wildcard-rule + `%2F..%2F` traversal probing, two-account safe confirmation with cache-busters) and cache-key parser fuzzing for poisoning.
4. **`xss` skill**: add client-side prototype-pollution source probing + DOM Invader gadget scan as a standard workflow (it's now a top-N web bug class by prevalence); extend server-side PP probes (json spaces/status/reflection/OAST) into a checklist with filter-bypass encodings.
5. **`auth` skill**: add OAuth 2.1-era checks — PKCE enforcement & downgrade tests (challenge-strip, `plain` acceptance), exact redirect matching, DCR redirect-scheme abuse (`javascript:` + form_post → AS XSS), audience validation for `private_key_jwt` across endpoints, silent-flow/BFF code-injection patterns. [superseded-risk: re-baseline against OAuth 2.1 draft-15 before implementing]
6. **`modern-browser` skill**: refresh XS-Leak technique list against 2025+ browsers (error-event oracles, frame counting, timing, CSP-redirect leaks) with the defense matrix (SameSite/COOP/frame-ancestors/Fetch-Metadata) as the target-side assessment. [superseded-risk: re-derive for 2026 browsers]
7. **`technique-kb` / `planner` / `campaign`**: ingest these as entries so plans surface parser-discrepancy scans, cache-deception fuzzing, and OAuth 2.1 checks for relevant archetypes; WAF-bypass differential testing (WAFFLED patterns) as a cross-cutting technique for payload skills.
8. **`skill-scientist` / `auto-research`**: adopt the micro-inspiration + evaluation-first + cascade loop from the HTTP Terminator for in-repo skill research, and the Repeater-Strike pattern (one finding → regex class sweep) for variant amplification in engagements. [CURRENT: HTTP Terminator (2026-08-05) is the reference blueprint; repo: github.com/PortSwigger/http-terminator]
