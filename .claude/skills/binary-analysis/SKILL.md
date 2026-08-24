# Binary Analysis

## Overview
Static and dynamic analysis of Windows binaries shipped by bounty targets:
desktop apps, updaters, agents, packed downloadables. Static triage is
stdlib-only and runs anywhere; dynamic sessions drive a local x64dbg debugger
through its MCP plugin (duty1g/x64dbg-mcp-server, 71 tools over HTTP with
bearer auth). All analysis is LOCAL on files you legitimately possess - this
skill never interacts with remote target infrastructure.

## Quick Reference
- **Skill**: binary-analysis
- **Version**: 1.0.0
- **Bounded Context**: BinaryAnalysisContext
- **Required tools**: `python3` (static); x64dbg + x64dbg-mcp-server plugin (dynamic)
- **Risk tier**: passive (toward targets - local file analysis only)

## Workflow Selection

| Intent | Workflow | Tier |
|---|---|---|
| First-pass on one executable | `pe-triage` | passive |
| Triage a folder of downloads | `pe-triage-batch` | passive |
| List tools on live x64dbg session | `mcp-tools` | passive |
| Read registers/modules/strings, set breakpoints | `mcp-call` | passive |

## Setup (one-time)
1. Download x64dbg from https://x64dbg.com
2. Install the MCP plugin per https://github.com/duty1g/x64dbg-mcp-server
   (copy `dist/` into the x64dbg root; server auto-starts on ports 9094/9095)
3. Copy the auto-generated bearer token: `echo TOKEN > .bb/x64dbg.token`

## Bounty-Relevant Uses
- Desktop app programs: analyze deeplink/protocol handlers, update mechanisms,
  license checks before touching them dynamically
- Packed binaries: triage flags UPX/VMP/Themida-style sections; dump after OEP
  via mcp-call pe-analysis intent, then re-triage the unpacked image
- Crash triage: breakpoint at watched APIs while reproducing to prove control
- Config discovery: strings/pattern intents reveal embedded endpoints feeding
  back into recon scope

## Evidence Required
- Static: full triage.json with section table and import watchlist hits
- Dynamic: mcp_call.json snapshots timestamped against your manual interaction
  steps; never include license keys or user data found in memory beyond what
  proves the finding

## References
- https://x64dbg.com
- https://github.com/duty1g/x64dbg-mcp-server
- Technique-kb tags: binary-analysis, desktop-apps
