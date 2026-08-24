# Runbook: Dynamic Session via x64dbg MCP

## Prerequisites
- x64dbg running locally with the duty1g MCP plugin installed and auto-started
- Bearer token saved at `.bb/x64dbg.token` (gitignored)

## Discover What The Session Offers
```bash
bin/bb-run binary-analysis mcp-tools     # writes mcp_tools.json (71 tools typical)
```

## Drive It By Intent
The client fuzzy-matches intent against discovered tool names, so workflows do
not break when the plugin renames things:

```bash
MCP_INTENT=registers   MCP_ARGS='{}' bin/bb-run binary-analysis mcp-call
MCP_INTENT=modules     MCP_ARGS='{}' bin/bb-run binary-analysis mcp-call
MCP_INTENT=strings     MCP_ARGS='{}' bin/bb-run binary-analysis mcp-call
MCP_INTENT=breakpoint  MCP_ARGS='{"address":"WinHttpSendRequest"}' bin/bb-run binary-analysis mcp-call
```

Check `matched_candidates` in the output; if the wrong tool matched, call by
exact `--name` instead.

## A Typical Bounty Flow
1. Load the target in x64dbg, run to entry point manually or via step/run intents
2. Set breakpoints on watchlist APIs surfaced by triage (network/crypto cluster)
3. Interact with the app manually (login, sync, update check)
4. On each hit: capture registers/memory-read snapshot via mcp-call
5. Correlate timestamps between your interaction notes and snapshot evidence

## Safety Notes
- Everything is local; nothing here talks to target servers except the app
  itself doing its normal job under YOUR account
- Breakpoints freeze the process: only run these against test instances or your
  own licensed copy where freezing is acceptable
- Memory snapshots can contain your own credentials/tokens - redact evidence
