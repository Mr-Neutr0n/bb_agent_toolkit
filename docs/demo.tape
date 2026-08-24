Output docs/demo.gif
Set FontSize 17
Set Width 1100
Set Height 640
Set Padding 28
Set Shell zsh
Set Theme "Dracula"
Set Framerate 14
Set CursorBlink false
Type "cd /Users/harikp/Developer/solo/bounty-harness"
Enter
Sleep 300ms
Type 'export PATH="$PWD/bin:$PATH"'
Enter
Sleep 300ms

Type "bb-run --version && bb-hunt --version"
Enter
Sleep 900ms

Type "bb-run list | head -10"
Enter
Sleep 1800ms

Type "bb-run identity-domain list"
Enter
Sleep 1300ms

Type "bin/bb-init example.com --program demo"
Enter
Sleep 800ms

Type "# CT firehose index: every subdomain on file, with first-seen dates"
Enter
Type "bb-run recon ct-index-enum"
Enter
Sleep 2000ms

Type "# every finding passes an impact gate before it can become a report"
Enter
Type "python3 .claude/skills/reporting/scripts/quality_gate.py check --report /tmp/nope.md 2>&1 | tail -2"
Enter
Sleep 1400ms

Ctrl+L
Type "# github.com/Mr-Neutr0n/bounty-harness  -  MIT  -  brew install mr-neutr0n/tap/bounty-harness"
Enter
Sleep 2000ms
