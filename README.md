# IR-ArtifactCollector

Windows DFIR / Incident Response triage artifact collector scripts, built to run through an edr
platform's script / live-response feature (CrowdStrike RTR, Microsoft Defender for Endpoint Live
Response, SentinelOne, Carbon Black, trillix Endpoint, etc.).

Both scripts **collect raw artifacts only** (registry hives, database files, raw event logs) for
offline parsing with dedicated, validated forensic tools (Eric Zimmerman's tools, RegRipper,
Hindsight, etc.). They deliberately avoid re-implementing complex binary/ESE/SQLite parsers
on the endpoint itself.

## Scripts

| Script | Scope | Description |
|---|---|---|
| [`scripts/IR-ArtifactCollector_v11.ps1`](scripts/IR-ArtifactCollector_v11.ps1) | Full triage | Execution evidence, user activity, file-system artifacts, and browser history. Version 1.9. |
| [`scripts/IR-ExecutionArtifactCollector.ps1`](scripts/IR-ExecutionArtifactCollector.ps1) | Execution-only | Scope-reduced fork of the script above — only "evidence of execution" artifacts (Prefetch, Amcache, ShimCache, BAM/DAM, UserAssist, MUICache, RecentApps, SRUM, Windows Timeline, process-creation event logs, WMI persistence). |

## Requirements

- PowerShell 5.1+
- Run as Administrator/SYSTEM (standard for EDR agent execution)
- [WinRAR](https://www.win-rar.com/) available on the host, or `rar.exe`/`WinRAR.exe` placed
  next to the script — output archiving is WinRAR-only, with no zip fallback

## Key behavior

- **Non-destructive**: read-only collection; never modifies or deletes source artifacts on the host.
- **Manifested & hashed**: every collected file is logged in `Manifest.csv` with a SHA-256 hash;
  the final packaged archive also gets its own sibling `.sha256` file.
- **Password-protected archive**: output is a single `.rar`, encrypted with `-hp` (file names +
  content) using a configurable password (default `infected`, the common convention for keeping
  malware-adjacent evidence from being auto-scanned/quarantined in transit).
- **Verified before cleanup**: the uncompressed case folder is only force-deleted after the
  archive is confirmed written and passes a WinRAR integrity test (`rar t`); if that check fails,
  the loose folder is kept and a warning is logged.

## Basic usage

```powershell
# Full triage collection, default settings
.\scripts\IR-ArtifactCollector_v11.ps1

# Execution-artifacts-only collection, custom output root and lookback window
.\scripts\IR-ExecutionArtifactCollector.ps1 -OutputRoot 'E:\Collections' -ProcessHistoryHours 72 -ZipPassword 'malware'
```

See the comment-based help at the top of each script (`Get-Help .\scripts\<script>.ps1 -Full`)
for the complete parameter list and changelog.

## Disclaimer

These scripts are intended for use by authorized incident responders on systems they are
authorized to investigate. Review and test in a lab environment before deploying against
production or client hosts.

## License

[MIT](LICENSE)
