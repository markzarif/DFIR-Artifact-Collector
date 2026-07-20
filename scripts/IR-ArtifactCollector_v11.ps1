#Requires -Version 5.1
<#
.SYNOPSIS
    Windows DFIR / Incident Response triage artifact collector, designed for execution via an
    EDR platform's script / live-response feature (e.g. Fidelis Endpoint script library,
    CrowdStrike RTR, Microsoft Defender for Endpoint Live Response, SentinelOne, Carbon Black, etc.).

.DESCRIPTION
    Collects the standard set of Windows "evidence of execution", user-activity, file-system,
    and browser artifacts used in incident response and forensic triage, and packages them into
    a single timestamped, hashed, manifested output folder (optionally zipped) for retrieval
    through the EDR console.

    DESIGN PHILOSOPHY - COLLECT RAW, PARSE OFFLINE:
    This script COLLECTS artifacts (registry hives, database files, raw event logs, etc.) for
    OFFLINE analysis with dedicated, validated forensic parsers. It deliberately does NOT try to
    fully decode complex binary/ESE/SQLite structures (ShimCache entries, UserAssist ROT13 +
    run-count structures, SRUM ESE tables, ActivitiesCache.db / Edge History SQLite records)
    on the endpoint itself. Reimplementing those parsers ad hoc in PowerShell is a common source
    of subtly wrong timelines in real investigations - use peer-reviewed tools instead, e.g.:
      - Eric Zimmerman's tools: PECmd (Prefetch), AmcacheParser, AppCompatCacheParser (ShimCache),
        RECmd/Registry Explorer (any hive incl. BAM/UserAssist/MRU keys), SBECmd (ShellBags),
        JLECmd (Jump Lists), SrumECmd (SRUM)
      - RegRipper (registry hives)
      - A SQLite browser / Hindsight (ActivitiesCache.db, browser History)
    A handful of SIMPLE, low-risk live snapshots (running processes, BAM/DAM FILETIME decode,
    current-session registry MRU dump) are included as a "quick look" convenience only, clearly
    labeled, and are never a substitute for the raw artifacts collected alongside them.

.NOTES
    Requires:     PowerShell 5.1+, run as Administrator/SYSTEM (standard for EDR agents)
    Tested on:    Windows 10 / 11 / Server 2016+ (paths/behaviour may vary on older builds)
    Non-destructive: read-only collection; does not modify or delete source artifacts on the host.
    Script version: 1.9
    Changelog:
      1.9 - Fixed WinRAR exit code 6 ("Open file error") aborting the archive step and leaving
            the uncompressed case folder in place. Root cause: Stop-Transcript was only called
            at the very end of the script, AFTER archiving - so _Logs\Transcript.txt was still
            open/held by Start-Transcript at the exact moment WinRAR walked the case folder to
            compress it, and WinRAR couldn't open that one file. Moved Stop-Transcript to run
            immediately before the archive step so no file inside the case folder is held open
            by this script when WinRAR reads it. Also changed Invoke-WinRarSync to capture and
            return WinRAR's own stdout/stderr text instead of discarding it, and both the
            archive-creation and integrity-test call sites now log that text on failure, so any
            future "file couldn't be opened" (or similar) error names the exact file in
            Collection.log instead of just showing a bare exit code.
      1.8 - REAL fix for the source folder not being deleted after compression. The 1.6/1.7
            "fix" kept the -ibck switch on both the archive step and the post-archive test.
            -ibck tells WinRAR.exe (the GUI binary) to fork itself off as a background job and
            return control to the caller immediately - it does NOT wait for the archive/test to
            actually finish. That means the script's own success checks (exit code + Test-Path
            + the `rar t` integrity test) were frequently evaluated before WinRAR had finished
            writing (or even created) the .rar file, so $archiveOkToDelete stayed $false and the
            uncompressed case folder was left behind even though a good archive showed up a
            moment later. Root-caused and fixed by dropping -ibck entirely and instead invoking
            WinRAR (both the archive step and the `t` integrity test) via a new
            Invoke-WinRarSync helper built on Start-Process -Wait -WindowStyle Hidden -PassThru,
            which blocks until WinRAR truly exits and returns its real ExitCode - this works
            identically whether Find-WinRAR resolved the console rar.exe or the GUI WinRAR.exe,
            and needs no interactive desktop session. Also removed the now-unnecessary
            Push-Location/Pop-Location dance (working directory is passed straight to
            Start-Process) which could otherwise leave the location stack unbalanced if an
            exception was thrown between the two calls.
      1.7 - Fixed the source folder sometimes NOT being force-deleted after compression: the
            post-archive WinRAR integrity test (`rar t`) now runs with the same silent switches
            as the archive step itself (-ibck -inul), since running it without them against the
            GUI WinRAR.exe binary could hang waiting on a non-interactive desktop session and
            never return control to the script. Also changed the delete decision so it is no
            longer gated on that test succeeding: as long as the .rar was already confirmed
            written and non-empty at creation time, the uncompressed case folder IS force-
            deleted - only an explicit "archive is corrupt" test result blocks it, not a
            hung/missing test tool. Hardened Remove-FolderPermanently further: it now strips
            Read-Only/Hidden/System attributes before deleting (registry hive copies are
            frequently Read-Only) and, after the existing robocopy /MIR fallback, falls back to
            cmd.exe's native `rd /s /q` as a last resort.
      1.6 - Added a hard integrity gate before deleting the uncompressed case folder: after
            archiving, the script now runs a WinRAR test (`rar t`, with the configured password
            if protected) against the .rar and only proceeds to delete the loose folder if that
            test passes. Folder deletion itself now goes through a new Remove-FolderPermanently
            helper - a Shift+Delete equivalent (Remove-Item already bypasses the Recycle Bin
            entirely; this wrapper adds a robocopy /MIR fallback for locked/in-use files and
            logs the permanent deletion explicitly for the case record) - so once collection
            finishes, the evidence is reachable ONLY through the password-protected archive, not
            through a leftover plaintext folder. If the archive fails verification (or WinRAR is
            unavailable for the test), the uncompressed folder is deliberately left in place and
            a warning is logged, rather than risk deleting the only good copy of the evidence.
      1.5 - Archiver is now WinRAR-ONLY. Removed the 7-Zip / tar.exe / Compress-Archive
            fallback chain entirely: the script no longer produces a .zip under any
            circumstance. Output is always a single .rar (via WinRAR.exe / rar.exe, default
            expected at C:\Program Files\WinRAR\WinRAR.exe), password-protected with -hp
            (encrypts both file names and content) unless -SkipZipPassword is passed. If
            WinRAR cannot be found or the archive step fails, the script logs a clear ERROR
            and leaves the uncompressed case folder in place - it does NOT silently fall back
            to an unencrypted zip. Archive call runs silent/non-interactive (-y -ibck -inul)
            so it works the same whether it resolves the console rar.exe or the GUI
            WinRAR.exe binary.
      1.4 - Added WinRAR as a first-class password-protected archiver alongside 7-Zip.
            Added a SHA256 hash calculation for the FINAL packaged output (the archive if one
            was produced, otherwise the loose case folder's manifest/log set) written to a
            sibling .sha256 file and recorded in the console summary, so the single artifact
            handed off from the endpoint carries its own integrity checksum independent of the
            per-file hashes already in Manifest.csv. Confirmed OutputRoot default remains
            D:\IRCollection (falls back to C:\Windows\Temp\IRCollection) and ZipPassword
            default remains 'infected'.
      1.3 - Broadened 7-Zip detection for password protection: now also checks for a portable
            7za.exe/7z.exe sitting next to the script itself ($PSScriptRoot - the recommended
            way to guarantee this works under EDR deployment, since it travels with the script
            as a companion file and needs no install or runtime internet access), plus the
            7-Zip installer's registry keys for non-default install locations. This does not
            change the fundamental constraint: if no copy of 7-Zip is reachable by any of these
            paths, the archive genuinely cannot be encrypted - there is no built-in Windows or
            PowerShell way to do this, so that case still logs a clear warning rather than
            silently producing an unprotected file labelled as protected.
      1.2 - Removed per-user NTUSER.DAT/UsrClass.dat raw hive collection entirely (drops
            UserAssist/MUICache/RecentApps/ShellBags/per-user-MRU/RDP-registry coverage - the
            live current-session snapshot is what remains for those). Default output moved to
            D:\IRCollection (falls back to C:\Windows\Temp\IRCollection if D: isn't present/ready).
            Output zip is now password-protected ("infected" by default) via 7-Zip when 7-Zip is
            found on the host; falls back to an UNPROTECTED archive with a clearly logged warning
            if 7-Zip isn't available, since neither Compress-Archive nor tar.exe support passwords.
      1.1 - Fixed NTUSER.DAT/UsrClass.dat copy failures for the currently logged-in user (a
            loaded hive is locked by the registry engine itself, not just the filesystem - now
            captured via reg.exe save against HKEY_USERS when a live SID is detected, same as
            SYSTEM.hive). Fixed archive creation aborting on files with very long generated
            names (e.g. some Windows 11 shell URI-based Recent-item .lnk files) exceeding
            MAX_PATH - filenames are now shortened safely when needed, and tar.exe is used for
            the final zip when available since it handles long paths, Compress-Archive does not.
      1.0 - Initial release.

.PARAMETER OutputRoot
    Root folder under which the timestamped collection folder is created.
    Default: D:\IRCollection (falls back to C:\Windows\Temp\IRCollection if D: doesn't exist
    or isn't ready on this host)

.PARAMETER ProcessHistoryHours
    How many hours back to pull Security 4688 / Sysmon Event ID 1 process-creation events.
    Default: 24

.PARAMETER SkipADS
    Skip the alternate-data-stream / Zone.Identifier scan (can take longer on large profiles).

.PARAMETER SkipEventLogRaw
    Skip exporting full raw .evtx copies of the major logs (the filtered last-N-hours process
    CSV still runs regardless).

.PARAMETER SkipCompress
    Leave the collection as a plain folder instead of zipping it at the end.

.PARAMETER KeepUncompressed
    Keep the uncompressed folder in addition to the zip (default is to delete the loose folder
    once it has been zipped, to minimise footprint left on the host).

.PARAMETER ZipPassword
    Password applied to the output .rar archive via WinRAR. Default: 'infected' (the
    conventional password security teams use so archives containing potentially
    malicious-adjacent material aren't auto-scanned/quarantined in transit - it's meant to be a
    known, publicly-recognised convention, not a secret).

.PARAMETER SkipZipPassword
    Produce a plain, unprotected .rar even though WinRAR is available.

.EXAMPLE
    .\IR-ArtifactCollector.ps1

.EXAMPLE
    .\IR-ArtifactCollector.ps1 -OutputRoot 'E:\Collections' -ProcessHistoryHours 72 -SkipADS -ZipPassword 'malware'
#>

# =====================================================================================
#  ARTIFACT COVERAGE MAP (mirrors the requested checklist so coverage is easy to verify)
# =====================================================================================
#  EXECUTION ARTIFACTS
#    Prefetch                      -> 01_ExecutionArtifacts\Prefetch\
#    Amcache.hve                   -> 01_ExecutionArtifacts\Amcache\
#    ShimCache (AppCompatCache)    -> inside 01_ExecutionArtifacts\RegistryHives\SYSTEM.hive (parse offline)
#    BAM / DAM                     -> inside SYSTEM.hive, + live FILETIME decode in
#                                      01_ExecutionArtifacts\BAM_DAM_LiveSnapshot.csv
#    UserAssist                    -> NOT COLLECTED (v1.2 removed per-user NTUSER.DAT/UsrClass.dat
#                                      hive copy - see script changelog)
#    MUICache                      -> NOT COLLECTED (same removal - lived in UsrClass.dat)
#    RecentApps                    -> live current-session-only snapshot in
#                                      02_UserActivity\LiveRegistrySnapshot_CurrentUser.txt only
#    SRUM Database                 -> 01_ExecutionArtifacts\SRUM\
#    Windows Timeline (ActivitiesCache.db) -> 01_ExecutionArtifacts\WindowsTimeline\<user>\
#                                      (feature removed on newer Windows builds - may be absent)
#    Event Logs (4688, Sysmon)     -> 01_ExecutionArtifacts\EventLogs\ (raw .evtx) and
#                                      01_ExecutionArtifacts\Processes\ProcessCreation_LastNHours.csv
#    WMI Persistence                -> 01_ExecutionArtifacts\WMI\WmiPersistence.csv (live query)
#
#  USER ACTIVITY
#    Jump Lists                    -> 02_UserActivity\JumpLists\<user>\
#    ShellBags                     -> NOT COLLECTED (lived in UsrClass.dat - v1.2 removed that hive copy)
#    Recent Files                  -> 02_UserActivity\RecentFiles\<user>\
#    Open/Save MRU, LastVisitedMRU, TypedPaths, RunMRU, WordWheelQuery, RDP MRU
#                                   -> live current-session-only snapshot in
#                                      02_UserActivity\LiveRegistrySnapshot_CurrentUser.txt
#                                      (per-user hive copy removed in v1.2 - see changelog)
#    Office Recent Files           -> 02_UserActivity\OfficeRecent\<user>\
#    RDP History                   -> raw TerminalServices-*.evtx logs (registry MRU no longer
#                                      collected per-user - see v1.2 changelog)
#    Explorer History               -> TypedPaths / WordWheelQuery (above) + live QuickAccess\
#                                      snapshot (current session only)
#
#  FILE ARTIFACTS
#    ThumbCache / IconCache        -> 03_FileArtifacts\ThumbIconCache\<user>\
#    Recycle Bin Metadata ($I*)    -> 03_FileArtifacts\RecycleBin\<SID>\
#    LNK Files                     -> 03_FileArtifacts\LNKFiles\<user>\ (Desktop) + RecentFiles\ above
#    Alternate Data Streams        -> 03_FileArtifacts\ADS\AlternateDataStreams.csv
#    Zone.Identifier Streams       -> 03_FileArtifacts\ADS\ZoneIdentifiers.csv
#    Startup Folder                -> 03_FileArtifacts\Startup\ + AutorunRegistryKeys.txt
#
#  BROWSER ARTIFACTS
#    Edge History                  -> 04_Browser\Edge\<user>_<profile>\History
# =====================================================================================

[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputRoot = 'D:\IRCollection',

    [Parameter()]
    [ValidateRange(1,8760)]
    [int]$ProcessHistoryHours = 24,

    [Parameter()]
    [switch]$SkipADS,

    [Parameter()]
    [switch]$SkipEventLogRaw,

    [Parameter()]
    [switch]$SkipCompress,

    [Parameter()]
    [switch]$KeepUncompressed,

    [Parameter()]
    [string]$ZipPassword = 'infected',

    [Parameter()]
    [switch]$SkipZipPassword
)

$ScriptVersion = '1.9'

#region ===== HELPER FUNCTIONS =====

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $line = "[$ts][$Level] $Message"
    try { Add-Content -LiteralPath $Script:LogFile -Value $line -ErrorAction Stop } catch { }
    switch ($Level) {
        "ERROR" { Write-Host $line -ForegroundColor Red }
        "WARN"  { Write-Host $line -ForegroundColor Yellow }
        default { Write-Host $line }
    }
}

function New-Folder {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

function Add-ManifestEntry {
    param(
        [string]$Category,
        [string]$Source,
        [string]$Destination,
        [string]$Status,
        [string]$SHA256 = ""
    )
    $entry = [PSCustomObject]@{
        TimestampUTC = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")
        Category     = $Category
        Source       = $Source
        Destination  = $Destination
        Status       = $Status
        SHA256       = $SHA256
    }
    [void]$Script:Manifest.Add($entry)
}

function Get-SafeDestPath {
    <# Guards against exceeding MAX_PATH (260 chars), which Compress-Archive in particular
       cannot read past. If DestFolder+FileName would be too long (e.g. Windows-generated
       Recent-item .lnk names built from long URI query strings), shortens the filename to a
       readable prefix + short hash for uniqueness + original extension, and logs the original
       name so nothing is silently lost - only the on-disk filename changes, never the content. #>
    param(
        [Parameter(Mandatory)][string]$DestFolder,
        [Parameter(Mandatory)][string]$FileName
    )
    $fullPath = Join-Path $DestFolder $FileName
    if ($fullPath.Length -le 240) { return $fullPath }

    $ext = [System.IO.Path]::GetExtension($FileName)
    $base = [System.IO.Path]::GetFileNameWithoutExtension($FileName)
    $md5 = [System.Security.Cryptography.MD5]::Create()
    $hashBytes = $md5.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($FileName))
    $shortHash = -join ($hashBytes[0..3] | ForEach-Object { $_.ToString("x2") })
    $budget = 240 - $DestFolder.Length - $ext.Length - $shortHash.Length - 2
    if ($budget -lt 10) { $budget = 10 }
    if ($base.Length -gt $budget) { $base = $base.Substring(0, $budget) }
    $safeName = "$base`_$shortHash$ext"
    Write-Log "Filename too long for a safe path, truncated: '$FileName' -> '$safeName'" "WARN"
    return (Join-Path $DestFolder $safeName)
}

function Repair-LongPaths {
    <# Safety net for bulk robocopy folder copies (Copy-ArtifactFolder), where files land with
       their original names and can't be renamed mid-copy. Run once at the end over the whole
       case folder: anything still over the safe length gets shortened in place, same scheme
       as Get-SafeDestPath, so the final Compress-Archive pass never trips over it. #>
    param([string]$Folder)
    if (-not (Test-Path -LiteralPath $Folder)) { return }
    $fixed = 0
    Get-ChildItem -LiteralPath $Folder -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
        $item = $_
        if ($item.FullName.Length -gt 240) {
            $parent = $item.DirectoryName
            $safeFull = Get-SafeDestPath -DestFolder $parent -FileName $item.Name
            if ($safeFull -ne $item.FullName) {
                try {
                    Rename-Item -LiteralPath $item.FullName -NewName (Split-Path -Leaf $safeFull) -ErrorAction Stop
                    $fixed++
                } catch {
                    Write-Log "Could not shorten long path for $($item.FullName): $($_.Exception.Message)" "WARN"
                }
            }
        }
    }
    if ($fixed -gt 0) { Write-Log "Repair-LongPaths: shortened $fixed file name(s) that exceeded the safe path length" }
}

function Copy-ArtifactFile {
    <# Copies a single file. Falls back to robocopy backup-mode (/B) for locked files. #>
    param(
        [Parameter(Mandatory)][string]$SourcePath,
        [Parameter(Mandatory)][string]$DestFolder,
        [string]$Category = "General"
    )
    if (-not (Test-Path -LiteralPath $SourcePath)) {
        Write-Log "SKIP (not found): $SourcePath" "WARN"
        Add-ManifestEntry -Category $Category -Source $SourcePath -Destination "" -Status "NotFound"
        return
    }
    New-Folder $DestFolder
    $fileName = Split-Path -Leaf $SourcePath
    $dest = Get-SafeDestPath -DestFolder $DestFolder -FileName $fileName
    try {
        Copy-Item -LiteralPath $SourcePath -Destination $dest -Force -ErrorAction Stop
        Write-Log "Collected: $SourcePath"
        $hash = (Get-FileHash -LiteralPath $dest -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
        Add-ManifestEntry -Category $Category -Source $SourcePath -Destination $dest -Status "OK" -SHA256 $hash
    } catch {
        try {
            $srcDir = Split-Path -Parent $SourcePath
            $rcArgs = @($srcDir, $DestFolder, $fileName, '/B', '/NP', '/NFL', '/NDL', '/NJH', '/NJS', '/R:1', '/W:1')
            $null = & robocopy @rcArgs
            # robocopy always writes under the ORIGINAL filename - if Get-SafeDestPath shortened
            # $dest for length, rename the robocopy output to match it.
            $robocopyOutput = Join-Path $DestFolder $fileName
            if ((Test-Path -LiteralPath $robocopyOutput) -and $robocopyOutput -ne $dest) {
                Rename-Item -LiteralPath $robocopyOutput -NewName (Split-Path -Leaf $dest) -Force -ErrorAction SilentlyContinue
            }
            if (Test-Path -LiteralPath $dest) {
                Write-Log "Collected (robocopy /B fallback): $SourcePath"
                $hash = (Get-FileHash -LiteralPath $dest -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
                Add-ManifestEntry -Category $Category -Source $SourcePath -Destination $dest -Status "OK(robocopy)" -SHA256 $hash
            } else {
                throw "robocopy fallback produced no output file"
            }
        } catch {
            Write-Log "ERROR copying $SourcePath : $($_.Exception.Message)" "ERROR"
            Add-ManifestEntry -Category $Category -Source $SourcePath -Destination "" -Status "Error: $($_.Exception.Message)"
        }
    }
}

function Copy-ArtifactFolder {
    <# Uses robocopy (backup mode) to collect a folder, matching one file mask. #>
    param(
        [Parameter(Mandatory)][string]$SourcePath,
        [Parameter(Mandatory)][string]$DestFolder,
        [string]$Category = "General",
        [string]$FileMask = "*.*",
        [switch]$Recurse
    )
    if (-not (Test-Path -LiteralPath $SourcePath)) {
        Write-Log "SKIP (not found): $SourcePath" "WARN"
        Add-ManifestEntry -Category $Category -Source $SourcePath -Destination "" -Status "NotFound"
        return
    }
    New-Folder $DestFolder
    $rcArgs = @($SourcePath, $DestFolder, $FileMask, '/B', '/NP', '/NFL', '/NDL', '/NJH', '/NJS', '/XJ', '/R:1', '/W:1')
    if ($Recurse) { $rcArgs += '/E' }
    $null = & robocopy @rcArgs
    $count = (Get-ChildItem -LiteralPath $DestFolder -Recurse -File -ErrorAction SilentlyContinue | Measure-Object).Count
    Write-Log "Collected $count file(s) from $SourcePath -> $DestFolder"
    Add-ManifestEntry -Category $Category -Source $SourcePath -Destination $DestFolder -Status "OK ($count files)"
}

function Export-RegistryHive {
    <# Uses reg.exe save to export a live registry hive root (works even while in use). #>
    param(
        [Parameter(Mandatory)][string]$HiveKey,
        [Parameter(Mandatory)][string]$DestFolder,
        [Parameter(Mandatory)][string]$FileName,
        [string]$Category = "RegistryHive"
    )
    New-Folder $DestFolder
    $dest = Join-Path $DestFolder $FileName
    try {
        $regOutput = & reg.exe save $HiveKey $dest /y 2>&1
        if ($LASTEXITCODE -eq 0 -and (Test-Path -LiteralPath $dest)) {
            Write-Log "Exported hive $HiveKey -> $dest"
            $hash = (Get-FileHash -LiteralPath $dest -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
            Add-ManifestEntry -Category $Category -Source $HiveKey -Destination $dest -Status "OK" -SHA256 $hash
        } else {
            Write-Log "ERROR exporting hive $HiveKey : $regOutput" "ERROR"
            Add-ManifestEntry -Category $Category -Source $HiveKey -Destination "" -Status "Error: $regOutput"
        }
    } catch {
        Write-Log "ERROR exporting hive $HiveKey : $($_.Exception.Message)" "ERROR"
        Add-ManifestEntry -Category $Category -Source $HiveKey -Destination "" -Status "Error: $($_.Exception.Message)"
    }
}

function Export-RegKeyLive {
    <# Best-effort LIVE snapshot of a registry key (current process's user context only) to text.
       NOT authoritative - many MRU values are binary PIDLs; parse the exported hive with a
       dedicated tool (RECmd / Registry Explorer) for accurate, complete results. #>
    param(
        [Parameter(Mandatory)][string]$KeyPath,
        [Parameter(Mandatory)][string]$DestFile
    )
    "===== $KeyPath =====" | Out-File -FilePath $DestFile -Encoding UTF8 -Append
    if (Test-Path -LiteralPath $KeyPath) {
        try {
            Get-ItemProperty -Path $KeyPath -ErrorAction Stop |
                Select-Object * -ExcludeProperty PS* |
                Out-String -Width 300 |
                Out-File -FilePath $DestFile -Encoding UTF8 -Append
        } catch {
            "  (error reading key: $($_.Exception.Message))" | Out-File -FilePath $DestFile -Encoding UTF8 -Append
        }
    } else {
        "  (not present in this context)" | Out-File -FilePath $DestFile -Encoding UTF8 -Append
    }
    "" | Out-File -FilePath $DestFile -Encoding UTF8 -Append
}

function Get-LocalUserProfiles {
    <# Authoritative list of real user profiles (S-1-5-21-* SIDs) from ProfileList,
       independent of whether the user is currently logged in. #>
    $profileListKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
    $results = New-Object System.Collections.ArrayList
    Get-ChildItem -Path $profileListKey -ErrorAction SilentlyContinue | ForEach-Object {
        $sid = $_.PSChildName
        $keyPath = $_.PSPath
        if ($sid -notmatch '^S-1-5-21-') { return }
        $props = Get-ItemProperty -Path $keyPath -ErrorAction SilentlyContinue
        if ($null -eq $props) { return }
        $profilePath = $props.ProfileImagePath
        if ([string]::IsNullOrWhiteSpace($profilePath)) { return }
        if (-not (Test-Path -LiteralPath $profilePath)) { return }
        $username = Split-Path -Leaf $profilePath
        [void]$results.Add([PSCustomObject]@{
            SID         = $sid
            Username    = $username
            ProfilePath = $profilePath
        })
    }
    return $results
}

function Get-BamDamSnapshot {
    <# Best-effort live decode of BAM/DAM (Background/Desktop Activity Moderator).
       Value data's first 8 bytes are a FILETIME of last execution - simple/stable enough to
       decode inline. The SYSTEM hive export alongside this remains the authoritative capture. #>
    param([string]$DestFile)
    $paths = @(
        "HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings",
        "HKLM:\SYSTEM\CurrentControlSet\Services\bam\UserSettings",
        "HKLM:\SYSTEM\CurrentControlSet\Services\dam\State\UserSettings",
        "HKLM:\SYSTEM\CurrentControlSet\Services\dam\UserSettings"
    )
    $rows = New-Object System.Collections.ArrayList
    foreach ($base in $paths) {
        if (-not (Test-Path -LiteralPath $base)) { continue }
        $sourceLabel = if ($base -match '\\bam\\') { 'BAM' } else { 'DAM' }
        Get-ChildItem -Path $base -ErrorAction SilentlyContinue | ForEach-Object {
            $sid = $_.PSChildName
            $keyPath = $_.PSPath
            $props = Get-ItemProperty -Path $keyPath -ErrorAction SilentlyContinue
            if ($null -eq $props) { return }
            $props.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object {
                $valueName = $_.Name
                $valueData = $_.Value
                $lastRun = $null
                try {
                    if ($valueData -is [byte[]] -and $valueData.Length -ge 8) {
                        $fileTime = [BitConverter]::ToInt64($valueData, 0)
                        if ($fileTime -gt 0) { $lastRun = [DateTime]::FromFileTimeUtc($fileTime) }
                    }
                } catch { }
                [void]$rows.Add([PSCustomObject]@{
                    Source           = $sourceLabel
                    SID              = $sid
                    ExecutablePath   = $valueName
                    LastExecutionUTC = $lastRun
                })
            }
        }
    }
    $rows | Sort-Object LastExecutionUTC -Descending | Export-Csv -Path $DestFile -NoTypeInformation -Encoding UTF8
    Write-Log "BAM/DAM live snapshot: $($rows.Count) entries"
}

function Get-RunningProcessSnapshot {
    param([string]$DestFile)
    $hashCache = @{}
    $procs = Get-CimInstance -ClassName Win32_Process -ErrorAction SilentlyContinue
    $rows = foreach ($p in $procs) {
        $owner = $null
        try {
            $ownerInfo = Invoke-CimMethod -InputObject $p -MethodName GetOwner -ErrorAction SilentlyContinue
            if ($ownerInfo -and $ownerInfo.ReturnValue -eq 0) { $owner = "$($ownerInfo.Domain)\$($ownerInfo.User)" }
        } catch { }
        $hash = $null
        if ($p.ExecutablePath -and (Test-Path -LiteralPath $p.ExecutablePath)) {
            if ($hashCache.ContainsKey($p.ExecutablePath)) {
                $hash = $hashCache[$p.ExecutablePath]
            } else {
                try {
                    $hash = (Get-FileHash -LiteralPath $p.ExecutablePath -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
                    $hashCache[$p.ExecutablePath] = $hash
                } catch { }
            }
        }
        [PSCustomObject]@{
            PID            = $p.ProcessId
            PPID           = $p.ParentProcessId
            Name           = $p.Name
            ExecutablePath = $p.ExecutablePath
            CommandLine    = $p.CommandLine
            Owner          = $owner
            CreationDate   = if ($p.CreationDate) { $p.CreationDate.ToString("yyyy-MM-dd HH:mm:ss") } else { $null }
            SHA256         = $hash
        }
    }
    $rows | Sort-Object CreationDate -Descending | Export-Csv -Path $DestFile -NoTypeInformation -Encoding UTF8
    Write-Log "Captured $(@($rows).Count) running processes (live snapshot)"
}

function Get-ProcessCreationHistory {
    <# Security 4688 + Sysmon Event ID 1 process-creation events for the last N hours. #>
    param(
        [string]$DestFile,
        [int]$Hours = 24
    )
    $startTime = (Get-Date).AddHours(-$Hours)
    $rows = New-Object System.Collections.ArrayList

    try {
        $events = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4688; StartTime = $startTime } -ErrorAction Stop
        foreach ($e in $events) {
            $xml = [xml]$e.ToXml()
            $data = @{}
            foreach ($d in $xml.Event.EventData.Data) { $data[$d.Name] = $d.'#text' }
            [void]$rows.Add([PSCustomObject]@{
                TimeCreated       = $e.TimeCreated
                Source            = 'Security-4688'
                NewProcessName    = $data['NewProcessName']
                NewProcessId      = $data['NewProcessId']
                ParentProcessName = $data['ParentProcessName']
                CommandLine       = $data['CommandLine']
                SubjectUserName   = $data['SubjectUserName']
                Hashes            = $null
            })
        }
        Write-Log "Collected $($events.Count) Security 4688 event(s) (last $Hours h)"
    } catch {
        Write-Log "Security 4688 unavailable / process-creation auditing likely not enabled: $($_.Exception.Message)" "WARN"
    }

    try {
        $events = Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Sysmon/Operational'; Id = 1; StartTime = $startTime } -ErrorAction Stop
        foreach ($e in $events) {
            $xml = [xml]$e.ToXml()
            $data = @{}
            foreach ($d in $xml.Event.EventData.Data) { $data[$d.Name] = $d.'#text' }
            [void]$rows.Add([PSCustomObject]@{
                TimeCreated       = $e.TimeCreated
                Source            = 'Sysmon-EID1'
                NewProcessName    = $data['Image']
                NewProcessId      = $data['ProcessId']
                ParentProcessName = $data['ParentImage']
                CommandLine       = $data['CommandLine']
                SubjectUserName   = $data['User']
                Hashes            = $data['Hashes']
            })
        }
        Write-Log "Collected $($events.Count) Sysmon Event ID 1 event(s) (last $Hours h)"
    } catch {
        Write-Log "Sysmon log unavailable (Sysmon likely not installed): $($_.Exception.Message)" "WARN"
    }

    $rows | Sort-Object TimeCreated -Descending | Export-Csv -Path $DestFile -NoTypeInformation -Encoding UTF8
}

function Export-EventLogsRaw {
    param([string]$DestFolder)
    New-Folder $DestFolder
    $logs = @(
        'Security',
        'System',
        'Application',
        'Microsoft-Windows-Sysmon/Operational',
        'Microsoft-Windows-TerminalServices-RDPClient/Operational',
        'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational',
        'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational',
        'Microsoft-Windows-PowerShell/Operational',
        'Windows PowerShell'
    )
    foreach ($log in $logs) {
        $safeName = $log -replace '[\\/]', '_'
        $dest = Join-Path $DestFolder "$safeName.evtx"
        try {
            $null = Get-WinEvent -ListLog $log -ErrorAction Stop
            & wevtutil.exe epl $log $dest /ow:true 2>&1 | Out-Null
            if (Test-Path -LiteralPath $dest) {
                Write-Log "Exported event log: $log"
                Add-ManifestEntry -Category "EventLogs" -Source $log -Destination $dest -Status "OK"
            } else {
                throw "wevtutil produced no output file"
            }
        } catch {
            Write-Log "SKIP event log (not found/accessible): $log" "WARN"
            Add-ManifestEntry -Category "EventLogs" -Source $log -Destination "" -Status "NotFound/Error"
        }
    }
}

function Get-WmiPersistenceArtifacts {
    <# Classic WMI persistence hunt: __EventFilter / *EventConsumer / __FilterToConsumerBinding
       in root\subscription. #>
    param([string]$DestFile)
    $rows = New-Object System.Collections.ArrayList
    try {
        Get-CimInstance -Namespace 'root/subscription' -ClassName '__EventFilter' -ErrorAction SilentlyContinue | ForEach-Object {
            [void]$rows.Add([PSCustomObject]@{ Type = 'EventFilter'; Name = $_.Name; Detail = $_.Query; Extra = $_.QueryLanguage })
        }
        Get-CimInstance -Namespace 'root/subscription' -ClassName 'CommandLineEventConsumer' -ErrorAction SilentlyContinue | ForEach-Object {
            [void]$rows.Add([PSCustomObject]@{ Type = 'CommandLineConsumer'; Name = $_.Name; Detail = $_.CommandLineTemplate; Extra = $_.RunAsUser })
        }
        Get-CimInstance -Namespace 'root/subscription' -ClassName 'ActiveScriptEventConsumer' -ErrorAction SilentlyContinue | ForEach-Object {
            [void]$rows.Add([PSCustomObject]@{ Type = 'ActiveScriptConsumer'; Name = $_.Name; Detail = $_.ScriptText; Extra = $_.ScriptingEngine })
        }
        Get-CimInstance -Namespace 'root/subscription' -ClassName '__FilterToConsumerBinding' -ErrorAction SilentlyContinue | ForEach-Object {
            [void]$rows.Add([PSCustomObject]@{ Type = 'FilterToConsumerBinding'; Name = ''; Detail = $_.Filter; Extra = $_.Consumer })
        }
        Write-Log "WMI persistence check complete: $($rows.Count) subscription object(s) found"
    } catch {
        Write-Log "ERROR querying WMI subscriptions: $($_.Exception.Message)" "ERROR"
    }
    $rows | Export-Csv -Path $DestFile -NoTypeInformation -Encoding UTF8
}

function Get-AlternateDataStreams {
    <# Scans a bounded set of high-value, user-facing folders (NOT the whole volume - that
       would be far too slow for a live-response script) for NTFS alternate data streams,
       and separately extracts Zone.Identifier content (source URL/zone of downloaded files). #>
    param(
        [string[]]$ScanPaths,
        [string]$DestFile,
        [string]$ZoneIdentifierDestFile
    )
    $adsRows = New-Object System.Collections.ArrayList
    $zoneRows = New-Object System.Collections.ArrayList

    foreach ($base in $ScanPaths) {
        if (-not (Test-Path -LiteralPath $base)) { continue }
        Get-ChildItem -LiteralPath $base -File -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
            $file = $_
            try {
                $streams = Get-Item -LiteralPath $file.FullName -Stream * -ErrorAction Stop |
                    Where-Object { $_.Stream -ne ':$DATA' }
                foreach ($s in $streams) {
                    [void]$adsRows.Add([PSCustomObject]@{
                        FilePath   = $file.FullName
                        StreamName = $s.Stream
                        Length     = $s.Length
                    })
                    if ($s.Stream -eq 'Zone.Identifier') {
                        $content = $null
                        try { $content = Get-Content -LiteralPath "$($file.FullName):Zone.Identifier" -Raw -ErrorAction Stop } catch { }
                        [void]$zoneRows.Add([PSCustomObject]@{
                            FilePath = $file.FullName
                            Content  = if ($content) { ($content -replace "`r`n", ' | ') } else { $null }
                        })
                    }
                }
            } catch { }
        }
    }
    $adsRows | Export-Csv -Path $DestFile -NoTypeInformation -Encoding UTF8
    $zoneRows | Export-Csv -Path $ZoneIdentifierDestFile -NoTypeInformation -Encoding UTF8
    Write-Log "ADS scan complete: $($adsRows.Count) alternate stream(s), $($zoneRows.Count) Zone.Identifier stream(s)"
}

function Get-QuickAccessSnapshot {
    <# Best-effort: Quick Access / Explorer "recent & frequent" is a per-interactive-session
       shell feature. Under a non-interactive SYSTEM context (typical for EDR scripts) this will
       often come back empty - that is expected, not a bug. Recent Files + Jump Lists collected
       elsewhere are the reliable, session-independent equivalents. #>
    param([string]$DestFile)
    $shell = $null
    try {
        $shell = New-Object -ComObject Shell.Application
        $qa = $shell.Namespace('shell:::{679f85cc-0de1-45ee-b0b4-e2e2c9bf1cfc}')
        $rows = New-Object System.Collections.ArrayList
        if ($qa) {
            foreach ($item in $qa.Items()) {
                [void]$rows.Add([PSCustomObject]@{ Name = $item.Name; Path = $item.Path })
            }
        }
        $rows | Export-Csv -Path $DestFile -NoTypeInformation -Encoding UTF8
        Write-Log "Quick Access snapshot captured ($($rows.Count) item(s)) - current session context only"
    } catch {
        Write-Log "Quick Access snapshot unavailable (expected under non-interactive SYSTEM context): $($_.Exception.Message)" "WARN"
        [void](New-Item -ItemType File -Path $DestFile -Force -ErrorAction SilentlyContinue)
    } finally {
        if ($shell) { [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($shell) }
    }
}

function Find-WinRAR {
    <# Locates the WinRAR command-line executable (rar.exe, or WinRAR.exe as a fallback - both
       accept the same -hp<password> switch for full filename+content encryption). Search order:
         1. $PSScriptRoot\rar.exe / winrar.exe - portable companion binary next to the script
            (no install, no runtime internet access needed, travels with the EDR script package).
         2. Standard install paths (Program Files / Program Files (x86)).
         3. WinRAR's own registry uninstall key ("Path" under Software\WinRAR, or the
            InstallLocation recorded by the installer), which catches non-default install paths.
         4. PATH. #>
    $candidates = New-Object System.Collections.ArrayList

    if ($PSScriptRoot) {
        [void]$candidates.Add((Join-Path $PSScriptRoot 'rar.exe'))
        [void]$candidates.Add((Join-Path $PSScriptRoot 'winrar.exe'))
    }
    if ($env:ProgramFiles) {
        [void]$candidates.Add((Join-Path $env:ProgramFiles 'WinRAR\rar.exe'))
        [void]$candidates.Add((Join-Path $env:ProgramFiles 'WinRAR\WinRAR.exe'))
    }
    if (${env:ProgramFiles(x86)}) {
        [void]$candidates.Add((Join-Path ${env:ProgramFiles(x86)} 'WinRAR\rar.exe'))
        [void]$candidates.Add((Join-Path ${env:ProgramFiles(x86)} 'WinRAR\WinRAR.exe'))
    }
    try {
        $reg1 = Get-ItemProperty -Path 'HKLM:\SOFTWARE\WinRAR' -ErrorAction Stop
        if ($reg1.exe64) { [void]$candidates.Add($reg1.exe64) }
        if ($reg1.exe32) { [void]$candidates.Add($reg1.exe32) }
    } catch { }
    try {
        $reg2 = Get-ItemProperty -Path 'HKLM:\SOFTWARE\WOW6432Node\WinRAR' -ErrorAction Stop
        if ($reg2.exe32) { [void]$candidates.Add($reg2.exe32) }
    } catch { }

    foreach ($c in $candidates) {
        if (Test-Path -LiteralPath $c) { return $c }
    }
    $onPath = Get-Command 'rar.exe','winrar.exe' -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($onPath) { return $onPath.Source }
    return $null
}

function Invoke-WinRarSync {
    <# Runs WinRAR (console rar.exe OR the GUI WinRAR.exe - both are handled identically here)
       and BLOCKS until it truly finishes, returning its real exit code.

       This replaces the old approach of passing -ibck to `& $winRar ...`. -ibck tells the GUI
       WinRAR.exe to fork the actual archive/test job into a background process and hand control
       back to the caller immediately - the call operator (&) then returns right away, often
       before the archive file exists or the integrity test has actually run. That race is what
       caused $archiveOkToDelete to stay $false and the uncompressed case folder to survive even
       though a valid archive appeared a moment later.

       Start-Process -Wait genuinely waits for the process tree's main process to exit, and
       -WindowStyle Hidden keeps it headless without needing WinRAR's own background-job switch,
       so this works the same for both rar.exe (console, no window anyway) and WinRAR.exe (GUI). #>
    param(
        [Parameter(Mandatory)][string]$WinRarPath,
        [Parameter(Mandatory)][string]$ArgumentString,
        [string]$WorkingDirectory
    )
    $stdOutFile = [System.IO.Path]::GetTempFileName()
    $stdErrFile = [System.IO.Path]::GetTempFileName()
    try {
        $procParams = @{
            FilePath               = $WinRarPath
            ArgumentList           = $ArgumentString
            WindowStyle            = 'Hidden'
            Wait                   = $true
            PassThru               = $true
            RedirectStandardOutput = $stdOutFile
            RedirectStandardError  = $stdErrFile
        }
        if ($WorkingDirectory) { $procParams['WorkingDirectory'] = $WorkingDirectory }
        $proc = Start-Process @procParams
        $output = ""
        try { $output = (Get-Content -LiteralPath $stdOutFile -Raw -ErrorAction SilentlyContinue) + (Get-Content -LiteralPath $stdErrFile -Raw -ErrorAction SilentlyContinue) } catch { }
        return [PSCustomObject]@{ ExitCode = $proc.ExitCode; Output = $output }
    } finally {
        Remove-Item -LiteralPath $stdOutFile, $stdErrFile -Force -ErrorAction SilentlyContinue
    }
}

function Remove-FolderPermanently {
    <# Permanently deletes a folder tree - equivalent to Explorer's Shift+Delete (bypasses the
       Recycle Bin entirely). Note: Remove-Item already never touches the Recycle Bin (that's an
       Explorer-shell-only concept, not something the underlying file-delete APIs use), so this
       is functionally a hard delete either way - this wrapper exists to make that guarantee
       explicit, log it clearly for the case record, strip Read-Only/Hidden/System attributes
       that can block deletion (registry hive copies, some .evtx exports), and fall back through
       robocopy-mirror and finally cmd.exe's rd /s /q for folders containing locked/in-use files
       that Remove-Item alone can choke on. #>
    param([Parameter(Mandatory)][string]$Folder)

    if (-not (Test-Path -LiteralPath $Folder)) { return $true }

    # Strip attributes that commonly block deletion (Read-Only especially, on copied hive files).
    try {
        Get-ChildItem -LiteralPath $Folder -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
            try { $_.Attributes = 'Normal' } catch { }
        }
    } catch { }

    try {
        Remove-Item -LiteralPath $Folder -Recurse -Force -ErrorAction Stop
        if (-not (Test-Path -LiteralPath $Folder)) {
            Write-Log "Permanently deleted uncompressed case folder (Shift+Delete equivalent, Recycle Bin bypassed): $Folder"
            return $true
        }
    } catch {
        Write-Log "Remove-Item failed on $Folder : $($_.Exception.Message) - trying robocopy-mirror fallback" "WARN"
    }

    # Fallback for locked/in-use files: mirror an empty temp folder over the target with
    # robocopy /MIR, which deletes destination files/folders not present in the (empty) source,
    # then remove the now-empty shell. Handles cases plain Remove-Item can't (e.g. long paths,
    # transient file locks from AV/EDR scanning the just-created collection).
    try {
        $emptyTemp = Join-Path $env:TEMP "empty_$([Guid]::NewGuid().ToString('N'))"
        New-Folder $emptyTemp
        $null = & robocopy $emptyTemp $Folder /MIR /NP /NFL /NDL /NJH /NJS /R:1 /W:1
        Remove-Item -LiteralPath $emptyTemp -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $Folder -Recurse -Force -ErrorAction SilentlyContinue
        if (-not (Test-Path -LiteralPath $Folder)) {
            Write-Log "Permanently deleted uncompressed case folder via robocopy /MIR fallback (Recycle Bin bypassed): $Folder"
            return $true
        }
    } catch {
        Write-Log "robocopy /MIR fallback errored on $Folder : $($_.Exception.Message)" "WARN"
    }

    # Last resort: cmd.exe's native rd /s /q, which sometimes succeeds where PowerShell/.NET
    # delete APIs report transient access-denied errors (e.g. AV re-scanning a just-written file).
    try {
        & cmd.exe /c "rd /s /q `"$Folder`"" 2>&1 | Out-Null
        if (-not (Test-Path -LiteralPath $Folder)) {
            Write-Log "Permanently deleted uncompressed case folder via cmd.exe rd /s /q fallback (Recycle Bin bypassed): $Folder"
            return $true
        } else {
            Write-Log "Uncompressed case folder still present after all delete attempts: $Folder - remove manually." "ERROR"
            return $false
        }
    } catch {
        Write-Log "ERROR permanently deleting $Folder : $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Invoke-CollectionStep {
    <# Uniform wrapper: logs start/end and ensures one failing category never aborts the run. #>
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][scriptblock]$Action
    )
    Write-Log "---- Starting: $Name ----"
    try {
        & $Action
        Write-Log "---- Completed: $Name ----"
    } catch {
        Write-Log "---- FAILED: $Name : $($_.Exception.Message) ----" "ERROR"
    }
}

#endregion

#region ===== SETUP =====

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Warning "Not running as Administrator/SYSTEM - many artifacts (registry hives, other users' profiles, protected event logs) will be inaccessible or incomplete. Most EDR live-response/script execution contexts run as SYSTEM automatically, so this usually only matters for manual/local testing."
}

$requestedDriveLetter = (Split-Path -Qualifier $OutputRoot -ErrorAction SilentlyContinue) -replace ':', ''
if ($requestedDriveLetter) {
    $driveReady = [System.IO.DriveInfo]::GetDrives() | Where-Object { $_.Name -eq "$requestedDriveLetter`:\" -and $_.IsReady }
    if (-not $driveReady) {
        $fallbackRoot = Join-Path $env:SystemRoot 'Temp\IRCollection'
        Write-Warning "Requested output drive $requestedDriveLetter`: not found or not ready on this host - falling back to $fallbackRoot"
        $OutputRoot = $fallbackRoot
    }
}

$CollectionStartUTC = (Get-Date).ToUniversalTime()
$TimestampTag = $CollectionStartUTC.ToString("yyyyMMdd_HHmmss")
$Hostname = $env:COMPUTERNAME
$CaseFolder = Join-Path $OutputRoot "$($Hostname)_$($TimestampTag)Z"

$execFolder       = Join-Path $CaseFolder "01_ExecutionArtifacts"
$prefetchFolder   = Join-Path $execFolder "Prefetch"
$amcacheFolder    = Join-Path $execFolder "Amcache"
$regHivesFolder   = Join-Path $execFolder "RegistryHives"
$srumFolder       = Join-Path $execFolder "SRUM"
$timelineFolder   = Join-Path $execFolder "WindowsTimeline"
$eventLogsFolder  = Join-Path $execFolder "EventLogs"
$processFolder    = Join-Path $execFolder "Processes"
$wmiFolder        = Join-Path $execFolder "WMI"

$userActFolder      = Join-Path $CaseFolder "02_UserActivity"
$jumpListsFolder    = Join-Path $userActFolder "JumpLists"
$recentFilesFolder  = Join-Path $userActFolder "RecentFiles"
$officeRecentFolder = Join-Path $userActFolder "OfficeRecent"
$quickAccessFolder  = Join-Path $userActFolder "QuickAccess"

$fileArtFolder    = Join-Path $CaseFolder "03_FileArtifacts"
$thumbIconFolder  = Join-Path $fileArtFolder "ThumbIconCache"
$recycleBinFolder = Join-Path $fileArtFolder "RecycleBin"
$lnkFolder        = Join-Path $fileArtFolder "LNKFiles"
$startupFolder    = Join-Path $fileArtFolder "Startup"
$adsFolder        = Join-Path $fileArtFolder "ADS"

$browserFolder = Join-Path $CaseFolder "04_Browser"
$edgeFolder    = Join-Path $browserFolder "Edge"

$logsFolder = Join-Path $CaseFolder "_Logs"

$allFolders = @(
    $execFolder, $prefetchFolder, $amcacheFolder, $regHivesFolder, $srumFolder, $timelineFolder, $eventLogsFolder, $processFolder, $wmiFolder,
    $userActFolder, $jumpListsFolder, $recentFilesFolder, $officeRecentFolder, $quickAccessFolder,
    $fileArtFolder, $thumbIconFolder, $recycleBinFolder, $lnkFolder, $startupFolder, $adsFolder,
    $browserFolder, $edgeFolder,
    $logsFolder
)
foreach ($f in $allFolders) { New-Folder $f }

$Script:LogFile = Join-Path $logsFolder "Collection.log"
$Script:Manifest = New-Object System.Collections.ArrayList

$transcriptPath = Join-Path $logsFolder "Transcript.txt"
try { Start-Transcript -Path $transcriptPath -Force | Out-Null } catch { }

Write-Log "===== IR-ArtifactCollector v$ScriptVersion starting on $Hostname ====="
Write-Log "Output folder: $CaseFolder"
Write-Log "Running elevated: $isAdmin"

$osInfo = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
$sysInfo = [PSCustomObject]@{
    Hostname            = $Hostname
    Domain              = $env:USERDOMAIN
    OSCaption           = $osInfo.Caption
    OSVersion           = $osInfo.Version
    CollectionStartUTC  = $CollectionStartUTC.ToString("yyyy-MM-dd HH:mm:ss")
    RunAsUser           = "$env:USERDOMAIN\$env:USERNAME"
    ScriptVersion       = $ScriptVersion
    IsElevated          = $isAdmin
    ProcessHistoryHours = $ProcessHistoryHours
}
$sysInfo | Format-List | Out-File -FilePath (Join-Path $logsFolder "SystemInfo.txt") -Encoding UTF8

$userProfiles = Get-LocalUserProfiles
Write-Log "Discovered $($userProfiles.Count) local user profile(s): $(($userProfiles | ForEach-Object { $_.Username }) -join ', ')"

#endregion

#region ===== 01: EXECUTION ARTIFACTS =====

Invoke-CollectionStep -Name "Prefetch" -Action {
    Copy-ArtifactFolder -SourcePath (Join-Path $env:SystemRoot "Prefetch") -DestFolder $prefetchFolder -Category "Prefetch" -FileMask "*.pf"
    Get-ChildItem -Path (Join-Path $env:SystemRoot "Prefetch") -Filter "*.pf" -ErrorAction SilentlyContinue |
        Select-Object Name, Length, CreationTime, LastWriteTime, LastAccessTime |
        Export-Csv -Path (Join-Path $prefetchFolder "PrefetchFileListing.csv") -NoTypeInformation -Encoding UTF8
    $pfEnabled = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" -ErrorAction SilentlyContinue
    if ($pfEnabled) {
        "EnablePrefetcher=$($pfEnabled.EnablePrefetcher)  EnableSuperfetch=$($pfEnabled.EnableSuperfetch)" |
            Out-File -FilePath (Join-Path $prefetchFolder "PrefetchConfig.txt") -Encoding UTF8
    }
}

Invoke-CollectionStep -Name "Amcache" -Action {
    Copy-ArtifactFolder -SourcePath (Join-Path $env:SystemRoot "AppCompat\Programs") -DestFolder $amcacheFolder -Category "Amcache" -Recurse
}

Invoke-CollectionStep -Name "SYSTEM Hive (ShimCache + BAM/DAM source)" -Action {
    Export-RegistryHive -HiveKey 'HKLM\SYSTEM' -DestFolder $regHivesFolder -FileName 'SYSTEM.hive' -Category "RegistryHive"
    Get-BamDamSnapshot -DestFile (Join-Path $execFolder "BAM_DAM_LiveSnapshot.csv")
}

# NOTE (v1.2): Per-user NTUSER.DAT / UsrClass.dat hive collection (UserAssist, MUICache,
# RecentApps, ShellBags, per-user MRU/RDP registry keys) was removed here at request, since it
# was the source of the reg-locking errors on the currently logged-in user. SYSTEM.hive above
# (ShimCache/BAM/DAM) and the live current-session snapshot further down are unaffected.

Invoke-CollectionStep -Name "SRUM Database" -Action {
    Copy-ArtifactFolder -SourcePath (Join-Path $env:SystemRoot "System32\sru") -DestFolder $srumFolder -Category "SRUM" -Recurse
}

Invoke-CollectionStep -Name "Windows Timeline (ActivitiesCache.db)" -Action {
    foreach ($u in $userProfiles) {
        $cdpBase = Join-Path $u.ProfilePath "AppData\Local\ConnectedDevicesPlatform"
        if (Test-Path -LiteralPath $cdpBase) {
            Get-ChildItem -LiteralPath $cdpBase -Directory -ErrorAction SilentlyContinue | ForEach-Object {
                $dbPath = Join-Path $_.FullName "ActivitiesCache.db"
                Copy-ArtifactFile -SourcePath $dbPath -DestFolder (Join-Path $timelineFolder $u.Username) -Category "WindowsTimeline"
            }
        } else {
            Write-Log "No ConnectedDevicesPlatform folder for $($u.Username) (Timeline disabled/unavailable/removed on this build)" "WARN"
        }
    }
}

Invoke-CollectionStep -Name "Event Logs (raw .evtx export)" -Action {
    if ($SkipEventLogRaw) {
        Write-Log "Raw event log export skipped (-SkipEventLogRaw)"
    } else {
        Export-EventLogsRaw -DestFolder $eventLogsFolder
    }
}

Invoke-CollectionStep -Name "Process Creation History (4688 + Sysmon EID1, last $ProcessHistoryHours h)" -Action {
    Get-ProcessCreationHistory -DestFile (Join-Path $processFolder "ProcessCreation_Last$($ProcessHistoryHours)Hours.csv") -Hours $ProcessHistoryHours
}

Invoke-CollectionStep -Name "Running Processes (live snapshot)" -Action {
    Get-RunningProcessSnapshot -DestFile (Join-Path $processFolder "RunningProcesses_LiveSnapshot.csv")
}

Invoke-CollectionStep -Name "WMI Persistence" -Action {
    Get-WmiPersistenceArtifacts -DestFile (Join-Path $wmiFolder "WmiPersistence.csv")
}

#endregion

#region ===== 02: USER ACTIVITY =====

Invoke-CollectionStep -Name "Jump Lists" -Action {
    foreach ($u in $userProfiles) {
        $destBase = Join-Path $jumpListsFolder $u.Username
        Copy-ArtifactFolder -SourcePath (Join-Path $u.ProfilePath "AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations") -DestFolder (Join-Path $destBase "AutomaticDestinations") -Category "JumpLists" -Recurse
        Copy-ArtifactFolder -SourcePath (Join-Path $u.ProfilePath "AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations") -DestFolder (Join-Path $destBase "CustomDestinations") -Category "JumpLists" -Recurse
    }
}

Invoke-CollectionStep -Name "Recent Files" -Action {
    foreach ($u in $userProfiles) {
        Copy-ArtifactFolder -SourcePath (Join-Path $u.ProfilePath "AppData\Roaming\Microsoft\Windows\Recent") -DestFolder (Join-Path $recentFilesFolder $u.Username) -Category "RecentFiles" -FileMask "*.lnk"
    }
}

Invoke-CollectionStep -Name "Office Recent Files" -Action {
    foreach ($u in $userProfiles) {
        Copy-ArtifactFolder -SourcePath (Join-Path $u.ProfilePath "AppData\Roaming\Microsoft\Office\Recent") -DestFolder (Join-Path $officeRecentFolder $u.Username) -Category "OfficeRecent" -Recurse
    }
}

Invoke-CollectionStep -Name "Live registry snapshot (current session user) - Open/Save MRU, LastVisitedMRU, TypedPaths, RunMRU, WordWheelQuery, RecentApps, RDP MRU" -Action {
    $liveSnapshotFile = Join-Path $userActFolder "LiveRegistrySnapshot_CurrentUser.txt"
    "Best-effort live snapshot for the CURRENT script execution context ($env:USERDOMAIN\$env:USERNAME) only." | Out-File -FilePath $liveSnapshotFile -Encoding UTF8
    "This is typically SYSTEM when run via EDR live-response, so most keys below may show as not present." | Out-File -FilePath $liveSnapshotFile -Encoding UTF8 -Append
    "Per-user NTUSER.DAT / UsrClass.dat raw hive collection was removed in v1.2, so this live, current-session-only snapshot is now the ONLY source for these keys - it will not have data for logged-off users." | Out-File -FilePath $liveSnapshotFile -Encoding UTF8 -Append
    "" | Out-File -FilePath $liveSnapshotFile -Encoding UTF8 -Append
    $liveKeys = @(
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Search\RecentApps',
        'HKCU:\Software\Microsoft\Terminal Server Client\Servers',
        'HKCU:\Software\Microsoft\Terminal Server Client\Default'
    )
    foreach ($k in $liveKeys) { Export-RegKeyLive -KeyPath $k -DestFile $liveSnapshotFile }
}

Invoke-CollectionStep -Name "Quick Access / Explorer History (live, current session)" -Action {
    Get-QuickAccessSnapshot -DestFile (Join-Path $quickAccessFolder "QuickAccess_LiveSnapshot.csv")
}

#endregion

#region ===== 03: FILE ARTIFACTS =====

Invoke-CollectionStep -Name "ThumbCache / IconCache" -Action {
    foreach ($u in $userProfiles) {
        $destDir = Join-Path $thumbIconFolder $u.Username
        Copy-ArtifactFolder -SourcePath (Join-Path $u.ProfilePath "AppData\Local\Microsoft\Windows\Explorer") -DestFolder $destDir -Category "ThumbIconCache" -FileMask "thumbcache_*.db"
        Copy-ArtifactFolder -SourcePath (Join-Path $u.ProfilePath "AppData\Local\Microsoft\Windows\Explorer") -DestFolder $destDir -Category "ThumbIconCache" -FileMask "iconcache_*.db"
        Copy-ArtifactFile -SourcePath (Join-Path $u.ProfilePath "AppData\Local\IconCache.db") -DestFolder $destDir -Category "ThumbIconCache"
    }
}

Invoke-CollectionStep -Name "Recycle Bin Metadata" -Action {
    $recycleBinRoot = Join-Path $env:SystemDrive '$Recycle.Bin'
    if (Test-Path -LiteralPath $recycleBinRoot) {
        Get-ChildItem -LiteralPath $recycleBinRoot -Directory -Force -ErrorAction SilentlyContinue | ForEach-Object {
            $sidFolder = $_.FullName
            $destDir = Join-Path $recycleBinFolder $_.Name
            Copy-ArtifactFolder -SourcePath $sidFolder -DestFolder $destDir -Category "RecycleBin" -FileMask '$I*'
        }
    } else {
        Write-Log "Recycle Bin root not found: $recycleBinRoot" "WARN"
    }
}

Invoke-CollectionStep -Name "LNK Files (Desktop)" -Action {
    foreach ($u in $userProfiles) {
        Copy-ArtifactFolder -SourcePath (Join-Path $u.ProfilePath "Desktop") -DestFolder (Join-Path $lnkFolder $u.Username) -Category "LNKFiles" -FileMask "*.lnk"
    }
    Copy-ArtifactFolder -SourcePath (Join-Path $env:PUBLIC "Desktop") -DestFolder (Join-Path $lnkFolder "Public") -Category "LNKFiles" -FileMask "*.lnk"
}

Invoke-CollectionStep -Name "Startup Folder + Autorun Registry Keys" -Action {
    foreach ($u in $userProfiles) {
        Copy-ArtifactFolder -SourcePath (Join-Path $u.ProfilePath "AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup") -DestFolder (Join-Path $startupFolder $u.Username) -Category "Startup" -Recurse
    }
    Copy-ArtifactFolder -SourcePath (Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs\StartUp") -DestFolder (Join-Path $startupFolder "AllUsers") -Category "Startup" -Recurse

    $autorunKeys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
    )
    $autorunDest = Join-Path $startupFolder "AutorunRegistryKeys.txt"
    "HKLM Run/RunOnce keys below reflect the whole machine. HKCU reflects only the script's own execution context ($env:USERDOMAIN\$env:USERNAME) - other users' HKCU Run/RunOnce keys are not captured anywhere in this collection (per-user hive copy was removed in v1.2)." | Out-File -FilePath $autorunDest -Encoding UTF8
    "" | Out-File -FilePath $autorunDest -Encoding UTF8 -Append
    foreach ($k in $autorunKeys) { Export-RegKeyLive -KeyPath $k -DestFile $autorunDest }
}

Invoke-CollectionStep -Name "Alternate Data Streams + Zone.Identifier" -Action {
    if ($SkipADS) {
        Write-Log "ADS/Zone.Identifier scan skipped (-SkipADS)"
    } else {
        $scanPaths = New-Object System.Collections.ArrayList
        foreach ($u in $userProfiles) {
            [void]$scanPaths.Add((Join-Path $u.ProfilePath "Downloads"))
            [void]$scanPaths.Add((Join-Path $u.ProfilePath "Desktop"))
            [void]$scanPaths.Add((Join-Path $u.ProfilePath "Documents"))
            [void]$scanPaths.Add((Join-Path $u.ProfilePath "AppData\Local\Temp"))
        }
        [void]$scanPaths.Add((Join-Path $env:SystemRoot "Temp"))
        Get-AlternateDataStreams -ScanPaths $scanPaths -DestFile (Join-Path $adsFolder "AlternateDataStreams.csv") -ZoneIdentifierDestFile (Join-Path $adsFolder "ZoneIdentifiers.csv")
    }
}

#endregion

#region ===== 04: BROWSER ARTIFACTS =====

Invoke-CollectionStep -Name "Edge History" -Action {
    foreach ($u in $userProfiles) {
        $edgeBase = Join-Path $u.ProfilePath "AppData\Local\Microsoft\Edge\User Data"
        if (Test-Path -LiteralPath $edgeBase) {
            Get-ChildItem -LiteralPath $edgeBase -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -eq 'Default' -or $_.Name -like 'Profile *' } |
            ForEach-Object {
                $profileName = $_.Name
                $profilePath = $_.FullName
                $destDir = Join-Path $edgeFolder "$($u.Username)_$($profileName)"
                Copy-ArtifactFile -SourcePath (Join-Path $profilePath "History") -DestFolder $destDir -Category "EdgeHistory"
                Copy-ArtifactFile -SourcePath (Join-Path $profilePath "History-journal") -DestFolder $destDir -Category "EdgeHistory"
            }
        } else {
            Write-Log "No Edge profile data for $($u.Username)" "WARN"
        }
    }
}

#endregion

#region ===== FINALIZE =====

$manifestPath = Join-Path $logsFolder "Manifest.csv"
$Script:Manifest | Export-Csv -Path $manifestPath -NoTypeInformation -Encoding UTF8

$errorCount = ($Script:Manifest | Where-Object { $_.Status -like 'Error*' }).Count
$okCount = ($Script:Manifest | Where-Object { $_.Status -like 'OK*' }).Count

Write-Log "===== Collection finished. Entries: $($Script:Manifest.Count)  OK: $okCount  Errors: $errorCount ====="

Repair-LongPaths -Folder $CaseFolder

# Stop the transcript BEFORE archiving. Start-Transcript keeps an open file handle on
# _Logs\Transcript.txt for as long as the script runs - if that handle is still open when
# WinRAR tries to read every file under the case folder to compress it, WinRAR can fail to
# open that specific file (exit code 6 / "Open file error") and abort the whole archive, which
# is exactly what left the uncompressed case folder behind. Stopping it here, before the
# archive step, guarantees no file inside the case folder is still held open by this script.
try { Stop-Transcript | Out-Null } catch { }

# Archiver: WinRAR ONLY. Output is a single password-protected .rar - no .zip is ever produced
# by this script (no 7-Zip, tar.exe, or Compress-Archive fallback). If WinRAR genuinely cannot
# be found/run on the host, the script does NOT silently fall back to an unencrypted zip; it
# logs a clear error and leaves the uncompressed case folder in place instead.
$archivePath = $null
$archiveType = $null
$isPasswordProtected = $false

if (-not $SkipCompress) {
    $compressed = $false
    $parentDir = Split-Path -Parent $CaseFolder
    $leafDir = Split-Path -Leaf $CaseFolder

    $winRar = Find-WinRAR
    if ($winRar) {
        $rarPath = "$CaseFolder.rar"
        try {
            # -hp<pwd> encrypts both file data AND file names/headers (stronger than -p<pwd>,
            # which only encrypts data and leaves the archive's file list readable).
            # -r recurses, -ep1 excludes the base folder from stored paths inside the archive,
            # -m5 = maximum compression, -y assumes yes on any prompts (non-interactive/EDR use),
            # -inul suppresses message/error dialogs. NOTE: -ibck is deliberately NOT used here
            # (see Invoke-WinRarSync / v1.8 changelog) - Start-Process -Wait -WindowStyle Hidden
            # is what actually keeps this headless AND makes the script wait for real completion.
            if ($SkipZipPassword) {
                $rarArgString = "a -r -ep1 -m5 -y -inul `"$rarPath`" `"$leafDir`""
            } else {
                $rarArgString = "a -r -ep1 -m5 -y -inul `"-hp$ZipPassword`" `"$rarPath`" `"$leafDir`""
            }
            $rarResult = Invoke-WinRarSync -WinRarPath $winRar -ArgumentString $rarArgString -WorkingDirectory $parentDir
            $rarExitCode = $rarResult.ExitCode
            if ($rarExitCode -eq 0 -and (Test-Path -LiteralPath $rarPath) -and (Get-Item -LiteralPath $rarPath).Length -gt 0) {
                $isPasswordProtected = -not $SkipZipPassword
                Write-Log "Archive created via WinRAR ($rarPath) - password-protected: $isPasswordProtected"
                $archivePath = $rarPath
                $archiveType = if ($isPasswordProtected) { 'WinRAR (.rar, -hp encryption)' } else { 'WinRAR (.rar, unprotected - -SkipZipPassword set)' }
                $compressed = $true
            } else {
                Write-Log "WinRAR exited with code $rarExitCode and produced no valid archive at $rarPath - uncompressed case folder retained." "ERROR"
                if ($rarResult.Output) { Write-Log "WinRAR output: $($rarResult.Output.Trim())" "ERROR" }
            }
        } catch {
            Write-Log "WinRAR compression failed: $($_.Exception.Message) - uncompressed case folder retained." "ERROR"
        }
    } else {
        Write-Log "WinRAR not found (checked alongside the script, Program Files, Program Files (x86), registry, PATH). No archive will be produced (this script is WinRAR-only, no zip fallback). Fix: install WinRAR (expected at C:\Program Files\WinRAR\WinRAR.exe) or place rar.exe/WinRAR.exe next to this script as a companion file." "ERROR"
    }

    if (-not $compressed) { $SkipCompress = $true }
}

# Integrity/confidentiality closeout: hash whatever the single artifact leaving the host is.
# If an archive was produced, hash the archive itself (this is the file that actually gets
# pulled off the endpoint through the EDR console) and write a sibling .sha256 file next to it
# in the same OutputRoot, in the conventional "<hash> *<filename>" format so it can be verified
# later with `certutil -hashfile` or `Get-FileHash` / `sha256sum -c` without needing this script.
$finalHashFile = $null
$finalHash = $null
if ($archivePath -and (Test-Path -LiteralPath $archivePath)) {
    try {
        $finalHash = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256 -ErrorAction Stop).Hash
        $finalHashFile = "$archivePath.sha256"
        $archiveLeaf = Split-Path -Leaf $archivePath
        "$finalHash *$archiveLeaf" | Out-File -FilePath $finalHashFile -Encoding ASCII -NoNewline
        Write-Log "Final archive SHA256: $finalHash  (written to $finalHashFile)"
        Add-ManifestEntry -Category "FinalArchive" -Source $CaseFolder -Destination $archivePath -Status "OK ($archiveType)" -SHA256 $finalHash
    } catch {
        Write-Log "ERROR hashing final archive $archivePath : $($_.Exception.Message)" "ERROR"
    }
} elseif ($SkipCompress) {
    Write-Log "No archive produced (-SkipCompress or all archivers failed) - no single-file hash to compute; per-file hashes remain in Manifest.csv." "WARN"
}

# Before deleting the ONLY other copy of the collected evidence (the loose case folder), verify
# the archive is actually intact. This is a best-effort integrity check, not a hard block: the
# archive was already confirmed written (exit code + Test-Path) at creation time above, so a
# hung/unavailable test tool should never be able to prevent the force-delete the user wants -
# only an EXPLICIT test failure (archive genuinely corrupt) blocks the delete.
$archiveVerified = $false
$archiveOkToDelete = $false
if ($archivePath -and (Test-Path -LiteralPath $archivePath) -and (Get-Item -LiteralPath $archivePath).Length -gt 0) {
    $archiveOkToDelete = $true   # default: archive exists and is non-empty -> safe to proceed
    $winRarForTest = Find-WinRAR
    if ($winRarForTest) {
        try {
            if ($isPasswordProtected) {
                $testArgString = "t -y -inul `"-p$ZipPassword`" `"$archivePath`""
            } else {
                $testArgString = "t -y -inul `"$archivePath`""
            }
            $testResult = Invoke-WinRarSync -WinRarPath $winRarForTest -ArgumentString $testArgString
            $testExitCode = $testResult.ExitCode
            if ($testExitCode -eq 0) {
                $archiveVerified = $true
                Write-Log "Archive integrity test PASSED (WinRAR -t): $archivePath"
                Add-ManifestEntry -Category "FinalArchive" -Source $archivePath -Destination $archivePath -Status "VerifiedOK" -SHA256 $finalHash
            } else {
                $archiveOkToDelete = $false
                Write-Log "Archive integrity test FAILED (WinRAR -t exit code $testExitCode): $archivePath - uncompressed case folder will NOT be deleted." "ERROR"
                if ($testResult.Output) { Write-Log "WinRAR output: $($testResult.Output.Trim())" "ERROR" }
            }
        } catch {
            Write-Log "Could not run archive integrity test: $($_.Exception.Message) - proceeding with force-delete anyway since the archive was already confirmed written." "WARN"
        }
    } else {
        Write-Log "WinRAR unavailable for post-archive integrity test - proceeding with force-delete anyway since the archive was already confirmed written." "WARN"
    }
}

# Manifest is re-exported after the archive/hash/verify step so Manifest.csv (inside the case
# folder, and therefore inside the archive itself if one was made) also reflects these entries.
$Script:Manifest | Export-Csv -Path $manifestPath -NoTypeInformation -Encoding UTF8 -Force

Write-Host ""
Write-Host "===================================================="
Write-Host " IR-ArtifactCollector v$ScriptVersion - Collection complete"
Write-Host " Host:        $Hostname"
Write-Host " Output path: $CaseFolder"
if ($archivePath -and (Test-Path -LiteralPath $archivePath)) {
    Write-Host " Archive:     $archivePath"
    Write-Host " Archiver:    $archiveType"
    if ($isPasswordProtected) {
        Write-Host " Protection:  PASSWORD-PROTECTED - open with WinRAR using the configured password"
    } else {
        Write-Host " Protection:  NOT password-protected (-SkipZipPassword was set)"
    }
    if ($finalHash) {
        Write-Host " SHA256:      $finalHash"
        Write-Host " Hash file:   $finalHashFile"
    }
    Write-Host " Verified (WinRAR -t): $archiveVerified"
    Write-Host " Source folder will be force-deleted: $($archiveOkToDelete -and -not $KeepUncompressed)"
}
Write-Host " Manifest entries: $($Script:Manifest.Count)   OK: $okCount   Errors: $errorCount"
Write-Host " (see _Logs\Manifest.csv and _Logs\Collection.log for full detail)"
Write-Host "===================================================="

# Only the archive should be able to expose the evidence going forward - the loose, unencrypted
# case folder is force/permanently deleted (Shift+Delete equivalent, Recycle Bin bypassed) as
# soon as the archive itself is confirmed written and non-empty, unless -KeepUncompressed was
# passed. A hung or missing WinRAR test binary does NOT block this; only an explicit "archive is
# corrupt" test result does.
if ($archiveOkToDelete -and -not $KeepUncompressed) {
    [void](Remove-FolderPermanently -Folder $CaseFolder)
} elseif ($archivePath -and -not $archiveOkToDelete -and -not $KeepUncompressed) {
    Write-Log "Uncompressed case folder retained at $CaseFolder because the archive failed integrity verification - investigate before manually deleting." "WARN"
}

#endregion
