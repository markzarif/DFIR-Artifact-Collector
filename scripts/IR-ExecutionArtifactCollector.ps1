#Requires -Version 5.1
<#
.SYNOPSIS
    Windows DFIR / Incident Response EXECUTION-ARTIFACT-ONLY collector, designed for execution via
    an EDR platform's script / live-response feature (e.g. Fidelis Endpoint script library,
    CrowdStrike RTR, Microsoft Defender for Endpoint Live Response, SentinelOne, Carbon Black, etc.).

.DESCRIPTION
    Collects ONLY "evidence of execution" artifacts and packages them into a single timestamped,
    hashed, manifested output folder (optionally zipped) for retrieval through the EDR console.

    This is a scope-reduced fork of IR-ArtifactCollector.ps1. Everything outside execution
    evidence has been removed on purpose: no Jump Lists, Recent Files, Office Recent Files,
    Quick Access, live user-activity registry MRU snapshot, ThumbCache/IconCache, Recycle Bin
    metadata, LNK files, Startup folder/Autorun keys, ADS/Zone.Identifier scanning, or browser
    history. See the ARTIFACT COVERAGE MAP below for the exact list of what remains.

    DESIGN PHILOSOPHY - COLLECT RAW, PARSE OFFLINE:
    This script COLLECTS artifacts (registry hives, database files, raw event logs, etc.) for
    OFFLINE analysis with dedicated, validated forensic parsers. It deliberately does NOT try to
    fully decode complex binary/ESE/SQLite structures (ShimCache entries, UserAssist ROT13 +
    run-count structures, SRUM ESE tables, ActivitiesCache.db records) on the endpoint itself.
    Reimplementing those parsers ad hoc in PowerShell is a common source of subtly wrong
    timelines in real investigations - use peer-reviewed tools instead, e.g.:
      - Eric Zimmerman's tools: PECmd (Prefetch), AmcacheParser, AppCompatCacheParser (ShimCache),
        RECmd/Registry Explorer (any hive incl. BAM/UserAssist/MUICache/RecentApps keys),
        SrumECmd (SRUM)
      - RegRipper (registry hives)
      - A SQLite browser / Hindsight (ActivitiesCache.db)
    A handful of SIMPLE, low-risk live snapshots (running processes, BAM/DAM FILETIME decode)
    are included as a "quick look" convenience only, clearly labeled, and are never a substitute
    for the raw artifacts collected alongside them.

.NOTES
    Requires:     PowerShell 5.1+, run as Administrator/SYSTEM (standard for EDR agents)
    Tested on:    Windows 10 / 11 / Server 2016+ (paths/behaviour may vary on older builds)
    Non-destructive: read-only collection; does not modify or delete source artifacts on the host.
    Script version: 1.0-exec (forked from IR-ArtifactCollector.ps1 v1.9)
    Changelog:
      1.0-exec - EXECUTION-ARTIFACTS-ONLY FORK of IR-ArtifactCollector.ps1 v1.9. Removed sections
            02_UserActivity (Jump Lists, Recent Files, Office Recent Files, live registry MRU
            snapshot, Quick Access), 03_FileArtifacts (ThumbCache/IconCache, Recycle Bin
            metadata, LNK Files, Startup Folder, Autorun registry keys, Alternate Data
            Streams/Zone.Identifier), and 04_Browser (Edge History) in their entirety, along
            with their folders, the -SkipADS parameter, and their manifest categories. All
            archiving/hashing/verification/force-delete machinery (WinRAR-only, Invoke-WinRarSync,
            Remove-FolderPermanently) is unchanged from v1.9 and carried over as-is.
            IMPORTANT DELTA vs the checklist this was requested against: the original v1.9
            script had ALREADY removed per-user NTUSER.DAT/UsrClass.dat hive collection back in
            its own v1.2 (see that changelog entry), which means UserAssist, MUICache, and
            RecentApps were NOT actually being collected in v1.9 despite appearing to be
            in-scope artifacts - only a live, current-session-only, non-authoritative registry
            read remained for RecentApps, and UserAssist/MUICache had NO coverage at all. Since
            this checklist explicitly asks for UserAssist, MUICache, and RecentApps, this fork
            RE-ADDS per-user hive collection (NTUSER.DAT + UsrClass.dat, via the same
            reg.exe-save-against-HKEY_USERS approach already used for SYSTEM.hive, which works
            for the currently logged-in user's locked/loaded hive) so those three keys are
            genuinely captured for offline parsing, not just nominally in scope. If you want
            this fork to match the ORIGINAL script's actual (reduced) behaviour instead - i.e.
            skip UserAssist/MUICache/RecentApps entirely and rely only on live current-session
            RecentApps - remove the "Per-User NTUSER.DAT / UsrClass.dat Hives" collection step
            below and the corresponding folder/manifest wiring.

.PARAMETER OutputRoot
    Root folder under which the timestamped collection folder is created.
    Default: D:\IRCollection (falls back to C:\Windows\Temp\IRCollection if D: doesn't exist
    or isn't ready on this host)

.PARAMETER ProcessHistoryHours
    How many hours back to pull Security 4688 / Sysmon Event ID 1 process-creation events.
    Default: 24

.PARAMETER SkipEventLogRaw
    Skip exporting full raw .evtx copies of the major logs (the filtered last-N-hours process
    CSV still runs regardless).

.PARAMETER SkipCompress
    Leave the collection as a plain folder instead of archiving it at the end.

.PARAMETER KeepUncompressed
    Keep the uncompressed folder in addition to the archive (default is to delete the loose
    folder once it has been archived, to minimise footprint left on the host).

.PARAMETER ZipPassword
    Password applied to the output .rar archive via WinRAR. Default: 'infected' (the
    conventional password security teams use so archives containing potentially
    malicious-adjacent material aren't auto-scanned/quarantined in transit - it's meant to be a
    known, publicly-recognised convention, not a secret).

.PARAMETER SkipZipPassword
    Produce a plain, unprotected .rar even though WinRAR is available.

.EXAMPLE
    .\IR-ExecutionArtifactCollector.ps1

.EXAMPLE
    .\IR-ExecutionArtifactCollector.ps1 -OutputRoot 'E:\Collections' -ProcessHistoryHours 72 -ZipPassword 'malware'
#>

# =====================================================================================
#  ARTIFACT COVERAGE MAP (execution-only scope)
# =====================================================================================
#  EXECUTION ARTIFACTS
#    Prefetch                      -> 01_ExecutionArtifacts\Prefetch\
#    Amcache.hve                   -> 01_ExecutionArtifacts\Amcache\
#    ShimCache (AppCompatCache)    -> inside 01_ExecutionArtifacts\RegistryHives\SYSTEM.hive (parse offline)
#    BAM / DAM                     -> inside SYSTEM.hive, + live FILETIME decode in
#                                      01_ExecutionArtifacts\BAM_DAM_LiveSnapshot.csv
#    UserAssist                    -> inside 01_ExecutionArtifacts\RegistryHives\<user>\UsrClass.dat
#                                      + NTUSER.DAT copies (parse offline - see NOTE below)
#    MUICache                      -> inside 01_ExecutionArtifacts\RegistryHives\<user>\UsrClass.dat
#                                      copy (parse offline - see NOTE below)
#    RecentApps                    -> inside 01_ExecutionArtifacts\RegistryHives\<user>\NTUSER.DAT
#                                      copy (parse offline - see NOTE below)
#    SRUM Database                 -> 01_ExecutionArtifacts\SRUM\
#    Windows Timeline (ActivitiesCache.db) -> 01_ExecutionArtifacts\WindowsTimeline\<user>\
#                                      (feature removed on newer Windows builds - may be absent)
#    Event Logs (4688, Sysmon)     -> 01_ExecutionArtifacts\EventLogs\ (raw .evtx) and
#                                      01_ExecutionArtifacts\Processes\ProcessCreation_LastNHours.csv
#    WMI Persistence                -> 01_ExecutionArtifacts\WMI\WmiPersistence.csv (live query)
#
#  NOTE on UserAssist / MUICache / RecentApps: these three live inside per-user NTUSER.DAT
#  (UserAssist, RecentApps) and UsrClass.dat (UserAssist for some paths, MUICache). This fork
#  RE-ADDS per-user hive export (removed in the parent script's own v1.2) specifically so these
#  three are actually captured. All three still need dedicated offline parsers to decode
#  (UserAssist is ROT13 + a binary run-count/FILETIME struct; MUICache/RecentApps are plain but
#  still easiest via RECmd/Registry Explorer) - nothing here decodes them on the endpoint.
#
#  EVERYTHING ELSE FROM THE ORIGINAL SCRIPT (Jump Lists, ShellBags, Recent Files, Office Recent
#  Files, Explorer MRU/TypedPaths/WordWheelQuery/RDP MRU, Quick Access, ThumbCache/IconCache,
#  Recycle Bin metadata, LNK files, Alternate Data Streams/Zone.Identifier, Startup folder,
#  Autorun registry keys, Edge History) IS INTENTIONALLY NOT COLLECTED BY THIS FORK.
# =====================================================================================

[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputRoot = 'D:\IRCollection',

    [Parameter()]
    [ValidateRange(1,8760)]
    [int]$ProcessHistoryHours = 24,

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

$ScriptVersion = '1.0-exec'

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
    <# Guards against exceeding MAX_PATH (260 chars). If DestFolder+FileName would be too long,
       shortens the filename to a readable prefix + short hash for uniqueness + original
       extension, and logs the original name so nothing is silently lost - only the on-disk
       filename changes, never the content. #>
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
       as Get-SafeDestPath, so the final archive pass never trips over it. #>
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

function Export-PerUserHives {
    <# UserAssist and RecentApps live in NTUSER.DAT; UserAssist (for some paths) and MUICache
       live in UsrClass.dat. Both are locked while a user session is loaded, exactly like
       SYSTEM.hive - so the same reg.exe-save-against-HKEY_USERS approach used for SYSTEM.hive
       is used here: if the user's SID is currently loaded under HKEY_USERS (i.e. they're
       logged in), save directly from the live loaded hive. If not, copy the on-disk file for
       the offline copy (works for logged-off users, though a hive that was never loaded this
       boot copies cleanly via robocopy backup-mode since nothing holds it open). #>
    param(
        [Parameter(Mandatory)]$UserProfile,
        [Parameter(Mandatory)][string]$DestFolder
    )
    $sid = $UserProfile.SID
    $destDir = Join-Path $DestFolder $UserProfile.Username
    New-Folder $destDir

    $loadedHivePath = "HKU:\$sid"
    $hkuDriveExists = Get-PSDrive -Name HKU -ErrorAction SilentlyContinue
    if (-not $hkuDriveExists) {
        try { $null = New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS -ErrorAction Stop } catch { }
    }
    $isLoaded = Test-Path -LiteralPath $loadedHivePath -ErrorAction SilentlyContinue

    if ($isLoaded) {
        Export-RegistryHive -HiveKey "HKU\$sid" -DestFolder $destDir -FileName "NTUSER.DAT" -Category "RegistryHive-NTUSER"
        Export-RegistryHive -HiveKey "HKU\$sid`_Classes" -DestFolder $destDir -FileName "UsrClass.dat" -Category "RegistryHive-UsrClass"
    } else {
        Copy-ArtifactFile -SourcePath (Join-Path $UserProfile.ProfilePath "NTUSER.DAT") -DestFolder $destDir -Category "RegistryHive-NTUSER"
        $usrClassPath = Join-Path $UserProfile.ProfilePath "AppData\Local\Microsoft\Windows\UsrClass.dat"
        Copy-ArtifactFile -SourcePath $usrClassPath -DestFolder $destDir -Category "RegistryHive-UsrClass"
        Write-Log "$($UserProfile.Username) not currently loaded under HKEY_USERS - copied on-disk hive files directly (offline user)"
    }
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
    # Execution-relevant logs only: process creation (Security/Sysmon), and System/Application
    # as general execution-adjacent context (service starts, crashes, MSI installs, etc).
    # RDP/TerminalServices and PowerShell operational logs were dropped here - those are
    # user-activity/lateral-movement artifacts, not execution-of-a-binary evidence.
    $logs = @(
        'Security',
        'System',
        'Application',
        'Microsoft-Windows-Sysmon/Operational'
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

function Find-WinRAR {
    <# Locates the WinRAR command-line executable (rar.exe, or WinRAR.exe as a fallback - both
       accept the same -hp<password> switch for full filename+content encryption). Search order:
         1. $PSScriptRoot\rar.exe / winrar.exe - portable companion binary next to the script.
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
    <# Runs WinRAR (console rar.exe OR the GUI WinRAR.exe) and BLOCKS until it truly finishes,
       returning its real exit code. Uses Start-Process -Wait -WindowStyle Hidden (not -ibck,
       which forks WinRAR.exe to the background and returns control before the job is actually
       done - see the parent script's v1.8 changelog for the full root-cause history). #>
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
       Recycle Bin entirely). Strips Read-Only/Hidden/System attributes that can block deletion
       (registry hive copies, some .evtx exports), and falls back through robocopy-mirror and
       finally cmd.exe's rd /s /q for folders containing locked/in-use files. #>
    param([Parameter(Mandatory)][string]$Folder)

    if (-not (Test-Path -LiteralPath $Folder)) { return $true }

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
$perUserHiveFolder = Join-Path $regHivesFolder "PerUser"
$srumFolder       = Join-Path $execFolder "SRUM"
$timelineFolder   = Join-Path $execFolder "WindowsTimeline"
$eventLogsFolder  = Join-Path $execFolder "EventLogs"
$processFolder    = Join-Path $execFolder "Processes"
$wmiFolder        = Join-Path $execFolder "WMI"

$logsFolder = Join-Path $CaseFolder "_Logs"

$allFolders = @(
    $execFolder, $prefetchFolder, $amcacheFolder, $regHivesFolder, $perUserHiveFolder, $srumFolder, $timelineFolder, $eventLogsFolder, $processFolder, $wmiFolder,
    $logsFolder
)
foreach ($f in $allFolders) { New-Folder $f }

$Script:LogFile = Join-Path $logsFolder "Collection.log"
$Script:Manifest = New-Object System.Collections.ArrayList

$transcriptPath = Join-Path $logsFolder "Transcript.txt"
try { Start-Transcript -Path $transcriptPath -Force | Out-Null } catch { }

Write-Log "===== IR-ExecutionArtifactCollector v$ScriptVersion starting on $Hostname ====="
Write-Log "Output folder: $CaseFolder"
Write-Log "Running elevated: $isAdmin"
Write-Log "SCOPE: execution artifacts only (Prefetch, Amcache, ShimCache/BAM/DAM, UserAssist, MUICache, RecentApps, SRUM, Windows Timeline, Event Logs 4688/Sysmon, WMI Persistence). No user-activity, file-system, or browser artifacts are collected."

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
    CollectionScope     = "Execution artifacts only"
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

Invoke-CollectionStep -Name "Per-User NTUSER.DAT / UsrClass.dat Hives (UserAssist + MUICache + RecentApps source)" -Action {
    foreach ($u in $userProfiles) {
        Export-PerUserHives -UserProfile $u -DestFolder $perUserHiveFolder
    }
}

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

#region ===== FINALIZE =====

$manifestPath = Join-Path $logsFolder "Manifest.csv"
$Script:Manifest | Export-Csv -Path $manifestPath -NoTypeInformation -Encoding UTF8

$errorCount = ($Script:Manifest | Where-Object { $_.Status -like 'Error*' }).Count
$okCount = ($Script:Manifest | Where-Object { $_.Status -like 'OK*' }).Count

Write-Log "===== Collection finished. Entries: $($Script:Manifest.Count)  OK: $okCount  Errors: $errorCount ====="

Repair-LongPaths -Folder $CaseFolder

# Stop the transcript BEFORE archiving - see parent script's v1.9 changelog for the root cause
# this avoids (WinRAR failing to open a Transcript.txt still held open by Start-Transcript).
try { Stop-Transcript | Out-Null } catch { }

# Archiver: WinRAR ONLY. Output is a single password-protected .rar - no .zip is ever produced
# by this script. If WinRAR genuinely cannot be found/run on the host, the script does NOT
# silently fall back to an unencrypted zip; it logs a clear error and leaves the uncompressed
# case folder in place instead.
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

$archiveVerified = $false
$archiveOkToDelete = $false
if ($archivePath -and (Test-Path -LiteralPath $archivePath) -and (Get-Item -LiteralPath $archivePath).Length -gt 0) {
    $archiveOkToDelete = $true
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

$Script:Manifest | Export-Csv -Path $manifestPath -NoTypeInformation -Encoding UTF8 -Force

Write-Host ""
Write-Host "===================================================="
Write-Host " IR-ExecutionArtifactCollector v$ScriptVersion - Collection complete"
Write-Host " Scope:       Execution artifacts only"
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

if ($archiveOkToDelete -and -not $KeepUncompressed) {
    [void](Remove-FolderPermanently -Folder $CaseFolder)
} elseif ($archivePath -and -not $archiveOkToDelete -and -not $KeepUncompressed) {
    Write-Log "Uncompressed case folder retained at $CaseFolder because the archive failed integrity verification - investigate before manually deleting." "WARN"
}

#endregion
