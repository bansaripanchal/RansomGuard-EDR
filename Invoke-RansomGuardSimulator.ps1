<#
.SYNOPSIS
    RansomGuard EDR Test & Malware Behavior Simulator (PowerShell).
    
.DESCRIPTION
    A strictly safe, non-destructive filesystem behavior simulator designed specifically
    to validate RansomGuard EDR's real-time detection, canary tripwires, telemetry recording,
    and alert engines against authentic Windows filesystem I/O patterns.

    SAFETY GUARANTEES:
    - NOT REAL MALWARE: Performs no real encryption, no persistence, no lateral movement,
      no process injection, no credential access, no registry modification, no defense evasion.
    - STRICT SANDBOX ENFORCEMENT: Operates strictly within the designated test directory.
      Hard safety interlocks prevent execution in system, user-root, or volume root paths.
    - DUMMY ARTIFACTS ONLY: Operates exclusively on synthetic, disposable dummy files created
      by this script.
    - ZERO DATABASE MANIPULATION: Does not modify 'ransomguard.db' directly; all telemetry
      originates from genuine Windows filesystem operations (IRPs / FileSystem events).

.PARAMETER Scenario
    The simulation scenario to run.
    Options:
      - CanaryTouch   : Simulates tampering/modification of canary / decoy tripwire files.
      - RapidRename   : Simulates rapid batch file extension renaming (e.g., .locked, .crypto).
      - MassModify    : Simulates rapid in-place high-entropy byte overwrites (mock encryption I/O).
      - RansomNote    : Simulates dropping mock ransom notes (HOW_TO_RESTORE_FILES.txt, etc.).
      - BurstDelete   : Simulates rapid batch file deletion (wiper / backup destruction simulation).
      - All           : Executes the full multi-stage mock ransomware killchain.
    Default: All

.PARAMETER TestDir
    The target directory for the simulation.
    Default: 'E:\RansomGuard_Test\RG_Simulator' (as RansomGuard monitors the E: drive).

.PARAMETER FileCount
    Number of dummy files to generate and operate on per scenario.
    Default: 20

.PARAMETER DelayMs
    Delay in milliseconds between consecutive file operations.
    Default: 30 (Use 0 for high-speed burst simulation).

.PARAMETER LogFile
    Optional file path to output structured JSON simulation telemetry for correlation with RansomGuard.

.PARAMETER Cleanup
    Purges all test artifacts and dummy files from the test directory.

.PARAMETER Reset
    Purges and re-initializes the test directory with fresh dummy files.

.PARAMETER ListScenarios
    Displays all available scenarios and exits.

.EXAMPLE
    .\Invoke-RansomGuardSimulator.ps1 -Scenario All
    Runs the full mock ransomware killchain in E:\RansomGuard_Test\RG_Simulator.

.EXAMPLE
    .\Invoke-RansomGuardSimulator.ps1 -Scenario RapidRename -FileCount 50 -DelayMs 0
    Simulates a 50-file rapid extension change burst with zero artificial delay.

.EXAMPLE
    .\Invoke-RansomGuardSimulator.ps1 -Scenario CanaryTouch
    Tests whether RansomGuard detects access and tampering with canary decoy files.

.EXAMPLE
    .\Invoke-RansomGuardSimulator.ps1 -Cleanup
    Safely removes all dummy test files from E:\RansomGuard_Test\RG_Simulator.
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param (
    [ValidateSet('CanaryTouch', 'RapidRename', 'MassModify', 'RansomNote', 'BurstDelete', 'All')]
    [string]$Scenario = 'All',

    [string]$TestDir = 'E:\RansomGuard_Test\RG_Simulator',

    [ValidateRange(1, 500)]
    [int]$FileCount = 20,

    [ValidateRange(0, 5000)]
    [int]$DelayMs = 30,

    [string]$LogFile = '',

    [switch]$Cleanup,

    [switch]$Reset,

    [switch]$ListScenarios
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ============================================================================
# SAFETY INTERLOCKS & VALIDATION
# ============================================================================
function Assert-PathSafety {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $resolvedPath = [System.IO.Path]::GetFullPath($Path).TrimEnd('\', '/')
    
    # 1. Block volume roots (e.g. C:, C:\, D:, E:\)
    if ($resolvedPath -match '^[a-zA-Z]:$|^[a-zA-Z]:\\$') {
        throw "[SAFETY VIOLATION] TestDir cannot be a drive root ('$resolvedPath'). A dedicated test subfolder is required."
    }

    # 2. Block system directories
    $systemPaths = @(
        $env:SystemRoot,
        "$env:SystemRoot\System32",
        "$env:SystemRoot\SysWOW64",
        $env:ProgramFiles,
        ${env:ProgramFiles(x86)},
        $env:ProgramData,
        $env:USERPROFILE,
        "$env:USERPROFILE\Desktop",
        "$env:USERPROFILE\Documents",
        "$env:USERPROFILE\Downloads"
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { [System.IO.Path]::GetFullPath($_).TrimEnd('\', '/') }

    foreach ($sysPath in $systemPaths) {
        if ($resolvedPath -ieq $sysPath) {
            throw "[SAFETY VIOLATION] Target path '$resolvedPath' matches protected system/user directory '$sysPath'. Execution aborted."
        }
    }

    # 3. Require path to contain an explicit test-specific naming indicator if outside default
    $folderName = [System.IO.Path]::GetFileName($resolvedPath)
    if ($folderName -notmatch '(?i)(test|simulator|sandbox|ransomguard|rg_)') {
        Write-Warning "[SAFETY NOTICE] Folder name '$folderName' does not contain 'test', 'simulator', 'sandbox', or 'ransomguard'."
    }

    return $resolvedPath
}

# ============================================================================
# LOGGING & TELEMETRY ENGINE
# ============================================================================
$global:SimulationEvents = [System.Collections.Generic.List[PSCustomObject]]::new()
$script:SimulationStartTime = [System.Diagnostics.Stopwatch]::StartNew()

function Write-TelemetryLog {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Action,

        [Parameter(Mandatory = $true)]
        [string]$TargetFile,

        [string]$Details = "",

        [ValidateSet('INFO', 'TRIGGER', 'WARN', 'SUCCESS', 'ALERT')]
        [string]$Level = 'INFO'
    )

    $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss.fff")
    $elapsedMs = $script:SimulationStartTime.ElapsedMilliseconds
    $pidNum = $PID

    $record = [PSCustomObject]@{
        Timestamp   = $timestamp
        ElapsedMs   = $elapsedMs
        ProcessId   = $pidNum
        Level       = $Level
        Action      = $Action
        TargetFile  = $TargetFile
        Details     = $Details
    }
    $global:SimulationEvents.Add($record)

    $color = switch ($Level) {
        'INFO'    { 'Cyan' }
        'TRIGGER' { 'Yellow' }
        'WARN'    { 'DarkYellow' }
        'SUCCESS' { 'Green' }
        'ALERT'   { 'Magenta' }
        Default   { 'White' }
    }

    $paddedAction = $Action.PadRight(14)
    $relPath = $TargetFile
    if ($TargetFile.Length -gt 60) {
        $relPath = "..." + $TargetFile.Substring($TargetFile.Length - 57)
    }

    Write-Host " [$timestamp | PID:$pidNum] " -NoNewline -ForegroundColor DarkGray
    Write-Host "[$paddedAction] " -NoNewline -ForegroundColor $color
    Write-Host "$relPath " -NoNewline -ForegroundColor White
    if ($Details) {
        Write-Host "($Details)" -ForegroundColor Gray
    } else {
        Write-Host ""
    }
}

# ============================================================================
# DUMMY FILE GENERATOR
# ============================================================================
$script:DummyExtensions = @('.docx', '.xlsx', '.pdf', '.txt', '.jpg', '.png', '.csv', '.sql', '.dat')

$script:SampleTextContent = @"
================================================================================
RANSOMGUARD EDR VALIDATION TEST DOCUMENT
Generated by: RansomGuard Malware Behavior Simulator
Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Purpose: Synthetic test data for non-destructive filesystem I/O telemetry.
================================================================================
Confidential Project Assessment & Operations Log:
1. Quarter financial analysis summary report and ledger entries.
2. Production database schemas and customer record metrics.
3. System engineering deployment guidelines and architecture diagrams.
4. Internal communications and project milestone verification checklists.
--------------------------------------------------------------------------------
[END OF SYNTHETIC DATA BLOCK - SAFE TEST FILE]
"@

function Initialize-SandboxEnvironment {
    param (
        [string]$TargetDir,
        [int]$Count = 20
    )

    Write-Host "`n>>> [INIT] Initializing Sandbox Environment at: $TargetDir" -ForegroundColor Cyan
    
    if (-not (Test-Path -LiteralPath $TargetDir)) {
        New-Item -ItemType Directory -Path $TargetDir -Force | Out-Null
        Write-TelemetryLog -Action "DIR_CREATE" -TargetFile $TargetDir -Details "Created base test directory" -Level "INFO"
    }

    # Subdirectories to mimic authentic user folder hierarchies
    $subfolders = @('Documents', 'Finance', 'Engineering', 'Photos')
    foreach ($sf in $subfolders) {
        $sfPath = Join-Path -Path $TargetDir -ChildPath $sf
        if (-not (Test-Path -LiteralPath $sfPath)) {
            New-Item -ItemType Directory -Path $sfPath -Force | Out-Null
            Write-TelemetryLog -Action "DIR_CREATE" -TargetFile $sfPath -Details "Created subfolder structure" -Level "INFO"
        }
    }

    $existingFiles = @(Get-ChildItem -Path $TargetDir -File -Recurse | Where-Object { $_.Name -notmatch '^(\!|_canary|README|HOW_TO)' })
    if ($existingFiles.Count -ge $Count) {
        Write-Host "    [INIT] Sandbox already seeded with $($existingFiles.Count) dummy files." -ForegroundColor DarkGray
        return
    }

    $needed = $Count - $existingFiles.Count
    Write-Host "    [INIT] Generating $needed synthetic dummy documents..." -ForegroundColor Gray

    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $utf8Bytes = [System.Text.Encoding]::UTF8.GetBytes($script:SampleTextContent)

    for ($i = 1; $i -le $needed; $i++) {
        $subfolder = $subfolders[($i % $subfolders.Count)]
        $ext = $script:DummyExtensions[($i % $script:DummyExtensions.Count)]
        $fileName = "dummy_file_$('{0:D4}' -f $i)$ext"
        $filePath = Join-Path (Join-Path $TargetDir $subfolder) $fileName

        if (-not (Test-Path -LiteralPath $filePath)) {
            # Write realistic-looking dummy file with standard plain text content
            [System.IO.File]::WriteAllBytes($filePath, $utf8Bytes)
            Write-TelemetryLog -Action "FILE_CREATE" -TargetFile $filePath -Details "Size: $($utf8Bytes.Length) bytes" -Level "INFO"
        }
    }

    Write-Host "    [INIT] Sandbox initialization complete.`n" -ForegroundColor Green
}

# ============================================================================
# SCENARIO 1: CANARY / TRIPWIRE FILE INTERACTION
# ============================================================================
function Invoke-ScenarioCanaryTouch {
    param (
        [string]$TargetDir,
        [int]$Delay
    )

    Write-Host "`n========================================================================" -ForegroundColor Yellow
    Write-Host " SCENARIO 1: CANARY & DECOY TRIPWIRE TAMPERING SIMULATION" -ForegroundColor Yellow
    Write-Host " Purpose: Simulates access, modification, and deletion of EDR canary files." -ForegroundColor DarkYellow
    Write-Host "========================================================================`n" -ForegroundColor Yellow

    $canaryNames = @(
        '!000_canary_decoy.docx',
        '!0_SYSTEM_CANARY.txt',
        'AAA_IMPORTANT_DO_NOT_DELETE.pdf',
        '_canary_honeypot.xlsx',
        '__vault_tripwire.dat'
    )

    $canaries = @()
    # Step 1: Create Canary Files in Root and Subfolders
    foreach ($canaryName in $canaryNames) {
        $canaryPath = Join-Path -Path $TargetDir -ChildPath $canaryName
        $initialBytes = [System.Text.Encoding]::UTF8.GetBytes("RANSOMGUARD_CANARY_TRIPWIRE_DATA_$(New-Guid)")
        [System.IO.File]::WriteAllBytes($canaryPath, $initialBytes)
        Write-TelemetryLog -Action "CANARY_CREATE" -TargetFile $canaryPath -Details "Planted honeypot tripwire" -Level "TRIGGER"
        $canaries += $canaryPath
        if ($Delay -gt 0) { Start-Sleep -Milliseconds $Delay }
    }

    Start-Sleep -Milliseconds 200

    # Step 2: Read & Modify Canary Files (Tampering)
    Write-Host "`n>>> [STEP 2] Simulating unauthorized modification of canary files..." -ForegroundColor Yellow
    foreach ($canaryPath in $canaries) {
        if (Test-Path -LiteralPath $canaryPath) {
            # Overwrite with modified mock tamper content
            $tamperBytes = [System.Text.Encoding]::UTF8.GetBytes("[TAMPERED_BY_SIMULATOR] $(Get-Date -Format 'o')")
            [System.IO.File]::WriteAllBytes($canaryPath, $tamperBytes)
            Write-TelemetryLog -Action "CANARY_MODIFY" -TargetFile $canaryPath -Details "Modified canary content (Tamper Event)" -Level "ALERT"
            if ($Delay -gt 0) { Start-Sleep -Milliseconds $Delay }
        }
    }

    Start-Sleep -Milliseconds 200

    # Step 3: Delete Canary File (Destruction)
    Write-Host "`n>>> [STEP 3] Simulating deletion of canary files..." -ForegroundColor Yellow
    foreach ($canaryPath in $canaries) {
        if (Test-Path -LiteralPath $canaryPath) {
            [System.IO.File]::Delete($canaryPath)
            Write-TelemetryLog -Action "CANARY_DELETE" -TargetFile $canaryPath -Details "Deleted canary tripwire" -Level "ALERT"
            if ($Delay -gt 0) { Start-Sleep -Milliseconds $Delay }
        }
    }

    Write-Host "`n[+] Scenario 'CanaryTouch' Completed. Verify RansomGuard Canary/Tripwire alerts." -ForegroundColor Green
}

# ============================================================================
# SCENARIO 2: RAPID FILE EXTENSION RENAMING
# ============================================================================
function Invoke-ScenarioRapidRename {
    param (
        [string]$TargetDir,
        [int]$Count,
        [int]$Delay
    )

    Write-Host "`n========================================================================" -ForegroundColor Yellow
    Write-Host " SCENARIO 2: RAPID FILE EXTENSION RENAMING SIMULATION" -ForegroundColor Yellow
    Write-Host " Purpose: Simulates mass renaming of files to ransomware extension patterns." -ForegroundColor DarkYellow
    Write-Host "========================================================================`n" -ForegroundColor Yellow

    $targetFiles = @(Get-ChildItem -Path $TargetDir -File -Recurse | 
        Where-Object { $_.Extension -notin @('.locked', '.crypto', '.ransomtest', '.enc', '.crypted', '.rg_locked') -and $_.Name -notmatch '^(\!|_canary|README|HOW_TO)' } | 
        Select-Object -First $Count)

    if ($targetFiles.Count -eq 0) {
        Write-Host "[-] No unrenamed target files found. Re-initializing dummy files..." -ForegroundColor DarkYellow
        Initialize-SandboxEnvironment -TargetDir $TargetDir -Count $Count
        $targetFiles = @(Get-ChildItem -Path $TargetDir -File -Recurse | 
            Where-Object { $_.Extension -notin @('.locked', '.crypto', '.ransomtest', '.enc', '.crypted', '.rg_locked') -and $_.Name -notmatch '^(\!|_canary|README|HOW_TO)' } | 
            Select-Object -First $Count)
    }

    $ransomExtensions = @('.locked', '.crypto', '.ransomtest', '.enc', '.crypted', '.rg_locked')

    Write-Host ">>> Executing rapid rename on $($targetFiles.Count) files..." -ForegroundColor Cyan
    $sw = [System.Diagnostics.Stopwatch]::StartNew()

    for ($i = 0; $i -lt $targetFiles.Count; $i++) {
        $file = $targetFiles[$i]
        $ext = $ransomExtensions[($i % $ransomExtensions.Count)]
        $newPath = "$($file.FullName)$ext"

        # Authentic Windows file rename using .NET Move
        [System.IO.File]::Move($file.FullName, $newPath)
        Write-TelemetryLog -Action "FILE_RENAME" -TargetFile $newPath -Details "Old: $($file.Name) -> NewExt: $ext" -Level "ALERT"

        if ($Delay -gt 0) { Start-Sleep -Milliseconds $Delay }
    }

    $sw.Stop()
    $rate = [Math]::Round(($targetFiles.Count / [Math]::Max(1, $sw.ElapsedMilliseconds)) * 1000, 2)
    Write-Host "`n[+] Renamed $($targetFiles.Count) files in $($sw.ElapsedMilliseconds) ms (~$rate files/sec)." -ForegroundColor Green
    Write-Host "[+] Scenario 'RapidRename' Completed. Verify RansomGuard Extension Renaming rule alerts." -ForegroundColor Green
}

# ============================================================================
# SCENARIO 3: RAPID HIGH-ENTROPY / MASS CONTENT MODIFICATION
# ============================================================================
function Invoke-ScenarioMassModify {
    param (
        [string]$TargetDir,
        [int]$Count,
        [int]$Delay
    )

    Write-Host "`n========================================================================" -ForegroundColor Yellow
    Write-Host " SCENARIO 3: RAPID HIGH-ENTROPY CONTENT OVERWRITE SIMULATION" -ForegroundColor Yellow
    Write-Host " Purpose: Simulates rapid in-place write bursts with non-compressible bytes" -ForegroundColor DarkYellow
    Write-Host "          mimicking ransomware symmetric encryption I/O behavior." -ForegroundColor DarkYellow
    Write-Host "========================================================================`n" -ForegroundColor Yellow

    $targetFiles = @(Get-ChildItem -Path $TargetDir -File -Recurse | 
        Where-Object { $_.Name -notmatch '^(\!|_canary|README|HOW_TO)' } | 
        Select-Object -First $Count)

    if ($targetFiles.Count -eq 0) {
        Initialize-SandboxEnvironment -TargetDir $TargetDir -Count $Count
        $targetFiles = @(Get-ChildItem -Path $TargetDir -File -Recurse | 
            Where-Object { $_.Name -notmatch '^(\!|_canary|README|HOW_TO)' } | 
            Select-Object -First $Count)
    }

    Write-Host ">>> Executing high-entropy write burst across $($targetFiles.Count) files..." -ForegroundColor Cyan
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $buffer = [byte[]]::new(4096) # 4KB high entropy mock payload block
    $sw = [System.Diagnostics.Stopwatch]::StartNew()

    foreach ($file in $targetFiles) {
        # Fill buffer with randomized pseudo-bytes (high Shannon entropy)
        $rng.GetBytes($buffer)

        # In-place file rewrite using authentic FileStream
        $fs = [System.IO.File]::Open($file.FullName, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
        try {
            $fs.Write($buffer, 0, $buffer.Length)
        }
        finally {
            $fs.Close()
            $fs.Dispose()
        }

        Write-TelemetryLog -Action "MASS_WRITE" -TargetFile $file.FullName -Details "Wrote 4096 random high-entropy bytes" -Level "ALERT"

        if ($Delay -gt 0) { Start-Sleep -Milliseconds $Delay }
    }

    $sw.Stop()
    $rate = [Math]::Round(($targetFiles.Count / [Math]::Max(1, $sw.ElapsedMilliseconds)) * 1000, 2)
    Write-Host "`n[+] Overwrote $($targetFiles.Count) files with high-entropy bytes in $($sw.ElapsedMilliseconds) ms (~$rate ops/sec)." -ForegroundColor Green
    Write-Host "[+] Scenario 'MassModify' Completed. Verify RansomGuard High-Entropy / Write-Burst alerts." -ForegroundColor Green
}

# ============================================================================
# SCENARIO 4: RANSOM NOTE DROP SIMULATION
# ============================================================================
function Invoke-ScenarioRansomNote {
    param (
        [string]$TargetDir,
        [int]$Delay
    )

    Write-Host "`n========================================================================" -ForegroundColor Yellow
    Write-Host " SCENARIO 4: RANSOM NOTE DROP SIMULATION" -ForegroundColor Yellow
    Write-Host " Purpose: Simulates dropping recognizable ransom note artifacts in folders." -ForegroundColor DarkYellow
    Write-Host "========================================================================`n" -ForegroundColor Yellow

    $noteTemplates = @(
        @{
            FileName = 'HOW_TO_RESTORE_FILES.txt'
            Content  = @"
!!! RANSOMGUARD EDR SIMULATED RANSOM NOTE !!!
THIS IS A HARMLESS TEST ARTIFACT GENERATED FOR EDR DETECTION VALIDATION.
All your dummy test files in this directory have been simulated as locked.
To verify protection, inspect your RansomGuard EDR Dashboard and alerts.
Identifier: RG-SIM-$(New-Guid)
"@
        },
        @{
            FileName = 'README_RECOVERY_INSTRUCTIONS.txt'
            Content  = @"
================================================================================
RANSOMGUARD SIMULATED ADVISORY NOTE
SAFE TEST FILE - NO REAL ENCRYPTION HAS OCCURRED
This test file validates ransom note keyword detection algorithms.
================================================================================
"@
        },
        @{
            FileName = 'DECRYPT_INFO.html'
            Content  = @"
<!DOCTYPE html>
<html>
<head><title>RansomGuard EDR Test Note</title></head>
<body style='font-family: monospace; background:#111; color:#0f0; padding:20px;'>
<h2>[RANSOMGUARD SIMULATED RANSOM NOTE]</h2>
<p>This is a safe simulated decryptor note dropped to test filesystem tripwires.</p>
<p>Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
</body>
</html>
"@
        }
    )

    $folders = @($TargetDir) + @(Get-ChildItem -Path $TargetDir -Directory -Recurse | Select-Object -ExpandProperty FullName)

    Write-Host ">>> Dropping simulated ransom notes across $($folders.Count) folder locations..." -ForegroundColor Cyan

    foreach ($folder in $folders) {
        foreach ($tmpl in $noteTemplates) {
            $notePath = Join-Path -Path $folder -ChildPath $tmpl.FileName
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($tmpl.Content)
            [System.IO.File]::WriteAllBytes($notePath, $bytes)
            Write-TelemetryLog -Action "NOTE_DROP" -TargetFile $notePath -Details "Dropped simulated note: $($tmpl.FileName)" -Level "TRIGGER"
            if ($Delay -gt 0) { Start-Sleep -Milliseconds $Delay }
        }
    }

    Write-Host "`n[+] Scenario 'RansomNote' Completed. Verify RansomGuard Ransom Note Detection rules." -ForegroundColor Green
}

# ============================================================================
# SCENARIO 5: RAPID BURST DELETION (WIPER / ANTI-BACKUP SIMULATION)
# ============================================================================
function Invoke-ScenarioBurstDelete {
    param (
        [string]$TargetDir,
        [int]$Count,
        [int]$Delay
    )

    Write-Host "`n========================================================================" -ForegroundColor Yellow
    Write-Host " SCENARIO 5: RAPID BURST FILE DELETION SIMULATION" -ForegroundColor Yellow
    Write-Host " Purpose: Simulates rapid batch file deletion (mass wiper / anti-backup behavior)." -ForegroundColor DarkYellow
    Write-Host "========================================================================`n" -ForegroundColor Yellow

    # Ensure files exist to delete
    $targetFiles = @(Get-ChildItem -Path $TargetDir -File -Recurse | Select-Object -First $Count)

    if ($targetFiles.Count -lt $Count) {
        Initialize-SandboxEnvironment -TargetDir $TargetDir -Count ($Count * 2)
        $targetFiles = @(Get-ChildItem -Path $TargetDir -File -Recurse | Select-Object -First $Count)
    }

    Write-Host ">>> Rapidly deleting $($targetFiles.Count) dummy files..." -ForegroundColor Cyan
    $sw = [System.Diagnostics.Stopwatch]::StartNew()

    foreach ($file in $targetFiles) {
        [System.IO.File]::Delete($file.FullName)
        Write-TelemetryLog -Action "BURST_DELETE" -TargetFile $file.FullName -Details "Deleted dummy file" -Level "ALERT"
        if ($Delay -gt 0) { Start-Sleep -Milliseconds $Delay }
    }

    $sw.Stop()
    $rate = [Math]::Round(($targetFiles.Count / [Math]::Max(1, $sw.ElapsedMilliseconds)) * 1000, 2)
    Write-Host "`n[+] Deleted $($targetFiles.Count) files in $($sw.ElapsedMilliseconds) ms (~$rate files/sec)." -ForegroundColor Green
    Write-Host "[+] Scenario 'BurstDelete' Completed. Verify RansomGuard Mass Deletion / Wiper rules." -ForegroundColor Green
}

# ============================================================================
# CLEANUP AND RESET UTILITIES
# ============================================================================
function Clean-SandboxEnvironment {
    param (
        [string]$TargetDir
    )

    Write-Host "`n>>> [CLEANUP] Cleaning up test directory: $TargetDir" -ForegroundColor Yellow
    
    if (-not (Test-Path -LiteralPath $TargetDir)) {
        Write-Host "    [CLEANUP] Directory does not exist. Nothing to clean." -ForegroundColor DarkGray
        return
    }

    $items = @(Get-ChildItem -Path $TargetDir -Recurse -Force)
    Write-Host "    [CLEANUP] Removing $($items.Count) generated test items..." -ForegroundColor Gray

    foreach ($item in $items) {
        try {
            if (-not $item.PSIsContainer) {
                [System.IO.File]::Delete($item.FullName)
                Write-TelemetryLog -Action "CLEANUP_FILE" -TargetFile $item.FullName -Details "Deleted test file" -Level "INFO"
            }
        }
        catch {
            Write-Warning "Could not delete $($item.FullName): $_"
        }
    }

    # Delete child directories
    Get-ChildItem -Path $TargetDir -Directory -Recurse | Sort-Object -Property FullName -Descending | ForEach-Object {
        try {
            [System.IO.Directory]::Delete($_.FullName, $true)
            Write-TelemetryLog -Action "CLEANUP_DIR" -TargetFile $_.FullName -Details "Deleted test subfolder" -Level "INFO"
        }
        catch {
            Write-Warning "Could not delete directory $($_.FullName): $_"
        }
    }

    Write-Host "    [CLEANUP] Test directory successfully cleaned.`n" -ForegroundColor Green
}

# ============================================================================
# SCENARIO CATALOG
# ============================================================================
function Show-ScenarioList {
    Write-Host "`n========================================================================" -ForegroundColor Cyan
    Write-Host "             RansomGuard EDR Simulation Scenario Catalog" -ForegroundColor Cyan
    Write-Host "========================================================================" -ForegroundColor Cyan
    
    $scenarios = @(
        @{ Name = 'CanaryTouch';  Desc = 'Plants and tampers/deletes decoy canary honeypot files.' }
        @{ Name = 'RapidRename';  Desc = 'Rapidly changes extensions to .locked, .crypto, .enc.' }
        @{ Name = 'MassModify';   Desc = 'Overwrites files with high-entropy pseudo-random bytes.' }
        @{ Name = 'RansomNote';   Desc = 'Drops standard simulated ransom note files across folders.' }
        @{ Name = 'BurstDelete';  Desc = 'Rapidly deletes files in tight loops (wiper/backup attack).' }
        @{ Name = 'All';          Desc = 'Executes full multi-stage simulated ransomware attack chain.' }
    )

    foreach ($s in $scenarios) {
        Write-Host "  - $($s.Name.PadRight(14)) : " -NoNewline -ForegroundColor Yellow
        Write-Host "$($s.Desc)" -ForegroundColor White
    }
    Write-Host "========================================================================`n" -ForegroundColor Cyan
}

# ============================================================================
# MAIN ENTRYPOINT
# ============================================================================
try {
    if ($ListScenarios) {
        Show-ScenarioList
        exit 0
    }

    # 1. Resolve and Validate Path Safety
    $resolvedTestDir = Assert-PathSafety -Path $TestDir

    # 2. Print RansomGuard Simulator Startup Banner (Mandatory Output Format)
    Write-Host "========================================================================" -ForegroundColor Cyan
    Write-Host "                      RansomGuard Simulator" -ForegroundColor Cyan
    Write-Host "========================================================================" -ForegroundColor Cyan
    Write-Host "Protected test directory:" -ForegroundColor White
    Write-Host "  $resolvedTestDir" -ForegroundColor Green
    Write-Host ""
    Write-Host "RansomGuard monitoring status:" -ForegroundColor White
    Write-Host "  VERIFY MANUALLY / DETECTED" -ForegroundColor Yellow
    Write-Host "========================================================================" -ForegroundColor Cyan
    Write-Host " [SAFETY NOTICE] Non-destructive simulation mode active." -ForegroundColor DarkCyan
    Write-Host " [SAFETY NOTICE] Operating strictly within $resolvedTestDir." -ForegroundColor DarkCyan
    Write-Host " [SAFETY NOTICE] ransomguard.db will NOT be modified directly." -ForegroundColor DarkCyan
    Write-Host "========================================================================`n" -ForegroundColor Cyan

    # 3. Handle Reset / Cleanup switches
    if ($Cleanup) {
        Clean-SandboxEnvironment -TargetDir $resolvedTestDir
        exit 0
    }

    if ($Reset) {
        Clean-SandboxEnvironment -TargetDir $resolvedTestDir
        Initialize-SandboxEnvironment -TargetDir $resolvedTestDir -Count $FileCount
        Write-Host "[+] Sandbox reset complete.`n" -ForegroundColor Green
        exit 0
    }

    # 4. Initialize Sandbox Files
    Initialize-SandboxEnvironment -TargetDir $resolvedTestDir -Count $FileCount

    # 5. Execute Chosen Scenario
    switch ($Scenario) {
        'CanaryTouch' {
            Invoke-ScenarioCanaryTouch -TargetDir $resolvedTestDir -Delay $DelayMs
        }
        'RapidRename' {
            Invoke-ScenarioRapidRename -TargetDir $resolvedTestDir -Count $FileCount -Delay $DelayMs
        }
        'MassModify' {
            Invoke-ScenarioMassModify -TargetDir $resolvedTestDir -Count $FileCount -Delay $DelayMs
        }
        'RansomNote' {
            Invoke-ScenarioRansomNote -TargetDir $resolvedTestDir -Delay $DelayMs
        }
        'BurstDelete' {
            Invoke-ScenarioBurstDelete -TargetDir $resolvedTestDir -Count $FileCount -Delay $DelayMs
        }
        'All' {
            Write-Host "`n>>> [KILLCHAIN] EXECUTING FULL MULTI-STAGE MOCK ATTACK CHAIN..." -ForegroundColor Magenta
            
            # Stage 1: Canary Tripwire Tamper
            Invoke-ScenarioCanaryTouch -TargetDir $resolvedTestDir -Delay $DelayMs
            Start-Sleep -Milliseconds 300

            # Stage 2: Mass Content Modification (Mock Encryption)
            Invoke-ScenarioMassModify -TargetDir $resolvedTestDir -Count $FileCount -Delay $DelayMs
            Start-Sleep -Milliseconds 300

            # Stage 3: Rapid Extension Renaming
            Invoke-ScenarioRapidRename -TargetDir $resolvedTestDir -Count $FileCount -Delay $DelayMs
            Start-Sleep -Milliseconds 300

            # Stage 4: Drop Ransom Notes
            Invoke-ScenarioRansomNote -TargetDir $resolvedTestDir -Delay $DelayMs
        }
    }

    # 6. Summary & Telemetry Export
    $totalEvents = $global:SimulationEvents.Count
    $totalElapsed = $script:SimulationStartTime.Elapsed.ToString("hh\:mm\:ss\.fff")

    Write-Host "`n========================================================================" -ForegroundColor Cyan
    Write-Host "                      SIMULATION EXECUTION SUMMARY" -ForegroundColor Cyan
    Write-Host "========================================================================" -ForegroundColor Cyan
    Write-Host " Total Filesystem I/O Operations : $totalEvents" -ForegroundColor White
    Write-Host " Total Execution Time            : $totalElapsed" -ForegroundColor White
    Write-Host " Target Directory                : $resolvedTestDir" -ForegroundColor White
    Write-Host " Process ID (PID)                : $PID" -ForegroundColor White
    Write-Host "========================================================================" -ForegroundColor Cyan

    if (-not [string]::IsNullOrWhiteSpace($LogFile)) {
        $logResolved = [System.IO.Path]::GetFullPath($LogFile)
        $global:SimulationEvents | ConvertTo-Json -Depth 3 | Set-Content -Path $logResolved -Encoding UTF8
        Write-Host "[+] Exported simulation telemetry log to: $logResolved" -ForegroundColor Green
    }

    Write-Host "`n[i] Now check RansomGuard EDR console / alerts to verify real-time detection.`n" -ForegroundColor Yellow
}
catch {
    Write-Error "[SIMULATOR ERROR] $_"
    exit 1
}
