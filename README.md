# Windows Automated Security Reconnaissance

Automated vulnerability enumeration and misconfiguration detection for Windows machines. Designed for **blue team use in lab environments** to identify security issues before red team simulations.

**Key features:**
- Runs 7 industry-standard privilege escalation / security auditing tools automatically
- In-memory execution for .NET tools (no files written to disk)
- EDR evasion techniques (AMSI bypass, ETW patch, randomized filenames)
- Full forensic cleanup after execution
- Live dashboard with progress tracking
- Skip-on-failure design — one tool failing never stops the others

## Prerequisites

- **OS:** Windows 10+ / Windows Server 2016+
- **Privileges:** Administrator (elevated prompt)
- **PowerShell:** 5.1 or later
- **.NET Framework:** 4.5+ (required for exe-based tools: WinPEAS, Seatbelt, SharpUp)
- **Network:** Internet access (if downloading from GitHub) or access to SMB share (if using local source)

## Quick Start

```powershell
# From an elevated PowerShell prompt:
powershell.exe -ExecutionPolicy Bypass -File .\Invoke-WindowsRecon.ps1
```

Or from an existing elevated session:

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
.\Invoke-WindowsRecon.ps1
```

## Configuration

All configuration is in the **Config Block** at the top of `Invoke-WindowsRecon.ps1`. Edit only this section.

### Tool Source

```powershell
$ToolSource = "url"    # "url" = download from GitHub, "local" = copy from SMB/file path
```

### Output Directory

```powershell
$OutputBaseDir = "$env:USERPROFILE\Desktop\ReconResults"
```

### Timeout

```powershell
$TimeoutSeconds = 600  # Per-tool execution timeout in seconds
```

### Enable/Disable Tools

Each tool has an `Enabled` field. Set to `$false` to skip:

```powershell
@{
    Name    = "WinPEAS"
    Enabled = $false     # Skip this tool
    ...
}
```

### Local Path Configuration

When using `$ToolSource = "local"`, update each tool's `LocalPath` to point to your SMB share or local directory:

```powershell
LocalPath = "\\your-fileserver\tools\winPEASany_ofs.exe"
```

## Adding Custom Tools

Copy an existing tool entry in `$ToolConfig` and modify:

```powershell
@{
    Name      = "MyTool"           # Display name
    Enabled   = $true
    Type      = "exe"              # exe (in-memory .NET), ps1 (in-memory), bat (disk)
    Url       = "https://..."      # GitHub download URL
    LocalPath = "\\server\tools\MyTool.exe"
    FileName  = "MyTool.exe"
    Args      = @("--audit")       # Command-line arguments
}
```

**Type behavior:**
- `exe` — Loaded as .NET assembly in memory via `[Reflection.Assembly]::Load()`. Never touches disk. Must be a .NET executable.
- `ps1` — Downloaded as string, executed via `[scriptblock]::Create()`. Never touches disk.
- `bat` — Written to disk with a randomized filename, executed, then securely deleted.

For `ps1` tools that require specific invocation (like calling a function after loading), add a case in the `Invoke-ToolRunner` runspace scriptblock's `ps1` switch.

## Included Tools

| Tool | Type | Description |
|------|------|-------------|
| **WinPEAS** | exe | Comprehensive Windows privilege escalation scanner. Checks services, registry, credentials, file permissions, and more. |
| **Seatbelt** | exe | .NET security auditing tool. Enumerates OS info, user data, browser history, interesting files, and security configurations. |
| **SharpUp** | exe | .NET port of PowerUp. Checks for common Windows privilege escalation vectors. |
| **JAWS** | ps1 | PowerShell enumeration script for identifying privilege escalation vectors. |
| **PowerUp** | ps1 | PowerSploit module for finding common Windows privilege escalation issues (service misconfigurations, DLL hijacking, etc.). |
| **Powerless** | bat | Batch script for Windows privilege escalation enumeration. Works without PowerShell. |
| **PrivescCheck** | ps1 | Enumerates common Windows misconfigurations that can be leveraged for privilege escalation. |

## Output Structure

```
Desktop\ReconResults\Recon_20260414_153022\
    recon-log.txt              # Detailed execution log
    WinPEAS-output.txt         # WinPEAS findings
    Seatbelt-output.txt        # Seatbelt findings
    SharpUp-output.txt         # SharpUp findings
    JAWS-output.txt            # JAWS findings
    PowerUp-output.txt         # PowerUp findings
    Powerless-output.txt       # Powerless findings
    PrivescCheck-output.txt    # PrivescCheck findings
    summary.txt                # Quick overview with tool statuses and timing
```

Only the results folder remains after execution. All tools and temporary files are cleaned up.

## EDR Evasion Techniques

| Technique | Purpose |
|-----------|---------|
| AMSI bypass (AmsiScanBuffer patch) | Prevents script content scanning by Windows Defender |
| ETW patch (EtwEventWrite) | Disables .NET/PowerShell telemetry events |
| In-memory .NET assembly loading | Exe tools never written to disk (avoids AV file scanning) |
| In-memory PS1 execution | PowerShell scripts loaded as strings (never touch disk) |
| Randomized filenames | Bat files use random names to avoid signature matching |
| Randomized User-Agent | Downloads use browser-like User-Agents to avoid network signatures |
| Forensic cleanup | Removes Prefetch, event logs, PS history, Defender history |

**When evasion might not work:**
- Kernel-level EDR hooks (e.g., ETW-TI via EtwThreatIntelProvider) are not bypassed
- Hardware-backed attestation will still see execution
- Some EDR products hook at a lower level than usermode AMSI/ETW
- The script should be **whitelisted** on target machines for reliable execution

## Troubleshooting

### Windows Defender blocks execution
- Whitelist the script path or add an exclusion: `Add-MpPreference -ExclusionPath "C:\path\to\script"`
- Or temporarily disable real-time protection for the test

### Download failures
- Check internet connectivity and firewall rules for GitHub access
- Switch to `$ToolSource = "local"` and host tools on an internal SMB share
- Check if your proxy requires authentication

### .NET tools fail to execute
- Ensure .NET Framework 4.5+ is installed
- Some tools require specific .NET versions — check tool documentation
- Error "No entry point found" means the exe is not a .NET assembly

### Tool produces no output
- Check `recon-log.txt` for detailed error messages
- The tool may have crashed — try running it manually to see the error
- Increase `$TimeoutSeconds` if the tool needs more time

### PowerShell execution policy
- Run with: `powershell.exe -ExecutionPolicy Bypass -File .\Invoke-WindowsRecon.ps1`
- Or set per-session: `Set-ExecutionPolicy Bypass -Scope Process -Force`

### Insufficient privileges
- Must run from an **elevated** (Administrator) PowerShell prompt
- Right-click PowerShell → "Run as administrator"

## Disclaimer

**AUTHORIZED USE ONLY.** This tool is designed for blue team security assessments in controlled lab environments with proper authorization. Do not use on systems you do not own or have explicit written permission to test. The authors are not responsible for misuse.
