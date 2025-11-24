<#
Hardening-Defender-Force-Reboot.ps1
Aggressive hardening focused on ensuring Microsoft Defender is active, firewall blocks inbound,
and important registry/security settings are applied. Creates backups and a restore helper.
Automatically reboots by default when finished.

Reference checklist PDF (uploaded): file:///mnt/data/fa5362e3-1371-49e6-9dae-b35bf8a8dcee.pdf

USAGE:
  # Dry-run (preview):
  .\Hardening-Defender-Force-Reboot.ps1 -WhatIf

  # Real run (auto-reboot by default):
  .\Hardening-Defender-Force-Reboot.ps1

  # Skip automatic reboot:
  .\Hardening-Defender-Force-Reboot.ps1 -NoReboot
#>

param(
    [switch]$WhatIf,
    [switch]$SafeMode,
    [switch]$NoReboot
)

# Default: auto-reboot unless -NoReboot passed
if (-not $PSBoundParameters.ContainsKey('NoReboot')) { $AutoReboot = $true } else { $AutoReboot = $false }

# --- Setup logging & paths ---
$Timestamp = (Get-Date).ToString("yyyyMMdd-HHmmss")
$LogDir = Join-Path $env:ProgramData "WindowsHardeningLogs"
if (-not (Test-Path $LogDir)) { New-Item -Path $LogDir -ItemType Directory -Force | Out-Null }
$LogFile = Join-Path $LogDir "Hardening-Defender-$Timestamp.log"
$RegBackupDir = Join-Path $LogDir "RegistryBackup-$Timestamp"
New-Item -Path $RegBackupDir -ItemType Directory -Force | Out-Null
$VerifyFile = Join-Path $LogDir "Verification-Defender-$Timestamp.json"
$ChecklistPdf = "file:///mnt/data/fa5362e3-1371-49e6-9dae-b35bf8a8dcee.pdf"

Function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $t = (Get-Date).ToString("o")
    $line = "$t [$Level] $Message"
    $line | Tee-Object -FilePath $LogFile -Append
    return $line
}

# Ensure elevated
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Log "Script must be run elevated (Run as Administrator)." "ERROR"
    throw "Administrator privileges required."
}

Write-Log "Hardening run starting. SafeMode=$SafeMode WhatIf=$WhatIf AutoReboot=$AutoReboot"
Write-Log "Checklist PDF reference: $ChecklistPdf"

# Simple invoker that respects WhatIf
function Invoke-Step {
    param(
        [ScriptBlock]$Action,
        [string]$Description,
        [ScriptBlock]$Verify = $null,
        [switch]$AllowFailure
    )
    Write-Log "STEP: $Description"
    if ($WhatIf) {
        Write-Log "WhatIf: would perform: $Description"
        return @{ Success = $true; Simulated = $true }
    }
    try {
        & $Action
        Write-Log "Applied: $Description"
    } catch {
        Write-Log ("Error applying {0}: {1}" -f $Description, $_) "ERROR"
        if (-not $AllowFailure) { return @{ Success = $false } }
    }
    if ($Verify) {
        try {
            $ok = & $Verify
            if ($ok) { Write-Log "Verified: $Description"; return @{ Success = $true; Verified = $true } }
            else { Write-Log "Verification FAILED: $Description" "WARN"; return @{ Success = $false; Verified = $false } }
        } catch {
            Write-Log ("Verification error for {0}: {1}" -f $Description, $_) "ERROR"
            return @{ Success = $false; Verified = $false }
        }
    } else {
        return @{ Success = $true }
    }
}

# Backup registry helper (reg.exe)
function Backup-RegistryKey {
    param([string]$KeyPath)
    $fname = ($KeyPath -replace '[\\:\s]','_') + ".reg"
    $outfile = Join-Path $RegBackupDir $fname
    if ($WhatIf) { Write-Log "WhatIf: would export $KeyPath to $outfile"; return }
    try {
        cmd.exe /c "reg export `"$KeyPath`" `"$outfile`" /y" > $null 2>&1
        Write-Log "Exported registry key $KeyPath -> $outfile"
    } catch {
        Write-Log ("Failed to export {0} : {1}" -f $KeyPath, $_) "WARN"
    }
}

# Pre-backup registry keys we will touch
$keysToBackup = @(
    "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
    "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender",
    "HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
    "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters",
    "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server",
    "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters",
    "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
)
foreach ($k in $keysToBackup) { Backup-RegistryKey -KeyPath $k }

# Save services snapshot
if (-not $WhatIf) {
    Get-Service | Sort-Object Status,Name | Out-File (Join-Path $LogDir "ServicesSnapshot-$Timestamp.txt")
    Write-Log "Saved services snapshot"
}

# Create System Restore point (best-effort)
function Create-RestorePoint {
    Write-Log "Creating System Restore point Pre-Hardening-$Timestamp (best-effort)"
    if ($WhatIf) { Write-Log "WhatIf: skipping restore point"; return @{ Success = $true } }
    try {
        if (Get-Command -Name Checkpoint-Computer -ErrorAction SilentlyContinue) {
            Checkpoint-Computer -Description ("Pre-Hardening-$Timestamp") -RestorePointType "MODIFY_SETTINGS"
            Write-Log "Created restore point Pre-Hardening-$Timestamp"
            return @{ Success = $true }
        } else {
            $wmim = Get-WmiObject -Namespace "root/default" -Class SystemRestore -ErrorAction SilentlyContinue
            if ($wmim) {
                $wmim.CreateRestorePoint("Pre-Hardening-$Timestamp", 0, 100) | Out-Null
                Write-Log "Created restore point (WMI fallback)."
                return @{ Success = $true }
            } else {
                Write-Log "System Restore not available" "WARN"
                return @{ Success = $false }
            }
        }
    } catch {
        Write-Log ("Failed to create restore point: {0}" -f $_) "WARN"
        return @{ Success = $false }
    }
}
Create-RestorePoint

# --- Helper: ensure Defender service and module ready, remove common disabling policies, update signatures, and run a full scan ---
function Ensure-DefenderActive {
    Write-Log "Ensure-DefenderActive: start"

    # Stop & disable known third-party Malwarebytes service if still present (best-effort)
    $mbServices = @("MBAMService","MBAMService.exe","MBAMProtection")
    foreach ($svcName in $mbServices) {
        $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
        if ($svc) {
            Invoke-Step -Action { Stop-Service -Name $svcName -Force -ErrorAction SilentlyContinue; Set-Service -Name $svcName -StartupType Disabled -ErrorAction SilentlyContinue } -Description ("Stop & disable possible Malwarebytes service: " + $svcName) -AllowFailure
        }
    }

    # Ensure WinDefend service exists and is running
    $winSvc = Get-Service -Name "WinDefend" -ErrorAction SilentlyContinue
    if (-not $winSvc) {
        Write-Log "WinDefend service not present. This system may be using third-party AV or Defender features unavailable." "ERROR"
    } else {
        if ($winSvc.Status -ne 'Running') {
            Invoke-Step -Action { Start-Service -Name "WinDefend" -ErrorAction Stop } -Description "Start WinDefend service" -AllowFailure
        }
        Invoke-Step -Action { Set-Service -Name "WinDefend" -StartupType Automatic -ErrorAction SilentlyContinue } -Description "Set WinDefend startup = Automatic"
    }

    # Remove common Defender-disable registry policy values (best-effort)
    $policyPaths = @(
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender",
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Defender",
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Defender\Real-Time Protection"
    )
    $namesToRemove = @("DisableAntiSpyware","DisableRealtimeMonitoring","DisableBehaviorMonitoring","DisableIntrusionPreventionSystem","DisableAntiVirus")
    foreach ($p in $policyPaths) {
        if (Test-Path $p) {
            foreach ($n in $namesToRemove) {
                $val = (Get-ItemProperty -Path $p -Name $n -ErrorAction SilentlyContinue).$n
                if ($null -ne $val) {
                    try {
                        if ($WhatIf) { Write-Log "WhatIf: would Remove-ItemProperty $p`:$n" } else {
                            Remove-ItemProperty -Path $p -Name $n -ErrorAction Stop
                            Write-Log "Removed policy value $n from $p"
                        }
                    } catch {
                        Write-Log ("Could NOT remove $n from $p (Tamper/MDM/GPO may protect it): {0}" -f $_) "WARN"
                    }
                }
            }
        }
    }

    # If Defender module present, run preferences + update + full scan
    if (Get-Command -Name Set-MpPreference -ErrorAction SilentlyContinue) {
        Invoke-Step -Action { Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue } -Description "Set MpPreference: enable realtime (best-effort)" -AllowFailure
        Invoke-Step -Action { Set-MpPreference -DisableBehaviorMonitoring $false -ErrorAction SilentlyContinue } -Description "Set MpPreference: enable behavior monitoring (best-effort)" -AllowFailure
        Invoke-Step -Action { Set-MpPreference -SubmitSamplesConsent SendAllSamples -ErrorAction SilentlyContinue } -Description "Set MpPreference: submit samples (best-effort)" -AllowFailure

        # Restore defaults then update signatures
        Invoke-Step -Action { 
            $mpCmd = Join-Path $env:ProgramFiles "Windows Defender\MpCmdRun.exe"
            if (Test-Path $mpCmd) { & $mpCmd -RestoreDefaults 2>&1 | Out-Null }
        } -Description "MpCmdRun -RestoreDefaults (if available)" -AllowFailure

        Invoke-Step -Action { Update-MpSignature -ErrorAction SilentlyContinue } -Description "Update Defender signatures" -AllowFailure

        # Start a full scan (this can be long). It's okay if it runs in background — we call Start and continue.
        Invoke-Step -Action { Start-MpScan -ScanType FullScan -Force -ErrorAction SilentlyContinue } -Description "Start full Defender scan (FullScan)" -AllowFailure
    } else {
        Write-Log "Defender PowerShell cmdlets not present on this machine; cannot run Update-MpSignature / Start-MpScan." "WARN"
    }

    # Report status
    try {
        $mpStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
        if ($mpStatus) {
            Write-Log ("Defender status: AntispywareEnabled={0}, AntivirusEnabled={1}, RealTimeProtectionEnabled={2}, AMServiceEnabled={3}, AMRunningMode={4}" -f $mpStatus.AntispywareEnabled, $mpStatus.AntivirusEnabled, $mpStatus.RealTimeProtectionEnabled, $mpStatus.AMServiceEnabled, $mpStatus.AMRunningMode)
        } else {
            Write-Log "Get-MpComputerStatus not available or returned nothing (maybe third-party AV present)." "WARN"
        }
    } catch {
        Write-Log ("Get-MpComputerStatus failed: {0}" -f $_) "WARN"
    }

    Write-Log "Ensure-DefenderActive: end"
}

# --- Firewall: enable & block inbound (create anchor rule) ---
Invoke-Step -Action {
    foreach ($p in @("Domain","Private","Public")) {
        Set-NetFirewallProfile -Profile $p -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow -Verbose:$false -ErrorAction SilentlyContinue
    }
    Set-Service -Name "MpsSvc" -StartupType Automatic -ErrorAction SilentlyContinue
    Start-Service -Name "MpsSvc" -ErrorAction SilentlyContinue
    if (-not $SafeMode) {
        if (-not (Get-NetFirewallRule -DisplayName "HARDEN_BLOCK_ALL_INBOUND" -ErrorAction SilentlyContinue)) {
            New-NetFirewallRule -DisplayName "HARDEN_BLOCK_ALL_INBOUND" -Direction Inbound -Action Block -Enabled True -Profile Any -Description "Anchor deny-all inbound for hardened host" | Out-Null
        } else {
            Set-NetFirewallRule -DisplayName "HARDEN_BLOCK_ALL_INBOUND" -Action Block -Enabled True | Out-Null
        }
    } else {
        Write-Log "SafeMode: skipping deny-all inbound anchor rule"
    }
} -Description "Configure Windows Firewall (block inbound by default)"

# --- Disable SMBv1 (best-effort) ---
Invoke-Step -Action {
    # Set registry flags and attempt to disable optional feature if present
    cmd.exe /c 'reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v SMB1 /t REG_DWORD /d 0 /f' > $null 2>&1
    cmd.exe /c 'reg add "HKLM\SYSTEM\CurrentControlSet\Services\MkSmb\Parameters" /v SMB1 /t REG_DWORD /d 0 /f' > $null 2>&1
    if (Get-Command -Name Disable-WindowsOptionalFeature -ErrorAction SilentlyContinue) {
        Try { Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart -ErrorAction SilentlyContinue } catch {}
    }
} -Description "Disable SMBv1 (best-effort)"

# --- Apply core registry/network hardening entries from checklist ---
Invoke-Step -Action { cmd.exe /c 'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v restrictanonymous /t REG_DWORD /d 1 /f' } -Description "Set restrictanonymous=1"
Invoke-Step -Action { cmd.exe /c 'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v restrictanonymoussam /t REG_DWORD /d 1 /f' } -Description "Set restrictanonymoussam=1"
Invoke-Step -Action { cmd.exe /c 'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v everyoneincludesanonymous /t REG_DWORD /d 0 /f' } -Description "Set everyoneincludesanonymous=0"
Invoke-Step -Action { cmd.exe /c 'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v lmcompatibilitylevel /t REG_DWORD /d 5 /f' } -Description "Set lmcompatibilitylevel=5"
Invoke-Step -Action { cmd.exe /c 'reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v EnablePlainTextPassword /t REG_DWORD /d 0 /f' } -Description "Disable plaintext passwords"

# --- Disable Remote Desktop if not SafeMode (user requested 'no inbound') ---
if (-not $SafeMode) {
    Invoke-Step -Action { cmd.exe /c 'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f' } -Description "Disable Remote Desktop (fDenyTSConnections=1)"
} else {
    Write-Log "SafeMode: skipping RDP disable"
}

# --- Apply local security policy via secedit (password & lockout - conservative) ---
$inf = @"
[Version]
signature=`"$CHICAGO$`"
Revision=1

[System Access]
MinimumPasswordLength = 12
MaximumPasswordAge = 90
MinimumPasswordAge = 1
PasswordComplexity = 1
PasswordHistorySize = 24
LockoutBadCount = 10
ResetLockoutCount = 15
LockoutDuration = 15
RequireLogonToChangePassword = 1
"@
$tempInf = Join-Path $env:TEMP ("hardening_defender_$Timestamp.inf")
if (-not $WhatIf) { $inf | Out-File -FilePath $tempInf -Encoding ASCII -Force }
Invoke-Step -Action { secedit /configure /db "secedit_defender_$Timestamp.sdb" /cfg $tempInf /areas SECURITYPOLICY > $null 2>&1 } -Description "Apply local security policy INF (password & lockout)" -AllowFailure

# --- Ensure Defender is active, remove leftover Malwarebytes parts, update, scan ---
Ensure-DefenderActive

# --- Verification summary (key items) ---
$report = [ordered]@{}
try {
    $fwok = $true
    foreach ($p in @("Domain","Private","Public")) {
        $cfg = Get-NetFirewallProfile -Profile $p -ErrorAction SilentlyContinue
        if (-not ($cfg -and $cfg.Enabled -and $cfg.DefaultInboundAction -eq 'Block')) { $fwok = $false }
    }
    $report.Firewall = $fwok
} catch { $report.Firewall = $false }
try { $report.UAC = ((Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name EnableLUA -ErrorAction SilentlyContinue).EnableLUA -eq 1) } catch { $report.UAC = $false }
try { $report.RDPDisabled = ((Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name fDenyTSConnections -ErrorAction SilentlyContinue).fDenyTSConnections -eq 1) } catch { $report.RDPDisabled = $false }
try {
    $mp = Get-MpComputerStatus -ErrorAction SilentlyContinue
    if ($mp) {
        $report.Defender_AntivirusEnabled = $mp.AntivirusEnabled
        $report.Defender_RealTime = $mp.RealTimeProtectionEnabled
        $report.Defender_AMService = $mp.AMServiceEnabled
    } else {
        $report.Defender_AntivirusEnabled = $null
        $report.Defender_RealTime = $null
        $report.Defender_AMService = $null
    }
} catch { $report.Defender_AntivirusEnabled = $null; $report.Defender_RealTime = $null; $report.Defender_AMService = $null }

$report | ConvertTo-Json -Depth 5 | Out-File -FilePath $VerifyFile -Encoding UTF8
Write-Log ("Verification saved to {0}" -f $VerifyFile)
foreach ($k in $report.Keys) { Write-Log ("{0,-30} : {1}" -f $k, $report[$k]) }

# --- Create restore helper script (imports .reg backups and launches System Restore UI) ---
$restoreScriptPath = Join-Path $LogDir "Hardening-Restore-Defender-$Timestamp.ps1"
$restoreScriptContent = @'
# Hardening restore helper (auto-generated)
$RegBackupDir = "{REGDIR}"
Write-Host "Importing registry backups from $RegBackupDir..."
foreach ($f in Get-ChildItem -Path $RegBackupDir -Filter *.reg -ErrorAction SilentlyContinue) {
    try {
        Write-Host "Importing $($f.Name)"
        cmd.exe /c "reg import `"$($f.FullName)`"" > $null 2>&1
        Write-Host "Imported $($f.Name)"
    } catch {
        Write-Host "Failed to import $($f.FullName) : $_"
    }
}
Write-Host "Launching System Restore UI (rstrui.exe). Choose Pre-Hardening restore point if present."
Start-Process -FilePath "rstrui.exe"
'@
$restoreScriptContent = $restoreScriptContent -replace "{REGDIR}", ($RegBackupDir -replace '\\','\\')
$restoreScriptContent | Out-File -FilePath $restoreScriptPath -Encoding ASCII -Force
Write-Log ("Wrote restore helper to {0}" -f $restoreScriptPath)

# --- Auto reboot if requested (default) ---
if ($AutoReboot) {
    if ($WhatIf) {
        Write-Log "WhatIf: would reboot now (AutoReboot enabled)."
    } else {
        Write-Log "AutoReboot enabled. Rebooting in 30 seconds to apply changes..."
        Start-Sleep -Seconds 30
        Write-Log "Restarting now."
        Restart-Computer -Force
    }
} else {
    Write-Log "AutoReboot is disabled. Please reboot to apply certain changes (recommended)."
}

Write-Log "Hardening run finished. Log: $LogFile ; Registry backups: $RegBackupDir ; Restore helper: $restoreScriptPath ; Verification: $VerifyFile"
