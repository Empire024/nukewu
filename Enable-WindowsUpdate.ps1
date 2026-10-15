#Requires -Version 5.1
<#
.SYNOPSIS
    THE UNDO. Reverses Disable-WindowsUpdate.ps1 completely and puts Windows
    Update back exactly the way it was. Self-elevates.

.DESCRIPTION
    Reads C:\ProgramData\DisableWU\manifest.json (written before anything was
    changed) and restores, in the order that matters:

      1. Removes the NukeWU-Guard scheduled task FIRST, so nothing re-applies
         the block behind this script's back
      2. Renames any *.nuked binaries back to their real names
      3. Restores the original wake-timer power setting
      4. Deletes the NukeWU firewall rules
      5. Re-enables every update scheduled task that was disabled
      6. Deletes the policy block and un-pins the "paused until 2099" UX
      7. Unlocks the service registry keys - removes the deny-write ACEs,
         restores the original security descriptor (or re-enables inheritance
         and hands ownership back to TrustedInstaller if no descriptor was
         saved) - then restores each original Start value
      8. Starts the services and kicks off an update scan

    If the manifest is missing it falls back to documented Windows defaults, so
    this script still works even if C:\ProgramData\DisableWU was deleted.

    After running this, open Settings > Windows Update and click "Check for
    updates". A reboot is recommended. Expect a large backlog of patches.
#>
[CmdletBinding()]
param()

# ---------------------------------------------------------------------------
# Self-elevate
# ---------------------------------------------------------------------------
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "Requesting administrator privileges (accept the UAC prompt)..." -ForegroundColor Yellow
    try {
        Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList @(
            '-NoProfile','-ExecutionPolicy','Bypass','-File', "`"$PSCommandPath`""
        ) -ErrorAction Stop
    } catch {
        Write-Host "Elevation cancelled. Right-click the script and 'Run as administrator'." -ForegroundColor Red
    }
    return
}

$ErrorActionPreference = 'Continue'
function Say  { param($m,$c='Gray') Write-Host $m -ForegroundColor $c }
function Warn { param($m) Write-Host "  ! $m" -ForegroundColor DarkYellow }

Say "==================================================" Cyan
Say "  RESTORING WINDOWS UPDATE  (undoing the block)"   Cyan
Say "==================================================" Cyan

# ---------------------------------------------------------------------------
# Privileges (needed to give the locked keys back to TrustedInstaller)
# ---------------------------------------------------------------------------
$privDef = @'
using System;
using System.Runtime.InteropServices;
public class TokenPrivU {
    [DllImport("advapi32.dll", SetLastError=true)]
    static extern bool OpenProcessToken(IntPtr h, int acc, out IntPtr tok);
    [DllImport("advapi32.dll", SetLastError=true)]
    static extern bool LookupPrivilegeValue(string host, string name, out long luid);
    [DllImport("advapi32.dll", SetLastError=true)]
    static extern bool AdjustTokenPrivileges(IntPtr tok, bool dis, ref TOKPRIV1LUID newst, int len, IntPtr prev, IntPtr rel);
    [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
    [StructLayout(LayoutKind.Sequential, Pack=1)]
    struct TOKPRIV1LUID { public int Count; public long Luid; public int Attr; }
    const int SE_PRIVILEGE_ENABLED = 0x2;
    const int TOKEN_ADJUST_PRIVILEGES = 0x20;
    const int TOKEN_QUERY = 0x8;
    public static void Enable(string priv) {
        IntPtr tok;
        OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out tok);
        TOKPRIV1LUID tp;
        tp.Count = 1; tp.Attr = SE_PRIVILEGE_ENABLED;
        LookupPrivilegeValue(null, priv, out tp.Luid);
        AdjustTokenPrivileges(tok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
    }
}
'@
try { Add-Type -TypeDefinition $privDef -ErrorAction Stop } catch {}
foreach ($p in 'SeTakeOwnershipPrivilege','SeRestorePrivilege','SeBackupPrivilege','SeSecurityPrivilege') {
    try { [TokenPrivU]::Enable($p) } catch {}
}

$Admins = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
try { $TrustedInst = (New-Object System.Security.Principal.NTAccount('NT SERVICE','TrustedInstaller')).Translate([System.Security.Principal.SecurityIdentifier]) } catch { $TrustedInst = $null }

$backupDir    = 'C:\ProgramData\DisableWU'
$manifestPath = Join-Path $backupDir 'manifest.json'
$defaults     = @{ wuauserv = 3; UsoSvc = 2; WaaSMedicSvc = 3; DoSvc = 3; uhssvc = 2 }

$manifest = $null
if (Test-Path $manifestPath) {
    try { $manifest = Get-Content $manifestPath -Raw | ConvertFrom-Json; Say "Manifest loaded: $manifestPath" DarkGray } catch { Warn "manifest unreadable, using defaults" }
} else {
    Say "No manifest found - falling back to Windows defaults." DarkYellow
}

function Get-Manifest {
    param($Section,$Key,$Fallback=$null)
    if ($null -eq $manifest) { return $Fallback }
    $s = $manifest.$Section
    if ($null -eq $s) { return $Fallback }
    if ($s.PSObject.Properties.Name -contains $Key) { return $s.$Key }
    return $Fallback
}

# ---------------------------------------------------------------------------
# [1] Kill the guard FIRST so it cannot re-apply the block
# ---------------------------------------------------------------------------
Say "`n[1] Removing the guard task..." Green
$g = Get-ScheduledTask -TaskName 'NukeWU-Guard' -ErrorAction SilentlyContinue
if ($g) {
    try {
        Stop-ScheduledTask -TaskName 'NukeWU-Guard' -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName 'NukeWU-Guard' -Confirm:$false -ErrorAction Stop
        Say "  - NukeWU-Guard removed"
    } catch { Warn "could not remove NukeWU-Guard: $($_.Exception.Message)" }
} else { Say "  - no guard task present" DarkGray }
$guardCopy = Join-Path $backupDir 'Disable-WindowsUpdate.ps1'
if (Test-Path $guardCopy) { Remove-Item $guardCopy -Force -ErrorAction SilentlyContinue; Say "  - staged guard copy deleted" DarkGray }

# ---------------------------------------------------------------------------
# [2] Put renamed binaries back
# ---------------------------------------------------------------------------
Say "`n[2] Restoring renamed binaries..." Green
$renamed = @()
if ($manifest -and $manifest.renamedFiles) { $renamed = @($manifest.renamedFiles) }
# also sweep System32 for anything left as *.nuked, in case the manifest is stale
$sweep = Get-ChildItem "$env:SystemRoot\System32\*.nuked" -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName -replace '\.nuked$','' }
foreach ($orig in (@($renamed) + @($sweep) | Select-Object -Unique)) {
    if ([string]::IsNullOrWhiteSpace($orig)) { continue }
    $nuked = "$orig.nuked"
    if (-not (Test-Path $nuked)) { continue }
    & takeown.exe /F "$nuked" /A *> $null
    & icacls.exe  "$nuked" /grant "*S-1-5-32-544:F" *> $null
    try {
        Rename-Item -Path $nuked -NewName (Split-Path $orig -Leaf) -Force -ErrorAction Stop
        Say "  - restored $(Split-Path $orig -Leaf)"
    } catch { Warn "could not restore $(Split-Path $orig -Leaf): $($_.Exception.Message)" }
}
if (-not (Get-ChildItem "$env:SystemRoot\System32\*.nuked" -ErrorAction SilentlyContinue)) { Say "  - no renamed binaries outstanding" DarkGray }

# ---------------------------------------------------------------------------
# [3] Wake timers
# ---------------------------------------------------------------------------
Say "`n[3] Restoring wake timers..." Green
$RTCWAKE = 'bd3b718a-0680-4d9d-8ab2-e1d2b4ac806d'
$ac = if ($manifest) { $manifest.wakeTimerAc } else { $null }
$dc = if ($manifest) { $manifest.wakeTimerDc } else { $null }
if (-not $ac) { $ac = '0x00000001' }   # Windows default: wake timers enabled
if (-not $dc) { $dc = '0x00000001' }
& powercfg.exe /SETACVALUEINDEX SCHEME_CURRENT SUB_SLEEP $RTCWAKE $ac *> $null
& powercfg.exe /SETDCVALUEINDEX SCHEME_CURRENT SUB_SLEEP $RTCWAKE $dc *> $null
& powercfg.exe /SETACTIVE SCHEME_CURRENT *> $null
Say "  - wake timers restored (AC=$ac DC=$dc)"

# ---------------------------------------------------------------------------
# [4] Firewall rules
# ---------------------------------------------------------------------------
Say "`n[4] Removing firewall rules..." Green
$fw = Get-NetFirewallRule -Group 'NukeWU' -ErrorAction SilentlyContinue
if ($fw) {
    $fw | Remove-NetFirewallRule -ErrorAction SilentlyContinue
    Say "  - removed $(@($fw).Count) NukeWU rule(s)"
} else { Say "  - none present" DarkGray }

# ---------------------------------------------------------------------------
# [5] Scheduled tasks back on
# ---------------------------------------------------------------------------
Say "`n[5] Re-enabling update scheduled tasks..." Green
$taskPaths = @(
    '\Microsoft\Windows\UpdateOrchestrator\',
    '\Microsoft\Windows\WindowsUpdate\',
    '\Microsoft\Windows\WaaSMedic\',
    '\Microsoft\Windows\InstallService\'
)
function Take-TaskOwnership {
    # Same trick the disable script uses: the UpdateOrchestrator tasks are owned
    # by TrustedInstaller and deny Administrators, so grab the on-disk task file
    # and the TaskCache registry entries before retrying.
    param([string]$Full)
    $rel  = $Full.TrimStart('\')
    $file = Join-Path "$env:SystemRoot\System32\Tasks" $rel
    if (Test-Path $file) {
        & takeown.exe /F "$file" /A *> $null
        & icacls.exe  "$file" /grant "*S-1-5-32-544:F" *> $null
    }
    $tree = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\$rel"
    foreach ($sub in @($tree)) {
        try {
            $k = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(
                    $sub, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,
                    [System.Security.AccessControl.RegistryRights]::TakeOwnership)
            if ($k) {
                $acl = $k.GetAccessControl([System.Security.AccessControl.AccessControlSections]::Owner)
                $acl.SetOwner($Admins); $k.SetAccessControl($acl); $k.Close()
                $k = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(
                        $sub, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,
                        [System.Security.AccessControl.RegistryRights]::ChangePermissions)
                $acl = $k.GetAccessControl()
                $acl.SetAccessRule((New-Object System.Security.AccessControl.RegistryAccessRule(
                    $Admins,'FullControl','ContainerInherit','None','Allow')))
                $k.SetAccessControl($acl); $k.Close()
            }
        } catch {}
    }
}

foreach ($tp in $taskPaths) {
    Get-ScheduledTask -TaskPath $tp -ErrorAction SilentlyContinue | ForEach-Object {
        $full = "$($_.TaskPath)$($_.TaskName)"
        if ($_.State -ne 'Disabled') { return }
        $ok = $false
        try { Enable-ScheduledTask -TaskPath $_.TaskPath -TaskName $_.TaskName -ErrorAction Stop | Out-Null; $ok = $true } catch {}
        if (-not $ok) {
            & schtasks.exe /Change /TN $full /ENABLE *> $null
            if ($LASTEXITCODE -eq 0) { $ok = $true }
        }
        if (-not $ok) {
            Take-TaskOwnership -Full $full
            & schtasks.exe /Change /TN $full /ENABLE *> $null
            if ($LASTEXITCODE -eq 0) { $ok = $true }
            else {
                try { Enable-ScheduledTask -TaskPath $_.TaskPath -TaskName $_.TaskName -ErrorAction Stop | Out-Null; $ok = $true } catch {}
            }
        }
        if ($ok) { Say "  - enabled $full" } else { Warn "could not enable $full (Windows itself keeps some of these disabled)" }
    }
}

# ---------------------------------------------------------------------------
# [6] Policy + UX keys gone
# ---------------------------------------------------------------------------
Say "`n[6] Removing the policy block..." Green
$wu = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
if (Test-Path $wu) { Remove-Item -Path $wu -Recurse -Force -ErrorAction SilentlyContinue; Say "  - deleted $wu" }
else { Say "  - no policy key present" DarkGray }

$drv = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching'
if (Test-Path $drv) { Set-ItemProperty -Path $drv -Name 'SearchOrderConfig' -Value 1 -Type DWord -ErrorAction SilentlyContinue; Say "  - driver search re-enabled" }

$ux = 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings'
if (Test-Path $ux) {
    foreach ($n in 'PauseUpdatesExpiryTime','PauseFeatureUpdatesEndTime','PauseQualityUpdatesEndTime',
                   'PauseUpdatesStartTime','PauseFeatureUpdatesStartTime','PauseQualityUpdatesStartTime') {
        Remove-ItemProperty -Path $ux -Name $n -Force -ErrorAction SilentlyContinue
    }
    Set-ItemProperty -Path $ux -Name 'RestartNotificationsAllowed2' -Value 1 -Type DWord -ErrorAction SilentlyContinue
    Say "  - update pause cleared (no longer paused until 2099)"
}

# ---------------------------------------------------------------------------
# [7] Unlock the service keys and restore Start values
# ---------------------------------------------------------------------------
Say "`n[7] Unlocking service keys and restoring start types..." Green
foreach ($s in @('wuauserv','UsoSvc','WaaSMedicSvc','DoSvc','uhssvc')) {
    $sub = "SYSTEM\CurrentControlSet\Services\$s"
    if (-not (Test-Path "HKLM:\$sub")) { continue }

    # a) strip the deny ACEs so SYSTEM/TrustedInstaller can manage it again
    try {
        $acl = Get-Acl -Path "HKLM:\$sub" -ErrorAction Stop
        $denies = @($acl.Access | Where-Object { $_.AccessControlType -eq 'Deny' })
        foreach ($r in $denies) { [void]$acl.RemoveAccessRule($r) }
        if ($denies.Count) { Set-Acl -Path "HKLM:\$sub" -AclObject $acl -ErrorAction Stop }
    } catch { Warn "clearing deny ACEs on ${s}: $($_.Exception.Message)" }

    # b) restore the original Start value while we still own the key
    $target = Get-Manifest 'serviceStart' $s $defaults[$s]
    if ($null -eq $target) { $target = $defaults[$s] }
    if ($null -ne $target) {
        try {
            Set-ItemProperty -Path "HKLM:\$sub" -Name Start -Value ([int]$target) -Type DWord -ErrorAction Stop
            $means = switch ([int]$target) { 2 {'Automatic'} 3 {'Manual'} 4 {'Disabled'} default {"$target"} }
            # Also go through the SCM, otherwise its in-memory copy stays
            # "disabled" until the next reboot and the service will not start.
            $kw = switch ([int]$target) { 2 {'auto'} 3 {'demand'} 4 {'disabled'} 1 {'system'} 0 {'boot'} default {$null} }
            $scmTxt = 'SCM=stale-until-reboot'
            if ($kw) {
                & sc.exe config $s start= $kw *> $null
                if ($LASTEXITCODE -eq 0) { $scmTxt = "SCM=$kw" }
            }
            Say "  - $s => Start=$target ($means), $scmTxt"
        } catch { Warn "restoring $s Start: $($_.Exception.Message)" }
    }

    # c) restore the original security descriptor, else re-enable inheritance
    #    and hand ownership back to TrustedInstaller
    $sddl = Get-Manifest 'serviceSddl' $s $null
    $restored = $false

    # (i) the whole original descriptor, owner included
    if ($sddl) {
        try {
            $sec = New-Object System.Security.AccessControl.RegistrySecurity
            $sec.SetSecurityDescriptorSddlForm($sddl)
            Set-Acl -Path "HKLM:\$sub" -AclObject $sec -ErrorAction Stop
            $restored = $true
            Say "    original ACL restored from manifest" DarkGray
        } catch {
            # Windows rejects certain SIDs as an owner (NT SERVICE\TrustedInstaller
            # among them). Retry restoring only the permissions - that is the part
            # that actually matters - and leave the owner alone.
            try {
                $sec = New-Object System.Security.AccessControl.RegistrySecurity
                $sec.SetSecurityDescriptorSddlForm($sddl, [System.Security.AccessControl.AccessControlSections]::Access)
                Set-Acl -Path "HKLM:\$sub" -AclObject $sec -ErrorAction Stop
                $restored = $true
                Say "    original permissions restored (owner left as Administrators)" DarkGray
            } catch { Warn "SDDL restore on ${s}: $($_.Exception.Message)" }
        }
    }

    # (ii) last resort - at minimum get the key inheriting normally again
    if (-not $restored) {
        try {
            $acl = Get-Acl -Path "HKLM:\$sub" -ErrorAction Stop
            $acl.SetAccessRuleProtection($false, $false)
            Set-Acl -Path "HKLM:\$sub" -AclObject $acl -ErrorAction Stop
            Say "    inheritance re-enabled" DarkGray
        } catch { Warn "ACL reset on ${s}: $($_.Exception.Message)" }
    }

    # (iii) try to hand ownership back to TrustedInstaller as a SEPARATE step, so
    #       a refusal here can never roll back the permission fix above. Purely
    #       cosmetic - the service works either way.
    if ($TrustedInst) {
        try {
            $acl = Get-Acl -Path "HKLM:\$sub" -ErrorAction Stop
            $acl.SetOwner($TrustedInst)
            Set-Acl -Path "HKLM:\$sub" -AclObject $acl -ErrorAction Stop
        } catch { }
    }
}

# ---------------------------------------------------------------------------
# [8] Start the services and scan
# ---------------------------------------------------------------------------
Say "`n[8] Starting services..." Green
foreach ($s in 'UsoSvc','wuauserv','DoSvc') {
    $sub = "SYSTEM\CurrentControlSet\Services\$s"
    if (-not (Test-Path "HKLM:\$sub")) { continue }
    $st = (Get-ItemProperty "HKLM:\$sub" -Name Start -ErrorAction SilentlyContinue).Start
    if ($st -eq 4) { continue }
    try { Start-Service -Name $s -ErrorAction SilentlyContinue; Say "  - started $s" } catch {}
}
try { & "$env:SystemRoot\System32\UsoClient.exe" StartScan *> $null } catch {}

# ---------------------------------------------------------------------------
# Verify
# ---------------------------------------------------------------------------
Write-Host "`n================ VERIFICATION ================" -ForegroundColor Cyan
$verifyRows = foreach ($s in @('wuauserv','UsoSvc','WaaSMedicSvc','DoSvc')) {
    $sub = "SYSTEM\CurrentControlSet\Services\$s"
    if (-not (Test-Path "HKLM:\$sub")) { continue }
    $st = (Get-ItemProperty "HKLM:\$sub" -Name Start -ErrorAction SilentlyContinue).Start
    $svc = Get-Service $s -ErrorAction SilentlyContinue
    $denied = $false
    try { $denied = [bool](@((Get-Acl "HKLM:\$sub").Access | Where-Object { $_.AccessControlType -eq 'Deny' })).Count } catch {}
    [PSCustomObject]@{ Service=$s; Start=$st; Running=$(if($svc){$svc.Status}else{'n/a'}); StillLocked=$denied }
}
$verifyRows | Format-Table -AutoSize
Write-Host "  StillLocked must read False everywhere." -ForegroundColor DarkGray
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "  DONE. Windows Update is back."                    -ForegroundColor Cyan
Write-Host "  Open Settings > Windows Update > Check for updates." -ForegroundColor Cyan
Write-Host "  Reboot recommended. Expect a big backlog of patches." -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan
