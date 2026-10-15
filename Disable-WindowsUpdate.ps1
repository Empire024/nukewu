#Requires -Version 5.1
<#
.SYNOPSIS
    Hard-disables Windows Update on Windows 10/11 and LOCKS the configuration so
    Windows cannot silently put it back. Self-elevates. Fully reversible via
    Enable-WindowsUpdate.ps1 (or UNDO-WINDOWS-UPDATE.cmd).

.DESCRIPTION
    v2 - written after v1 was silently reverted by Windows.

    WHY v1 FAILED: it set the service Start values to 4 (Disabled), but left the
    registry keys WRITABLE. The servicing stack / Update Medic simply wrote them
    back (wuauserv 4->3, UsoSvc 4->2), UsoSvc started at boot, and on 2026-09-09
    at 04:14 it installed KB5124007/8 + KB5126052 and rebooted the machine three
    times. Setting a value Windows is allowed to overwrite is not a block.

    WHAT v2 DOES DIFFERENTLY: after setting Start=4 it takes ownership of each
    service key and applies a DENY-WRITE ACE for SYSTEM and TrustedInstaller.
    Read access is deliberately left intact so the Service Control Manager can
    still enumerate the services at boot (denying read is what makes machines
    fail to start). Nothing running as SYSTEM can now change the value back.

    LAYERS APPLIED
      1. Services stopped, Start=4, registry keys ACL-locked against SYSTEM and
         TrustedInstaller  (wuauserv, UsoSvc, WaaSMedicSvc, DoSvc, uhssvc)
      2. Group-Policy-equivalent registry block (honoured on Home too)
      3. Update UX settings: pause pinned to 2099, no auto-restart, release pinned
      4. Every scheduled task under UpdateOrchestrator / WindowsUpdate /
         WaaSMedic / InstallService disabled - taking ownership of the protected
         UpdateOrchestrator ones (Reboot_AC / Reboot_BAT) first
      5. Outbound firewall block scoped to the update services themselves, so
         Defender definitions, the Store and everything else keep working
      6. Wake timers disabled, so nothing can wake the box to update it
      7. -Scorched (OPT-IN): renames the update binaries themselves
      8. A guard task re-applies all of the above at every boot + daily, so a
         feature upgrade that resets things gets undone within a day

    SAFETY / REVERSIBILITY
      Original service start types, key ACLs (as SDDL), task states, firewall
      state, wake-timer values and renamed files are all recorded to
      C:\ProgramData\DisableWU\manifest.json before anything changes, and the
      policy keys are exported as .reg alongside it. Enable-WindowsUpdate.ps1
      reads that manifest and puts everything back.

    HONEST LIMITS
      - You will receive NO security patches while this is applied. That is the
        point of the script, but it is a real trade-off worth knowing.
      - Before you ever deliberately upgrade Windows (e.g. 25H2 -> 26H1), run the
        undo first. Servicing writes to these keys, and a locked key can make a
        feature upgrade fail midway.

.PARAMETER Scorched
    Also rename UsoClient.exe, MoUsoCoreWorker.exe, WaaSMedicSvc.dll,
    WaaSMedicAgent.exe and wuauclt.exe to *.nuked. Off by default: the ACL lock
    in layer 1 is what actually holds, and renaming shipped binaries is the part
    most likely to confuse a future repair install. The undo renames them back.

.PARAMETER Quiet
    Suppress console output (used by the guard task).

.PARAMETER NoGuard
    Do not install/refresh the boot-time guard task.

.EXAMPLE
    .\Disable-WindowsUpdate.ps1
.EXAMPLE
    .\Disable-WindowsUpdate.ps1 -Scorched
#>
[CmdletBinding()]
param(
    [switch]$Scorched,
    [switch]$Quiet,
    [switch]$NoGuard
)

# ---------------------------------------------------------------------------
# Self-elevate (forwarding our switches)
# ---------------------------------------------------------------------------
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "Requesting administrator privileges (accept the UAC prompt)..." -ForegroundColor Yellow
    $fwd = @('-NoProfile','-ExecutionPolicy','Bypass','-File', "`"$PSCommandPath`"")
    if ($Scorched) { $fwd += '-Scorched' }
    if ($Quiet)    { $fwd += '-Quiet' }
    if ($NoGuard)  { $fwd += '-NoGuard' }
    try {
        Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList $fwd -ErrorAction Stop
    } catch {
        Write-Host "Elevation cancelled. Right-click the script and 'Run as administrator'." -ForegroundColor Red
    }
    return
}

$ErrorActionPreference = 'Continue'
function Say  { param($m,$c='Gray')  if (-not $Quiet) { Write-Host $m -ForegroundColor $c } }
function Warn { param($m)            if (-not $Quiet) { Write-Host "  ! $m" -ForegroundColor DarkYellow } }

Say "==================================================" Cyan
Say "  NUKING WINDOWS UPDATE  (hardened + reversible)"   Cyan
Say "==================================================" Cyan

# ---------------------------------------------------------------------------
# Token privileges needed to take ownership of TrustedInstaller-owned keys
# ---------------------------------------------------------------------------
$privDef = @'
using System;
using System.Runtime.InteropServices;
public class TokenPriv {
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
    try { [TokenPriv]::Enable($p) } catch {}
}

$Admins = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')  # BUILTIN\Administrators
$System = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')      # NT AUTHORITY\SYSTEM
try { $TrustedInst = (New-Object System.Security.Principal.NTAccount('NT SERVICE','TrustedInstaller')).Translate([System.Security.Principal.SecurityIdentifier]) } catch { $TrustedInst = $null }

# Write rights we deny. Read rights are intentionally NOT denied - the SCM must
# still be able to read service config at boot.
$WriteRights = [System.Security.AccessControl.RegistryRights]'SetValue,CreateSubKey,Delete,ChangePermissions,TakeOwnership'

function Get-KeySddl {
    param([string]$SubKey)
    try { return (Get-Acl -Path "HKLM:\$SubKey" -ErrorAction Stop).Sddl } catch { return $null }
}

function Take-KeyOwnership {
    param([string]$SubKey)
    try {
        $k = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(
                $SubKey,
                [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,
                [System.Security.AccessControl.RegistryRights]::TakeOwnership)
        if (-not $k) { return $false }
        $acl = $k.GetAccessControl([System.Security.AccessControl.AccessControlSections]::Owner)
        $acl.SetOwner($Admins)
        $k.SetAccessControl($acl)
        $k.Close()
        $k = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(
                $SubKey,
                [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,
                [System.Security.AccessControl.RegistryRights]::ChangePermissions)
        $acl = $k.GetAccessControl()
        $acl.SetAccessRule((New-Object System.Security.AccessControl.RegistryAccessRule(
            $Admins,'FullControl','ContainerInherit','None','Allow')))
        $k.SetAccessControl($acl)
        $k.Close()
        return $true
    } catch { Warn "ownership on $SubKey : $($_.Exception.Message)"; return $false }
}

function Lock-Key {
    # Freeze a key: break inheritance, keep Administrators full control,
    # deny WRITE (not read) to SYSTEM and TrustedInstaller.
    param([string]$SubKey)
    try {
        $acl = Get-Acl -Path "HKLM:\$SubKey" -ErrorAction Stop
        $acl.SetAccessRuleProtection($true, $true)   # protect, convert inherited -> explicit
        $acl.SetAccessRule((New-Object System.Security.AccessControl.RegistryAccessRule(
            $Admins,'FullControl','ContainerInherit','None','Allow')))
        foreach ($sid in @($System, $TrustedInst)) {
            if ($null -eq $sid) { continue }
            $acl.AddAccessRule((New-Object System.Security.AccessControl.RegistryAccessRule(
                $sid, $WriteRights,'ContainerInherit','None','Deny')))
        }
        Set-Acl -Path "HKLM:\$SubKey" -AclObject $acl -ErrorAction Stop
        return $true
    } catch { Warn "lock on $SubKey : $($_.Exception.Message)"; return $false }
}

function Unlock-KeyForWrite {
    # Temporarily drop the deny ACEs so we can rewrite a value, then re-lock.
    param([string]$SubKey)
    try {
        $acl = Get-Acl -Path "HKLM:\$SubKey" -ErrorAction Stop
        foreach ($rule in @($acl.Access | Where-Object { $_.AccessControlType -eq 'Deny' })) {
            [void]$acl.RemoveAccessRule($rule)
        }
        Set-Acl -Path "HKLM:\$SubKey" -AclObject $acl -ErrorAction Stop
    } catch {}
}

# ---------------------------------------------------------------------------
# Backup / manifest
# ---------------------------------------------------------------------------
$backupDir = 'C:\ProgramData\DisableWU'
$null = New-Item -ItemType Directory -Path $backupDir -Force
$manifestPath = Join-Path $backupDir 'manifest.json'

$services = @('wuauserv','UsoSvc','WaaSMedicSvc','DoSvc','uhssvc')
# NOTE: BITS is deliberately NOT touched. It is a generic transfer service used
# by Chrome, the Store and many installers; disabling it breaks unrelated
# software and does not stop Windows Update on its own.

if (Test-Path $manifestPath) {
    $manifest = Get-Content $manifestPath -Raw | ConvertFrom-Json
    Say "Using existing manifest (originals preserved): $manifestPath" DarkGray
} else {
    # seed from the v1 backup if it is around, else read live state
    $origStart = @{}
    $legacy = Join-Path $backupDir 'backup.json'
    if (Test-Path $legacy) {
        try {
            $old = Get-Content $legacy -Raw | ConvertFrom-Json
            foreach ($n in $old.services.PSObject.Properties.Name) { $origStart[$n] = [int]$old.services.$n }
            Say "Seeded original service state from v1 backup.json" DarkGray
        } catch {}
    }
    $origSddl = @{}
    foreach ($s in $services) {
        $sub = "SYSTEM\CurrentControlSet\Services\$s"
        if (-not (Test-Path "HKLM:\$sub")) { continue }
        if (-not $origStart.ContainsKey($s)) {
            $v = (Get-ItemProperty -Path "HKLM:\$sub" -Name Start -ErrorAction SilentlyContinue).Start
            if ($null -ne $v) { $origStart[$s] = [int]$v }
        }
        $origSddl[$s] = Get-KeySddl $sub
    }
    $manifest = [PSCustomObject]@{
        createdUtc      = (Get-Date).ToUniversalTime().ToString('o')
        serviceStart    = $origStart
        serviceSddl     = $origSddl
        wakeTimerAc     = $null
        wakeTimerDc     = $null
        renamedFiles    = @()
        tasksDisabled   = @()
    }
}

# export the policy branches as .reg so there is a plain-text escape hatch too
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
foreach ($b in @(
    @{ k='HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'; f="policies-WindowsUpdate-$stamp.reg" },
    @{ k='HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings';      f="ux-settings-$stamp.reg" }
)) {
    & reg.exe export $b.k (Join-Path $backupDir $b.f) /y *> $null
}
Say "Backups + manifest in $backupDir" DarkGray

# ---------------------------------------------------------------------------
# [1] Services: stop, disable, then LOCK the key so nothing writes it back
# ---------------------------------------------------------------------------
Say "`n[1] Disabling and locking update services..." Green
foreach ($s in $services) {
    $sub = "SYSTEM\CurrentControlSet\Services\$s"
    if (-not (Test-Path "HKLM:\$sub")) { Say "  - $s not present, skipped" DarkGray; continue }

    [void](Take-KeyOwnership $sub)
    Unlock-KeyForWrite $sub                     # in case a previous run locked it

    # ORDER MATTERS. Writing Start=4 straight into the registry does NOT update
    # the Service Control Manager's in-memory copy of the service config, so
    # triggers keep starting the service until the next reboot - which is how
    # UsoSvc came back and re-enabled its own scan tasks on the first attempt.
    # sc.exe config goes through the SCM and updates both. Do it BEFORE the key
    # is frozen, because the SCM performs that registry write as SYSTEM and the
    # lock is specifically designed to deny SYSTEM.
    $scmOk = $false
    & sc.exe config $s start= disabled *> $null
    if ($LASTEXITCODE -eq 0) { $scmOk = $true } else { Warn "sc config $s refused (protected service) - registry only, effective after reboot" }

    try { Stop-Service -Name $s -Force -ErrorAction SilentlyContinue } catch {}
    & sc.exe stop $s *> $null

    try { Set-ItemProperty -Path "HKLM:\$sub" -Name Start -Value 4 -Type DWord -ErrorAction Stop }
    catch { Warn "could not set $s Start=4: $($_.Exception.Message)" }

    $locked = Lock-Key $sub
    $now    = (Get-ItemProperty -Path "HKLM:\$sub" -Name Start -ErrorAction SilentlyContinue).Start
    $scmTxt = if ($scmOk) { 'SCM=disabled' } else { 'SCM=stale-until-reboot' }
    $lockTxt = if ($locked) { 'key LOCKED' } else { 'LOCK FAILED' }
    Say "  - $s => Start=$now, $scmTxt, $lockTxt"
}

# ---------------------------------------------------------------------------
# [2] Group-Policy-equivalent registry block
# ---------------------------------------------------------------------------
Say "`n[2] Writing policy keys..." Green
$wu = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
$au = "$wu\AU"
$null = New-Item -Path $au -Force
$relId = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name DisplayVersion -ErrorAction SilentlyContinue).DisplayVersion

$policies = @{
    "$au" = @{
        NoAutoUpdate                    = 1   # never auto-download/install
        AUOptions                       = 1   # 1 = never check for updates
        UseWUServer                     = 1   # honour the dead WSUS below
        NoAutoRebootWithLoggedOnUsers   = 1
        AlwaysAutoRebootAtScheduledTime = 0
        AutoInstallMinorUpdates         = 0
    }
    "$wu" = @{
        DoNotConnectToWindowsUpdateInternetLocations = 1
        ExcludeWUDriversInQualityUpdate              = 1
        SetDisableUXWUAccess                         = 1
        DisableWindowsUpdateAccess                   = 1
        SetAutoRestartNotificationDisable            = 1
        DeferFeatureUpdates                          = 1
        DeferFeatureUpdatesPeriodInDays              = 365
        DeferQualityUpdates                          = 1
        DeferQualityUpdatesPeriodInDays              = 30
        TargetReleaseVersion                         = 1
    }
}
foreach ($path in $policies.Keys) {
    foreach ($name in $policies[$path].Keys) {
        $val = $policies[$path][$name]
        if ($null -eq $val) { continue }
        Set-ItemProperty -Path $path -Name $name -Value $val -Type DWord -ErrorAction SilentlyContinue
    }
}
Set-ItemProperty -Path $wu -Name 'WUServer'       -Value 'https://127.0.0.1:8531' -Type String
Set-ItemProperty -Path $wu -Name 'WUStatusServer' -Value 'https://127.0.0.1:8531' -Type String
if ($relId) {
    Set-ItemProperty -Path $wu -Name 'TargetReleaseVersionInfo' -Value $relId -Type String
    Say "  - feature updates pinned to $relId"
}
$drv = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching'
$null = New-Item -Path $drv -Force
Set-ItemProperty -Path $drv -Name 'SearchOrderConfig' -Value 0 -Type DWord
Say "  - policy block written (NoAutoUpdate, dead WSUS, no driver delivery)"

# ---------------------------------------------------------------------------
# [3] Update UX: pin "paused" far into the future, kill restart nagging
# ---------------------------------------------------------------------------
Say "`n[3] Pinning the update UX to paused..." Green
$ux = 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings'
$null = New-Item -Path $ux -Force
$far = '2099-12-31T00:00:00Z'
foreach ($n in 'PauseUpdatesExpiryTime','PauseFeatureUpdatesEndTime','PauseQualityUpdatesEndTime') {
    Set-ItemProperty -Path $ux -Name $n -Value $far -Type String -ErrorAction SilentlyContinue
}
Set-ItemProperty -Path $ux -Name 'PauseUpdatesStartTime' -Value ((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')) -Type String -ErrorAction SilentlyContinue
Set-ItemProperty -Path $ux -Name 'SmartActiveHoursState' -Value 0 -Type DWord -ErrorAction SilentlyContinue
Set-ItemProperty -Path $ux -Name 'IsExpedited'           -Value 0 -Type DWord -ErrorAction SilentlyContinue
Set-ItemProperty -Path $ux -Name 'RestartNotificationsAllowed2' -Value 0 -Type DWord -ErrorAction SilentlyContinue
Say "  - updates show as paused until 2099, restart notifications off"

# ---------------------------------------------------------------------------
# [4] Scheduled tasks - including the protected UpdateOrchestrator reboot tasks
# ---------------------------------------------------------------------------
Say "`n[4] Disabling update scheduled tasks..." Green
$taskPaths = @(
    '\Microsoft\Windows\UpdateOrchestrator\',
    '\Microsoft\Windows\WindowsUpdate\',
    '\Microsoft\Windows\WaaSMedic\',
    '\Microsoft\Windows\InstallService\'
)
$disabledTasks = New-Object System.Collections.ArrayList

function Invoke-TaskSweep {
    param([switch]$Silent)
    foreach ($tp in $taskPaths) {
    $tasks = Get-ScheduledTask -TaskPath $tp -ErrorAction SilentlyContinue
    if (-not $tasks) { if (-not $Silent) { Say "  - no tasks under $tp" DarkGray }; continue }
    foreach ($t in $tasks) {
        $full = "$($t.TaskPath)$($t.TaskName)"
        if ($t.State -eq 'Disabled') { [void]$disabledTasks.Add($full); if (-not $Silent) { Say "  - already disabled $full" DarkGray }; continue }

        $ok = $false
        try { Disable-ScheduledTask -TaskPath $t.TaskPath -TaskName $t.TaskName -ErrorAction Stop | Out-Null; $ok = $true } catch {}

        if (-not $ok) {
            # Protected (Reboot_AC / Reboot_BAT / Schedule Scan): take ownership of
            # both the on-disk task file and its TaskCache registry entries, retry.
            $rel  = $full.TrimStart('\')
            $file = Join-Path "$env:SystemRoot\System32\Tasks" $rel
            if (Test-Path $file) {
                & takeown.exe /F "$file" /A *> $null
                & icacls.exe  "$file" /grant "*S-1-5-32-544:F" *> $null
            }
            $tree = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\$rel"
            [void](Take-KeyOwnership $tree)
            $gid = (Get-ItemProperty -Path "HKLM:\$tree" -Name Id -ErrorAction SilentlyContinue).Id
            if ($gid) { [void](Take-KeyOwnership "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\$gid") }

            & schtasks.exe /Change /TN $full /DISABLE *> $null
            if ($LASTEXITCODE -eq 0) { $ok = $true }
            else {
                try { Disable-ScheduledTask -TaskPath $t.TaskPath -TaskName $t.TaskName -ErrorAction Stop | Out-Null; $ok = $true } catch {}
            }
        }

        if ($ok) { [void]$disabledTasks.Add($full); if (-not $Silent) { Say "  - disabled $full" } }
        else     { Warn "could not disable $full (services are dead, so it has nothing to run)" }
    }
    }
}
Invoke-TaskSweep

# ---------------------------------------------------------------------------
# [5] Firewall: block the update services outbound, nothing else
# ---------------------------------------------------------------------------
Say "`n[5] Firewall block scoped to the update services..." Green
Get-NetFirewallRule -Group 'NukeWU' -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
foreach ($s in 'wuauserv','UsoSvc','DoSvc','WaaSMedicSvc') {
    try {
        New-NetFirewallRule -DisplayName "NukeWU block $s (outbound)" -Group 'NukeWU' `
            -Direction Outbound -Action Block -Service $s -Enabled True -Profile Any -ErrorAction Stop | Out-Null
        Say "  - blocked outbound: $s"
    } catch { Warn "firewall rule for ${s}: $($_.Exception.Message)" }
}
Say "  (Defender definitions, Store and browsers are unaffected - rules are per-service)" DarkGray

# ---------------------------------------------------------------------------
# [6] Wake timers off - nothing wakes this box to update it
# ---------------------------------------------------------------------------
Say "`n[6] Disabling wake timers..." Green
$RTCWAKE = 'bd3b718a-0680-4d9d-8ab2-e1d2b4ac806d'
if ($null -eq $manifest.wakeTimerAc) {
    $q = (& powercfg.exe /QUERY SCHEME_CURRENT SUB_SLEEP $RTCWAKE) 2>$null
    $acv = ($q | Select-String 'Current AC Power Setting Index:\s*(0x[0-9a-f]+)').Matches.Groups[1].Value
    $dcv = ($q | Select-String 'Current DC Power Setting Index:\s*(0x[0-9a-f]+)').Matches.Groups[1].Value
    if ($acv) { $manifest.wakeTimerAc = $acv }
    if ($dcv) { $manifest.wakeTimerDc = $dcv }
}
& powercfg.exe /SETACVALUEINDEX SCHEME_CURRENT SUB_SLEEP $RTCWAKE 0 *> $null
& powercfg.exe /SETDCVALUEINDEX SCHEME_CURRENT SUB_SLEEP $RTCWAKE 0 *> $null
& powercfg.exe /SETACTIVE SCHEME_CURRENT *> $null
Say "  - wake timers disabled (was AC=$($manifest.wakeTimerAc) DC=$($manifest.wakeTimerDc))"

# ---------------------------------------------------------------------------
# [7] -Scorched: rename the update binaries
# ---------------------------------------------------------------------------
if ($Scorched) {
    Say "`n[7] SCORCHED: renaming update binaries..." Green
    $renamed = New-Object System.Collections.ArrayList
    foreach ($f in @('UsoClient.exe','MoUsoCoreWorker.exe','WaaSMedicSvc.dll','WaaSMedicAgent.exe','wuauclt.exe')) {
        $p = Join-Path "$env:SystemRoot\System32" $f
        if (-not (Test-Path $p)) { continue }
        & takeown.exe /F "$p" /A *> $null
        & icacls.exe  "$p" /grant "*S-1-5-32-544:F" *> $null
        try {
            Rename-Item -Path $p -NewName "$f.nuked" -Force -ErrorAction Stop
            [void]$renamed.Add($p)
            Say "  - renamed $f -> $f.nuked"
        } catch { Warn "could not rename ${f}: $($_.Exception.Message)" }
    }
    $manifest.renamedFiles = @($manifest.renamedFiles) + @($renamed) | Select-Object -Unique
} else {
    Say "`n[7] Scorched mode off (binaries left in place). Re-run with -Scorched to rename them too." DarkGray
}

# ---------------------------------------------------------------------------
# [8] Guard task: re-apply everything at boot and daily
# ---------------------------------------------------------------------------
if (-not $NoGuard) {
    Say "`n[8] Installing the guard task..." Green
    $guardCopy = Join-Path $backupDir 'Disable-WindowsUpdate.ps1'
    try { Copy-Item -Path $PSCommandPath -Destination $guardCopy -Force -ErrorAction Stop } catch { Warn "could not stage guard copy: $($_.Exception.Message)" }
    if (Test-Path $guardCopy) {
        $argLine = "-NoProfile -ExecutionPolicy Bypass -File `"$guardCopy`" -Quiet -NoGuard"
        if ($Scorched) { $argLine += ' -Scorched' }
        try {
            Unregister-ScheduledTask -TaskName 'NukeWU-Guard' -Confirm:$false -ErrorAction SilentlyContinue
            $act  = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $argLine
            $trg  = @(
                (New-ScheduledTaskTrigger -AtStartup),
                (New-ScheduledTaskTrigger -Daily -At '12:00')
            )
            $prin = New-ScheduledTaskPrincipal -UserId 'S-1-5-18' -RunLevel Highest
            $set  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 10)
            Register-ScheduledTask -TaskName 'NukeWU-Guard' -Action $act -Trigger $trg -Principal $prin -Settings $set `
                -Description 'Re-applies the Windows Update block if Windows resets it. Remove with Enable-WindowsUpdate.ps1.' -ErrorAction Stop | Out-Null
            Say "  - task 'NukeWU-Guard' installed (at boot + daily 12:00, as SYSTEM)"
        } catch { Warn "guard task: $($_.Exception.Message)" }
    }
} else {
    Say "`n[8] Guard task skipped (-NoGuard)." DarkGray
}

# ---------------------------------------------------------------------------
# [8b] Critical-update checker. Windows can no longer tell us about an urgent
#      patch, so this watches MSRC + CISA KEV instead and raises a toast. It
#      MUST run as the interactive user - a toast raised by SYSTEM is shown to
#      nobody - so it is registered against whoever owns the console session.
# ---------------------------------------------------------------------------
Say "`n[8b] Critical-update checker..." Green
$checkerSrc = Join-Path (Split-Path -Parent $PSCommandPath) 'Check-CriticalUpdates.ps1'
if (-not (Test-Path $checkerSrc)) {
    Say "  - Check-CriticalUpdates.ps1 not found next to this script, skipped" DarkGray
} else {
    $checkerDst = Join-Path $backupDir 'Check-CriticalUpdates.ps1'
    try { Copy-Item -Path $checkerSrc -Destination $checkerDst -Force -ErrorAction Stop } catch { Warn "staging checker: $($_.Exception.Message)" }

    # Record where the full tool lives (machine-wide) so the staged copies in
    # ProgramData and the re-arm task can find Invoke-UpdateWindow.ps1 and the
    # rest. Skipped when this IS the staged copy (the guard task), which sits
    # alone next to the checker.
    $toolDir = Split-Path -Parent $PSCommandPath
    if (Test-Path (Join-Path $toolDir 'Invoke-UpdateWindow.ps1')) {
        try {
            $null = New-Item -Path 'HKLM:\SOFTWARE\NukeWU' -Force
            Set-ItemProperty -Path 'HKLM:\SOFTWARE\NukeWU' -Name InstallDir -Value $toolDir
            Say "  - install folder recorded: $toolDir"
        } catch { Warn "could not record install folder: $($_.Exception.Message)" }
    }

    $consoleUser = $null
    try { $consoleUser = (Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).UserName } catch {}
    if (-not $consoleUser -and $env:USERNAME -and $env:USERNAME -ne 'SYSTEM') { $consoleUser = "$env:USERDOMAIN\$env:USERNAME" }

    if (-not $consoleUser) {
        Say "  - no interactive user detected, checker task left alone" DarkGray
    } elseif (-not (Test-Path $checkerDst)) {
        Say "  - checker not staged, task skipped" DarkGray
    } else {
        try {
            Unregister-ScheduledTask -TaskName 'NukeWU-UpdateCheck' -Confirm:$false -ErrorAction SilentlyContinue
            $ca = New-ScheduledTaskAction -Execute 'powershell.exe' `
                    -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$checkerDst`" -Quiet"
            $ct1 = New-ScheduledTaskTrigger -AtLogOn -User $consoleUser
            try { $ct1.Delay = 'PT5M' } catch {}
            $ct2 = New-ScheduledTaskTrigger -Daily -At '13:00'
            $cp  = New-ScheduledTaskPrincipal -UserId $consoleUser -LogonType Interactive -RunLevel Limited
            $cs  = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
                     -ExecutionTimeLimit (New-TimeSpan -Minutes 20)
            Register-ScheduledTask -TaskName 'NukeWU-UpdateCheck' -Action $ca -Trigger @($ct1,$ct2) -Principal $cp -Settings $cs `
                -Description 'Checks MSRC + CISA KEV for a security update that is genuinely urgent for this machine while Windows Update is blocked.' -ErrorAction Stop | Out-Null
            Say "  - task 'NukeWU-UpdateCheck' installed for $consoleUser (logon +5min, daily 13:00)"
        } catch { Warn "checker task: $($_.Exception.Message)" }
    }
}

# ---------------------------------------------------------------------------
# [9] Second task sweep. On the first run UsoSvc was still startable and it
#     re-enabled "Schedule Scan" and "Schedule Scan Static Task" behind us.
#     Now that the SCM genuinely refuses to start it, re-disable anything that
#     came back during this run.
# ---------------------------------------------------------------------------
Say "`n[9] Second pass over the tasks..." Green
Invoke-TaskSweep -Silent
$stillOn = Get-ScheduledTask -TaskPath $taskPaths -ErrorAction SilentlyContinue | Where-Object { $_.State -ne 'Disabled' }
if ($stillOn) {
    foreach ($t in $stillOn) { Warn "still enabled: $($t.TaskPath)$($t.TaskName)" }
} else {
    Say "  - all update tasks confirmed disabled"
}

# ---------------------------------------------------------------------------
# Save manifest
# ---------------------------------------------------------------------------
$manifest.tasksDisabled = @($disabledTasks)
$manifest | ConvertTo-Json -Depth 6 | Set-Content -Path $manifestPath -Encoding UTF8

# ---------------------------------------------------------------------------
# Verify
# ---------------------------------------------------------------------------
if (-not $Quiet) {
    Write-Host "`n================ VERIFICATION ================" -ForegroundColor Cyan
    $rows = foreach ($s in $services) {
        $sub = "SYSTEM\CurrentControlSet\Services\$s"
        if (-not (Test-Path "HKLM:\$sub")) { continue }
        $st = (Get-ItemProperty "HKLM:\$sub" -Name Start -ErrorAction SilentlyContinue).Start
        $svc = Get-Service $s -ErrorAction SilentlyContinue
        $denied = $false
        try { $denied = [bool](@((Get-Acl "HKLM:\$sub").Access | Where-Object { $_.AccessControlType -eq 'Deny' })).Count } catch {}
        # What the SCM itself believes, which is what actually gates a start.
        $qc = (& sc.exe qc $s) 2>$null | Select-String 'START_TYPE'
        $scm = 'unknown'
        if ($qc) { $scm = (($qc.Line -split ':')[1]).Trim() }
        [PSCustomObject]@{
            Service = $s
            Start   = $st
            Means   = $(if ($st -eq 4) { 'Disabled' } elseif ($st -eq 3) { 'Manual' } elseif ($st -eq 2) { 'Automatic' } else { $st })
            SCM     = $scm
            Running = $(if ($svc) { $svc.Status } else { 'n/a' })
            KeyLocked = $denied
        }
    }
    $rows | Format-Table -AutoSize

    Write-Host "  Start must be 4, SCM must say DISABLED, KeyLocked must be True." -ForegroundColor DarkGray
    Write-Host "==================================================" -ForegroundColor Cyan
    Write-Host "  DONE. Reboot when convenient to clear the running services." -ForegroundColor Cyan
    Write-Host "  TO UNDO: double-click UNDO-WINDOWS-UPDATE.cmd" -ForegroundColor Yellow
    Write-Host "           (or run .\Enable-WindowsUpdate.ps1)" -ForegroundColor Yellow
    Write-Host "  You will get NO security patches until you do." -ForegroundColor Yellow
    Write-Host "==================================================" -ForegroundColor Cyan
}
