#Requires -Version 5.1
<#
.SYNOPSIS
    Opens a controlled update window: unblocks Windows Update, installs what is
    pending, then puts the block back - including across the reboot. Self-elevates.

.DESCRIPTION
    This is the "yes, I do want this patch" path. It exists so that unblocking is
    never a decision you have to remember to reverse.

    SEQUENCE
      1. Arms a one-shot scheduled task, NukeWU-ReArm, that runs at the NEXT boot
         as SYSTEM. This is armed FIRST, on purpose: from this moment on, even if
         the machine crashes, loses power, or you walk away mid-update, the block
         comes back by itself on the next start.
      2. Runs Enable-WindowsUpdate.ps1 (removes the guard task, deny-ACEs,
         firewall rules, policy keys, and restores the services).
      3. Searches, downloads and installs pending software updates through the
         Windows Update COM API. Drivers are excluded.
      4. If a reboot is needed, asks you. NukeWU-ReArm re-applies the block after
         that reboot, waiting for servicing to finish first, then deletes itself.
         If no reboot is needed, the block is re-applied immediately and the
         re-arm task is removed.

    The re-arm task waits for TrustedInstaller/TiWorker to go idle before
    re-blocking, so it cannot interrupt Windows finishing an install.

.PARAMETER AutoReboot
    Reboot without asking if the updates require it.
.PARAMETER NoInstall
    Unblock and list what is pending, but install nothing. The block is restored
    at the end. Useful to see what you would be getting.
#>
[CmdletBinding()]
param(
    [switch]$AutoReboot,
    [switch]$NoInstall,
    # Answer every prompt yes and do not pause at the end. Does NOT imply a
    # reboot - pass -AutoReboot as well if you want that too.
    [switch]$Yes
)

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Disable   = Join-Path $ScriptDir 'Disable-WindowsUpdate.ps1'
$Enable    = Join-Path $ScriptDir 'Enable-WindowsUpdate.ps1'
$StateDir  = 'C:\ProgramData\DisableWU'

# --------------------------------------------------------------------------
# Self-elevate
# --------------------------------------------------------------------------
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "Requesting administrator privileges (accept the UAC prompt)..." -ForegroundColor Yellow
    $fwd = @('-NoProfile','-ExecutionPolicy','Bypass','-File', "`"$($MyInvocation.MyCommand.Path)`"")
    if ($AutoReboot) { $fwd += '-AutoReboot' }
    if ($NoInstall)  { $fwd += '-NoInstall' }
    if ($Yes)        { $fwd += '-Yes' }
    try { Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList $fwd -ErrorAction Stop }
    catch { Write-Host "Elevation cancelled." -ForegroundColor Red; Start-Sleep 4 }
    return
}

$ErrorActionPreference = 'Continue'
foreach ($p in @($Disable,$Enable)) {
    if (-not (Test-Path $p)) { Write-Host "MISSING: $p" -ForegroundColor Red; Read-Host 'Enter to exit'; return }
}

Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "  CONTROLLED UPDATE WINDOW"                          -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "  Unblock Windows Update -> install -> re-block."
Write-Host "  The re-block is armed BEFORE anything is unblocked,"
Write-Host "  so it happens even if this is interrupted."
Write-Host ""

# show the last checker report if there is one
$txt = Join-Path $env:LOCALAPPDATA 'NukeWU\last-report.txt'
if (Test-Path $txt) {
    Write-Host "--- last critical-update check ---" -ForegroundColor DarkGray
    Get-Content $txt | Select-Object -First 25 | ForEach-Object { Write-Host "  $_" -ForegroundColor DarkGray }
    Write-Host ""
}

if (-not $NoInstall -and -not $Yes) {
    $ans = Read-Host "Proceed? Windows Update will be enabled and updates installed. [y/N]"
    if ($ans -notmatch '^(y|yes)$') { Write-Host "Cancelled - nothing changed." -ForegroundColor Yellow; Start-Sleep 3; return }
}

# --------------------------------------------------------------------------
# [1] Arm the re-block FIRST
# --------------------------------------------------------------------------
Write-Host "`n[1] Arming the automatic re-block..." -ForegroundColor Green
$rearm = Join-Path $StateDir 'ReArm.ps1'
$null = New-Item -ItemType Directory -Path $StateDir -Force
@'
# One-shot: re-applies the Windows Update block after an update reboot, then
# deletes itself. Waits for servicing to finish so it cannot interrupt an install.
$log = 'C:\ProgramData\DisableWU\rearm.log'
function L { param($m) "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')  $m" | Add-Content -Path $log -Encoding UTF8 }
L 'rearm triggered'
$deadline = (Get-Date).AddMinutes(45)
while ((Get-Date) -lt $deadline) {
    $busy = Get-Process -Name 'TiWorker','TrustedInstaller','wuauclt','MoUsoCoreWorker' -ErrorAction SilentlyContinue
    if (-not $busy) { break }
    L ("waiting for servicing: " + (($busy | Select-Object -Expand Name -Unique) -join ','))
    Start-Sleep -Seconds 30
}
Start-Sleep -Seconds 20
$d = 'C:\ProgramData\DisableWU\Disable-WindowsUpdate.ps1'
if (-not (Test-Path $d)) {
    $inst = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\NukeWU' -Name InstallDir -ErrorAction SilentlyContinue).InstallDir
    if ($inst) { $d = Join-Path $inst 'Disable-WindowsUpdate.ps1' }
}
if (-not (Test-Path $d)) { $d = 'C:\claude\Disable-WindowsUpdate.ps1' }
if (Test-Path $d) {
    L "re-applying block using $d"
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $d -Quiet
    L "block re-applied (exit $LASTEXITCODE)"
} else {
    L 'ERROR: no disable script found - block NOT re-applied'
}
schtasks.exe /Delete /TN "NukeWU-ReArm" /F | Out-Null
L 'rearm task removed'
'@ | Set-Content -Path $rearm -Encoding UTF8

# make sure the staged copy the re-arm prefers is current
try { Copy-Item -Path $Disable -Destination (Join-Path $StateDir 'Disable-WindowsUpdate.ps1') -Force } catch {}

try {
    Unregister-ScheduledTask -TaskName 'NukeWU-ReArm' -Confirm:$false -ErrorAction SilentlyContinue
    $a = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$rearm`""
    $t = New-ScheduledTaskTrigger -AtStartup
    try { $t.Delay = 'PT3M' } catch {}
    $p = New-ScheduledTaskPrincipal -UserId 'S-1-5-18' -RunLevel Highest
    $s = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Hours 1)
    Register-ScheduledTask -TaskName 'NukeWU-ReArm' -Action $a -Trigger $t -Principal $p -Settings $s `
        -Description 'One-shot: re-applies the Windows Update block after an update reboot, then removes itself.' | Out-Null
    Write-Host "  - NukeWU-ReArm armed (runs at next boot, then self-deletes)"
} catch {
    Write-Host "  ! Could not arm the re-block: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "    Aborting - refusing to unblock without a way back." -ForegroundColor Red
    Read-Host 'Enter to exit'; return
}

# --------------------------------------------------------------------------
# [2] Unblock
# --------------------------------------------------------------------------
Write-Host "`n[2] Unblocking Windows Update..." -ForegroundColor Green
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $Enable | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray }

Write-Host "  - waiting for the update services to come up..."
$ok = $false
for ($i=0; $i -lt 20; $i++) {
    Start-Sleep -Seconds 2
    try { Start-Service wuauserv -ErrorAction SilentlyContinue } catch {}
    $svc = Get-Service wuauserv -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -eq 'Running') { $ok = $true; break }
}
Write-Host $(if ($ok) { "  - wuauserv is running" } else { "  ! wuauserv did not start - the search may fail" })

# --------------------------------------------------------------------------
# [3] Search / download / install
# --------------------------------------------------------------------------
Write-Host "`n[3] Searching for updates..." -ForegroundColor Green
$rebootNeeded = $false
try {
    $session  = New-Object -ComObject Microsoft.Update.Session
    $searcher = $session.CreateUpdateSearcher()
    $res = $searcher.Search("IsInstalled=0 AND Type='Software' AND IsHidden=0")
    $found = @($res.Updates)
    Write-Host "  - $($found.Count) update(s) available"
    foreach ($u in $found) { Write-Host ("      * " + $u.Title) -ForegroundColor DarkGray }

    if (-not $found.Count) {
        Write-Host "  - nothing to install"
    } elseif ($NoInstall) {
        Write-Host "  - -NoInstall given, installing nothing" -ForegroundColor Yellow
    } else {
        $coll = New-Object -ComObject Microsoft.Update.UpdateColl
        foreach ($u in $found) {
            if (-not $u.EulaAccepted) { try { $u.AcceptEula() } catch {} }
            [void]$coll.Add($u)
        }
        Write-Host "`n  - downloading..."
        $dl = $session.CreateUpdateDownloader(); $dl.Updates = $coll
        $dr = $dl.Download()
        Write-Host "    download result code $($dr.ResultCode) (2 = succeeded)"

        $inst = New-Object -ComObject Microsoft.Update.UpdateColl
        foreach ($u in $found) { if ($u.IsDownloaded) { [void]$inst.Add($u) } }
        Write-Host "  - installing $($inst.Count) update(s)..."
        if ($inst.Count) {
            $ins = $session.CreateUpdateInstaller(); $ins.Updates = $inst
            $ir = $ins.Install()
            Write-Host "    install result code $($ir.ResultCode) (2 = succeeded)"
            $rebootNeeded = [bool]$ir.RebootRequired
            for ($i=0; $i -lt $inst.Count; $i++) {
                $t = $inst.Item($i).Title
                $c = $ir.GetUpdateResult($i).ResultCode
                Write-Host ("      {0}  {1}" -f $(if($c -eq 2){'OK  '}else{"rc=$c"}), $t) -ForegroundColor DarkGray
            }
        }
    }
} catch {
    Write-Host "  ! Update search/install failed: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "    The block will still be restored." -ForegroundColor Yellow
}

# also honour a pending-reboot flag set by servicing itself
if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { $rebootNeeded = $true }

# --------------------------------------------------------------------------
# [4] Re-block
# --------------------------------------------------------------------------
Write-Host "`n[4] Finishing..." -ForegroundColor Green
if ($rebootNeeded) {
    Write-Host "  - a reboot is required to finish installing." -ForegroundColor Yellow
    Write-Host "  - Windows Update stays enabled until that reboot; NukeWU-ReArm"
    Write-Host "    will re-apply the block automatically once servicing settles."
    $doIt = $AutoReboot
    if (-not $AutoReboot -and -not $Yes) {
        $r = Read-Host "`n  Reboot now? [y/N]"
        $doIt = ($r -match '^(y|yes)$')
    }
    if ($doIt) {
        Write-Host "  - rebooting in 15 seconds. Ctrl+C to abort." -ForegroundColor Yellow
        Start-Sleep -Seconds 15
        Restart-Computer -Force
        return
    } else {
        Write-Host "  - not rebooting. Reboot when you like; the block returns by itself." -ForegroundColor Yellow
        Write-Host "    To re-block right now WITHOUT rebooting, run:" -ForegroundColor Yellow
        Write-Host "      $Disable" -ForegroundColor Yellow
    }
} else {
    Write-Host "  - no reboot needed. Re-applying the block now..."
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $Disable -Quiet
    Unregister-ScheduledTask -TaskName 'NukeWU-ReArm' -Confirm:$false -ErrorAction SilentlyContinue
    Write-Host "  - block restored, re-arm task removed"

    Get-Service wuauserv,UsoSvc,WaaSMedicSvc,DoSvc -ErrorAction SilentlyContinue |
        Select-Object Name,Status,StartType | Format-Table -AutoSize
}

Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "  Done."                                            -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan
if (-not $Yes) { Read-Host "Press Enter to close" }
