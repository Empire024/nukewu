#Requires -Version 5.1
<#
.SYNOPSIS
    Watches Microsoft's own security data for a patch that is genuinely urgent for
    THIS machine while Windows Update is blocked, and raises a Windows toast when
    one appears. Runs as the logged-on user - no admin rights needed.

.DESCRIPTION
    Windows Update is disabled on this box, so nothing can scan for updates any
    more. This checker replaces that signal using two public, authoritative feeds
    that do not need Windows Update at all:

      1. MSRC Security Update Guide (CVRF)
         https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/<YYYY-MMM>
         Gives, per CVE: which products are affected, severity, CVSS, whether it
         is exploited in the wild, and the KB + exact FixedBuild that fixes it.

      2. CISA Known Exploited Vulnerabilities catalogue
         https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
         The authoritative "this is being used against real people right now" list.

    HOW "AM I PATCHED?" IS DECIDED
    Not with Get-HotFix - that is unreliable for cumulative updates. Instead the
    script compares this machine's build revision (UBR) against the FixedBuild
    that MSRC lists for our exact product. Example: this machine is
    10.0.26200.9445; a CVE whose FixedBuild is 10.0.26200.9445 is already fixed,
    one listing 10.0.26200.9600 is not.

    WHAT COUNTS AS "CRUCIAL"  (nothing else raises a toast)
      URGENT - affects us, not patched, AND (exploited in the wild per MSRC
               OR listed in CISA KEV)
      HIGH   - affects us, not patched, AND severity Critical AND CVSS >= 9.0
               AND network attack vector (AV:N)

    Everything else is recorded in the report but never notified, so the toast
    keeps meaning something.

    It will not nag: it re-notifies only when the set of crucial CVEs changes, or
    after 7 days if the same ones are still unpatched.

.PARAMETER Install
    Register the scheduled task (at logon +5min, and daily at 13:00) and the
    nukewu: protocol handler used by the toast's "Update now" button.
.PARAMETER Uninstall
    Remove the scheduled task and protocol handler.
.PARAMETER Simulate
    Pretend something urgent was found, to test the toast and the update flow.
.PARAMETER Force
    Ignore the "already told you" throttle and notify anyway.
.PARAMETER Quiet
    No console output (used by the scheduled task).

.EXAMPLE
    .\Check-CriticalUpdates.ps1                # check now, print a report
.EXAMPLE
    .\Check-CriticalUpdates.ps1 -Simulate      # see what the alert looks like
#>
[CmdletBinding()]
param(
    [switch]$Install,
    [switch]$Uninstall,
    [switch]$Simulate,
    [switch]$Force,
    [switch]$Quiet,
    # Test aid: pretend this machine's build revision is older than it is, to
    # verify the real detection logic against real MSRC data. Changes nothing.
    [int]$PretendUbr = 0
)

$ErrorActionPreference = 'Continue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# --------------------------------------------------------------------------
# Config
# --------------------------------------------------------------------------
$StateDir   = Join-Path $env:LOCALAPPDATA 'NukeWU'
$CacheDir   = Join-Path $StateDir 'cache'
$ReportPath = Join-Path $StateDir 'last-report.json'
$TextReport = Join-Path $StateDir 'last-report.txt'
$AlertState = Join-Path $StateDir 'last-alert.json'
$LogPath    = Join-Path $StateDir 'checker.log'
$RenotifyAfterDays = 7
$CacheHours = 20

# The updater the toast button launches, and the folder the Start Menu
# shortcuts point at. This script may be running from its staged copy in
# ProgramData (the scheduled task), so "next to me" is tried first, then the
# install folder recorded by -Install (HKCU) or Disable-WindowsUpdate.ps1
# (HKLM), then the folder the tool was originally developed in.
function Resolve-ToolDir {
    $cands = @($PSScriptRoot)
    foreach ($hive in 'HKCU:\Software\NukeWU', 'HKLM:\SOFTWARE\NukeWU') {
        try { $cands += (Get-ItemProperty -Path $hive -Name InstallDir -ErrorAction Stop).InstallDir } catch {}
    }
    $cands += 'C:\claude'
    foreach ($c in $cands) {
        if ($c -and (Test-Path (Join-Path $c 'Invoke-UpdateWindow.ps1'))) { return $c }
    }
    return $PSScriptRoot
}
$ToolDir      = Resolve-ToolDir
$UpdateScript = Join-Path $ToolDir 'Invoke-UpdateWindow.ps1'
# Defined here, not next to Show-Toast: the -Uninstall block below needs it,
# and an empty value there would make the cleanup path delete every registered
# AppUserModelId for this user, not just ours.
$ToastAumId   = 'NukeWU.WindowsUpdateControl'

$null = New-Item -ItemType Directory -Path $CacheDir -Force -ErrorAction SilentlyContinue

function Say  { param($m,$c='Gray') if (-not $Quiet) { Write-Host $m -ForegroundColor $c } }
function Log  {
    param($m)
    try { "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')  $m" | Add-Content -Path $LogPath -Encoding UTF8 } catch {}
}

# --------------------------------------------------------------------------
# Install / uninstall the scheduled task + protocol handler
# --------------------------------------------------------------------------
function Register-Protocol {
    # Lets the toast's "Update now" button launch the updater. HKCU, no admin.
    $base = 'HKCU:\Software\Classes\nukewu'
    $null = New-Item -Path "$base\shell\open\command" -Force
    Set-ItemProperty -Path $base -Name '(default)'   -Value 'URL:NukeWU Protocol'
    Set-ItemProperty -Path $base -Name 'URL Protocol' -Value ''
    $cmd = '"' + (Join-Path $PSHOME 'powershell.exe') + '" -NoProfile -ExecutionPolicy Bypass -File "' + $UpdateScript + '"'
    Set-ItemProperty -Path "$base\shell\open\command" -Name '(default)' -Value $cmd
}

function New-StartMenuShortcuts {
    # A notification is easy to miss or dismiss, so these are the permanent way
    # in: press Start, type "Windows Update", pick one.
    $dir = Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\Windows Update Control'
    $null = New-Item -ItemType Directory -Path $dir -Force
    $src  = Split-Path -Parent $UpdateScript
    $sh   = New-Object -ComObject WScript.Shell
    $ps = Join-Path $PSHOME 'powershell.exe'
    # Custom artwork, so the group does not look like five copies of powershell.
    # Falls back to stock shell32 icons if assets\ ever goes missing.
    $icoBlock  = Join-Path $src 'assets\nukewu-block.ico'
    $icoUpdate = Join-Path $src 'assets\nukewu-update.ico'
    $iBlock  = if (Test-Path $icoBlock)  { "$icoBlock,0" }  else { 'shell32.dll,220' }
    $iUpdate = if (Test-Path $icoUpdate) { "$icoUpdate,0" } else { 'shell32.dll,46' }
    $items = @(
        # The UI is the main way in. It is launched WITHOUT -WindowStyle Hidden
        # on purpose - that would set SW_HIDE in STARTUPINFO, which .NET applies
        # to the first window created (the form), so the form would never show.
        # The script hides its own console from the inside instead.
        @{ Name='Windows Update Control';               Target='WindowsUpdateControl.ps1'; ViaPs=$true;  Desc='Status, checks and update/unblock buttons in one window';                 Icon=$iBlock },
        @{ Name='Windows Update - check if I need one'; Target='CHECK-UPDATES.cmd';        Desc='Check MSRC and CISA KEV for a security update that is urgent for this PC'; Icon=$iUpdate },
        @{ Name='Windows Update - update now (safely)'; Target='UPDATE-NOW.cmd';           Desc='Unblock, install updates, then re-block automatically';                   Icon=$iUpdate },
        @{ Name='Windows Update - unblock (undo)';      Target='UNDO-WINDOWS-UPDATE.cmd';  Desc='Turn Windows Update back on permanently';                                 Icon=$iUpdate },
        @{ Name='Windows Update - re-block';            Target='NUKE-WINDOWS-UPDATE.cmd';  Desc='Re-apply the Windows Update block';                                       Icon=$iBlock }
    )
    $made = 0
    foreach ($i in $items) {
        $t = Join-Path $src $i.Target
        if (-not (Test-Path $t)) { continue }
        try {
            $lnk = $sh.CreateShortcut((Join-Path $dir ($i.Name + '.lnk')))
            if ($i.ViaPs) {
                $lnk.TargetPath = $ps
                $lnk.Arguments  = "-NoProfile -ExecutionPolicy Bypass -File `"$t`""
            } else {
                $lnk.TargetPath = $t
            }
            $lnk.WorkingDirectory = $src
            $lnk.Description      = $i.Desc
            $lnk.IconLocation     = $i.Icon
            $lnk.Save()
            $made++
        } catch { Log "shortcut '$($i.Name)' failed: $($_.Exception.Message)" }
    }
    return @{ Count = $made; Dir = $dir }
}

if ($Uninstall) {
    Unregister-ScheduledTask -TaskName 'NukeWU-UpdateCheck' -Confirm:$false -ErrorAction SilentlyContinue
    Remove-Item -Path 'HKCU:\Software\Classes\nukewu' -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path 'HKCU:\Software\NukeWU' -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "HKCU:\Software\Classes\AppUserModelId\$ToastAumId" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path (Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\Windows Update Control') -Recurse -Force -ErrorAction SilentlyContinue
    Say "Checker task, protocol handler and Start Menu shortcuts removed." Yellow
    return
}

if ($Install) {
    # Remember where the tool lives, so the staged copy of this script that the
    # scheduled task runs can still find Invoke-UpdateWindow.ps1 and friends.
    try {
        $null = New-Item -Path 'HKCU:\Software\NukeWU' -Force
        Set-ItemProperty -Path 'HKCU:\Software\NukeWU' -Name InstallDir -Value $ToolDir
    } catch { Log "could not record InstallDir: $($_.Exception.Message)" }
    Register-Protocol
    $self = $MyInvocation.MyCommand.Path

    # The elevated setup (Disable-WindowsUpdate.ps1 layer 8b) registers this task
    # too, pointed at the staged copy in ProgramData. A non-elevated run cannot
    # overwrite a task an admin created, so if a healthy one is already there,
    # leave it alone instead of failing noisily.
    $existing = Get-ScheduledTask -TaskName 'NukeWU-UpdateCheck' -ErrorAction SilentlyContinue
    $amAdmin  = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
                ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if ($existing -and -not $amAdmin) {
        Say "Scheduled task 'NukeWU-UpdateCheck' already registered ($($existing.State)) - left as is." Green
        Say "  (re-run this elevated, or run Disable-WindowsUpdate.ps1, to re-point it)" DarkGray
        $sc0 = New-StartMenuShortcuts
        Say "Created $($sc0.Count) Start Menu shortcut(s) under 'Windows Update Control'" Green
        Say "  -> press Start and type 'Windows Update' to find them" DarkGray
        return
    }

    try {
        Unregister-ScheduledTask -TaskName 'NukeWU-UpdateCheck' -Confirm:$false -ErrorAction SilentlyContinue
        $act = New-ScheduledTaskAction -Execute (Join-Path $PSHOME 'powershell.exe') `
                 -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$self`" -Quiet"
        $t1 = New-ScheduledTaskTrigger -AtLogOn -User "$env:USERDOMAIN\$env:USERNAME"
        try { $t1.Delay = 'PT5M' } catch { }   # not settable on every build; harmless
        $t2 = New-ScheduledTaskTrigger -Daily -At '13:00'
        # Runs as the interactive user on purpose: a toast raised by SYSTEM is
        # never shown to anyone. Checking needs no admin rights.
        $prin = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType Interactive -RunLevel Limited
        $set  = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
                  -ExecutionTimeLimit (New-TimeSpan -Minutes 20)
        # -Force overwrites an existing registration; -ErrorAction Stop is
        # required because Register-ScheduledTask reports failure as a
        # NON-terminating error and would otherwise be reported as success.
        Register-ScheduledTask -TaskName 'NukeWU-UpdateCheck' -Action $act -Trigger @($t1,$t2) -Principal $prin -Settings $set -Force `
            -Description 'Checks MSRC + CISA KEV for a security update that is genuinely urgent for this machine while Windows Update is blocked.' `
            -ErrorAction Stop | Out-Null
        Say "Installed scheduled task 'NukeWU-UpdateCheck' (logon +5min, daily 13:00) as $env:USERNAME" Green
        Say "Registered nukewu: protocol for the toast button" Green
    } catch {
        Say "Could not register the task: $($_.Exception.Message)" Red
    }
    $sc = New-StartMenuShortcuts
    Say "Created $($sc.Count) Start Menu shortcut(s) under 'Windows Update Control'" Green
    Say "  -> press Start and type 'Windows Update' to find them" DarkGray
    return
}

# --------------------------------------------------------------------------
# Work out which MSRC product this machine is
# --------------------------------------------------------------------------
function Get-MsrcProductName {
    $cv   = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $disp = $cv.DisplayVersion                      # e.g. 25H2
    $arch = switch ($env:PROCESSOR_ARCHITECTURE) { 'AMD64' {'x64'} 'ARM64' {'ARM64'} default {'x64'} }
    $fam  = if ($cv.ProductName -match 'Windows 11' -or [int]$cv.CurrentBuild -ge 22000) { 'Windows 11' } else { 'Windows 10' }
    return @{
        Name  = "$fam Version $disp for $arch-based Systems"
        Build = [int]$cv.CurrentBuild
        Ubr   = [int]$cv.UBR
        Disp  = $disp
        Arch  = $arch
        Fam   = $fam
    }
}

function Get-Json {
    param([string]$Url,[string]$CacheFile,[int]$TtlHours = $CacheHours)
    if ((Test-Path $CacheFile) -and ((Get-Date) - (Get-Item $CacheFile).LastWriteTime).TotalHours -lt $TtlHours) {
        try { return (Get-Content $CacheFile -Raw | ConvertFrom-Json) } catch {}
    }
    try {
        Invoke-WebRequest -Uri $Url -Headers @{Accept='application/json'} -OutFile $CacheFile -UseBasicParsing -TimeoutSec 120 -ErrorAction Stop
        return (Get-Content $CacheFile -Raw | ConvertFrom-Json)
    } catch {
        Log "fetch failed $Url : $($_.Exception.Message)"
        if (Test-Path $CacheFile) {
            Log "using stale cache for $Url"
            try { return (Get-Content $CacheFile -Raw | ConvertFrom-Json) } catch {}
        }
        return $null
    }
}

function Get-FixedUbr {
    param([string]$fb)
    if ($fb -match '^(\d+)\.(\d+)\.(\d+)\.(\d+)$') { return @([int]$Matches[3],[int]$Matches[4]) }
    return $null
}

# --------------------------------------------------------------------------
# Toast
# --------------------------------------------------------------------------
function Register-ToastAppId {
    try {
        $k = "HKCU:\Software\Classes\AppUserModelId\$ToastAumId"
        if (-not (Test-Path $k)) { $null = New-Item -Path $k -Force -ErrorAction Stop }
        Set-ItemProperty -Path $k -Name DisplayName -Value 'Windows Update Control' -Type String -ErrorAction Stop
        $ico = Join-Path (Split-Path -Parent $UpdateScript) 'assets\nukewu-block.png'
        if (Test-Path $ico) { Set-ItemProperty -Path $k -Name IconUri -Value $ico -Type String -ErrorAction Stop }
        return $true
    } catch { return $false }
}

function Show-Toast {
    param([string]$Title,[string]$Body,[string]$Detail,[switch]$Urgent)
    try {
        [void][Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType=WindowsRuntime]
        [void][Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType=WindowsRuntime]
        # A toast takes its header name and small icon from the AppUserModelID
        # that raises it. Borrowing powershell.exe's makes every notification say
        # "Windows PowerShell"; registering our own under HKCU fixes both. If the
        # registration fails we fall back, because a plain-looking toast beats no
        # toast at all - this is the safety net for a machine that cannot patch
        # itself.
        $appId = '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe'
        if (Register-ToastAppId) { $appId = $ToastAumId }
        $esc = {
            param($s)
            $s -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;' -replace '"','&quot;'
        }
        # Toasts cannot read .ico, hence the PNG. Without it the toast shows the
        # PowerShell logo, because that is the AppUserModelID we borrow above.
        $logo = Join-Path (Split-Path -Parent $UpdateScript) 'assets\nukewu-block.png'
        $logoXml = if (Test-Path $logo) { "`n      <image placement=`"appLogoOverride`" src=`"$(& $esc $logo)`"/>" } else { '' }
        $xml = @"
<toast scenario="reminder" activationType="protocol" launch="nukewu:update">
  <visual>
    <binding template="ToastGeneric">
      <text>$(& $esc $Title)</text>
      <text>$(& $esc $Body)</text>
      <text placement="attribution">$(& $esc $Detail)</text>$logoXml
    </binding>
  </visual>
  <actions>
    <action content="Update now (safely)" activationType="protocol" arguments="nukewu:update"/>
    <action content="Remind me later" activationType="system" arguments="dismiss"/>
  </actions>
</toast>
"@
        $doc = New-Object Windows.Data.Xml.Dom.XmlDocument
        $doc.LoadXml($xml)
        $toast = New-Object Windows.UI.Notifications.ToastNotification($doc)
        [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($appId).Show($toast)
        Log "toast shown: $Title"
        return $true
    } catch {
        Log "toast failed: $($_.Exception.Message)"
        # Fallback so an alert is never silently lost
        try {
            Add-Type -AssemblyName System.Windows.Forms
            [System.Windows.Forms.MessageBox]::Show("$Body`n`n$Detail`n`nRun: $UpdateScript", $Title,
                'OK', 'Warning') | Out-Null
            return $true
        } catch { return $false }
    }
}

# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------
$me = Get-MsrcProductName
if ($PretendUbr -gt 0) { $me.Ubr = $PretendUbr }
Say "==================================================" Cyan
Say "  CRITICAL UPDATE CHECK"                            Cyan
Say "==================================================" Cyan
Say "This machine : $($me.Name)"
Say "Build        : $($me.Build).$($me.Ubr)"
if ($PretendUbr -gt 0) { Say "               (TEST: pretending UBR is $PretendUbr)" Yellow }
Log "check start: $($me.Name) build $($me.Build).$($me.Ubr)"

$findings = @()

if ($Simulate) {
    Say "`n(SIMULATION - not a real finding)" Yellow
    $findings = @([PSCustomObject]@{
        CVE='CVE-2026-00000'; Tier='URGENT'; Severity='Critical'; CVSS=9.8
        Impact='Remote Code Execution'; KB='KB0000000'; FixedBuild="10.0.$($me.Build).99999"
        Exploited=$true; InKev=$true; Title='SIMULATED - test of the alert path'
        Reason='simulated'
    })
} else {
    # ---- CISA KEV -------------------------------------------------------
    $kevIds = New-Object System.Collections.Generic.HashSet[string]
    $kev = Get-Json -Url 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json' `
                    -CacheFile (Join-Path $CacheDir 'kev.json')
    if ($kev) {
        foreach ($x in @($kev.vulnerabilities)) {
            if ($x.vendorProject -eq 'Microsoft') { [void]$kevIds.Add($x.cveID) }
        }
        Say "CISA KEV     : $($kevIds.Count) Microsoft CVEs (catalogue $($kev.catalogVersion))"
    } else {
        Say "CISA KEV     : unavailable (offline?) - continuing on MSRC only" DarkYellow
    }

    # ---- MSRC CVRF: this month and last month ---------------------------
    $docs = @()
    foreach ($off in 0,-1) {
        $d   = (Get-Date).AddMonths($off)
        $tag = '{0}-{1}' -f $d.Year, ([System.Globalization.CultureInfo]::GetCultureInfo('en-US').DateTimeFormat.GetAbbreviatedMonthName($d.Month))
        $doc = Get-Json -Url "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/$tag" -CacheFile (Join-Path $CacheDir "cvrf-$tag.json")
        if ($doc) { $docs += ,@($tag,$doc); Say "MSRC         : loaded $tag ($(@($doc.Vulnerability).Count) CVEs)" }
    }
    if (-not $docs.Count) {
        Say "MSRC         : unavailable - cannot assess. No alert raised." DarkYellow
        Log "no MSRC documents available; aborting without alert"
        return
    }

    foreach ($pair in $docs) {
        $tag = $pair[0]; $doc = $pair[1]

        # our ProductID inside this document
        $prod = @($doc.ProductTree.FullProductName) | Where-Object { $_.Value -eq $me.Name } | Select-Object -First 1
        if (-not $prod) {
            $prod = @($doc.ProductTree.FullProductName) |
                    Where-Object { $_.Value -match "^$([regex]::Escape($me.Fam)) Version $($me.Disp) for $($me.Arch)" } |
                    Select-Object -First 1
        }
        if (-not $prod) { Say "  ($($tag): this product not listed - skipped)" DarkGray; continue }
        $pidOurs = $prod.ProductID

        foreach ($v in @($doc.Vulnerability)) {
            $affected = $false
            foreach ($st in @($v.ProductStatuses)) {
                if ($st.Type -eq 3 -and (@($st.ProductID) -contains $pidOurs)) { $affected = $true; break }
            }
            if (-not $affected) { continue }

            # exploitation status is stated once for the whole CVE
            $expText = ''
            $expT = @($v.Threats) | Where-Object { $_.Type -eq 1 } | Select-Object -First 1
            if ($expT) { $expText = [string]$expT.Description.Value }
            $exploited = $expText -match 'Exploited:\s*Yes'
            $disclosed = $expText -match 'Publicly Disclosed:\s*Yes'

            $sevT = @($v.Threats) | Where-Object { $_.Type -eq 3 -and (@($_.ProductID) -contains $pidOurs) } | Select-Object -First 1
            $sev  = if ($sevT) { [string]$sevT.Description.Value } else { '' }

            $impT = @($v.Threats) | Where-Object { $_.Type -eq 0 -and (@($_.ProductID) -contains $pidOurs) } | Select-Object -First 1
            $impact = if ($impT) { [string]$impT.Description.Value } else { '' }

            $cs = @($v.CVSSScoreSets) | Where-Object { @($_.ProductID) -contains $pidOurs } | Select-Object -First 1
            $score  = if ($cs) { [double]$cs.BaseScore } else { 0 }
            $vector = if ($cs) { [string]$cs.Vector } else { '' }

            # best vendor-fix remediation for our product
            $rem = @($v.Remediations) |
                   Where-Object { $_.Type -eq 2 -and (@($_.ProductID) -contains $pidOurs) -and $_.Description.Value -match '^\d+$' } |
                   Sort-Object { $x = Get-FixedUbr $_.FixedBuild; if ($x) { $x[1] } else { 0 } } -Descending |
                   Select-Object -First 1

            $kb = ''; $fixedBuild = ''; $patched = 'unknown'
            if ($rem) {
                $kb = 'KB' + $rem.Description.Value
                $fixedBuild = [string]$rem.FixedBuild
                $fu = Get-FixedUbr $fixedBuild
                if ($fu) {
                    if ($fu[0] -ne $me.Build) { $patched = 'other-branch' }
                    elseif ($me.Ubr -ge $fu[1]) { $patched = 'yes' }
                    else { $patched = 'no' }
                }
            }

            $inKev = $kevIds.Contains($v.CVE)

            # Only unpatched (or genuinely unknown) things can be crucial.
            if ($patched -eq 'yes' -or $patched -eq 'other-branch') { continue }

            $tier = $null; $reason = ''
            if ($exploited -or $inKev) {
                $tier = 'URGENT'
                $parts = @()
                if ($exploited) { $parts += 'exploited in the wild (MSRC)' }
                if ($inKev)     { $parts += 'listed in CISA KEV' }
                $reason = $parts -join '; '
            } elseif ($sev -eq 'Critical' -and $score -ge 9.0 -and $vector -match 'AV:N') {
                $tier = 'HIGH'
                $reason = "Critical, CVSS $score, remotely reachable"
                if ($disclosed) { $reason += ', publicly disclosed' }
            }
            if (-not $tier) { continue }

            $findings += [PSCustomObject]@{
                CVE=$v.CVE; Tier=$tier; Severity=$sev; CVSS=$score; Impact=$impact
                KB=$kb; FixedBuild=$fixedBuild; Exploited=$exploited; InKev=$inKev
                Title=[string]$v.Title.Value; Reason=$reason; Month=$tag; Patched=$patched
            }
        }
    }
    $findings = @($findings | Sort-Object CVE -Unique | Sort-Object @{e={if($_.Tier -eq 'URGENT'){0}else{1}}}, @{e={-$_.CVSS}})
}

# --------------------------------------------------------------------------
# Report
# --------------------------------------------------------------------------
$urgent = @($findings | Where-Object { $_.Tier -eq 'URGENT' })
$high   = @($findings | Where-Object { $_.Tier -eq 'HIGH' })

$report = [PSCustomObject]@{
    checkedUtc = (Get-Date).ToUniversalTime().ToString('o')
    product    = $me.Name
    build      = "$($me.Build).$($me.Ubr)"
    urgent     = $urgent.Count
    high       = $high.Count
    findings   = $findings
}
try { $report | ConvertTo-Json -Depth 6 | Set-Content -Path $ReportPath -Encoding UTF8 } catch {}

$lines = @()
$lines += "Critical update check - $(Get-Date -Format 'yyyy-MM-dd HH:mm')"
$lines += "Machine: $($me.Name)  build $($me.Build).$($me.Ubr)"
$lines += ""
if (-not $findings.Count) {
    $lines += "Nothing crucial outstanding. Windows Update can stay blocked."
} else {
    foreach ($f in $findings) {
        $lines += "[$($f.Tier)] $($f.CVE)  $($f.Severity) CVSS $($f.CVSS)  $($f.Impact)"
        $lines += "         $($f.Title)"
        $lines += "         fixed by $($f.KB) (build $($f.FixedBuild)) - $($f.Reason)"
        $lines += ""
    }
}
try { $lines -join "`r`n" | Set-Content -Path $TextReport -Encoding UTF8 } catch {}

Say ""
if (-not $findings.Count) {
    Say "RESULT: nothing crucial outstanding." Green
    Say "        Windows Update can stay blocked."
    Log "result: clean"
} else {
    Say "RESULT: $($urgent.Count) urgent, $($high.Count) high-severity unpatched issue(s)" Red
    foreach ($f in ($findings | Select-Object -First 12)) {
        $c = if ($f.Tier -eq 'URGENT') { 'Red' } else { 'Yellow' }
        Say ("  [{0}] {1}  CVSS {2}  {3}  -> {4}" -f $f.Tier,$f.CVE,$f.CVSS,$f.Impact,$f.KB) $c
        Say ("           {0}" -f $f.Reason) DarkGray
    }
    if ($findings.Count -gt 12) { Say "  ... and $($findings.Count - 12) more (see $TextReport)" DarkGray }
}
Say ""
Say "Full report: $TextReport" DarkGray

# --------------------------------------------------------------------------
# Notify - but do not nag
# --------------------------------------------------------------------------
if (-not $findings.Count) {
    if (Test-Path $AlertState) { Remove-Item $AlertState -Force -ErrorAction SilentlyContinue }
    Log "result: clean, no alert"
    return
}

$sig = (($findings | ForEach-Object { $_.CVE }) -join ',')
$shouldNotify = $true
if (-not $Force -and (Test-Path $AlertState)) {
    try {
        $prev = Get-Content $AlertState -Raw | ConvertFrom-Json
        if ($prev.signature -eq $sig) {
            $age = ((Get-Date) - [datetime]$prev.notifiedLocal).TotalDays
            if ($age -lt $RenotifyAfterDays) {
                $shouldNotify = $false
                Say "Already notified $([math]::Round($age,1)) day(s) ago for the same CVEs - staying quiet." DarkGray
                Log "throttled (same signature, $([math]::Round($age,1))d)"
            }
        }
    } catch {}
}

if ($shouldNotify) {
    $top = $findings[0]
    if ($urgent.Count) {
        $title = "Security update you should probably install"
        $body  = "$($urgent.Count) vulnerability(ies) affecting this PC are being exploited in the wild and are not patched here. Top: $($top.CVE) - $($top.Impact)."
    } else {
        $title = "Important security update available"
        $body  = "$($high.Count) critical, remotely-exploitable issue(s) affecting this PC are unpatched. Top: $($top.CVE) - CVSS $($top.CVSS)."
    }
    $detail = "Fixed by $($top.KB). Windows Update is currently blocked on this PC."
    if (Show-Toast -Title $title -Body $body -Detail $detail) {
        try {
            [PSCustomObject]@{ signature=$sig; notifiedLocal=(Get-Date).ToString('o'); count=$findings.Count } |
                ConvertTo-Json | Set-Content -Path $AlertState -Encoding UTF8
        } catch {}
        Say "Toast raised." Yellow
    } else {
        Say "Could not raise a notification - see $LogPath" Red
    }
}

Say ""
Say "To update safely (unblock -> update -> re-block automatically):" Cyan
Say "  $UpdateScript" Cyan
