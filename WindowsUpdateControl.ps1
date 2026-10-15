#Requires -Version 5.1
<#
.SYNOPSIS
    Small desktop UI for the Windows Update block: shows whether the block is
    holding, what the last critical-update check found, and gives you buttons for
    check / update / unblock / re-block instead of remembering script names.

.DESCRIPTION
    Runs as you, NOT elevated. Reading status needs no admin rights; the two
    actions that do (unblock, re-block, update) launch elevated on their own and
    raise a normal UAC prompt. That way the window itself is never a privileged
    process sitting open on your desktop.

    Long actions run as a child process and are polled by a timer, so the window
    never freezes or shows "not responding" while a check or an update runs.
#>
[CmdletBinding()]
param()

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# Crisper text on high-DPI displays, and hide our own console window.
#
# NOTE: do NOT launch this script with -WindowStyle Hidden. That sets SW_HIDE in
# the process STARTUPINFO, which .NET applies to the FIRST window the process
# creates - which is the form, not the console. The form then never appears.
# Launch normally and hide the console from inside instead, as below.
try {
    Add-Type -MemberDefinition @'
[DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
[DllImport("kernel32.dll")] public static extern IntPtr GetConsoleWindow();
[DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
'@ -Name Dpi -Namespace Win32 -ErrorAction SilentlyContinue
    [void][Win32.Dpi]::SetProcessDPIAware()
    $con = [Win32.Dpi]::GetConsoleWindow()
    if ($con -ne [IntPtr]::Zero) { [void][Win32.Dpi]::ShowWindow($con, 0) }   # 0 = SW_HIDE
} catch {}
[System.Windows.Forms.Application]::EnableVisualStyles()

$ScriptDir   = Split-Path -Parent $MyInvocation.MyCommand.Path
$Disable     = Join-Path $ScriptDir 'Disable-WindowsUpdate.ps1'
$Enable      = Join-Path $ScriptDir 'Enable-WindowsUpdate.ps1'
$Checker     = Join-Path $ScriptDir 'Check-CriticalUpdates.ps1'
$Updater     = Join-Path $ScriptDir 'Invoke-UpdateWindow.ps1'
$StateDir    = Join-Path $env:LOCALAPPDATA 'NukeWU'
$ReportTxt   = Join-Path $StateDir 'last-report.txt'
$ReportJson  = Join-Path $StateDir 'last-report.json'
$Services    = @('wuauserv','UsoSvc','WaaSMedicSvc','DoSvc')
$PSExe       = Join-Path $PSHOME 'powershell.exe'
$IconFile    = Join-Path $ScriptDir 'assets\nukewu-block.ico'

$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
           ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# ---------------------------------------------------------------------------
# Palette
# ---------------------------------------------------------------------------
$ColBg      = [System.Drawing.Color]::FromArgb(250,250,251)
$ColCard    = [System.Drawing.Color]::White
$ColText    = [System.Drawing.Color]::FromArgb(28,30,34)
$ColMuted   = [System.Drawing.Color]::FromArgb(110,116,124)
$ColGood    = [System.Drawing.Color]::FromArgb(22,128,72)
$ColBad     = [System.Drawing.Color]::FromArgb(190,40,40)
$ColWarn    = [System.Drawing.Color]::FromArgb(176,110,10)
$FontUI     = New-Object System.Drawing.Font('Segoe UI',9)
$FontBig    = New-Object System.Drawing.Font('Segoe UI',15,[System.Drawing.FontStyle]::Bold)
$FontSmall  = New-Object System.Drawing.Font('Segoe UI',8.25)
$FontMono   = New-Object System.Drawing.Font('Consolas',9)

# ---------------------------------------------------------------------------
# Status probing (no admin needed)
# ---------------------------------------------------------------------------
function Get-ServiceRows {
    $rows = @()
    foreach ($s in $Services) {
        $key = "HKLM:\SYSTEM\CurrentControlSet\Services\$s"
        if (-not (Test-Path $key)) { continue }
        $start = $null
        try { $start = (Get-ItemProperty $key -Name Start -ErrorAction Stop).Start } catch {}
        $locked = $null
        try {
            $locked = [bool](@((Get-Acl $key).Access | Where-Object { $_.AccessControlType -eq 'Deny' })).Count
        } catch { $locked = $null }
        $svc = Get-Service $s -ErrorAction SilentlyContinue
        $means = switch ($start) { 2 {'Automatic'} 3 {'Manual'} 4 {'Disabled'} 1 {'System'} 0 {'Boot'} default {"$start"} }
        $rows += [PSCustomObject]@{
            Name    = $s
            Start   = $means
            Running = $(if ($svc) { [string]$svc.Status } else { 'n/a' })
            Locked  = $(if ($null -eq $locked) { '?' } elseif ($locked) { 'yes' } else { 'no' })
            Ok      = ($start -eq 4 -and $locked -eq $true)
        }
    }
    return $rows
}

function Get-TaskState {
    param([string]$Name)
    try {
        $t = Get-ScheduledTask -TaskName $Name -ErrorAction Stop
        return [string]$t.State
    } catch { return $null }
}

function Get-OverallState {
    $rows = Get-ServiceRows
    if (-not $rows.Count) { return 'unknown' }
    $blocked   = @($rows | Where-Object { $_.Ok }).Count
    if ($blocked -eq $rows.Count) { return 'blocked' }
    if ($blocked -eq 0)           { return 'open' }
    return 'partial'
}

# ---------------------------------------------------------------------------
# Window
# ---------------------------------------------------------------------------
$form                  = New-Object System.Windows.Forms.Form
$form.Text             = 'Windows Update Control'
$form.Size             = New-Object System.Drawing.Size(780,700)
$form.MinimumSize      = New-Object System.Drawing.Size(700,600)
$form.StartPosition    = 'CenterScreen'
$form.BackColor        = $ColBg
$form.Font             = $FontUI
# Without this the window and its taskbar button inherit powershell.exe's icon.
if (Test-Path $IconFile) {
    try { $form.Icon = New-Object System.Drawing.Icon $IconFile } catch {}
}

# --- header ---------------------------------------------------------------
$header            = New-Object System.Windows.Forms.Panel
$header.Location   = New-Object System.Drawing.Point(0,0)
$header.Size       = New-Object System.Drawing.Size(780,78)
$header.BackColor  = $ColCard
$header.Anchor     = 'Top,Left,Right'
$form.Controls.Add($header)

$lblState          = New-Object System.Windows.Forms.Label
$lblState.Location = New-Object System.Drawing.Point(18,14)
$lblState.Size     = New-Object System.Drawing.Size(600,30)
$lblState.Font     = $FontBig
$header.Controls.Add($lblState)

$lblStateSub          = New-Object System.Windows.Forms.Label
$lblStateSub.Location = New-Object System.Drawing.Point(20,46)
$lblStateSub.Size     = New-Object System.Drawing.Size(730,20)
$lblStateSub.ForeColor= $ColMuted
$header.Controls.Add($lblStateSub)

# --- services list --------------------------------------------------------
$lblSvc          = New-Object System.Windows.Forms.Label
$lblSvc.Location = New-Object System.Drawing.Point(18,90)
$lblSvc.Size     = New-Object System.Drawing.Size(300,18)
$lblSvc.Text     = 'Update services'
$lblSvc.ForeColor= $ColMuted
$form.Controls.Add($lblSvc)

$lv                = New-Object System.Windows.Forms.ListView
$lv.Location       = New-Object System.Drawing.Point(18,110)
$lv.Size           = New-Object System.Drawing.Size(444,116)
$lv.View           = 'Details'
$lv.FullRowSelect  = $true
$lv.GridLines      = $false
$lv.HeaderStyle    = 'Nonclickable'
$lv.BackColor      = $ColCard
$lv.Anchor         = 'Top,Left'
[void]$lv.Columns.Add('Service',126)
[void]$lv.Columns.Add('Start type',88)
[void]$lv.Columns.Add('Running',82)
[void]$lv.Columns.Add('Key locked',86)
$form.Controls.Add($lv)

# --- protection summary ---------------------------------------------------
$lblProt          = New-Object System.Windows.Forms.Label
$lblProt.Location = New-Object System.Drawing.Point(478,90)
$lblProt.Size     = New-Object System.Drawing.Size(270,18)
$lblProt.Text     = 'Protection'
$lblProt.ForeColor= $ColMuted
$form.Controls.Add($lblProt)

$txtProt              = New-Object System.Windows.Forms.TextBox
$txtProt.Location     = New-Object System.Drawing.Point(478,110)
$txtProt.Size         = New-Object System.Drawing.Size(268,116)
$txtProt.Multiline    = $true
$txtProt.ReadOnly     = $true
$txtProt.BorderStyle  = 'FixedSingle'
$txtProt.BackColor    = $ColCard
$txtProt.Font         = $FontSmall
$txtProt.Anchor       = 'Top,Left,Right'
$form.Controls.Add($txtProt)

# --- action buttons -------------------------------------------------------
function New-Button {
    param($Text,$X,$Y,$W,$H,$Primary)
    $b = New-Object System.Windows.Forms.Button
    $b.Text = $Text
    $b.Location = New-Object System.Drawing.Point($X,$Y)
    $b.Size = New-Object System.Drawing.Size($W,$H)
    $b.FlatStyle = 'System'
    $b.UseVisualStyleBackColor = $true
    if ($Primary) { $b.Font = New-Object System.Drawing.Font('Segoe UI',9,[System.Drawing.FontStyle]::Bold) }
    return $b
}

$btnCheck  = New-Button 'Check for critical updates' 18  242 218 34 $true
$btnUpdate = New-Button 'Update now (safely)'        244 242 180 34 $false
$btnBlock  = New-Button 'Re-apply block'             432 242 150 34 $false
$btnUnblock= New-Button 'Unblock permanently'        590 242 156 34 $false
foreach ($b in @($btnCheck,$btnUpdate,$btnBlock,$btnUnblock)) { $form.Controls.Add($b) }

$lblHint          = New-Object System.Windows.Forms.Label
$lblHint.Location = New-Object System.Drawing.Point(18,280)
$lblHint.Size     = New-Object System.Drawing.Size(730,16)
$lblHint.ForeColor= $ColMuted
$lblHint.Font     = $FontSmall
$lblHint.Text     = 'Update / block / unblock need administrator rights and will show a UAC prompt.'
$lblHint.Anchor   = 'Top,Left,Right'
$form.Controls.Add($lblHint)

# --- report ---------------------------------------------------------------
$lblRep          = New-Object System.Windows.Forms.Label
$lblRep.Location = New-Object System.Drawing.Point(18,306)
$lblRep.Size     = New-Object System.Drawing.Size(730,18)
$lblRep.ForeColor= $ColMuted
$lblRep.Anchor   = 'Top,Left,Right'
$form.Controls.Add($lblRep)

$txtRep              = New-Object System.Windows.Forms.TextBox
$txtRep.Location     = New-Object System.Drawing.Point(18,326)
$txtRep.Size         = New-Object System.Drawing.Size(728,260)
$txtRep.Multiline    = $true
$txtRep.ReadOnly     = $true
$txtRep.ScrollBars   = 'Vertical'
$txtRep.BorderStyle  = 'FixedSingle'
$txtRep.BackColor    = $ColCard
$txtRep.Font         = $FontMono
$txtRep.Anchor       = 'Top,Bottom,Left,Right'
$form.Controls.Add($txtRep)

# --- footer ---------------------------------------------------------------
$btnRefresh = New-Button 'Refresh'           18  600 90  30 $false
$btnOpen    = New-Object System.Windows.Forms.LinkLabel
$btnOpen.Text     = 'Open full report'
$btnOpen.Location = New-Object System.Drawing.Point(118,608)
$btnOpen.Size     = New-Object System.Drawing.Size(110,20)
$btnTest    = New-Object System.Windows.Forms.LinkLabel
$btnTest.Text     = 'Test notification'
$btnTest.Location = New-Object System.Drawing.Point(236,608)
$btnTest.Size     = New-Object System.Drawing.Size(110,20)
$btnDocs    = New-Object System.Windows.Forms.LinkLabel
$btnDocs.Text     = 'Read me'
$btnDocs.Location = New-Object System.Drawing.Point(354,608)
$btnDocs.Size     = New-Object System.Drawing.Size(60,20)
$btnClose   = New-Button 'Close' 656 600 90 30 $false
foreach ($c in @($btnRefresh,$btnOpen,$btnTest,$btnDocs,$btnClose)) { $c.Anchor='Bottom,Left'; $form.Controls.Add($c) }

# Nothing here changes the machine except the four action buttons, and that is
# not obvious from the labels alone - "Refresh" in particular reads like it might
# go and do something.
$tip = New-Object System.Windows.Forms.ToolTip
$tip.AutoPopDelay = 12000
$tip.InitialDelay = 400
$tip.SetToolTip($btnRefresh, "Re-reads the machine and repaints this window: service start types, whether the registry keys are still locked, the guard and checker tasks, firewall rules and the last saved report.`r`n`r`nChanges nothing, contacts nobody, needs no admin rights. Use it after something else may have altered the block.")
$tip.SetToolTip($btnCheck,   "Asks Microsoft's MSRC feed and the CISA exploited-vulnerability catalogue whether anything unpatched on this build is genuinely urgent. Read-only - it does not install anything.")
$tip.SetToolTip($btnUpdate,  "Unblocks Windows Update, installs what is pending, then re-applies the block automatically. Needs admin rights.")
$tip.SetToolTip($btnBlock,   "Re-applies the full block. Safe to run at any time. Needs admin rights.")
$tip.SetToolTip($btnUnblock, "Turns Windows Update back on permanently and leaves it on - including automatic reboots. Needs admin rights.")
$tip.SetToolTip($btnOpen,    "Opens the last check's full report in Notepad.")
$tip.SetToolTip($btnTest,    "Raises a sample notification so you can confirm toasts still reach you.")
$btnClose.Anchor = 'Bottom,Right'

$lblBusy          = New-Object System.Windows.Forms.Label
$lblBusy.Location = New-Object System.Drawing.Point(430,608)
$lblBusy.Size     = New-Object System.Drawing.Size(220,20)
$lblBusy.ForeColor= $ColWarn
$lblBusy.TextAlign= 'MiddleRight'
$lblBusy.Anchor   = 'Bottom,Right'
$form.Controls.Add($lblBusy)

# ---------------------------------------------------------------------------
# Refresh
# ---------------------------------------------------------------------------
function Update-Ui {
    $rows = Get-ServiceRows
    $lv.Items.Clear()
    foreach ($r in $rows) {
        $it = New-Object System.Windows.Forms.ListViewItem($r.Name)
        [void]$it.SubItems.Add($r.Start)
        [void]$it.SubItems.Add($r.Running)
        [void]$it.SubItems.Add($r.Locked)
        $it.ForeColor = if ($r.Ok) { $ColGood } else { $ColBad }
        [void]$lv.Items.Add($it)
    }

    switch (Get-OverallState) {
        'blocked' {
            $lblState.Text = 'Windows Update is BLOCKED'
            $lblState.ForeColor = $ColGood
            $lblStateSub.Text = 'All update services are disabled and their registry keys are locked against SYSTEM.'
        }
        'open' {
            $lblState.Text = 'Windows Update is ACTIVE'
            $lblState.ForeColor = $ColBad
            $lblStateSub.Text = 'Windows can install updates and restart this PC on its own.'
        }
        'partial' {
            $lblState.Text = 'Windows Update is PARTLY blocked'
            $lblState.ForeColor = $ColWarn
            $lblStateSub.Text = 'Some services are not disabled or not locked. Re-apply the block.'
        }
        default {
            $lblState.Text = 'State unknown'
            $lblState.ForeColor = $ColWarn
            $lblStateSub.Text = 'Could not read the service configuration.'
        }
    }

    # protection panel
    $p = @()
    $chk = Get-TaskState 'NukeWU-UpdateCheck'
    $p += "Critical-update check : $(if ($chk) { $chk } else { 'not installed' })"
    $grd = Get-TaskState 'NukeWU-Guard'
    if ($grd)        { $p += "Block guard (SYSTEM)  : $grd" }
    elseif ($IsAdmin){ $p += "Block guard (SYSTEM)  : MISSING" }
    else             { $p += "Block guard (SYSTEM)  : hidden (admin only)" }
    $rearm = Get-TaskState 'NukeWU-ReArm'
    if ($rearm) { $p += "Re-arm pending        : yes ($rearm)" }
    try {
        $fw = @(Get-NetFirewallRule -Group 'NukeWU' -ErrorAction Stop).Count
        $p += "Firewall rules        : $fw"
    } catch { $p += "Firewall rules        : ?" }
    $p += ''
    $p += "Build : $((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuild).$((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').UBR)"
    $txtProt.Lines = $p

    # report
    if (Test-Path $ReportTxt) {
        $when = (Get-Item $ReportTxt).LastWriteTime
        $summary = ''
        try {
            $j = Get-Content $ReportJson -Raw | ConvertFrom-Json
            if ([int]$j.urgent -gt 0 -or [int]$j.high -gt 0) {
                $summary = " - $($j.urgent) urgent, $($j.high) high"
            } else { $summary = ' - nothing crucial' }
        } catch {}
        $lblRep.Text = "Last check: $($when.ToString('yyyy-MM-dd HH:mm'))$summary"
        $txtRep.Text = (Get-Content $ReportTxt -Raw)
    } else {
        $lblRep.Text = 'Last check: never - press "Check for critical updates"'
        $txtRep.Text = ''
    }
}

# ---------------------------------------------------------------------------
# Running child processes without freezing the window
# ---------------------------------------------------------------------------
$script:proc = $null
$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 400

function Set-Busy {
    param([string]$What)
    $script:busyText = $What
    $lblBusy.Text = $What
    foreach ($b in @($btnCheck,$btnUpdate,$btnBlock,$btnUnblock,$btnRefresh)) { $b.Enabled = -not $What }
    $form.Cursor = if ($What) { 'AppStarting' } else { 'Default' }
}

function Start-Action {
    param([string]$File,[string[]]$Extra,[switch]$Elevated,[string]$Busy,[switch]$Visible)
    if ($script:proc) { return }
    # deliberately not $args - that is an automatic variable
    $argList = @('-NoProfile','-ExecutionPolicy','Bypass','-File',"`"$File`"") + $Extra
    try {
        $sp = @{ FilePath = $PSExe; ArgumentList = $argList; PassThru = $true }
        if ($Elevated) { $sp['Verb'] = 'RunAs' }
        if (-not $Visible) { $sp['WindowStyle'] = 'Hidden' }
        $script:proc = Start-Process @sp -ErrorAction Stop
        Set-Busy $Busy
        $timer.Start()
    } catch {
        # Most common cause: the user dismissed the UAC prompt.
        $script:proc = $null
        Set-Busy ''
        [void][System.Windows.Forms.MessageBox]::Show($form,
            "Could not start:`n$($_.Exception.Message)", 'Windows Update Control',
            'OK','Warning')
    }
}

$timer.Add_Tick({
    if ($script:proc -and $script:proc.HasExited) {
        $timer.Stop()
        $script:proc = $null
        Set-Busy ''
        Update-Ui
    }
})

# ---------------------------------------------------------------------------
# Events
# ---------------------------------------------------------------------------
$btnCheck.Add_Click({
    if (-not (Test-Path $Checker)) {
        [void][System.Windows.Forms.MessageBox]::Show($form,"Missing:`n$Checker",'Windows Update Control','OK','Error'); return
    }
    Start-Action -File $Checker -Extra @('-Quiet') -Busy 'Checking MSRC + CISA KEV...'
})

$btnUpdate.Add_Click({
    if (-not (Test-Path $Updater)) {
        [void][System.Windows.Forms.MessageBox]::Show($form,"Missing:`n$Updater",'Windows Update Control','OK','Error'); return
    }
    $r = [System.Windows.Forms.MessageBox]::Show($form,
        "This will:`n`n  1. Arm the automatic re-block (before anything else)`n  2. Unblock Windows Update`n  3. Install pending updates`n  4. Put the block back, including across a reboot`n`nA console window will open so you can watch it.`n`nContinue?",
        'Update now (safely)','YesNo','Question')
    if ($r -ne 'Yes') { return }
    Start-Action -File $Updater -Elevated -Visible -Busy 'Update window open...'
})

$btnBlock.Add_Click({
    Start-Action -File $Disable -Extra @('-Quiet') -Elevated -Busy 'Re-applying the block...'
})

$btnUnblock.Add_Click({
    $r = [System.Windows.Forms.MessageBox]::Show($form,
        "This turns Windows Update back on PERMANENTLY and removes the guard task.`n`nWindows will then be free to install updates and restart this PC on its own again.`n`nIf you only want to install updates and keep the block, press Cancel and use `"Update now (safely)`" instead.`n`nUnblock permanently?",
        'Unblock Windows Update','OKCancel','Warning')
    if ($r -ne 'OK') { return }
    Start-Action -File $Enable -Elevated -Busy 'Unblocking...'
})

$btnRefresh.Add_Click({ Update-Ui })
$btnClose.Add_Click({ $form.Close() })

$btnOpen.Add_LinkClicked({
    if (Test-Path $ReportTxt) { Start-Process notepad.exe $ReportTxt }
    else { [void][System.Windows.Forms.MessageBox]::Show($form,'No report yet - run a check first.','Windows Update Control','OK','Information') }
})

$btnTest.Add_LinkClicked({
    Start-Action -File $Checker -Extra @('-Simulate','-Force','-Quiet') -Busy 'Sending a test notification...'
})

$btnDocs.Add_LinkClicked({
    $doc = Join-Path $ScriptDir 'README.md'
    if (Test-Path $doc) { Start-Process notepad.exe $doc }
})

$form.Add_Shown({
    Update-Ui
    # Belt and braces: force the window visible and focused even if the process
    # was started with an odd STARTUPINFO show-state.
    try { [void][Win32.Dpi]::ShowWindow($form.Handle, 1) } catch {}   # 1 = SW_SHOWNORMAL
    $form.WindowState = 'Normal'
    $form.TopMost = $true; $form.TopMost = $false
    $form.Activate()
})
[void]$form.ShowDialog()
$timer.Dispose()
$form.Dispose()
