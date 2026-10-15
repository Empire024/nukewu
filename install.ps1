<#
.SYNOPSIS
    Installs NukeWU - the Windows Update removal tool - straight from GitHub.

.DESCRIPTION
    1. Downloads the tool into the install folder (default C:\ProgramData\NukeWU).
       Uses git if it is on the PATH, otherwise the repo zip - git is not required.
    2. Registers the Start Menu shortcuts ("Windows Update Control"), the toast
       protocol handler and the critical-update checker task.
    3. Applies the Windows Update block (Disable-WindowsUpdate.ps1). This needs
       admin rights: run from an elevated shell and it happens inline, otherwise a
       UAC prompt appears and the block runs in its own window. Skip with -NoBlock.

    One-liner, any PowerShell (elevated or not):

        irm https://raw.githubusercontent.com/Empire024/nukewu/main/install.ps1 | iex

    With options:

        & ([scriptblock]::Create((irm https://raw.githubusercontent.com/Empire024/nukewu/main/install.ps1))) -NoBlock

    Undo later with <install folder>\UNDO-WINDOWS-UPDATE.cmd. See README.md.

.PARAMETER Dest
    Install folder. Default: C:\ProgramData\NukeWU (machine-wide, readable by the
    user-level UI and the SYSTEM-level guard task alike).
.PARAMETER NoBlock
    Download and register shortcuts only. Do not touch Windows Update.
.PARAMETER Scorched
    Also rename the update binaries (UsoClient.exe etc.). Off by default; README.
.PARAMETER Ref
    Branch or tag to install. Default: main.
#>
[CmdletBinding()]
param(
    [string]$Dest = (Join-Path $env:ProgramData 'NukeWU'),
    [switch]$NoBlock,
    [switch]$Scorched,
    [string]$Ref = 'main'
)

$ErrorActionPreference = 'Stop'
try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch {}

$Repo    = 'Empire024/nukewu'
$RepoUrl = "https://github.com/$Repo"
$ZipUrl  = "$RepoUrl/archive/$Ref.zip"

function Say { param($m, $c = 'Gray') Write-Host $m -ForegroundColor $c }

if ($env:OS -ne 'Windows_NT') { throw 'NukeWU only runs on Windows.' }
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
           ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

Say "==================================================" Cyan
Say "  NukeWU installer   $RepoUrl  ($Ref)"            Cyan
Say "==================================================" Cyan
Say "  install folder : $Dest"
Say "  elevated       : $isAdmin"
Say "  apply block    : $(-not $NoBlock)"

# ---------------------------------------------------------------------------
# [1] Fetch
# ---------------------------------------------------------------------------
$git = Get-Command git.exe -ErrorAction SilentlyContinue
if ($git -and (Test-Path (Join-Path $Dest '.git'))) {
    Say "`n[1] Updating the existing clone in $Dest..." Green
    & git -C $Dest fetch --quiet origin
    if ($LASTEXITCODE -ne 0) { throw "git fetch failed ($LASTEXITCODE)" }
    & git -C $Dest checkout --quiet $Ref
    if ($LASTEXITCODE -ne 0) { throw "git checkout $Ref failed ($LASTEXITCODE)" }
    & git -C $Dest pull --quiet --ff-only origin $Ref
    if ($LASTEXITCODE -ne 0) { throw "git pull failed ($LASTEXITCODE)" }
} elseif ($git -and -not (Test-Path $Dest)) {
    Say "`n[1] Cloning into $Dest..." Green
    & git clone --quiet --branch $Ref "$RepoUrl.git" $Dest
    if ($LASTEXITCODE -ne 0) { throw "git clone failed ($LASTEXITCODE)" }
} else {
    Say "`n[1] Downloading $ZipUrl..." Green
    $tmp = Join-Path $env:TEMP ('nukewu-' + [guid]::NewGuid().ToString('n'))
    $null = New-Item -ItemType Directory -Path $tmp -Force
    $zip = Join-Path $tmp 'nukewu.zip'
    Invoke-WebRequest -Uri $ZipUrl -OutFile $zip -UseBasicParsing
    Expand-Archive -Path $zip -DestinationPath $tmp -Force
    $root = Get-ChildItem -Path $tmp -Directory | Select-Object -First 1
    if (-not $root) { throw 'zip did not contain a folder' }
    $null = New-Item -ItemType Directory -Path $Dest -Force
    Copy-Item -Path (Join-Path $root.FullName '*') -Destination $Dest -Recurse -Force
    Remove-Item -Path $tmp -Recurse -Force -ErrorAction SilentlyContinue
}

$required = 'Disable-WindowsUpdate.ps1','Enable-WindowsUpdate.ps1','Check-CriticalUpdates.ps1',
            'Invoke-UpdateWindow.ps1','WindowsUpdateControl.ps1'
foreach ($f in $required) {
    if (-not (Test-Path (Join-Path $Dest $f))) { throw "download incomplete: $f missing from $Dest" }
}
# Strip the mark-of-the-web so nothing is treated as a blocked download.
Get-ChildItem -Path $Dest -Recurse -File | Unblock-File -ErrorAction SilentlyContinue
Say "  - $((Get-ChildItem -Path $Dest -Recurse -File).Count) files in place"

# ---------------------------------------------------------------------------
# [2] Shortcuts, protocol handler, checker task (no admin needed)
# ---------------------------------------------------------------------------
Say "`n[2] Start Menu shortcuts, toast protocol, critical-update checker..." Green
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Dest 'Check-CriticalUpdates.ps1') -Install

# ---------------------------------------------------------------------------
# [3] The block
# ---------------------------------------------------------------------------
if ($NoBlock) {
    Say "`n[3] Block NOT applied (-NoBlock). Apply later with $Dest\NUKE-WINDOWS-UPDATE.cmd" Yellow
} else {
    Say "`n[3] Applying the Windows Update block..." Green
    $blockArgs = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$(Join-Path $Dest 'Disable-WindowsUpdate.ps1')`"")
    if ($Scorched) { $blockArgs += '-Scorched' }
    if ($isAdmin) {
        & powershell.exe @blockArgs
    } else {
        Say "  not elevated - accept the UAC prompt; the block runs in its own window and this one waits for it." Yellow
        try {
            Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList $blockArgs -Wait -ErrorAction Stop
        } catch {
            Say "  elevation cancelled - block not applied. Run $Dest\NUKE-WINDOWS-UPDATE.cmd later." Red
        }
    }
}

# ---------------------------------------------------------------------------
# [4] Result
# ---------------------------------------------------------------------------
Say "`n[4] Update services now:" Green
Get-Service -Name wuauserv, UsoSvc, WaaSMedicSvc, DoSvc -ErrorAction SilentlyContinue |
    Format-Table Name, Status, StartType -AutoSize | Out-String | Write-Host
if (-not $NoBlock) { Say "  Blocked = every row reads Stopped / Disabled." DarkGray }

Say "Installed to $Dest" Cyan
Say "  UI      : press Start, type 'Windows Update', pick 'Windows Update Control'  (or $Dest\WINDOWS-UPDATE-UI.cmd)"
Say "  Undo    : $Dest\UNDO-WINDOWS-UPDATE.cmd"
Say "  Update  : $Dest\UPDATE-NOW.cmd   (unblock -> install -> re-block)"
Say "  Docs    : $Dest\README.md"
