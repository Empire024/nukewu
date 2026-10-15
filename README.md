# NukeWU — Windows Update, blocked (and how to unblock it)

Disables Windows Update on Windows 10/11 and **locks it so Windows cannot quietly
turn it back on**, with a guard task that re-applies the block, a one-click undo, an
"update now, safely" path that re-blocks itself after the reboot, and a checker
that watches MSRC + CISA KEV so you still hear about a patch that genuinely
matters. Everything is reversible; nothing here needs a third-party tool.

## Install

In any PowerShell on the target machine (elevated or not; the block step raises a
UAC prompt if it has to):

```powershell
irm https://raw.githubusercontent.com/Empire024/nukewu/main/install.ps1 | iex
```

That downloads this repo to `C:\ProgramData\NukeWU`, creates the Start Menu
shortcuts and the checker task, applies the block and prints the service state.
Git is used if present and not required otherwise. Options:

```powershell
# files + shortcuts only, do not touch Windows Update yet
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/Empire024/nukewu/main/install.ps1))) -NoBlock
# other folder / also rename the update binaries
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/Empire024/nukewu/main/install.ps1))) -Dest D:\Tools\NukeWU -Scorched
```

Or clone the repo anywhere and double-click `NUKE-WINDOWS-UPDATE.cmd`.
Re-running the installer updates an existing install in place.

Requirements: Windows 10/11 x64 (built and verified on Windows 11 Home 25H2),
Windows PowerShell 5.1 (built in), an administrator account for the block and
the undo. The Windows release is detected at run time, so any current build works.

## Background: what happened on 2026-09-09

The machine was supposed to stay on overnight. It rebooted three times instead:

| Time | Event |
|---|---|
| 03:31–03:36 | KB5124007, KB5124008, KB5126052 staged and installed by `UpdateAgentLCU` |
| 04:14:36 | Servicing flagged "a reboot is necessary" |
| 04:15 / 04:16 / 04:17 | Three restarts, initiated by `TrustedInstaller.exe`, reason `Operating System: Upgrade (Planned)` |
| 04:18:47 | Final boot; packages committed |

No crash, no bugcheck, no power loss. Event IDs 41/6008/1001 are all absent and there
are no minidumps. This was Windows Update, start to finish.

**Why it was allowed at 4am:** active hours are 09:00–03:00, so 03:00–09:00 is the
window Windows treats as free to restart in.

## Why the first block failed

`Disable-WindowsUpdate.ps1` v1 ran on 2026-08-16 and set the update services to
`Start=4` (Disabled). By 2026-09-09 Windows had written them back:

| Service | v1 set | Found on 09-09 |
|---|---|---|
| `wuauserv` | 4 | **3 (Manual), running** |
| `UsoSvc` | 4 | **2 (Automatic), running** |
| `WaaSMedicSvc` | 4 | **3 (Manual)** |

The policy keys and the task disables from v1 *did* survive — only the service
`Start` values were reverted. Setting a registry value that SYSTEM is still
allowed to overwrite is not a block; the servicing stack just wrote it back and
`UsoSvc` started at boot as normal.

## What v2 does differently

Two key changes.

**a) Deny SYSTEM the write.** After setting `Start=4`, v2 **takes ownership of each
service key and denies write access to SYSTEM and TrustedInstaller**. Read access
is left alone on purpose — denying read would stop the Service Control Manager
reading service config at boot, which is how people brick machines doing this.

**b) Tell the SCM, not just the registry.** Writing `Start=4` straight into the
registry does *not* update the Service Control Manager's in-memory copy of the
service config. The first run of v2 hit exactly this: the registry said Disabled,
but the SCM still believed Manual/Automatic, happily started `wuauserv` and
`UsoSvc` on demand, and a running `UsoSvc` then re-enabled its own `Schedule Scan`
and `Schedule Scan Static Task`. v2 now calls `sc.exe config <svc> start= disabled`
**before** freezing the key (the SCM performs that write as SYSTEM, so it has to
happen before the lock), and sweeps the tasks a second time once the services are
genuinely unstartable.

Full layer list:

1. **Services** `wuauserv`, `UsoSvc`, `WaaSMedicSvc`, `DoSvc`, `uhssvc` — stopped,
   `Start=4`, registry key ACL-locked against SYSTEM + TrustedInstaller.
2. **Policy keys** — `NoAutoUpdate`, `AUOptions=1`, a dead WSUS server, no driver
   delivery, feature updates pinned to the current release.
3. **Update UX** — pause pinned to 2099, restart notifications off.
4. **Scheduled tasks** — everything under `UpdateOrchestrator`, `WindowsUpdate`,
   `WaaSMedic`, `InstallService` disabled, taking ownership of the protected
   `Reboot_AC` / `Reboot_BAT` tasks first.
5. **Firewall** — outbound block scoped *to the update services themselves*, so
   Defender definitions, the Store and browsers are unaffected.
6. **Wake timers** — disabled, so nothing can wake the box to update it.
7. **`-Scorched`** (opt-in) — renames `UsoClient.exe`, `MoUsoCoreWorker.exe`,
   `WaaSMedicSvc.dll`, `WaaSMedicAgent.exe`, `wuauclt.exe` to `*.nuked`.
8. **Guard task** `NukeWU-Guard` — re-applies all of the above at every boot and
   daily at 12:00, as SYSTEM. If a feature upgrade ever resets things, it snaps
   back within a day.

### Deliberately NOT touched

- **BITS** — a generic transfer service used by Chrome, the Store and many
  installers. Disabling it breaks unrelated software and does not stop Windows
  Update on its own.
- **TrustedInstaller / `InstallService`** — needed for optional features and the
  Store. Their update-scanning *tasks* are disabled instead.
- **Read access on any key** — see above.

---

## TO GO BACK

**Double-click `UNDO-WINDOWS-UPDATE.cmd`** and accept the UAC prompt.

Or from a terminal (wherever you installed it):

```powershell
C:\ProgramData\NukeWU\Enable-WindowsUpdate.ps1
```

The undo removes the guard task *first* so nothing re-applies the block behind
it, then reverses every layer in order: renames binaries back, restores wake
timers, deletes the firewall rules, re-enables the tasks, deletes the policy
keys, strips the deny ACEs, restores the original security descriptors and the
original `Start` values, then starts the services and triggers a scan.

It prints a verification table at the end. **`StillLocked` must read `False`
everywhere.**

### What makes the undo reliable

Before anything is changed, `Disable-WindowsUpdate.ps1` writes
`C:\ProgramData\DisableWU\manifest.json` containing:

- original `Start` value for every service it touches
- original ACL of every key it locks, as SDDL
- original wake-timer AC/DC power values
- every task it disabled
- every file it renamed

plus timestamped `.reg` exports of the policy and UX branches in the same folder.
If that folder is ever deleted the undo still runs, falling back to documented
Windows defaults.

---

## Verified on 2026-09-09

Final state after applying:

```
Service      Start Means    SCM          Running KeyLocked
wuauserv         4 Disabled 4   DISABLED Stopped      True
UsoSvc           4 Disabled 4   DISABLED Stopped      True
WaaSMedicSvc     4 Disabled 4   DISABLED Stopped      True
DoSvc            4 Disabled 4   DISABLED Stopped      True
```

**Adversarial test.** A probe was run *as `NT AUTHORITY\SYSTEM`* — the exact
identity that reverted v1 — attempting to set each service back to `Start=3` and
then start it:

```
identity: NT AUTHORITY\SYSTEM
wuauserv     : DENIED (SecurityException)   Start is now 4
UsoSvc       : DENIED (SecurityException)   Start is now 4
WaaSMedicSvc : DENIED (SecurityException)   Start is now 4
DoSvc        : DENIED (SecurityException)   Start is now 4
wuauserv : start refused
UsoSvc   : start refused
```

All update scheduled tasks confirmed disabled afterwards.

**The undo was tested too**, on a single locked key (`DoSvc`) so Windows Update
was never actually re-opened: deny ACEs removed, `Start` restored to 2, SCM back
to `AUTO_START`, and a second SYSTEM probe confirmed `SYSTEM CAN WRITE` again.
That test also caught a real bug — Windows rejects `NT SERVICE\TrustedInstaller`
as a key owner (`The security identifier is not allowed to be the owner of this
object`), which could have aborted the permission restore. The undo now restores
permissions and ownership as separate steps, so an owner refusal cannot roll back
the fix. One cosmetic consequence: after undoing, these keys may be owned by
`BUILTIN\Administrators` rather than `TrustedInstaller`. The services work
normally either way.

## Things worth knowing

- **Delivery Optimization (`DoSvc`) is disabled**, which is part of the update
  delivery stack. Microsoft Store downloads use it too, so Store installs may be
  slower or occasionally fail while the block is on. `BITS` is deliberately left
  running so most other software is unaffected. If Store downloads matter to you,
  the undo brings `DoSvc` back.
- **The guard task is invisible from a non-elevated shell.** It runs as SYSTEM, so
  `Get-ScheduledTask -TaskName NukeWU-Guard` says "not found" unless the shell is
  elevated. That is normal, not a missing task.
- **You get no security patches while this is applied.** That is the intent, but
  it is a real trade-off. Nothing else changes about how the machine runs.
- **Before deliberately upgrading Windows** (e.g. 25H2 → 26H1), run the undo
  first. Servicing writes to these keys, and a locked key can fail an upgrade
  partway through.
- **To check the block is still holding:**

  ```powershell
  Get-Service wuauserv,UsoSvc,WaaSMedicSvc | Select Name,Status,StartType
  ```

  All three should read `Stopped` / `Disabled`.

- `sc config` is refused (exit 5) on `WaaSMedicSvc` and `DoSvc` — those two have
  restrictive service-object permissions even for administrators. Their registry
  keys are still set and locked, so they are disabled from the next boot onward;
  the script reports this as `SCM=stale-until-reboot` rather than hiding it.

## The critical-update checker

Windows Update can no longer scan, so nothing on this PC would ever tell you a
patch actually matters. `Check-CriticalUpdates.ps1` replaces that signal using two
public feeds that do not involve Windows Update at all:

- **MSRC Security Update Guide (CVRF)** — per CVE: affected products, severity,
  CVSS, whether it is exploited in the wild, and the KB + exact `FixedBuild`.
- **CISA Known Exploited Vulnerabilities** — the authoritative "this is being used
  against real people right now" list.

**How "am I patched?" is decided:** not with `Get-HotFix`, which is unreliable for
cumulative updates. It compares this machine's build revision against the
`FixedBuild` MSRC lists for our exact product (`Windows 11 Version 25H2 for
x64-based Systems`, MSRC product ID `20438`, both worked out at run time). A PC on
`10.0.26200.9445` treats a CVE fixed in `.9445` as patched and one fixed in `.9600` as not.

**What raises a notification** — nothing else does, so the toast keeps meaning
something:

| Tier | Condition |
|---|---|
| `URGENT` | Affects us, unpatched, AND exploited in the wild (MSRC) or listed in CISA KEV |
| `HIGH` | Affects us, unpatched, AND Critical severity AND CVSS >= 9.0 AND network-reachable (`AV:N`) |

It will not nag: it re-notifies only when the set of CVEs changes, or after 7 days
if the same ones are still unpatched.

It runs **as you, not as SYSTEM** — a toast raised by SYSTEM is shown to nobody —
at logon +5 minutes and daily at 13:00, via the `NukeWU-UpdateCheck` task.

### If you miss or dismiss the notification

The toast is not the only way in, and it is not meant to be. **Press Start and type
"Windows Update"** — four shortcuts are installed under *Windows Update Control*:

| Shortcut | Does |
|---|---|
| Windows Update Control | **The UI — status and all four actions in one window** |
| Windows Update - check if I need one | Runs the check now and prints the report |
| Windows Update - update now (safely) | Unblock -> install -> re-block, automatically |
| Windows Update - unblock (undo) | Turn Windows Update back on permanently |
| Windows Update - re-block | Re-apply the block |

The last report is always on disk at `%LOCALAPPDATA%\NukeWU\last-report.txt`,
whether or not you saw the toast.

> Note: clicking the **body** of the notification originally did nothing but
> dismiss it. That was a bug — the toast declared `launch="nukewu:open"` with no
> `activationType`, so it defaulted to `foreground`, which needs a registered COM
> activator that PowerShell does not have. It is now `activationType="protocol"`,
> so clicking the body opens the updater like the button does.

## Updating without giving up the block

`UPDATE-NOW.cmd` -> `Invoke-UpdateWindow.ps1` is the "yes, I want this patch" path.
It exists so unblocking is never something you have to remember to reverse.

1. **Arms `NukeWU-ReArm` first**, before anything is unblocked. From that moment
   the block returns on the next boot even if the machine crashes, loses power, or
   you walk away mid-update.
2. Runs the undo.
3. Installs pending software updates through the Windows Update COM API (drivers
   excluded).
4. If a reboot is needed it asks. `NukeWU-ReArm` re-applies the block after that
   reboot — **waiting for TiWorker/TrustedInstaller to go idle first**, so it
   cannot interrupt Windows finishing an install — then deletes itself. If no
   reboot is needed, the block goes back immediately and the re-arm task is
   removed.

Useful flags: `-NoInstall` (unblock, list what is pending, install nothing,
re-block), `-Yes` (no prompts), `-AutoReboot`.

### Verified end to end

A full round trip was run with `-NoInstall -Yes`: re-arm armed -> block removed
(all four services unlocked, `StillLocked=False`, original ACLs restored from the
manifest) -> update search ran successfully against Microsoft (0 updates, matching
the checker) -> block re-applied, all four services back to `Stopped`/`Disabled`,
re-arm task cleaned up.

The detection logic was verified against real MSRC data by pretending the machine
was on an older build (`-PretendUbr 9000`). It correctly flagged **CVE-2026-81963**
(Windows Update Stack privesc) and **CVE-2026-68820** (AFD privesc) as `URGENT`,
both exploited in the wild and in CISA KEV, plus ten CVSS 9.8 remote-code-execution
issues as `HIGH`.

## The UI

`WindowsUpdateControl.ps1` is a small WinForms window that puts all of the above
behind buttons. It is the easiest way in — **press Start and type "Windows Update",
then pick "Windows Update Control"** (or run `WINDOWS-UPDATE-UI.cmd`).

It shows:

- whether the block is **BLOCKED / PARTLY blocked / ACTIVE**, derived from the
  live service state and whether the deny-ACEs are actually present
- each update service: start type, running state, key-locked
- the guard task, the checker task, any pending re-arm, firewall rule count, build
- the last critical-update check, in full

and gives you four buttons: **Check for critical updates**, **Update now (safely)**,
**Re-apply block**, **Unblock permanently** — plus links for the full report, a
test notification, and this document.

**Refresh** only re-reads the machine and repaints the window — service start
types, whether the registry keys are still locked, the guard and checker tasks,
firewall rules, and the last saved report. It changes nothing, contacts nothing
and needs no admin rights. Use it after something else may have altered the
block (an elevated run from a terminal, a Windows feature update, a reboot).
Every control has a tooltip saying what it does and whether it needs admin.

### Icons

`assets\nukewu-block.ico` (red prohibition sign) and `assets\nukewu-update.ico`
(green download arrow) are generated artwork, not stock Windows icons. They are
used for the window and taskbar button, and for all five Start Menu shortcuts —
otherwise everything inherits `powershell.exe`'s icon. `assets\nukewu-block.png`
is the same art as a PNG, because toasts cannot read `.ico`.

Toasts also register their own AppUserModelID under
`HKCU\Software\Classes\AppUserModelId\NukeWU.WindowsUpdateControl`, which is
what makes a notification say **"Windows Update Control"** instead of
**"Windows PowerShell"**. If that registration ever fails the code falls back to
borrowing PowerShell's AUMID — an ugly toast is much better than no toast, since
this is the safety net for a machine that cannot patch itself. `-Uninstall`
removes the key.

The window itself runs **as you, not elevated**, so there is never a privileged
process sitting open on your desktop. Reading status needs no admin rights; the
three actions that do launch elevated on their own and raise a normal UAC prompt.
Actions run as a child process polled by a timer, so the window never freezes
while a check or an update is running.

> Gotcha worth recording: do **not** launch this script with
> `-WindowStyle Hidden`. That sets `SW_HIDE` in the process STARTUPINFO, which
> .NET applies to the *first window the process creates* — which is the form, not
> the console. The window then never appears, while the process sits there alive.
> It is launched normally and hides its own console from the inside instead.

## Files

| File | What it is |
|---|---|
| `install.ps1` | **One-line installer**: downloads this repo, adds the shortcuts and checker, applies the block |
| `WINDOWS-UPDATE-UI.cmd` | **The UI — start here** |
| `WindowsUpdateControl.ps1` | The UI itself |
| `NUKE-WINDOWS-UPDATE.cmd` | Double-click to apply the block |
| `UNDO-WINDOWS-UPDATE.cmd` | **Double-click to undo it** |
| `Disable-WindowsUpdate.ps1` | The block. `-Scorched`, `-Quiet`, `-NoGuard` |
| `Enable-WindowsUpdate.ps1` | The undo |
| `CHECK-UPDATES.cmd` | Check whether anything urgent is outstanding |
| `Check-CriticalUpdates.ps1` | The checker. `-Install`, `-Simulate`, `-Force`, `-PretendUbr` |
| `UPDATE-NOW.cmd` | **Update safely: unblock -> install -> re-block** |
| `Invoke-UpdateWindow.ps1` | The update window. `-NoInstall`, `-Yes`, `-AutoReboot` |
| `assets\` | Icons for the window, shortcuts and toasts |
| `assets\make-icons.ps1` | Regenerates that artwork |
| `C:\ProgramData\DisableWU\manifest.json` | Everything needed to reverse it |
| `%LOCALAPPDATA%\NukeWU\last-report.txt` | The most recent check result |

## Scheduled tasks

| Task | Runs as | When |
|---|---|---|
| `NukeWU-Guard` | SYSTEM | Boot + daily 12:00 - re-applies the block if Windows resets it |
| `NukeWU-UpdateCheck` | you | Logon +5min + daily 13:00 - the critical-update check |
| `NukeWU-ReArm` | SYSTEM | Only exists during an update window; self-deletes |

`NukeWU-Guard` and `NukeWU-ReArm` run as SYSTEM, so they are invisible to
`Get-ScheduledTask` from a non-elevated shell. That is normal.
