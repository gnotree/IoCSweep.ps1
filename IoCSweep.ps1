<#
.SYNOPSIS
  IoCSweep.ps1 — Windows host sweep for Indicators of Compromise (IoCs).

.DESCRIPTION
  Read-only triage that inventories common persistence/running surfaces and optionally
  matches user-provided IoCs. Outputs CSV/TXT into a timestamped folder under a
  configurable output root.

  Output root resolution (in order):
    1) -OutputRoot parameter
    2) $env:HOSTAUDIT_ROOT
    3) "$HOME\Reports\HostAudit"

.PARAMETER IoCFile
  Optional path to a newline-delimited list (hashes, filenames, domains, paths).

.PARAMETER HashTrees
  Optional list of directories to hash recursively for *.exe;*.dll;*.sys (slow).

.PARAMETER OutputRoot
  Optional explicit output root (overrides HOSTAUDIT_ROOT env var).

.PARAMETER RecentDays
  How many days back for "recent files" collection (default: 7).

.PARAMETER NoExplorer
  Do not open Explorer on the results folder after completion.

.NOTES
  • Requires PowerShell 7+ and administrative rights (auto-elevates).
  • Repository-safe: no environment-specific paths embedded.
  • All actions are read-only; no system modifications.

.EXAMPLES
  pwsh -File .\IoCSweep.ps1
  pwsh -File .\IoCSweep.ps1 -IoCFile 'C:\feeds\ioc_list.txt'
  pwsh -File .\IoCSweep.ps1 -HashTrees 'C:\Windows\System32','C:\Program Files'
  pwsh -File .\IoCSweep.ps1 -OutputRoot 'D:\Forensics\HostAudits' -NoExplorer
#>

[CmdletBinding()]
param(
  [string]$IoCFile,
  [string[]]$HashTrees,
  [string]$OutputRoot,
  [int]$RecentDays = 7,
  [switch]$NoExplorer
)

# ----------------------------- Elevation -----------------------------
function Ensure-Admin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $p  = [Security.Principal.WindowsPrincipal]::new($id)
  if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[*] Elevation required — relaunching as admin..." -ForegroundColor Yellow
    $pwshExe = Join-Path $PSHOME 'pwsh.exe'
    $args = @('-NoLogo','-File',$PSCommandPath)
    if ($IoCFile)   { $args += @('-IoCFile', $IoCFile) }
    if ($HashTrees) { $args += @('-HashTrees'); $args += $HashTrees }
    if ($OutputRoot){ $args += @('-OutputRoot', $OutputRoot) }
    if ($RecentDays -ne 7) { $args += @('-RecentDays', $RecentDays) }
    if ($NoExplorer) { $args += '-NoExplorer' }
    Start-Process -FilePath $pwshExe -ArgumentList $args -Verb RunAs | Out-Null
    exit
  }
}
Ensure-Admin

# ----------------------------- Output Paths -----------------------------
function Resolve-OutputRoot {
  param([string]$Override)
  if ($Override) { return $Override }
  if ($env:HOSTAUDIT_ROOT) { return $env:HOSTAUDIT_ROOT }
  return (Join-Path $HOME 'Reports\HostAudit')
}

$Root = Resolve-OutputRoot -Override $OutputRoot
if (-not (Test-Path $Root)) { New-Item -ItemType Directory -Path $Root -Force | Out-Null }
$HostName = $env:COMPUTERNAME
$Stamp = Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'
$OutDir = Join-Path $Root "${HostName}_${Stamp}"
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

# File targets
$CsvServices = Join-Path $OutDir "IoC_Services_${HostName}_${Stamp}.csv"
$CsvDrivers  = Join-Path $OutDir "IoC_Drivers_${HostName}_${Stamp}.csv"
$CsvAutoruns = Join-Path $OutDir "IoC_Autoruns_${HostName}_${Stamp}.csv"
$CsvTasks    = Join-Path $OutDir "IoC_ScheduledTasks_${HostName}_${Stamp}.csv"
$CsvWMI      = Join-Path $OutDir "IoC_WMIEventSubscriptions_${HostName}_${Stamp}.csv"
$CsvProcs    = Join-Path $OutDir "IoC_Processes_${HostName}_${Stamp}.csv"
$CsvNet      = Join-Path $OutDir "IoC_Network_${HostName}_${Stamp}.txt"
$CsvRecent   = Join-Path $OutDir "IoC_RecentFiles_${HostName}_${Stamp}.csv"
$CsvUnsigned = Join-Path $OutDir "IoC_UnsignedDrivers_${HostName}_${Stamp}.csv"
$CsvHashes   = Join-Path $OutDir "IoC_FileHashes_${HostName}_${Stamp}.csv"
$TxtSummary  = Join-Path $OutDir "IoC_Summary_${HostName}_${Stamp}.txt"

function Write-Sum([string]$s){ $s | Out-File -FilePath $TxtSummary -Append -Encoding UTF8 }
"IoC Sweep: $((Get-Date).ToString('u'))" | Out-File -FilePath $TxtSummary -Encoding UTF8
Write-Sum "Host: $HostName"
Write-Sum "Output: $OutDir`n"

# ----------------------------- Helpers -----------------------------
function Normalize-Path([string]$raw){
  if (-not $raw) { return $null }
  $p = $raw.Trim('"')
  $p = $p -replace '^(\\\\\?\\)',''
  $p = $p -replace '^(?i)\\SystemRoot', "$env:SystemRoot"
  if ($p -match '^(?i)\\Windows\\') { $p = "$($env:SystemDrive)$p" }
  return $p
}

# Load IoCs (if any)
$IoCs = @()
if ($IoCFile) {
  if (-not (Test-Path $IoCFile)) { Write-Warning "IoC file not found: $IoCFile" }
  else { $IoCs = Get-Content -Path $IoCFile | ForEach-Object { $_.Trim() } | Where-Object { $_ } }
}

# ----------------------------- 1) Services -----------------------------
Write-Host "[1/12] Services" -ForegroundColor Cyan
$sv = Get-CimInstance Win32_Service | Select-Object Name,DisplayName,StartMode,State,PathName
$sv | Export-Csv -Path $CsvServices -NoTypeInformation -Encoding UTF8

# ----------------------------- 2) Drivers -----------------------------
Write-Host "[2/12] Drivers" -ForegroundColor Cyan
$drivers = Get-CimInstance Win32_SystemDriver | Select-Object Name,DisplayName,State,StartMode,PathName
$drivers | Export-Csv -Path $CsvDrivers -NoTypeInformation -Encoding UTF8

# ----------------------------- 3) Autoruns -----------------------------
Write-Host "[3/12] Autoruns" -ForegroundColor Cyan
$autorunKeys = @(
  'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
  'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
  'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
  'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
  'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
)
$autoruns = foreach ($k in $autorunKeys) {
  if (Test-Path $k) {
    Get-ItemProperty -Path $k | Select-Object @{n='Key';e={$k}}, * |
      ForEach-Object {
        $props = $_.PSObject.Properties | Where-Object { $_.Name -notin 'PSPath','PSParentPath','PSChildName','PSDrive','PSProvider' }
        foreach ($p in $props) { [pscustomobject]@{ Key=$k; ValueName=$p.Name; Value=$p.Value } }
      }
  }
}
$autoruns | Export-Csv -Path $CsvAutoruns -NoTypeInformation -Encoding UTF8

# ----------------------------- 4) Scheduled Tasks -----------------------------
Write-Host "[4/12] Scheduled Tasks" -ForegroundColor Cyan
$tasks = Get-ScheduledTask | Select-Object TaskName,TaskPath,State,Actions
$tasks | Export-Csv -Path $CsvTasks -NoTypeInformation -Encoding UTF8

# ----------------------------- 5) WMI Subscriptions -----------------------------
Write-Host "[5/12] WMI Subscriptions" -ForegroundColor Cyan
try {
  $wmiFilters = Get-WmiObject -Namespace root\subscription -Class __EventFilter -ErrorAction SilentlyContinue |
               Select-Object Name,Query
  $wmiFilters | Export-Csv -Path $CsvWMI -NoTypeInformation -Encoding UTF8
} catch { Write-Sum "WMI enumeration failed: $($_.Exception.Message)" }

# ----------------------------- 6) Processes -----------------------------
Write-Host "[6/12] Processes" -ForegroundColor Cyan
$procs = Get-CimInstance Win32_Process | Select-Object ProcessId,Name,CommandLine,ExecutablePath
$procs | Export-Csv -Path $CsvProcs -NoTypeInformation -Encoding UTF8

# ----------------------------- 7) Network -----------------------------
Write-Host "[7/12] Network (netstat)" -ForegroundColor Cyan
try { (& netstat -ano) | Out-File -FilePath $CsvNet -Encoding UTF8 } catch { Write-Sum "Netstat failed: $($_.Exception.Message)" }

# ----------------------------- 8) Recent Files -----------------------------
Write-Host "[8/12] Recent Files (last $RecentDays days)" -ForegroundColor Cyan
$folders = @((Join-Path $HOME 'Downloads'), (Join-Path $HOME 'Desktop'), $env:TEMP)
$cutoff = (Get-Date).AddDays(-$RecentDays)
$recent = foreach ($f in $folders) {
  if (Test-Path $f) {
    Get-ChildItem -Path $f -Recurse -ErrorAction SilentlyContinue |
      Where-Object { -not $_.PSIsContainer -and $_.LastWriteTime -ge $cutoff } |
      Select-Object FullName,Length,LastWriteTime
  }
}
$recent | Export-Csv -Path $CsvRecent -NoTypeInformation -Encoding UTF8

# ----------------------------- 9) Unsigned / Non-Microsoft Drivers -----------------------------
Write-Host "[9/12] Driver Signatures" -ForegroundColor Cyan
$driversFull = Get-CimInstance Win32_SystemDriver | Where-Object { $_.PathName -match '\\.sys' }
$unsigned = foreach ($d in $driversFull) {
  $path = Normalize-Path $d.PathName
  if ($path -and (Test-Path $path)) {
    $sig = $null; try { $sig = Get-AuthenticodeSignature -FilePath $path } catch {}
    [pscustomobject]@{
      Name=$d.Name; DisplayName=$d.DisplayName; Path=$path;
      SignatureStatus = $(if ($sig) { $sig.Status } else { 'NoSignature' });
      Publisher = $(if ($sig -and $sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { $null })
    }
  } else {
    [pscustomobject]@{ Name=$d.Name; DisplayName=$d.DisplayName; Path=$path; SignatureStatus='Missing'; Publisher=$null }
  }
}
$unsigned | Where-Object { $_.SignatureStatus -ne 'Valid' -or ($_.Publisher -and $_.Publisher -notmatch 'Microsoft') } |
  Export-Csv -Path $CsvUnsigned -NoTypeInformation -Encoding UTF8

# ----------------------------- 10) Optional Hashing -----------------------------
if ($HashTrees) {
  Write-Host "[10/12] Hashing trees: $($HashTrees -join ', ')" -ForegroundColor Cyan
  $patterns = '*.exe','*.dll','*.sys'
  $hashRows = foreach ($root in $HashTrees) {
    if (-not (Test-Path $root)) { continue }
    foreach ($pat in $patterns) {
      Get-ChildItem -Path $root -Recurse -Include $pat -File -ErrorAction SilentlyContinue |
        ForEach-Object {
          $h = $null; try { $h = Get-FileHash -Algorithm SHA256 -Path $_.FullName } catch {}
          if ($h) { [pscustomobject]@{ Path=$_.FullName; Algorithm=$h.Algorithm; SHA256=$h.Hash; Length=$_.Length; LastWriteTime=$_.LastWriteTime } }
        }
    }
  }
  $hashRows | Export-Csv -Path $CsvHashes -NoTypeInformation -Encoding UTF8
}

# ----------------------------- 11) IoC Matching -----------------------------
Write-Host "[11/12] IoC matching" -ForegroundColor Cyan
if ($IoCs.Count -gt 0) {
  $matches = @()
  foreach ($ioc in $IoCs) {
    $pattern = [regex]::Escape($ioc)
    $matches += ($sv      | Where-Object { $_.Name -match $pattern -or $_.DisplayName -match $pattern -or $_.PathName -match $pattern })
    $matches += ($drivers | Where-Object { $_.Name -match $pattern -or $_.DisplayName -match $pattern -or $_.PathName -match $pattern })
    $matches += ($autoruns| Where-Object { $_.Value -match $pattern -or $_.ValueName -match $pattern })
    $matches += ($procs   | Where-Object { $_.Name -match $pattern -or $_.CommandLine -match $pattern -or $_.ExecutablePath -match $pattern })
    $matches += ($recent  | Where-Object { $_.FullName -match $pattern })
  }
  if ($matches.Count -gt 0) {
    $iocOut = Join-Path $OutDir "IoC_Matches_${HostName}_${Stamp}.txt"
    $matches | Out-File -FilePath $iocOut -Encoding UTF8
    Write-Sum "IoC matches found: $($matches.Count). See: $iocOut"
  } else { Write-Sum 'No IoC matches found against provided list.' }
} else {
  Write-Sum 'No IoC list provided; skipped IoC-specific matching.'
}

# ----------------------------- 12) Finalize -----------------------------
Write-Sum "\nFiles written to $OutDir"
Write-Host "\n[+] IoC sweep complete. Reports saved to:`n$OutDir" -ForegroundColor Green
if (-not $NoExplorer) { try { Start-Process explorer.exe $OutDir } catch {} }
