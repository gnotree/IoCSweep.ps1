<#
.SYNOPSIS
  IoC Sweep: enumerates high-signal persistence and compromise surfaces and optionally matches user-provided IoCs.

.DESCRIPTION
  Collects:
    • Services, drivers, autoruns, scheduled tasks, WMI permanent event subs, processes, listening ports
    • Recent files in user hotspots (Desktop/Downloads/Temp)
    • Unsigned and non-Microsoft kernel drivers
    • Basic Defender/AMSI tamper hints
  Optional:
    • -IoCFile: a newline-delimited list of IoCs (hashes, filenames, domains, paths) to match in collected metadata
    • -HashTrees: compute SHA256 for *.exe, *.dll, *.sys under selected roots (slow) and export

  Outputs CSV/TXT to T:\GNO-JUNGLE\Jaguar\Reports\HostAudit\<HOST>_<STAMP> and opens folder in Explorer.
  Read-only; does not modify system state. PowerShell 7+ recommended.

.EXAMPLES
  pwsh -File .\IoCSweep.ps1
  pwsh -File .\IoCSweep.ps1 -IoCFile C:\temp\my_iocs.txt
  pwsh -File .\IoCSweep.ps1 -HashTrees 'C:\Windows\System32','C:\Program Files' -RecentDays 14 -NoExplorer
#>

param(
  [string]$IoCFile,
  [string[]]$HashTrees,
  [int]$RecentDays = 7,
  [switch]$NoExplorer
)

# ----------------------------- Elevation -----------------------------
function Ensure-Admin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $p  = New-Object Security.Principal.WindowsPrincipal($id)
  if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[*] Elevation required — relaunching as admin..." -ForegroundColor Yellow
    $pwshExe = Join-Path $PSHOME 'pwsh.exe'
    $args = @('-NoLogo','-File',$PSCommandPath)
    if ($IoCFile) { $args += @('-IoCFile', $IoCFile) }
    if ($HashTrees) { $args += @('-HashTrees'); $args += $HashTrees }
    if ($RecentDays -ne 7) { $args += @('-RecentDays', $RecentDays) }
    if ($NoExplorer) { $args += '-NoExplorer' }
    Start-Process -FilePath $pwshExe -ArgumentList $args -Verb RunAs | Out-Null
    exit
  }
}
Ensure-Admin

# ----------------------------- Paths -----------------------------
$Root = 'T:\GNO-JUNGLE\Jaguar\Reports\HostAudit'
if (-not (Test-Path $Root)) { New-Item -ItemType Directory -Path $Root -Force | Out-Null }
$HostName = $env:COMPUTERNAME
$Stamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$OutDir = Join-Path $Root "${HostName}_${Stamp}"
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

# Artifact paths
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

# ----------------------------- Helpers -----------------------------
function Write-Sum([string]$s){ Add-Content -Path $TxtSummary -Value $s }
function Normalize-Path([string]$raw){
  if (-not $raw) { return $null }
  $p = $raw.Trim('"')
  $p = $p -replace '^(\\\\\?\\)',''
  $p = $p -replace '^(?i)\\SystemRoot', "$env:SystemRoot"
  if ($p -match '^(?i)\\Windows\\') { $p = "$($env:SystemDrive)$p" }
  return $p
}

# ----------------------------- IoC list -----------------------------
$IoCs = @()
if ($IoCFile) {
  if (-not (Test-Path $IoCFile)) { Write-Warning "IoC file not found: $IoCFile" }
  else {
    $IoCs = Get-Content -Path $IoCFile | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }
    Write-Host "[*] Loaded $($IoCs.Count) IoC entries"
  }
}

Write-Sum "IoC Sweep: $((Get-Date).ToString('u'))"
Write-Sum "Host: $HostName"
Write-Sum "OutDir: $OutDir`n"

# ----------------------------- 1) Services -----------------------------
Write-Host "[1/12] Enumerating running services..." -ForegroundColor Cyan
$sv = Get-CimInstance Win32_Service | Select-Object Name,DisplayName,StartMode,State,PathName
$sv | Export-Csv -Path $CsvServices -NoTypeInformation -Encoding UTF8

# ----------------------------- 2) Drivers -----------------------------
Write-Host "[2/12] Enumerating system drivers..." -ForegroundColor Cyan
$drivers = Get-CimInstance Win32_SystemDriver | Select-Object Name,DisplayName,State,StartMode,PathName
$drivers | Export-Csv -Path $CsvDrivers -NoTypeInformation -Encoding UTF8

# ----------------------------- 3) Autoruns -----------------------------
Write-Host "[3/12] Enumerating autoruns (registry)..." -ForegroundColor Cyan
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
      foreach ($p in $props) {
        [pscustomobject]@{ Key=$k; ValueName=$p.Name; Value=$p.Value }
      }
    }
  }
}
$autoruns | Export-Csv -Path $CsvAutoruns -NoTypeInformation -Encoding UTF8

# ----------------------------- 4) Scheduled tasks -----------------------------
Write-Host "[4/12] Enumerating scheduled tasks..." -ForegroundColor Cyan
$tasks = Get-ScheduledTask | Select-Object TaskName,TaskPath,State,Actions
$tasks | Export-Csv -Path $CsvTasks -NoTypeInformation -Encoding UTF8

# ----------------------------- 5) WMI subs -----------------------------
Write-Host "[5/12] Enumerating WMI permanent event subscriptions..." -ForegroundColor Cyan
try {
  $wmiFilters = Get-WmiObject -Namespace root\subscription -Class __EventFilter -ErrorAction SilentlyContinue | Select-Object Name,Query
  $wmiFilters | Export-Csv -Path $CsvWMI -NoTypeInformation -Encoding UTF8
} catch { Write-Sum "WMI enumeration failed: $($_.Exception.Message)" }

# ----------------------------- 6) Processes -----------------------------
Write-Host "[6/12] Enumerating processes..." -ForegroundColor Cyan
$procs = Get-CimInstance Win32_Process | Select-Object ProcessId,Name,CommandLine,ExecutablePath
$procs | Export-Csv -Path $CsvProcs -NoTypeInformation -Encoding UTF8

# ----------------------------- 7) Network -----------------------------
Write-Host "[7/12] Capturing network endpoints (netstat -ano)..." -ForegroundColor Cyan
try { (& netstat -ano) | Out-File -FilePath $CsvNet -Encoding UTF8 } catch { Write-Sum "Netstat failed: $($_.Exception.Message)" }

# ----------------------------- 8) Recent files -----------------------------
Write-Host "[8/12] Recent files (last $RecentDays days)..." -ForegroundColor Cyan
$folders = @(
  (Join-Path $HOME 'Downloads'),
  (Join-Path $HOME 'Desktop'),
  $env:TEMP
)
$cutoff = (Get-Date).AddDays(-$RecentDays)
$recent = foreach ($f in $folders) {
  if (Test-Path $f) {
    Get-ChildItem -Path $f -Recurse -ErrorAction SilentlyContinue |
      Where-Object { -not $_.PSIsContainer -and $_.LastWriteTime -ge $cutoff } |
      Select-Object FullName,Length,LastWriteTime
  }
}
$recent | Export-Csv -Path $CsvRecent -NoTypeInformation -Encoding UTF8

# ----------------------------- 9) Unsigned/non-Microsoft drivers -----------------------------
Write-Host "[9/12] Checking kernel driver signatures..." -ForegroundColor Cyan
$driversFull = Get-CimInstance Win32_SystemDriver | Where-Object { $_.PathName -match '\\.sys' }
$unsigned = foreach ($d in $driversFull) {
  $path = Normalize-Path $d.PathName
  if ($path -and (Test-Path $path)) {
    $sig = $null; try { $sig = Get-AuthenticodeSignature -FilePath $path } catch {}
    [pscustomobject]@{
      Name = $d.Name
      DisplayName = $d.DisplayName
      Path = $path
      SignatureStatus = $(if ($sig) { $sig.Status } else { 'NoSignature' })
      Publisher = $(if ($sig -and $sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { $null })
    }
  } else {
    [pscustomobject]@{ Name=$d.Name; DisplayName=$d.DisplayName; Path=$path; SignatureStatus='Missing'; Publisher=$null }
  }
}
$unsigned | Where-Object { $_.SignatureStatus -ne 'Valid' -or ($_.Publisher -and $_.Publisher -notmatch 'Microsoft') } |
  Export-Csv -Path $CsvUnsigned -NoTypeInformation -Encoding UTF8

# ----------------------------- 10) Defender / AMSI quick checks -----------------------------
Write-Host "[10/12] Defender & AMSI quick checks..." -ForegroundColor Cyan
try {
  $mp = Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue
  if ($mp) {
    $mpc = Get-MpComputerStatus
    Write-Sum "Defender: AMServiceEnabled=$($mpc.AMServiceEnabled) RealTime=$($mpc.RealTimeProtectionEnabled) Antispyware=$($mpc.AntispywareEnabled)"
  } else { Write-Sum 'Defender: Get-MpComputerStatus not available.' }
} catch { Write-Sum "Defender check failed: $($_.Exception.Message)" }
try {
  $execPol = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell' -Name 'ExecutionPolicy' -ErrorAction SilentlyContinue).ExecutionPolicy
  Write-Sum "PowerShell (HKLM) ExecutionPolicy: $execPol"
} catch {}

# ----------------------------- 11) Optional file hashing -----------------------------
if ($HashTrees) {
  Write-Host "[11/12] Hashing files under: $($HashTrees -join ', ') (SHA256 *.exe;*.dll;*.sys) ..." -ForegroundColor Cyan
  $patterns = '*.exe','*.dll','*.sys'
  $hashRows = foreach ($root in $HashTrees) {
    if (-not (Test-Path $root)) { continue }
    foreach ($pat in $patterns) {
      Get-ChildItem -Path $root -Recurse -Include $pat -File -ErrorAction SilentlyContinue |
        ForEach-Object {
          $h = $null; try { $h = Get-FileHash -Algorithm SHA256 -Path $_.FullName } catch {}
          if ($h) {
            [pscustomobject]@{ Path=$_.FullName; Algorithm=$h.Algorithm; SHA256=$h.Hash; Length=$_.Length; LastWriteTime=$_.LastWriteTime }
          }
        }
    }
  }
  $hashRows | Export-Csv -Path $CsvHashes -NoTypeInformation -Encoding UTF8
}

# ----------------------------- 12) IoC matching -----------------------------
Write-Host "[12/12] IoC matching (if list provided)..." -ForegroundColor Cyan
if ($IoCs.Count -gt 0) {
  $matches = @()
  foreach ($ioc in $IoCs) {
    $pattern = [regex]::Escape($ioc)
    $matches += ($sv | Where-Object { $_.Name -match $pattern -or $_.DisplayName -match $pattern -or $_.PathName -match $pattern })
    $matches += ($drivers | Where-Object { $_.Name -match $pattern -or $_.DisplayName -match $pattern -or $_.PathName -match $pattern })
    $matches += ($autoruns | Where-Object { $_.Value -match $pattern -or $_.ValueName -match $pattern })
    $matches += ($procs | Where-Object { $_.Name -match $pattern -or $_.CommandLine -match $pattern -or $_.ExecutablePath -match $pattern })
    $matches += ($recent | Where-Object { $_.FullName -match $pattern })
  }
  if ($matches.Count -gt 0) {
    $iocOut = Join-Path $OutDir "IoC_Matches_${HostName}_${Stamp}.txt"
    $matches | Out-File -FilePath $iocOut -Encoding UTF8
    Write-Sum "IoC matches found: see $iocOut"
  } else {
    Write-Sum 'No IoC matches found against provided list.'
  }
} else {
  Write-Sum 'No IoC list provided; skipped IoC-specific matching.'
}

# ----------------------------- Done -----------------------------
Write-Sum "\nFiles written to $OutDir"
Write-Host "\n[+] IoC sweep complete. Reports saved to:`n$OutDir" -ForegroundColor Green
if (-not $NoExplorer) { try { Start-Process explorer.exe $OutDir } catch {} }
