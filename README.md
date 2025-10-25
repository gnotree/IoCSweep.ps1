# IoCSweep.ps1 — README

## Purpose

**IoCSweep.ps1** performs automated collection and analysis of potential Indicators of Compromise (IoCs) on Windows. It is a modular forensic sweep tool that runs safely in read-only mode. The script is ideal for blue-team or incident-response baselines.

## What It Does

The sweep checks multiple persistence and runtime vectors, including:

* **Running Processes** — active executables, file paths, digital signatures, hashes
* **Kernel Drivers** — current and loaded `.sys` modules with publisher and hash info
* **Autoruns** — Run / RunOnce / Startup folder entries
* **Services** — all installed and running Windows services
* **Scheduled Tasks** — all task definitions and associated actions
* **WMI Event Subscriptions** — known persistence mechanism
* **Recent Files** — last accessed or modified items under user profiles
* **Network Connections** — open TCP/UDP sessions and listeners (from `netstat`)

## Optional Features

* **IoC File Input:** specify a text file with domains, file names, paths, or hashes. Each line is checked across all collected data.
* **HashTrees:** optionally hash entire directories (for deep integrity sweeps)
* **HashFast (planned):** hashes only loaded driver and process binaries for quick integrity validation.

## Output

Each run creates a timestamped directory under the default root:

```
T:\GNO-JUNGLE\Jaguar\Reports\HostAudit\<HOST>_<YYYY-MM-DD_HH-mm-ss>\
```

### Output Files

| File                              | Description                                 |
| --------------------------------- | ------------------------------------------- |
| `IoC_Summary_*.txt`               | Human-readable sweep summary                |
| `IoC_Processes_*.csv`             | Active processes with signature & hash data |
| `IoC_Drivers_*.csv`               | Loaded kernel drivers                       |
| `IoC_Services_*.csv`              | Service configuration + binary path         |
| `IoC_Autoruns_*.csv`              | Autorun persistence entries                 |
| `IoC_ScheduledTasks_*.csv`        | All task actions & triggers                 |
| `IoC_WMIEventSubscriptions_*.csv` | WMI event filters & consumers               |
| `IoC_RecentFiles_*.csv`           | File-system recency list                    |
| `IoC_Network_*.txt`               | Active network connections                  |

All files are CSV/TXT for easy import into Excel or SIEM.

## Usage

```powershell
# Basic sweep (auto-elevates)
pwsh -File .\IoCSweep.ps1

# Sweep with IoC feed from file
pwsh -File .\IoCSweep.ps1 -IoCFile 'C:\feeds\ioc_list.txt'

# Include recursive hashing of directories
pwsh -File .\IoCSweep.ps1 -HashTrees 'C:\Windows\System32','C:\Program Files'

# Skip opening the folder afterward
pwsh -File .\IoCSweep.ps1 -NoExplorer
```

## Switches

| Switch               | Description                                        |
| -------------------- | -------------------------------------------------- |
| `-IoCFile <path>`    | Path to IoC list file (hashes, domains, filenames) |
| `-HashTrees <paths>` | Directories to hash recursively                    |
| `-NoExplorer`        | Prevent auto-opening of output folder              |

## Typical Workflow

1. Run **Host-Audit.ps1** for baseline integrity check.
2. Run **IoCSweep.ps1** to enumerate active indicators.
3. Review `IoC_Summary_*.txt` first.
4. Correlate with external threat intel (VirusTotal, MITRE ATT&CK).

## Interpreting Results

* Entries marked with *Signature Invalid* or *Unknown Publisher* should be verified.
* Unexpected autoruns, scheduled tasks, or unsigned drivers may indicate persistence mechanisms.
* Network results show foreign connections (look for public IPs outside normal services).

## Requirements

* PowerShell 7+ (`pwsh`)
* Administrator privileges (script auto-elevates)
* Default output path available or creatable (`T:` Dev Drive supported)

## Safety

* Read-only collection only — no modification, deletion, or registry changes.
* All results stored locally; no remote upload.

## Troubleshooting

* **Access Denied:** re-run elevated (admin).
* **Missing T: drive:** verify your Dev Drive is mounted; use Auto-Remap if needed.
* **Large hash operations slow:** limit with `-HashFast` (when available) or target fewer paths.

## Example Integration (Profile Aliases)

```powershell
function IoC-Sweep     { pwsh -File "$HOME\IoCSweep.ps1" }
function IoC-Hash      { pwsh -File "$HOME\IoCSweep.ps1" -HashTrees 'C:\Windows\System32','C:\Program Files' }
Set-Alias iocsweep IoC-Sweep
Set-Alias iochash  IoC-Hash
```

---

**Authoring note:** IoCSweep complements `Host-Audit.ps1` as part of the Jaguar host triage suite. Customize the default root path in the script header if your `T:` volume changes.
