# IoCSweep.ps1 — GitHub README

## Overview

**IoCSweep.ps1** is a PowerShell-based forensic triage tool for Windows systems. It automates the collection of potential Indicators of Compromise (IoCs) and provides structured output for blue team analysis or incident response.

It is designed for **transparency, portability, and zero system impact** — the script performs read-only enumeration and stores all results locally.

---

## ✳️ Features

* Enumerates **running processes**, **kernel drivers**, **autoruns**, **services**, **scheduled tasks**, and **WMI event subscriptions**.
* Captures **recently modified files** and **network connections**.
* Supports optional **IoC file matching** (filenames, paths, domains, or hashes).
* Supports optional **directory hashing** for deep scans (`-HashTrees`).
* Auto-elevates if required for system-level enumeration.
* Generates timestamped reports in portable CSV/TXT format.

---

## 🧠 Why IoCSweep

Use IoCSweep to:

* Quickly identify signs of persistence or lateral movement.
* Verify the integrity and origin of drivers and executables.
* Establish clean baselines for recurring host sweeps.
* Supplement threat hunting or incident response playbooks.

---

## ⚙️ Requirements

* **Windows 10/11** or **Windows Server 2016+**
* **PowerShell 7.0+ (`pwsh`)**
* Administrator privileges (script auto-elevates when needed)

---

## 📁 Output

Each run writes results to a timestamped folder under a configurable output root.

Default behavior:

```powershell
$env:HOSTAUDIT_ROOT   # If defined, IoCSweep writes here
$HOME\Reports\HostAudit  # Fallback if HOSTAUDIT_ROOT is not defined
```

Folder structure example:

```
<OUTPUT_ROOT>/MyPC_2025-10-25_20-15-33/
├── IoC_Summary_MyPC_2025-10-25_20-15-33.txt
├── IoC_Processes_MyPC_2025-10-25_20-15-33.csv
├── IoC_Drivers_MyPC_2025-10-25_20-15-33.csv
├── IoC_Services_MyPC_2025-10-25_20-15-33.csv
├── IoC_Autoruns_MyPC_2025-10-25_20-15-33.csv
├── IoC_ScheduledTasks_MyPC_2025-10-25_20-15-33.csv
├── IoC_WMIEventSubscriptions_MyPC_2025-10-25_20-15-33.csv
├── IoC_RecentFiles_MyPC_2025-10-25_20-15-33.csv
├── IoC_Network_MyPC_2025-10-25_20-15-33.txt
└── IoC_UnsignedDrivers_MyPC_2025-10-25_20-15-33.csv
```

All files are stored in UTF-8 CSV/TXT format for compatibility with Excel, Splunk, SIEMs, or text search tools.

---

## 🧩 Parameters

| Parameter            | Description                                                                |
| -------------------- | -------------------------------------------------------------------------- |
| `-IoCFile <path>`    | Path to newline-delimited list of IoCs (hashes, domains, filenames, paths) |
| `-HashTrees <paths>` | Recursively hash specified directories (e.g., `C:\Windows\System32`)       |
| `-OutputRoot <path>` | Custom root folder for reports (overrides environment variable)            |
| `-RecentDays <int>`  | Number of days to include for recent file scan (default: 7)                |
| `-NoExplorer`        | Skip auto-opening the results folder                                       |

---

## 🚀 Usage Examples

```powershell
# Standard sweep (auto-elevates)
pwsh -File .\IoCSweep.ps1

# Sweep with IoC list
pwsh -File .\IoCSweep.ps1 -IoCFile 'C:\intel\ioc_feed.txt'

# Deep scan: hash Windows and Program Files directories
pwsh -File .\IoCSweep.ps1 -HashTrees 'C:\Windows\System32','C:\Program Files'

# Custom output root (override default)
pwsh -File .\IoCSweep.ps1 -OutputRoot 'D:\Forensics\IoCScans'

# Quiet run, no Explorer popup
pwsh -File .\IoCSweep.ps1 -NoExplorer
```

---

## 🔍 Interpretation Tips

* **Unsigned or non-Microsoft drivers** often require validation.
* **Unexpected autoruns or tasks** may indicate persistence mechanisms.
* **Foreign IPs or odd domains** in network results may represent exfiltration or C2 channels.
* Review `IoC_Summary_*.txt` first — it provides a human-readable rollup of key findings.

---

## 🧰 Integrating with Profiles

You can add convenient aliases to your PowerShell profile:

```powershell
function IoC-Sweep { pwsh -File "$HOME\IoCSweep.ps1" }
Set-Alias iocsweep IoC-Sweep
```

Then just run:

```powershell
iocsweep
```

---

## 🧾 License

Released under the MIT License. Contributions and forks welcome.

IoCSweep is part of a modular forensic tooling framework for Windows security ana
