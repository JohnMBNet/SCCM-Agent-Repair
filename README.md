<div align="center">

# SCCM Agent Diagnostic & Repair Tool

<img src="logo.png" alt="SCCM Agent Repair Logo" width="120" height="120">

### A Comprehensive PowerShell Tool for SCCM Client Troubleshooting

[![PowerShell](https://img.shields.io/badge/PowerShell-5.0+-5391FE?style=for-the-badge&logo=powershell&logoColor=white)](https://docs.microsoft.com/en-us/powershell/)
[![Windows](https://img.shields.io/badge/Windows-10%20%7C%2011%20%7C%20Server-0078D6?style=for-the-badge&logo=windows&logoColor=white)](https://www.microsoft.com/windows)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![Website](https://img.shields.io/badge/Website-JohnBooth.uk-4d96ff?style=for-the-badge&logo=google-chrome&logoColor=white)](https://johnbooth.uk)

---

**Diagnose, troubleshoot, and repair SCCM/ConfigMgr client agents with ease.**

[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [Diagnostics](#-diagnostic-tests) • [Repair Options](#-repair-options) • [Troubleshooting](#-troubleshooting)

---

</div>

## Overview

**SCCM Agent Diagnostic & Repair Tool** is a standalone PowerShell script designed to help IT administrators quickly diagnose and repair Microsoft System Center Configuration Manager (SCCM/ConfigMgr) client agents. No external modules or dependencies required - just pure PowerShell 5.0 that comes pre-installed on Windows.

The tool automatically discovers your SCCM infrastructure, runs comprehensive diagnostics, displays clear results, and offers both targeted quick-fix repairs and complete client reinstallation options.

---

## ✨ Features

<table>
<tr>
<td width="50%">

### 🔍 Auto-Discovery
- Automatic SCCM server detection
- WMI-based discovery
- Registry configuration lookup
- Active Directory search fallback
- No manual server entry required

</td>
<td width="50%">

### 🩺 Comprehensive Diagnostics
- Client installation verification
- Service health monitoring
- WMI repository validation
- Management Point connectivity
- Policy and inventory status

</td>
</tr>
<tr>
<td width="50%">

### 🔧 Smart Repairs
- Targeted self-check and fix
- Service restart automation
- Policy refresh triggers
- WMI repository repair
- Inventory cycle initiation

</td>
<td width="50%">

### 🔄 Complete Reinstall
- Full client uninstallation
- Registry and file cleanup
- WMI namespace purge
- Automated reinstallation
- Source auto-detection

</td>
</tr>
</table>

### Additional Highlights

| Feature | Description |
|---------|-------------|
| 🚀 **Zero Dependencies** | Pure PowerShell - no external modules or libraries required |
| 🎯 **PowerShell 5.0** | Works with standard Windows PowerShell (not PowerShell 7) |
| 🔒 **Admin Enforced** | Built-in administrator privilege verification |
| 📊 **Color-Coded Output** | Clear PASS/FAIL/WARNING indicators for all tests |
| 📝 **Detailed Logging** | Comprehensive error tracking throughout diagnostics |
| ⚡ **Interactive Menu** | Easy-to-navigate menu system for all operations |

---

## 📸 Screenshots

<div align="center">

### Diagnostic Output
*Clear, color-coded results for all diagnostic tests*

```
======================================================================
  SCCM Agent Diagnostic Tool
======================================================================

  Computer: WORKSTATION01
  User: Administrator
  Date: 2025-01-19 14:30:00

--- Auto-Discovering SCCM Server ---

  Checking WMI... Found!

  [PASS] Management Point    sccm.contoso.com
  [INFO] Site Code           PS1
  [INFO] Discovery Method    WMI

--- Checking SCCM Client Installation ---

  [PASS] SCCM Client Installed    Version: 5.00.9096.1000
  [INFO] Install Path             C:\Windows\CCM

--- Checking SCCM Services ---

  [PASS] SMS Agent Host (CcmExec)                 Status: Running
  [PASS] Background Intelligent Transfer (BITS)   Status: Running
  [PASS] Windows Update (wuauserv)                Status: Running
  [PASS] Windows Management Instrumentation       Status: Running
```

### Repair Options Menu
*Simple menu-driven interface for repair operations*

```
======================================================================
  SCCM Agent Repair Options
======================================================================

  1. Run Diagnostics Only
  2. Self-Check and Fix (Targeted Repairs)
  3. Complete SCCM Agent Repair (Uninstall/Reinstall)
  4. Exit

  Enter your choice (1-4):
```

</div>

---

## 🚀 Installation

### Prerequisites

- **Windows 10**, **Windows 11**, or **Windows Server 2016+**
- **PowerShell 5.0** or later (pre-installed on modern Windows)
- **Administrator privileges** (required for all operations)
- **SCCM/ConfigMgr client** (for diagnostics - installer needed for repair)

### Quick Start

1. **Download the script**
   ```powershell
   git clone https://github.com/yourusername/SCCM-Agent-Repair.git
   cd SCCM-Agent-Repair
   ```

2. **Run as Administrator**
   ```powershell
   # Right-click PowerShell → Run as Administrator
   .\SCCM-Agent-Diagnostic.ps1
   ```

3. **Follow the interactive menu**

   The tool will guide you through diagnostics and repair options.

### Single-File Deployment

The script is completely self-contained. Simply copy `SCCM-Agent-Diagnostic.ps1` to any machine and run it - no installation required.

```powershell
# Copy to remote machine and execute
Copy-Item .\SCCM-Agent-Diagnostic.ps1 \\TARGETPC\C$\Temp\
Invoke-Command -ComputerName TARGETPC -ScriptBlock { C:\Temp\SCCM-Agent-Diagnostic.ps1 }
```

---

## 📖 Usage

### Running the Tool

```powershell
# Standard execution (requires Run as Administrator)
.\SCCM-Agent-Diagnostic.ps1
```

### Menu Options

| Option | Description |
|--------|-------------|
| **1. Run Diagnostics Only** | Performs all diagnostic tests and displays results with repair recommendations |
| **2. Self-Check and Fix** | Runs diagnostics then performs targeted repairs for detected issues |
| **3. Complete Repair** | Full uninstall, cleanup, and reinstall of the SCCM client |
| **4. Exit** | Closes the tool |

### Workflow

```
┌─────────────────────────────────────────────────────────────────┐
│                        Start Script                             │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│              Check Administrator Privileges                      │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Display Main Menu                            │
└─────────────────────────────────────────────────────────────────┘
                              │
            ┌─────────────────┼─────────────────┐
            ▼                 ▼                 ▼
     ┌───────────┐     ┌───────────┐     ┌───────────┐
     │ Diagnose  │     │ Self-Fix  │     │ Complete  │
     │   Only    │     │  Repair   │     │  Repair   │
     └───────────┘     └───────────┘     └───────────┘
            │                 │                 │
            ▼                 ▼                 ▼
     ┌───────────┐     ┌───────────┐     ┌───────────┐
     │  Display  │     │  Targeted │     │ Uninstall │
     │  Results  │     │   Fixes   │     │ & Reinstl │
     └───────────┘     └───────────┘     └───────────┘
```

---

## 🩺 Diagnostic Tests

The tool performs the following comprehensive diagnostics:

### SCCM Server Discovery
| Method | Description |
|--------|-------------|
| **WMI** | Queries `SMS_Authority` and `SMS_Client` classes |
| **Registry** | Reads from `HKLM:\SOFTWARE\Microsoft\CCM` |
| **Active Directory** | Searches for `mSSMSManagementPoint` objects |

### Client Health Checks

| Test | What It Checks |
|------|----------------|
| **Client Installation** | Verifies CCM folder exists and gets version from ccmexec.exe |
| **Service Status** | CcmExec, BITS, Windows Update, WMI services |
| **WMI Repository** | Core WMI health and SCCM namespaces (root\ccm, etc.) |
| **MP Connectivity** | Ping and TCP connection to Management Point |
| **Client Health** | CcmEvalReport.xml results and SMS_Client status |
| **Cache Status** | Cache location, size, and item count |
| **Certificates** | SMS store and client authentication certificates |
| **Policies** | Machine policy presence and count |
| **Log Files** | Critical log existence and recent error detection |

---

## 🔧 Repair Options

### Option 2: Self-Check and Fix

Performs targeted repairs based on diagnostic findings:

| Repair Action | When Applied |
|---------------|--------------|
| **Start Services** | Critical services (CcmExec, BITS, WMI) not running |
| **WMI Repair** | WMI repository corruption detected |
| **Policy Refresh** | Triggers machine policy retrieval and evaluation |
| **Inventory Cycles** | Initiates hardware and software inventory |
| **CcmEval** | Runs built-in client health evaluation |
| **Policy Reset** | Clears and rebuilds policy store if empty |

### Option 3: Complete Repair

Full client reinstallation process:

1. **Stop Services** - Halts CcmExec and related services
2. **Uninstall Client** - Runs `ccmsetup.exe /uninstall`
3. **Cleanup Files** - Removes CCM folders and cache
4. **Cleanup Registry** - Purges CCM/SMS registry keys
5. **Cleanup WMI** - Removes ccm namespace
6. **Reinstall** - Locates and runs ccmsetup.exe with discovered settings

---

## 📁 Project Structure

```
SCCM-Agent-Repair/
├── 📄 SCCM-Agent-Diagnostic.ps1    # Main diagnostic and repair script
├── 📁 images/
│   └── 🖼️ logo.png                  # Project logo
├── 📄 LICENSE                       # MIT License
└── 📄 README.md                     # This file
```

---

## 🛡️ Security

- **Administrator Required**: Script enforces admin privileges at startup
- **No External Calls**: All operations use built-in Windows APIs
- **No Data Collection**: Everything runs locally on the target machine
- **Safe Defaults**: Complete repair requires explicit confirmation

---

## 🔧 Troubleshooting

### Common Issues

<details>
<summary><strong>Script won't run - Execution Policy</strong></summary>

```powershell
# Temporarily bypass for this session
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process

# Then run the script
.\SCCM-Agent-Diagnostic.ps1
```
</details>

<details>
<summary><strong>"Must be run as Administrator" error</strong></summary>

Right-click PowerShell and select **Run as Administrator**, then navigate to the script location and run it.

```powershell
# Or use this from an admin prompt
Start-Process powershell -Verb RunAs -ArgumentList "-File `"C:\Path\To\SCCM-Agent-Diagnostic.ps1`""
```
</details>

<details>
<summary><strong>SCCM Server not discovered</strong></summary>

If auto-discovery fails:
- Verify the client was previously installed and configured
- Check network connectivity to domain controllers
- The complete repair option will prompt for manual server entry
</details>

<details>
<summary><strong>Complete repair can't find ccmsetup.exe</strong></summary>

The script searches common locations:
- `C:\Windows\ccmsetup\ccmsetup.exe`
- `\\<ManagementPoint>\SMS_<SiteCode>\Client\ccmsetup.exe`
- `\\<Domain>\NETLOGON\ccmsetup.exe`

If not found, you'll be prompted to enter the path manually.
</details>

<details>
<summary><strong>Services won't start after repair</strong></summary>

Try these steps:
1. Reboot the machine
2. Run the Self-Check and Fix option again
3. Check Windows Event Viewer for specific errors
4. Consider the Complete Repair option
</details>

---

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/NewFeature`)
3. **Commit** your changes (`git commit -m 'Add NewFeature'`)
4. **Push** to the branch (`git push origin feature/NewFeature`)
5. **Open** a Pull Request

### Ideas for Contributions

- [ ] HTML report export option
- [ ] Remote computer support via `-ComputerName` parameter
- [ ] Scheduled task creation for automated health checks
- [ ] Integration with Windows Event Log
- [ ] Additional repair actions for edge cases
- [ ] Verbose logging to file option

---

## 📜 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

---

## 👨‍💻 Author

<div align="center">

**Created with ❤️ by John Booth**

[![Website](https://img.shields.io/badge/Website-JohnBooth.uk-4d96ff?style=for-the-badge&logo=google-chrome&logoColor=white)](https://johnbooth.uk)
[![GitHub](https://img.shields.io/badge/GitHub-Profile-181717?style=for-the-badge&logo=github&logoColor=white)](https://github.com/yourusername)

---

<sub>If you find this project useful, please consider giving it a ⭐</sub>

</div>
