<div align="center">

# JMB Windows Update Manager

<img src="web/images/logo.png" alt="JMB Windows Update Manager Logo" width="120" height="120">

### A Modern, Elegant Windows Update Management Dashboard

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1+-5391FE?style=for-the-badge&logo=powershell&logoColor=white)](https://docs.microsoft.com/en-us/powershell/)
[![Windows](https://img.shields.io/badge/Windows-10%20%7C%2011-0078D6?style=for-the-badge&logo=windows&logoColor=white)](https://www.microsoft.com/windows)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![Website](https://img.shields.io/badge/Website-JohnBooth.uk-4d96ff?style=for-the-badge&logo=google-chrome&logoColor=white)](https://johnbooth.uk)

---

**Take control of your Windows updates with a beautiful, dark-themed web dashboard.**

[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [Screenshots](#-screenshots) • [API](#-api-reference) • [Contributing](#-contributing)

---

</div>

## Overview

**JMB Windows Update Manager** transforms the way you interact with Windows Updates. No more digging through Settings or wrestling with the command line. This elegant, locally-hosted web dashboard provides complete visibility and control over your system's update status.

Built entirely in **PowerShell** with a modern **Material Design + Bootflat** dark-themed interface, it delivers a premium experience while keeping everything running securely on your local machine.

---

## ✨ Features

<table>
<tr>
<td width="50%">

### 📊 Real-Time Dashboard
- System information at a glance
- Windows version, build & architecture
- Disk space visualization
- System uptime tracking
- Last update check timestamp

</td>
<td width="50%">

### 🔄 Pending Updates
- Total pending update count
- Color-coded by category
- Visual progress indicators
- Download status tracking
- Risk level assessment

</td>
</tr>
<tr>
<td width="50%">

### 📋 Comprehensive Update History
- Full update table with sorting
- Filter by status & category
- Clickable KB article links
- Installation timestamps
- Success/failure indicators

</td>
<td width="50%">

### 🔔 Smart Notifications
- Security-critical alerts
- Configurable quiet hours
- Restart deadline warnings
- Auto-refresh capability
- Non-intrusive updates

</td>
</tr>
</table>

### Additional Highlights

| Feature | Description |
|---------|-------------|
| 🌙 **Dark Mode** | Easy on the eyes with a carefully crafted dark theme |
| 🚀 **Lightweight** | Pure PowerShell - no external dependencies required |
| 🔒 **Secure** | Runs entirely on localhost - your data never leaves your machine |
| 📱 **Responsive** | Works beautifully on any screen size |
| ⚡ **Fast** | Background polling keeps data fresh without blocking the UI |
| 🎨 **Customizable** | Add your own logo and configure to your preferences |

---

## 📸 Screenshots

<div align="center">

### Dashboard Overview
*System information, disk usage, and update status at a glance*

```
┌─────────────────────────────────────────────────────────────────┐
│  🖥️ Dashboard                                                    │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐         │
│   │ Pending  │ │ Security │ │ Disk     │ │ Uptime   │         │
│   │    3     │ │    1     │ │ 120.5 GB │ │ 2d 5h    │         │
│   └──────────┘ └──────────┘ └──────────┘ └──────────┘         │
│                                                                 │
│   ┌─────────────────────────┐ ┌─────────────────────────┐     │
│   │ System Information      │ │ Storage                 │     │
│   │ Windows 11 Pro          │ │ ████████████░░░░ 75%    │     │
│   │ Build 22631.2715        │ │ 120.5 GB Free           │     │
│   └─────────────────────────┘ └─────────────────────────┘     │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Pending Updates View
*Color-coded updates with risk assessment and progress tracking*

### Update History Table
*Complete history with filtering and sorting capabilities*

</div>

---

## 🚀 Installation

### Prerequisites

- **Windows 10** or **Windows 11**
- **PowerShell 5.1** or later (pre-installed on Windows 10/11)
- **Administrator privileges** (recommended for full functionality)

### Quick Start

1. **Clone the repository**
   ```powershell
   git clone https://github.com/yourusername/WindowsUpdateDash.git
   cd WindowsUpdateDash
   ```

2. **Run the dashboard**
   ```powershell
   .\Start-UpdateDashboard.ps1
   ```

3. **Open your browser**

   The dashboard will automatically open at `http://localhost:8080`

### Custom Port

```powershell
.\Start-UpdateDashboard.ps1 -Port 9000
```

### Without Auto-Opening Browser

```powershell
.\Start-UpdateDashboard.ps1 -NoBrowser
```

---

## 📖 Usage

### Starting the Server

```powershell
# Basic start (opens browser automatically)
.\Start-UpdateDashboard.ps1

# Custom port
.\Start-UpdateDashboard.ps1 -Port 3000

# Without opening browser
.\Start-UpdateDashboard.ps1 -NoBrowser

# Combine options
.\Start-UpdateDashboard.ps1 -Port 9000 -NoBrowser
```

### Stopping the Server

Press `Ctrl+C` in the PowerShell window to gracefully stop the server.

### Navigation

| Page | Description |
|------|-------------|
| **Dashboard** | Overview of system info, disk space, uptime, and update counts |
| **Pending Updates** | Detailed view of updates waiting to be installed |
| **All Updates** | Complete history table with filtering options |
| **Settings** | Configure notifications, quiet hours, and refresh intervals |

### Customization

#### Custom Logo

Replace `web/images/logo.png` with your own logo (recommended size: 80x80 pixels or larger).

#### Settings

Configure via the Settings page or edit `config/settings.json`:

```json
{
    "quietHoursEnabled": false,
    "quietHoursStart": "22:00",
    "quietHoursEnd": "07:00",
    "autoRefreshInterval": 60,
    "notificationsEnabled": true,
    "showSecurityAlerts": true,
    "theme": "dark"
}
```

---

## 🔌 API Reference

The dashboard exposes a RESTful API on localhost for all data operations.

### Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/system-info` | System information (OS, disk, uptime) |
| `GET` | `/api/pending-updates` | List of pending updates |
| `GET` | `/api/update-history` | Complete update history |
| `GET` | `/api/alerts` | Security alerts and notifications |
| `GET` | `/api/settings` | Current settings |
| `POST` | `/api/settings` | Update settings |
| `GET` | `/api/restart-status` | Check if restart is required |

### Example Response

```json
// GET /api/system-info
{
    "Windows": {
        "ProductName": "Windows 11 Pro",
        "Version": "23H2",
        "BuildNumber": "22631.2715",
        "Architecture": "64-bit"
    },
    "Disk": {
        "TotalGB": 500.0,
        "FreeGB": 120.5,
        "PercentUsed": 75.9
    },
    "Uptime": {
        "Formatted": "2d 5h 30m",
        "TotalHours": 53.5
    }
}
```

---

## 📁 Project Structure

```
WindowsUpdateDash/
├── 📄 Start-UpdateDashboard.ps1    # Main entry point
├── 📁 modules/
│   ├── 📄 HttpServer.psm1          # HTTP server & routing
│   ├── 📄 SystemInfo.psm1          # System information
│   └── 📄 WindowsUpdateAPI.psm1    # Windows Update API
├── 📁 web/
│   ├── 📄 index.html               # Single-page application
│   ├── 📁 css/
│   │   └── 📄 style.css            # Dark Material Design
│   ├── 📁 js/
│   │   └── 📄 app.js               # Frontend logic
│   └── 📁 images/
│       └── 🖼️ logo.png              # Your custom logo
├── 📁 config/
│   └── 📄 settings.json            # User preferences
├── 📄 LICENSE
└── 📄 README.md
```

---

## 🛡️ Security

- **Local Only**: The server binds exclusively to `localhost` - no external network access
- **No Data Collection**: All data stays on your machine
- **No External Dependencies**: Pure PowerShell with built-in Windows APIs
- **Read-Only Operations**: The dashboard only reads update information, it doesn't modify or install updates

---

## 🔧 Troubleshooting

### Common Issues

<details>
<summary><strong>Port already in use</strong></summary>

```powershell
# Use a different port
.\Start-UpdateDashboard.ps1 -Port 9000
```
</details>

<details>
<summary><strong>Logo not displaying</strong></summary>

Ensure your logo is:
- Named `logo.png`
- Located in `web/images/`
- A valid PNG file (not renamed from another format)
</details>

<details>
<summary><strong>Limited update information</strong></summary>

Run PowerShell as Administrator for full Windows Update API access:
```powershell
# Right-click PowerShell → Run as Administrator
.\Start-UpdateDashboard.ps1
```
</details>

<details>
<summary><strong>Updates not refreshing</strong></summary>

- Check the refresh button (spinning = loading)
- Verify the server is still running in PowerShell
- Check browser console for errors (F12)
</details>

---

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/AmazingFeature`)
3. **Commit** your changes (`git commit -m 'Add AmazingFeature'`)
4. **Push** to the branch (`git push origin feature/AmazingFeature`)
5. **Open** a Pull Request

### Ideas for Contributions

- [ ] Light theme option
- [ ] Update scheduling functionality
- [ ] System restore point creation
- [ ] Email notifications
- [ ] Multi-language support
- [ ] Export update history to CSV

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
