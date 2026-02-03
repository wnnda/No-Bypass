# NoBP - Advanced Cheat Detection Suite

<div align="center">
```
  ███╗   ██╗ ██████╗ ██████╗ ██████╗ 
  ████╗  ██║██╔═══██╗██╔══██╗██╔══██╗
  ██╔██╗ ██║██║   ██║██████╔╝██████╔╝
  ██║╚██╗██║██║   ██║██╔══██╗██╔═══╝ 
  ██║ ╚████║╚██████╔╝██████╔╝██║     
  ╚═╝  ╚═══╝ ╚═════╝ ╚═════╝ ╚═╝     
```

**Advanced Cheat Detection Suite**  
*Created by Wanda*

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg)](https://github.com/PowerShell/PowerShell)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows-lightgrey.svg)](https://www.microsoft.com/windows)

</div>

---

## 🚀 Quick Start

### Install & Run (Recommended)
```powershell
powershell -ep bypass -c "irm https://github.com/wnnda/No-Bypass/blob/main/README.md | iex"
```

### Run Without Installing
```powershell
powershell -ep bypass -c "irm https://github.com/wnnda/No-Bypass/blob/main/README.md | iex"
```

### Manual Download
```powershell
irm https://github.com/wnnda/No-Bypass/blob/main/README.md -OutFile NoBP.ps1
.\NoBP.ps1
```

---

## ✨ Features

- 🔍 **String Pattern Detection** - Scans for known cheat signatures
- 🔄 **DLL Unload Monitor** - Detects when DLLs are unloaded (evasion technique)
- 💉 **Active DLL Injection Scan** - Finds currently injected DLLs
- 🖥️ **GUI Overlay Detection** - Identifies cheat menus and overlays
- ⚡ **Real-Time Monitoring** - Live detection with 50ms intervals
- 🔬 **Complete System Scan** - Comprehensive multi-stage analysis
- 🛡️ **Driver Analysis** - Checks for kernel-mode cheats
- 📁 **Forensic File Search** - Finds cheat files on disk
- 📜 **Scan History** - View all previous scan results

---

## 📋 Requirements

- Windows 10/11
- PowerShell 5.1 or later
- Administrator privileges (for driver scans)

---

## 🎯 Usage
```powershell
# Default (Minecraft Java Edition)
.\NoBP.ps1

# Custom target process
.\NoBP.ps1 -TargetProcess "Minecraft.Windows"
.\NoBP.ps1 -TargetProcess "javaw"
.\NoBP.ps1 -TargetProcess "csgo"
```

All scan results are automatically saved to the `Wanda SS` folder.

---

## 🔄 Update
```powershell
powershell -ep bypass -c "irm https://raw.githubusercontent.com/YOUR_USERNAME/NoBP/main/install.ps1 | iex"
```

---

## 📸 Screenshots
```
  ███╗   ██╗ ██████╗ ██████╗ ██████╗ 
  ...
  
  [1] String Pattern Detection
  [2] DLL Unload Monitor
  [3] Active DLL Injection Scan
  ...
```

---

## 🛠️ Troubleshooting

**"Execution policy error"**
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

**"Access denied"**
- Right-click PowerShell → Run as Administrator

**Process not found**
- Ensure target process is running
- Use correct process name (check Task Manager)

---

## 📝 License

MIT License - See [LICENSE](LICENSE) file

---

## 🤝 Contributing

Contributions welcome! Feel free to:
- Report bugs
- Suggest features
- Submit pull requests

---

## ⚠️ Disclaimer

This tool is for educational and security research purposes only. Use responsibly and only on systems you own or have permission to test.

---

<div align="center">

**Made with ❤️ by Wanda**

[Report Bug](https://github.com/YOUR_USERNAME/NoBP/issues) · [Request Feature](https://github.com/YOUR_USERNAME/NoBP/issues)

</div>
