<p align="center">
  <img src="Docs/images/banner.png" alt="Custodian-HT Banner" width="800"/>
</p>

<h1 align="center">Custodian-HT</h1>

<p align="center">
  <strong>Threat Hunting and Digital Forensics Toolkit for Windows and Linux</strong>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#documentation">Documentation</a> •
  <a href="#requirements">Requirements</a> •
  <a href="#license">License</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/PowerShell-5.1%2B-blue?logo=powershell" alt="PowerShell 5.1+"/>
  <img src="https://img.shields.io/badge/PowerShell-7.x-blue?logo=powershell" alt="PowerShell 7.x"/>
  <img src="https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-lightgrey" alt="Platform"/>
  <img src="https://img.shields.io/badge/License-MIT-green" alt="License"/>
  <img src="https://img.shields.io/github/v/release/yourusername/Custodian-HT" alt="Release"/>
</p>

---

## Overview

**Custodian-HT** is a comprehensive, modular threat hunting and digital forensics toolkit designed for SOC analysts, DFIR investigators, and security professionals. It provides an interactive menu-driven interface for rapid triage, artifact collection, and threat hunting across Windows and Linux systems—both locally and remotely.

Built for real-world incident response scenarios, Custodian-HT integrates with industry-standard tools like KAPE, Hayabusa, Chainsaw, Eric Zimmerman's tools, Volatility3, and YARA to provide a complete forensic analysis workflow.

## Features

### 🔍 Local Operations
| Feature | Description |
|---------|-------------|
| **Quick Triage** | Comprehensive system triage with automated HTML report generation |
| **Collection Modules** | Network, Event Logs, System Artifacts, Persistence, Browser Extensions |
| **Hunt Playbooks** | Guided threat hunting for Ransomware, Lateral Movement, Credential Access, and more |
| **Analysis Tools** | Integration with Hayabusa, Chainsaw, YARA, Sigma, EZTools, Volatility3 |
| **OSINT Integration** | VirusTotal, AbuseIPDB, URLhaus, AlienVault OTX lookups |

### 🖥️ Windows Remote Hunting
| Feature | Description |
|---------|-------------|
| **WinRM Connection** | PowerShell Remoting with Kerberos/NTLM authentication |
| **PSExec Connection** | SMB-based alternative when WinRM is unavailable |
| **Remote Triage** | Execute collection modules on remote Windows systems |
| **Remote KAPE** | Deploy and run KAPE on remote systems, retrieve results |
| **Script Deployment** | Deploy custom PowerShell scripts for collection |
| **Hash Search** | Search for IOCs by hash across remote systems |

### 🐧 Linux Remote Hunting
| Feature | Description |
|---------|-------------|
| **SSH Connection** | Key-based and password authentication with smart fallback |
| **Full System Triage** | Deploy collection script, execute, retrieve artifacts |
| **AVML Memory Capture** | Remote Linux memory acquisition |
| **Quick Triage** | Live forensic commands executed via SSH |
| **Hash Search** | Search for IOCs across remote Linux filesystems |

### 📦 KAPE & Memory
| Feature | Description |
|---------|-------------|
| **Local KAPE Collection** | Triage, Full, or Custom collection modes |
| **Remote KAPE Deployment** | Deploy, execute, and retrieve KAPE from remote systems |
| **Memory Capture** | DumpIt and Magnet RAM Capture support with Secure Boot detection |

### 🔬 Scanning & Detection
| Feature | Description |
|---------|-------------|
| **Loki-RS Scanner** | IOC scanning with YARA rules (local and remote) |
| **yarGen** | YARA rule generation from samples |
| **Sigma Rules** | Detection rule conversion and deployment |

### 📊 Vulnerability Intelligence
| Feature | Description |
|---------|-------------|
| **Patch Tuesday Analysis** | Microsoft monthly vulnerability analysis and reporting |

## Quick Start

### Installation

```powershell
# Clone the repository
git clone https://github.com/yourusername/Custodian-HT.git
cd Custodian-HT

# Run the initialization script
.\Initialize-CustodianHT.ps1

# Launch the toolkit
.\Custodian-HTLauncher.ps1
```

### First Run

1. **Configure API Keys** (optional): Edit `Config\Custodian-HT.json` to add your VirusTotal, AbuseIPDB, and other API keys for OSINT lookups.

2. **Install External Tools** (optional): Place tools in the `Tools\` directory:
   - `Tools\kape\` - KAPE
   - `Tools\hayabusa\` - Hayabusa
   - `Tools\chainsaw\` - Chainsaw
   - `Tools\yara\` - YARA
   - `Tools\PSTools\` - Sysinternals PSExec
   - `Tools\DumpIt\` - Memory capture tools

3. **Launch**: Run `.\Custodian-HTLauncher.ps1` and select your operation from the interactive menu.

## Screenshots

<details>
<summary>Click to expand screenshots</summary>

### Main Menu
```
  ██████╗██╗   ██╗███████╗████████╗ ██████╗ ██████╗ ██╗ █████╗ ███╗   ██╗       ██╗  ██╗████████╗
 ██╔════╝██║   ██║██╔════╝╚══██╔══╝██╔═══██╗██╔══██╗██║██╔══██╗████╗  ██║       ██║  ██║╚══██╔══╝
 ██║     ██║   ██║███████╗   ██║   ██║   ██║██║  ██║██║███████║██╔██╗ ██║█████╗███████║   ██║
 ██║     ██║   ██║╚════██║   ██║   ██║   ██║██║  ██║██║██╔══██║██║╚██╗██║╚════╝██╔══██║   ██║
 ╚██████╗╚██████╔╝███████║   ██║   ╚██████╔╝██████╔╝██║██║  ██║██║ ╚████║       ██║  ██║   ██║
  ╚═════╝ ╚═════╝ ╚══════╝   ╚═╝    ╚═════╝ ╚═════╝ ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝       ╚═╝  ╚═╝   ╚═╝

  Threat Hunting and DFIR Toolkit v2.2.18
  RootGuard Cyber Defence

  Target: localhost

  LOCAL OPERATIONS
  [1] Quick Triage            - Comprehensive system triage + HTML report
  [2] Collection Modules      - Network, Logs, System, Persistence
  [3] Hunt Playbooks          - Guided threat hunting scenarios
  [4] Analysis Tools          - Hayabusa, Chainsaw, YARA, Sigma
  [5] EZTools                 - Eric Zimmerman's forensic tools
  [6] OSINT                   - Threat intelligence lookups

  REMOTE OPERATIONS
  [7] Windows Remote          - WinRM hunting (hybrid: modules + deployment)
  [8] Linux Remote            - SSH hunting (deployment-based)

  KAPE & MEMORY
  [K] KAPE Collection         - Local and remote KAPE acquisition
  [M] Memory Capture          - Local memory dump (DumpIt/MagnetRAM)

  SCANNING & DETECTION
  [S] Scanning Tools          - Loki-RS IOC scanner, yarGen rule generator

  VULNERABILITY INTELLIGENCE
  [P] Patch Tuesday           - Microsoft monthly vulnerability analysis

  [0] Exit
```

</details>

## Requirements

### System Requirements
- **Operating System**: Windows 10/11 or Windows Server 2016+
- **PowerShell**: 5.1 or 7.x (both supported)
- **Privileges**: Administrator recommended for full functionality

### For Remote Operations
| Target | Requirements |
|--------|--------------|
| **Windows (WinRM)** | WinRM enabled (`Enable-PSRemoting -Force`), TCP 5985/5986 |
| **Windows (PSExec)** | Admin shares accessible (C$), TCP 445, PSExec.exe |
| **Linux (SSH)** | SSH service running, TCP 22, sudo privileges recommended |

### Optional Tools
These tools enhance Custodian-HT's capabilities when placed in the `Tools\` directory:

| Tool | Purpose | Download |
|------|---------|----------|
| KAPE | Artifact collection | [Kroll](https://www.kroll.com/en/services/cyber-risk/incident-response-litigation-support/kroll-artifact-parser-extractor-kape) |
| Hayabusa | Event log analysis | [GitHub](https://github.com/Yamato-Security/hayabusa) |
| Chainsaw | Sigma-based hunting | [GitHub](https://github.com/WithSecureLabs/chainsaw) |
| YARA | Pattern scanning | [GitHub](https://github.com/VirusTotal/yara) |
| EZTools | Forensic parsers | [Eric Zimmerman](https://ericzimmerman.github.io/) |
| Volatility3 | Memory analysis | [GitHub](https://github.com/volatilityfoundation/volatility3) |
| PSExec | Remote execution | [Sysinternals](https://docs.microsoft.com/en-us/sysinternals/downloads/psexec) |
| DumpIt | Memory capture | [Magnet Forensics](https://www.magnetforensics.com/) |
| AVML | Linux memory capture | [GitHub](https://github.com/microsoft/avml) |
| Loki | IOC scanner | [GitHub](https://github.com/Neo23x0/Loki) |

## Directory Structure

```
Custodian-HT/
├── Custodian-HTLauncher.ps1    # Main launcher script
├── Custodian-HT.psm1           # Root module
├── Initialize-CustodianHT.ps1  # Setup script
├── Config/
│   └── Custodian-HT.json       # Configuration (API keys, paths)
├── Modules/
│   ├── CustodianCore.psm1      # Core functions
│   ├── CustodianNetwork.psm1   # Network collection
│   ├── CustodianSystem.psm1    # System artifacts
│   ├── CustodianEventLogs.psm1 # Event log collection
│   ├── CustodianPlaybooks.psm1 # Hunt playbooks
│   ├── CustodianOSINT.psm1     # Threat intelligence
│   ├── CustodianAnalysis.psm1  # Analysis tool wrappers
│   ├── CustodianScanning.psm1  # IOC scanning
│   ├── CustodianPatchTuesday.psm1 # Vulnerability intel
│   └── ...
├── Tools/                      # External tools directory
├── Output/                     # Collection output
│   ├── Triage/
│   ├── Collection/
│   ├── Memory/
│   └── Analysis/
├── Scripts/
│   ├── Custodian-linux.sh      # Linux triage script
│   └── Invoke-ThreatHunt.ps1   # Windows deployment script
└── docs/
    └── USER_GUIDE.md           # Detailed documentation
```

## Documentation

- **[User Guide](docs/USER_GUIDE.md)** - Detailed usage instructions
- **[Installation Guide](docs/INSTALLATION.md)** - Setup and configuration
- **[Module Reference](docs/MODULES.md)** - Available functions and parameters
- **[Playbook Guide](docs/PLAYBOOKS.md)** - Hunt playbook documentation
- **[Troubleshooting](docs/TROUBLESHOOTING.md)** - Common issues and solutions

## Hunt Playbooks

Custodian-HT includes pre-built threat hunting playbooks:

| Playbook | Description |
|----------|-------------|
| **Ransomware Hunt** | Encryption activity, shadow copy deletion, suspicious extensions |
| **Lateral Movement** | RDP, SMB, WMI, PsExec indicators |
| **Persistence Hunt** | Autoruns, scheduled tasks, services, WMI subscriptions |
| **Credential Access** | LSASS access, SAM dumps, Kerberos attacks |
| **Data Exfiltration** | Large files, archives, cloud storage activity |
| **LOLBins Hunt** | PowerShell, WMIC, CertUtil, BitsAdmin abuse |
| **Webshell Hunt** | Web directory anomalies, IIS log analysis |
| **BEC Investigation** | Email client artifacts, Outlook data |

## Contributing

Contributions are welcome! Please read our [Contributing Guide](CONTRIBUTING.md) for details on:
- Code style and standards
- Submitting pull requests
- Reporting bugs
- Requesting features

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [Eric Zimmerman](https://ericzimmerman.github.io/) - EZTools suite
- [Yamato Security](https://github.com/Yamato-Security) - Hayabusa
- [WithSecure Labs](https://github.com/WithSecureLabs) - Chainsaw
- [Florian Roth](https://github.com/Neo23x0) - YARA rules and Loki
- [Volatility Foundation](https://github.com/volatilityfoundation) - Volatility3
- [Kroll](https://www.kroll.com/) - KAPE
- [Microsoft](https://github.com/microsoft/avml) - AVML

## Disclaimer

This tool is provided for legitimate security testing and incident response purposes only. Users are responsible for ensuring they have proper authorization before using this tool on any system. The authors are not responsible for any misuse or damage caused by this tool.

---

<p align="center">
  <strong>RootGuard Cyber Defence</strong><br>
  <em>Threat Hunting • Detection Engineering • Incident Response</em>
</p>
