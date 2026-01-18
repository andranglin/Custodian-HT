# Installation Guide

> Step-by-step guide to installing and configuring Custodian-HT

---

## Table of Contents

1. [System Requirements](#system-requirements)
2. [Quick Installation](#quick-installation)
3. [Manual Installation](#manual-installation)
4. [External Tools Setup](#external-tools-setup)
5. [Configuration](#configuration)
6. [Verification](#verification)
7. [Updating](#updating)
8. [Uninstallation](#uninstallation)

---

## System Requirements

### Minimum Requirements

| Component | Requirement |
|-----------|-------------|
| **OS** | Windows 10/11 or Windows Server 2016+ |
| **PowerShell** | 5.1 (built-in) or PowerShell 7.x |
| **RAM** | 8 GB (16 GB recommended for memory analysis) |
| **Storage** | 10 GB free (more for collections and memory dumps) |
| **Privileges** | Administrator (recommended) |

### For Remote Operations

| Target Type | Requirements |
|-------------|--------------|
| **Windows (WinRM)** | TCP 5985/5986 open, WinRM enabled |
| **Windows (PSExec)** | TCP 445 open, Admin shares accessible |
| **Linux (SSH)** | TCP 22 open, SSH service running |

### Network Requirements

For OSINT lookups, ensure outbound HTTPS (443) access to:
- api.virustotal.com
- api.abuseipdb.com
- urlhaus.abuse.ch
- otx.alienvault.com

---

## Quick Installation

### Option 1: Git Clone

```powershell
# Clone the repository
git clone https://github.com/yourusername/Custodian-HT.git

# Navigate to directory
cd Custodian-HT

# Run initialization
.\Initialize-CustodianHT.ps1

# Launch
.\Custodian-HTLauncher.ps1
```

### Option 2: Download ZIP

1. Download the latest release from [Releases](https://github.com/yourusername/Custodian-HT/releases)
2. Extract to your preferred location (e.g., `C:\Tools\Custodian-HT`)
3. Open PowerShell as Administrator
4. Navigate to the extracted folder
5. Run `.\Initialize-CustodianHT.ps1`
6. Launch with `.\Custodian-HTLauncher.ps1`

---

## Manual Installation

### Step 1: Download Files

Download or clone the repository to your system:

```powershell
# Create tools directory
New-Item -ItemType Directory -Path "C:\Tools\Custodian-HT" -Force

# Navigate to it
Set-Location "C:\Tools\Custodian-HT"

# Clone (or extract ZIP here)
git clone https://github.com/yourusername/Custodian-HT.git .
```

### Step 2: Create Directory Structure

The initialization script creates these directories, but you can create them manually:

```powershell
# Core directories
$directories = @(
    "Config",
    "Modules",
    "Tools",
    "Tools\kape",
    "Tools\hayabusa",
    "Tools\chainsaw",
    "Tools\yara",
    "Tools\PSTools",
    "Tools\DumpIt",
    "Tools\EZTools",
    "Tools\AVML",
    "Output",
    "Output\Triage",
    "Output\Collection",
    "Output\Memory",
    "Output\Analysis",
    "Scripts",
    "docs"
)

foreach ($dir in $directories) {
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
}
```

### Step 3: Set Execution Policy

```powershell
# For current user (safest)
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# Or for local machine (requires Admin)
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine
```

### Step 4: Unblock Downloaded Files

If downloaded from the internet:

```powershell
Get-ChildItem -Path . -Recurse | Unblock-File
```

### Step 5: Verify Module Loading

```powershell
# Test module import
Import-Module .\Custodian-HT.psm1 -Force -Verbose

# List available commands
Get-Command -Module Custodian-HT
```

---

## External Tools Setup

Custodian-HT integrates with several external forensic tools. Place them in the `Tools\` directory:

### KAPE (Kroll Artifact Parser and Extractor)

1. Download from [Kroll](https://www.kroll.com/en/services/cyber-risk/incident-response-litigation-support/kroll-artifact-parser-extractor-kape)
2. Extract to `Tools\kape\`
3. Ensure `kape.exe` is at `Tools\kape\kape.exe`

```
Tools\kape\
├── kape.exe
├── Targets\
├── Modules\
└── Documentation\
```

### Hayabusa

1. Download from [GitHub Releases](https://github.com/Yamato-Security/hayabusa/releases)
2. Extract to `Tools\hayabusa\`

```
Tools\hayabusa\
├── hayabusa.exe
└── rules\
```

### Chainsaw

1. Download from [GitHub Releases](https://github.com/WithSecureLabs/chainsaw/releases)
2. Extract to `Tools\chainsaw\`

```
Tools\chainsaw\
├── chainsaw.exe
└── rules\
```

### PSExec (Sysinternals)

1. Download from [Microsoft](https://docs.microsoft.com/en-us/sysinternals/downloads/psexec)
2. Extract to `Tools\PSTools\`

```
Tools\PSTools\
├── PsExec.exe
├── PsExec64.exe
└── ...
```

### DumpIt / Magnet RAM Capture

**DumpIt:**
1. Download from [Magnet Forensics](https://www.magnetforensics.com/resources/magnet-dumpit-for-windows/)
2. Place in `Tools\DumpIt\`

**Magnet RAM Capture:**
1. Download from [Magnet Forensics](https://www.magnetforensics.com/resources/magnet-ram-capture/)
2. Place in `Tools\DumpIt\`

```
Tools\DumpIt\
├── DumpIt.exe
└── MagnetRAMCapture.exe
```

### EZTools (Eric Zimmerman's Tools)

1. Download from [Eric Zimmerman's website](https://ericzimmerman.github.io/)
2. Extract to `Tools\EZTools\`

```
Tools\EZTools\
├── AmcacheParser.exe
├── LECmd.exe
├── PECmd.exe
├── RBCmd.exe
├── SBECmd.exe
├── JLECmd.exe
├── RecentFileCacheParser.exe
├── SrumECmd.exe
└── RegistryExplorer\
```

### YARA

1. Download from [GitHub Releases](https://github.com/VirusTotal/yara/releases)
2. Extract to `Tools\yara\`
3. Add your YARA rules to `Tools\yara\rules\`

```
Tools\yara\
├── yara64.exe
└── rules\
    ├── malware\
    └── custom\
```

### AVML (Linux Memory Capture)

1. Download from [GitHub Releases](https://github.com/microsoft/avml/releases)
2. Place in `Tools\AVML\`

```
Tools\AVML\
└── avml
```

### Loki-RS / Loki

1. Download from [GitHub](https://github.com/Neo23x0/Loki)
2. Extract to `Tools\loki\`

```
Tools\loki\
├── loki.exe
└── signature-base\
```

### Volatility3

1. Install via pip: `pip install volatility3`
2. Or download standalone from [GitHub](https://github.com/volatilityfoundation/volatility3)
3. Place in `Tools\volatility3\`

---

## Configuration

### API Keys Configuration

Edit `Config\Custodian-HT.json`:

```json
{
    "APIKeys": {
        "VirusTotal": "your-virustotal-api-key",
        "AbuseIPDB": "your-abuseipdb-api-key",
        "AlienVault": "your-alienvalut-otx-key"
    },
    "Paths": {
        "OutputBase": "Output",
        "ToolsPath": "Tools"
    },
    "Settings": {
        "DefaultTimespan": 7,
        "MaxEventLogEntries": 10000
    }
}
```

### Getting API Keys

| Service | How to Get Key |
|---------|----------------|
| **VirusTotal** | [Sign up](https://www.virustotal.com/gui/join-us) → API Key in profile |
| **AbuseIPDB** | [Sign up](https://www.abuseipdb.com/register) → API Keys section |
| **AlienVault OTX** | [Sign up](https://otx.alienvault.com/) → Settings → API Integration |

### Configuring OpenSSH Client (for Linux Remote)

OpenSSH is usually pre-installed on Windows 10/11. To verify:

```powershell
# Check if installed
Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH.Client*'

# Install if missing
Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0
```

### Setting Up SSH Keys

For seamless Linux remote connections:

```powershell
# Generate key pair
ssh-keygen -t rsa -b 4096

# Copy to Linux target
ssh-copy-id user@linux-target

# Test connection
ssh user@linux-target
```

---

## Verification

### Test Module Loading

```powershell
# Import and verify
Import-Module .\Custodian-HT.psm1 -Force

# Check commands are available
Get-Command -Module Custodian-HT | Measure-Object
# Should return 30+ commands

# Test a core function
Get-CustodianPath -PathType "Triage"
# Should return: C:\Path\To\Custodian-HT\Output\Triage
```

### Test Launcher

```powershell
.\Custodian-HTLauncher.ps1

# Should display:
# [+] Custodian-HT modules loaded successfully
# [+] CustodianPatchTuesday module loaded
# 
# (Banner and menu)
```

### Test External Tools

```powershell
# Test KAPE
.\Tools\kape\kape.exe --help

# Test Hayabusa
.\Tools\hayabusa\hayabusa.exe --version

# Test PSExec
.\Tools\PSTools\PsExec.exe -accepteula
```

---

## Updating

### Via Git

```powershell
cd C:\Tools\Custodian-HT
git pull origin main

# Re-run initialization if needed
.\Initialize-CustodianHT.ps1
```

### Manual Update

1. Download new release
2. Backup your `Config\` directory
3. Backup any custom scripts in `Scripts\`
4. Extract new version over existing
5. Restore your configuration files

### Updating External Tools

Check each tool's GitHub releases page for updates:
- [Hayabusa Releases](https://github.com/Yamato-Security/hayabusa/releases)
- [Chainsaw Releases](https://github.com/WithSecureLabs/chainsaw/releases)
- [YARA Releases](https://github.com/VirusTotal/yara/releases)

---

## Uninstallation

### Remove Custodian-HT

```powershell
# Remove the directory
Remove-Item -Path "C:\Tools\Custodian-HT" -Recurse -Force

# Remove any remaining module cache
Remove-Item -Path "$env:USERPROFILE\Documents\PowerShell\Modules\Custodian-HT" -Recurse -Force -ErrorAction SilentlyContinue
```

### Clean Up Collected Data

If you want to remove collected evidence:

```powershell
# Remove output directory (CAREFUL - this deletes all collected evidence!)
Remove-Item -Path "C:\Tools\Custodian-HT\Output" -Recurse -Force
```

---

## Troubleshooting Installation

### "Running scripts is disabled"

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### "Module not found"

Ensure you're running from the Custodian-HT directory:

```powershell
Set-Location "C:\Tools\Custodian-HT"
.\Custodian-HTLauncher.ps1
```

### "Access denied" on initialization

Run PowerShell as Administrator:

1. Right-click PowerShell
2. Select "Run as Administrator"
3. Navigate to Custodian-HT
4. Run initialization

### External tool not detected

Verify the tool is in the correct location:

```powershell
# Check KAPE
Test-Path ".\Tools\kape\kape.exe"

# Check Hayabusa  
Test-Path ".\Tools\hayabusa\hayabusa.exe"
```

---

## Support

For installation issues:
- Check [Troubleshooting](docs/TROUBLESHOOTING.md)
- Open a [GitHub Issue](https://github.com/yourusername/Custodian-HT/issues)

---

*Custodian-HT - RootGuard Cyber Defence*