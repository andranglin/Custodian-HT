#Requires -Version 5.1
<#
.SYNOPSIS
    Initialize Custodian-HT Directory Structure
.DESCRIPTION
    Creates the complete directory structure for Custodian-HT toolkit including
    Tools, Config, Modules, Output, Scripts, and Docs folders with README files.
.AUTHOR
    RootGuard Cyber Defence
.VERSION
    2.2.18
.EXAMPLE
    .\Initialize-CustodianHT.ps1
    .\Initialize-CustodianHT.ps1 -Force
#>

[CmdletBinding()]
param(
    [Parameter()][switch]$IncludeSamples,
    [Parameter()][switch]$Force
)

#region Configuration
$Script:Version = "2.2.18"
$Script:BasePath = $PSScriptRoot
if (-not $Script:BasePath) { $Script:BasePath = $PWD.Path }

$Script:Directories = @(
    # Tools directories - matches Custodian-HTLauncher.ps1 expectations
    "Tools",
    "Tools\Hayabusa",
    "Tools\Chainsaw",
    "Tools\YARA",
    "Tools\YARA\rules",
    "Tools\Sigma",
    "Tools\Sigma\rules",
    "Tools\EZTools",
    "Tools\AVML",
    "Tools\kape",                    # lowercase to match launcher
    "Tools\DumpIt",
    "Tools\MagnetRAMCapture",        # matches launcher path
    "Tools\PSTools",                 # for PsExec - matches launcher
    "Tools\Sysinternals",            # full Sysinternals suite
    "Tools\Volatility3",
    "Tools\Loki",                    # IOC scanner
    "Tools\Hindsight",
    "Tools\CyberChef",
    "Tools\yarGen",
    
    # Config directory
    "Config",
    "Config\Templates",
    "Config\Rules",
    
    # Modules directory
    "Modules",
    
    # Scripts directory - for deployment scripts
    "Scripts",
    
    # Output directories
    "Output",
    "Output\Logs",
    "Output\Analysis",
    "Output\Collection",
    "Output\Memory",
    "Output\Triage",
    "Output\Cache",
    "Output\Reports",
    "Output\Temp",
    "Output\Evidence",
    
    # Docs directories
    "Docs",
    "Docs\examples",
    "Docs\images",
    "Docs\playbooks"
)

$Script:ReadmeFiles = @{
    "README.md" = @"
# Custodian-HT - Threat Hunting & DFIR Toolkit

**Version:** $Script:Version  
**Author:** Ridgeline Cyber Defence  
**PowerShell:** 5.1+ (Windows PowerShell and PowerShell 7+)

---

## Overview

Custodian-HT is a comprehensive, modular threat hunting and digital forensics toolkit designed for SOC analysts and DFIR investigators. It integrates industry-standard tools (Hayabusa, Chainsaw, YARA, Sigma, EZTools, KAPE) with custom PowerShell modules for rapid incident response, threat hunting, and forensic analysis.

### Key Features

- **Local & Remote Operations:** Windows (WinRM/PSExec) and Linux (SSH) support
- **Tool Integration:** Hayabusa, Chainsaw, YARA, Sigma, EZTools, KAPE, Volatility3, Loki
- **OSINT Capabilities:** VirusTotal, AbuseIPDB, URLhaus, AlienVault OTX
- **Hunt Playbooks:** Ransomware, lateral movement, persistence, credential access, data exfil
- **Memory Analysis:** DumpIt, MagnetRAM, AVML (Linux), Volatility3 integration
- **Automated Reporting:** HTML triage reports, CSV exports

---

## Quick Start

### 1. Initialize Directory Structure
``````powershell
.\Initialize-CustodianHT.ps1
``````

### 2. Install Dependencies
``````powershell
.\Setup-CustodianHT.ps1
``````

### 3. Configure API Keys (Optional)
Edit ``Config\Custodian-HT.json`` to add OSINT API keys.

### 4. Launch Custodian-HT
``````powershell
.\Custodian-HTLauncher.ps1
``````

---

## Main Menu Options

| Option | Description |
|--------|-------------|
| [1] Quick Triage | Comprehensive system triage + HTML report |
| [2] Collection Modules | Network, Logs, System, Persistence |
| [3] Hunt Playbooks | Guided threat hunting scenarios |
| [4] Analysis Tools | Hayabusa, Chainsaw, YARA, Sigma |
| [5] EZTools | Eric Zimmerman's forensic tools |
| [6] OSINT | Threat intelligence lookups |
| [7] Windows Remote | WinRM/PSExec-based remote hunting |
| [8] Linux Remote | SSH-based remote hunting |
| [K] KAPE Collection | Local and remote KAPE acquisition |
| [M] Memory Capture | DumpIt/MagnetRAM memory dump |
| [S] Scanning Tools | Loki IOC scanner, yarGen |
| [P] Patch Tuesday | Microsoft vulnerability analysis |

---

## Directory Structure

``````
Custodian-HT\
├── Custodian-HTLauncher.ps1     # Main interactive launcher
├── Custodian-HT.psm1            # Root module
├── Initialize-CustodianHT.ps1   # This script
├── Setup-CustodianHT.ps1        # Tool installer
├── Tools\                       # External forensic tools
│   ├── Hayabusa\
│   ├── Chainsaw\
│   ├── YARA\
│   ├── kape\
│   ├── PSTools\                 # PsExec for remote execution
│   ├── DumpIt\
│   ├── MagnetRAMCapture\
│   ├── EZTools\
│   ├── AVML\
│   ├── Loki\
│   └── Volatility3\
├── Config\                      # Configuration files
├── Modules\                     # PowerShell modules
├── Scripts\                     # Deployment scripts
│   ├── Custodian-linux.sh
│   └── Invoke-ThreatHunt.ps1
├── Output\                      # All output data
│   ├── Triage\
│   ├── Collection\
│   ├── Memory\
│   ├── Analysis\
│   └── Reports\
└── Docs\                        # Documentation
``````

---

## Requirements

- Windows 10/11 or Windows Server 2016+
- PowerShell 5.1 or PowerShell 7+
- Administrator privileges (recommended)

For remote operations:
- Windows targets: WinRM (TCP 5985/5986) or SMB (TCP 445)
- Linux targets: SSH (TCP 22)

---

## License

MIT License - See LICENSE file for details.

---

*Ridgeline Cyber Defence - Threat Hunting • Detection Engineering • Incident Response*
"@

    "Tools\README.md" = @"
# Custodian-HT Tools Directory

Place external forensic tools in their respective subdirectories.

## Required Tools

| Tool | Subdirectory | Download |
|------|--------------|----------|
| Hayabusa | Tools\Hayabusa\ | https://github.com/Yamato-Security/hayabusa |
| Chainsaw | Tools\Chainsaw\ | https://github.com/WithSecureLabs/chainsaw |
| YARA | Tools\YARA\ | https://github.com/VirusTotal/yara |
| KAPE | Tools\kape\ | https://www.kroll.com/kape |
| EZTools | Tools\EZTools\ | https://ericzimmerman.github.io/ |
| PSTools | Tools\PSTools\ | https://docs.microsoft.com/en-us/sysinternals/downloads/psexec |
| DumpIt | Tools\DumpIt\ | https://www.magnetforensics.com/ |
| Loki | Tools\Loki\ | https://github.com/Neo23x0/Loki |

## Optional Tools

| Tool | Subdirectory | Download |
|------|--------------|----------|
| Volatility3 | Tools\Volatility3\ | https://github.com/volatilityfoundation/volatility3 |
| AVML | Tools\AVML\ | https://github.com/microsoft/avml |
| MagnetRAM | Tools\MagnetRAMCapture\ | https://www.magnetforensics.com/ |
| CyberChef | Tools\CyberChef\ | https://github.com/gchq/CyberChef |
| Hindsight | Tools\Hindsight\ | https://github.com/obsidianforensics/hindsight |

## Automatic Installation

Run ``Setup-CustodianHT.ps1`` to automatically download and install most tools.

``````powershell
.\Setup-CustodianHT.ps1
``````

Note: KAPE and MagnetRAM require manual download due to licensing.
"@

    "Scripts\README.md" = @"
# Custodian-HT Scripts Directory

Deployment scripts for remote collection.

## Windows Deployment
- **Invoke-ThreatHunt.ps1** - Comprehensive Windows threat hunting script
  - Deployed via WinRM or copied manually
  - Collects: processes, network, persistence, logs, etc.

## Linux Deployment
- **Custodian-linux.sh** - Linux triage collection script
  - Deployed via SCP, executed via SSH
  - Collects: processes, network, users, logs, cron, etc.

## Usage

These scripts are automatically deployed by the launcher when using:
- [7] Windows Remote → [5] Deploy Invoke-ThreatHunt.ps1
- [8] Linux Remote → [1] Full System Triage
"@

    "Docs\README.md" = @"
# Custodian-HT Documentation

## Contents

### /playbooks
Threat hunting playbook documentation:
- Ransomware investigation
- Lateral movement detection
- Persistence mechanism hunting
- Credential access investigation
- Data exfiltration detection
- Living-off-the-land (LOLBins) detection
- Webshell hunting
- Business Email Compromise (BEC) investigation

### /examples
Sample scripts and usage examples for:
- Quick triage collection
- Remote Windows hunting
- Remote Linux hunting
- OSINT investigations
- Memory analysis workflows

### /images
Screenshots and diagrams for documentation.

## Online Documentation

- User Guide: docs/USER_GUIDE.md
- Installation: docs/INSTALLATION.md
"@
}
#endregion

#region Helper Functions
function Write-InitLog {
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet("INFO","SUCCESS","WARN","ERROR")][string]$Level = "INFO"
    )
    
    $colors = @{
        INFO = "Cyan"
        SUCCESS = "Green"
        WARN = "Yellow"
        ERROR = "Red"
    }
    
    $symbols = @{
        INFO = "[*]"
        SUCCESS = "[+]"
        WARN = "[!]"
        ERROR = "[-]"
    }
    
    Write-Host "$($symbols[$Level]) $Message" -ForegroundColor $colors[$Level]
}

function Show-Banner {
    Clear-Host
    Write-Host ""
    Write-Host "===================================================================" -ForegroundColor Cyan
    Write-Host "          CUSTODIAN-HT INITIALIZATION v$Script:Version             " -ForegroundColor Cyan
    Write-Host "                   Ridgeline Cyber Defence                         " -ForegroundColor Cyan
    Write-Host "===================================================================" -ForegroundColor Cyan
    Write-Host ""
}
#endregion

#region Main Functions
function New-DirectoryStructure {
    Write-InitLog "Creating directory structure..." -Level "INFO"
    Write-Host ""
    
    $created = 0
    $existed = 0
    
    foreach ($dir in $Script:Directories) {
        $fullPath = Join-Path $Script:BasePath $dir
        
        if (Test-Path $fullPath) {
            if ($Force) {
                Write-InitLog "  Recreating: $dir" -Level "WARN"
                Remove-Item -Path $fullPath -Recurse -Force -ErrorAction SilentlyContinue
                New-Item -ItemType Directory -Path $fullPath -Force | Out-Null
                $created++
            } else {
                Write-InitLog "  Exists: $dir" -Level "INFO"
                $existed++
            }
        } else {
            try {
                New-Item -ItemType Directory -Path $fullPath -Force -ErrorAction Stop | Out-Null
                Write-InitLog "  Created: $dir" -Level "SUCCESS"
                $created++
            } catch {
                Write-InitLog "  Failed: $dir - $_" -Level "ERROR"
            }
        }
    }
    
    Write-Host ""
    Write-InitLog "Summary: $created created, $existed existed" -Level "SUCCESS"
}

function New-ReadmeFiles {
    Write-Host ""
    Write-InitLog "Creating README files..." -Level "INFO"
    Write-Host ""
    
    foreach ($file in $Script:ReadmeFiles.GetEnumerator()) {
        $filePath = Join-Path $Script:BasePath $file.Key
        
        # Create parent directory if needed
        $parentDir = Split-Path $filePath -Parent
        if (-not (Test-Path $parentDir)) {
            New-Item -ItemType Directory -Path $parentDir -Force | Out-Null
        }
        
        if ((Test-Path $filePath) -and -not $Force) {
            Write-InitLog "  Exists: $($file.Key)" -Level "INFO"
            continue
        }
        
        try {
            $file.Value | Out-File -FilePath $filePath -Encoding UTF8 -Force
            Write-InitLog "  Created: $($file.Key)" -Level "SUCCESS"
        } catch {
            Write-InitLog "  Failed: $($file.Key) - $_" -Level "ERROR"
        }
    }
}

function New-ConfigFile {
    Write-Host ""
    Write-InitLog "Creating configuration file..." -Level "INFO"
    
    $configPath = Join-Path $Script:BasePath "Config\Custodian-HT.json"
    
    if ((Test-Path $configPath) -and -not $Force) {
        Write-InitLog "  Configuration file already exists" -Level "INFO"
        return
    }
    
    # Configuration matching launcher expectations
    $config = @{
        Version = $Script:Version
        LastUpdated = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        Paths = @{
            Tools = "Tools"
            Output = "Output"
            Temp = "Output\Temp"
            Logs = "Output\Logs"
            Config = "Config"
            Modules = "Modules"
            Scripts = "Scripts"
        }
        APIKeys = @{
            VirusTotal = ""
            AbuseIPDB = ""
            AlienVault = ""
            HybridAnalysis = ""
            URLhaus = ""
            Malshare = ""
            Shodan = ""
            GreyNoise = ""
        }
        Settings = @{
            DefaultTimeout = 30
            MaxConcurrentScans = 5
            LogLevel = "INFO"
            EnableMemoryAnalysis = $true
            EnableOSINT = $true
            EnableRemoteCollection = $true
            MaxLogAge = 30
            MaxCacheAge = 7
            DefaultTimespan = 7
            MaxEventLogEntries = 10000
            AutoGenerateReports = $true
        }
        Tools = @{
            Hayabusa = "Tools\Hayabusa"
            Chainsaw = "Tools\Chainsaw"
            YARA = "Tools\YARA"
            Sigma = "Tools\Sigma"
            EZTools = "Tools\EZTools"
            KAPE = "Tools\kape"
            Volatility3 = "Tools\Volatility3"
            PSTools = "Tools\PSTools"
            DumpIt = "Tools\DumpIt"
            MagnetRAM = "Tools\MagnetRAMCapture"
            AVML = "Tools\AVML"
            Loki = "Tools\Loki"
        }
        RemoteDefaults = @{
            WinRMPort = 5985
            WinRMPortHTTPS = 5986
            SSHPort = 22
            SMBPort = 445
            ConnectionTimeout = 30
        }
        KAPE = @{
            DefaultTargets = "!SANS_Triage"
            DefaultModules = "!EZParser"
        }
    } | ConvertTo-Json -Depth 10
    
    try {
        $config | Out-File -FilePath $configPath -Encoding UTF8 -Force
        Write-InitLog "  Created: Config\Custodian-HT.json" -Level "SUCCESS"
    } catch {
        Write-InitLog "  Failed to create config file: $_" -Level "ERROR"
    }
}

function New-LicenseFile {
    Write-Host ""
    Write-InitLog "Creating LICENSE file..." -Level "INFO"
    
    $licensePath = Join-Path $Script:BasePath "LICENSE"
    
    if ((Test-Path $licensePath) -and -not $Force) {
        Write-InitLog "  LICENSE file already exists" -Level "INFO"
        return
    }
    
    $license = @"
MIT License

Copyright (c) 2025-2026 Ridgeline Cyber Defence

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"@
    
    try {
        $license | Out-File -FilePath $licensePath -Encoding UTF8 -Force
        Write-InitLog "  Created: LICENSE" -Level "SUCCESS"
    } catch {
        Write-InitLog "  Failed to create LICENSE: $_" -Level "ERROR"
    }
}

function New-GitIgnore {
    Write-Host ""
    Write-InitLog "Creating .gitignore file..." -Level "INFO"
    
    $gitignorePath = Join-Path $Script:BasePath ".gitignore"
    
    if ((Test-Path $gitignorePath) -and -not $Force) {
        Write-InitLog "  .gitignore file already exists" -Level "INFO"
        return
    }
    
    $gitignore = @"
# Output directories (contain evidence - never commit)
Output/
*.dmp
*.raw
*.lime
*.zip
*.7z

# Configuration with API keys
Config/Custodian-HT.json
!Config/Custodian-HT.json.template

# External tools (download separately)
Tools/*/

# Keep directory structure
!Tools/.gitkeep
!Output/.gitkeep

# Logs and temp
*.log
*.tmp

# IDE files
.vscode/
.idea/

# OS files
.DS_Store
Thumbs.db
desktop.ini
"@
    
    try {
        $gitignore | Out-File -FilePath $gitignorePath -Encoding UTF8 -Force
        Write-InitLog "  Created: .gitignore" -Level "SUCCESS"
    } catch {
        Write-InitLog "  Failed to create .gitignore: $_" -Level "ERROR"
    }
}

function New-GitKeepFiles {
    # Create .gitkeep files to preserve empty directories in git
    $keepDirs = @("Tools", "Output", "Output\Triage", "Output\Collection", "Output\Memory", "Output\Analysis")
    
    foreach ($dir in $keepDirs) {
        $keepPath = Join-Path $Script:BasePath "$dir\.gitkeep"
        if (-not (Test-Path $keepPath)) {
            "" | Out-File -FilePath $keepPath -Encoding UTF8 -Force -ErrorAction SilentlyContinue
        }
    }
}

function Show-Summary {
    Write-Host ""
    Write-Host "===================================================================" -ForegroundColor Cyan
    Write-InitLog "Initialization Complete!" -Level "SUCCESS"
    Write-Host "===================================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Next Steps:" -ForegroundColor Cyan
    Write-Host "  1. Run Setup-CustodianHT.ps1 to download tools" -ForegroundColor White
    Write-Host "  2. Configure API keys in Config\Custodian-HT.json" -ForegroundColor White
    Write-Host "  3. Run Custodian-HTLauncher.ps1 to start hunting!" -ForegroundColor White
    Write-Host ""
    Write-Host "Directory Structure:" -ForegroundColor Cyan
    Write-Host "  $Script:BasePath" -ForegroundColor White
    Write-Host "  ├── Tools\        (external forensic tools)" -ForegroundColor Gray
    Write-Host "  ├── Config\       (configuration files)" -ForegroundColor Gray
    Write-Host "  ├── Modules\      (PowerShell modules)" -ForegroundColor Gray
    Write-Host "  ├── Scripts\      (deployment scripts)" -ForegroundColor Gray
    Write-Host "  ├── Output\       (all collection/analysis output)" -ForegroundColor Gray
    Write-Host "  └── Docs\         (documentation and playbooks)" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Tool Paths (matching launcher):" -ForegroundColor Cyan
    Write-Host "  Tools\kape\kape.exe" -ForegroundColor Gray
    Write-Host "  Tools\PSTools\PsExec.exe" -ForegroundColor Gray
    Write-Host "  Tools\DumpIt\DumpIt.exe" -ForegroundColor Gray
    Write-Host "  Tools\MagnetRAMCapture\MagnetRAMCapture.exe" -ForegroundColor Gray
    Write-Host "  Tools\AVML\avml" -ForegroundColor Gray
    Write-Host ""
}
#endregion

#region Main Execution
Show-Banner

Write-InitLog "Base Path: $Script:BasePath" -Level "INFO"
Write-InitLog "Force Mode: $(if ($Force) {'Enabled'} else {'Disabled'})" -Level "INFO"

# Create directory structure
New-DirectoryStructure

# Create README files
New-ReadmeFiles

# Create configuration file
New-ConfigFile

# Create LICENSE
New-LicenseFile

# Create .gitignore
New-GitIgnore

# Create .gitkeep files
New-GitKeepFiles

# Show summary
Show-Summary
#endregion