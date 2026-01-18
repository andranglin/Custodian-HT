# Custodian-HT User Guide

> Comprehensive documentation for the Custodian-HT Threat Hunting and DFIR Toolkit

---

## Table of Contents

1. [Getting Started](#getting-started)
2. [Local Operations](#local-operations)
3. [Windows Remote Hunting](#windows-remote-hunting)
4. [Linux Remote Hunting](#linux-remote-hunting)
5. [KAPE Collection](#kape-collection)
6. [Memory Capture](#memory-capture)
7. [Analysis Tools](#analysis-tools)
8. [OSINT & Threat Intelligence](#osint--threat-intelligence)
9. [Scanning Tools](#scanning-tools)
10. [Hunt Playbooks](#hunt-playbooks)
11. [Troubleshooting](#troubleshooting)

---

## Getting Started

### Launching the Toolkit

```powershell
# Navigate to the Custodian-HT directory
cd C:\Path\To\Custodian-HT

# Run the launcher
.\Custodian-HTLauncher.ps1
```

### First-Time Setup

1. **Initialize the environment** (if not already done):
   ```powershell
   .\Initialize-CustodianHT.ps1
   ```

2. **Configure API keys** for OSINT lookups:
   Edit `Config\Custodian-HT.json`:
   ```json
   {
     "APIKeys": {
       "VirusTotal": "your-api-key-here",
       "AbuseIPDB": "your-api-key-here",
       "AlienVault": "your-api-key-here"
     }
   }
   ```

3. **Install external tools** in the `Tools\` directory (see [Requirements](#requirements)).

### Understanding the Interface

The main menu displays:
- **Target**: Current target system (localhost or connected remote)
- **Menu Sections**: Organized by operation type
- **Keyboard Shortcuts**: Numbers and letters for selection

---

## Local Operations

### [1] Quick Triage

Performs comprehensive local system triage and generates an HTML report.

**What it collects:**
- Network connections (TCP/UDP)
- Running processes with command lines
- Autoruns and persistence mechanisms
- Scheduled tasks
- Services
- Event logs (last 24 hours)
- Network configuration and DNS cache
- SMB sessions

**Usage:**
```
Select option: 1

=== QUICK TRIAGE ===

Case Name (default: Triage-20260118): Investigation-001

Starting comprehensive triage collection...
    Output: C:\Custodian-HT\Output\Triage\Investigation-001

[1/8] Network connections...
[2/8] System information...
...
[8/8] Generating HTML report...

Quick Triage Complete!
    Location: C:\Custodian-HT\Output\Triage\Investigation-001
```

**Output:**
- Individual CSV files for each artifact type
- `TriageReport.html` - Interactive HTML report

---

### [2] Collection Modules

Granular artifact collection with individual module selection.

**Available Modules:**

| Module | Artifacts Collected |
|--------|---------------------|
| **Network Collection** | Connections, ARP cache, DNS cache, SMB sessions, Firewall rules |
| **Event Logs** | Security, System, PowerShell, Sysmon (configurable) |
| **System Artifacts** | Autoruns, Services, Drivers, Certificates |
| **Persistence** | Registry run keys, WMI subscriptions, Scheduled tasks |
| **Browser Extensions** | Chrome, Edge, Firefox extensions |
| **Additional Forensics** | IFEO, WDigest settings, Print monitors, WSL |

**Usage:**
```
Select option: 2

COLLECTION MODULES
[1] Network Collection    - Connections, ARP, DNS, SMB, Firewall
[2] Event Logs            - Security, System, PowerShell, Sysmon
[3] System Artifacts      - Autoruns, Services, Drivers, Certificates
[4] Persistence           - Registry, WMI, Scheduled Tasks
[5] Browser Extensions    - Chrome, Edge, Firefox
[6] Additional Forensics  - IFEO, WDigest, Print Monitors, WSL

[0] Back to Main Menu

Select option: 1
```

---

### [3] Hunt Playbooks

Guided threat hunting scenarios with automated artifact collection and analysis.

**Available Playbooks:**

| Playbook | Target Threats |
|----------|----------------|
| **Ransomware Hunt** | Encryption activity, VSS deletion, suspicious extensions |
| **Lateral Movement Hunt** | RDP, SMB, WMI, PsExec indicators |
| **Persistence Hunt** | Autoruns, tasks, services, WMI subscriptions |
| **Credential Access Hunt** | LSASS, SAM, Kerberos activity |
| **Data Exfiltration Hunt** | Large files, archives, cloud storage |
| **LOLBins Hunt** | PowerShell, WMIC, CertUtil abuse |
| **Webshell Hunt** | Web directories, IIS logs |
| **BEC Investigation** | Email client, Outlook files |

**Example - Ransomware Hunt:**
```
Select playbook: 1

=== RANSOMWARE HUNT ===

[*] Checking for ransomware indicators...
[*] Searching for encrypted file extensions...
[*] Checking Volume Shadow Copy status...
[*] Analyzing recent file activity...

Results saved to: C:\Custodian-HT\Output\Triage\RansomwareHunt_20260118
```

---

## Windows Remote Hunting

### Connecting to a Remote Windows System

**Menu Path:** Main Menu → [7] Windows Remote

**Connection Methods:**

#### Option 1: WinRM (PowerShell Remoting)

```
=== WINDOWS REMOTE CONNECTION ===

Connection Method:
[1] WinRM (PowerShell Remoting) - Requires WinRM enabled
[2] PSExec (SMB-based)          - Uses admin shares, more reliable
[0] Cancel

Select method: 1

Target Hostname or IP (e.g., lab-pc02 or lab-pc02.lab.local): server01.domain.local
[*] Detected FQDN - using domain authentication
[*] Domain authentication - use format: DOMAIN\username or user@domain.local

Enter Admin Credentials for server01.domain.local: DOMAIN\admin
[*] Connecting to server01.domain.local via WinRM...
[*] Attempting Kerberos authentication...
[+] Connected successfully!
    Remote: SERVER01 (DOMAIN) - PS 5.1.19041.1
```

**Prerequisites for WinRM:**
```powershell
# On the TARGET system (run as Administrator):
Enable-PSRemoting -Force
winrm quickconfig
```

**Credential Formats:**
- Domain: `DOMAIN\username` or `username@domain.fqdn`
- Local: `.\username` or `COMPUTERNAME\username`

#### Option 2: PSExec (SMB-based)

Use when WinRM is unavailable or blocked. Requires:
- Admin share access (C$)
- TCP port 445 (SMB)
- PsExec.exe in `Tools\PSTools\`

```
Select method: 2

=== PSEXEC CONNECTION ===

[+] Found PsExec: C:\Custodian-HT\Tools\PSTools\PsExec.exe
Target Hostname or IP: server01
[*] Credentials required for remote access
[*] Use format: DOMAIN\username or username@domain.local

[*] Establishing authenticated SMB connection...
[*] Authenticating...
[+] SMB authentication successful
[+] Admin share access confirmed

[+] PSExec connection ready!
    Target: server01
    User: DOMAIN\admin
    Method: PSExec (SMB)
```

### Windows Remote Menu

Once connected, the remote menu provides:

```
WINDOWS REMOTE HUNTING - server01.domain.local

QUICK OPERATIONS (via WinRM + Modules)
[1] Quick Triage          - Fast collection via module functions
[2] Run Playbook          - Execute hunt playbook remotely
[3] Network Collection    - Get-CustodianNetworkConnections
[4] Persistence Check     - Get-CustodianPersistence

COMPREHENSIVE OPERATIONS (Deployment)
[5] Deploy Invoke-ThreatHunt.ps1 - Full Windows DFIR collection
[6] Remote KAPE Collection - Deploy and run KAPE
[7] Memory Capture        - Deploy DumpIt/MagnetRAM

UTILITIES
[8] Hash Search           - Search files by hash
[9] Interactive PowerShell - Enter-PSSession
[R] RDP Connection        - Open mstsc.exe

[D] Disconnect
[0] Back
```

### PSExec Remote Menu

```
WINDOWS REMOTE (PSEXEC) - server01

QUICK COLLECTION
[1] Quick Triage          - System info, processes, connections
[2] Process List          - Get running processes
[3] Network Connections   - Get netstat output
[4] Scheduled Tasks       - List scheduled tasks
[5] Services              - List services

DEPLOYMENT
[6] Copy & Run Script     - Deploy and execute PS script
[7] Run Command           - Execute custom command
[8] PowerShell Command    - Execute PowerShell command

FILE OPERATIONS
[C] Copy File TO Target   - Copy file to remote system
[G] Get File FROM Target  - Copy file from remote system
[D] Browse Remote         - List remote directory

[0] Disconnect & Back
```

---

## Linux Remote Hunting

### Connecting to a Remote Linux System

**Menu Path:** Main Menu → [8] Linux Remote

**Prerequisites:**
- OpenSSH Client installed on Windows
- SSH service running on target (port 22)
- User with sudo privileges (recommended)

```
=== LINUX REMOTE CONNECTION ===

SSH Target (user@hostname or user@IP): analyst@192.168.1.100
SSH Key detected at default location. Use it? (Y/n): Y

[*] Attempting Key Authentication (~/.ssh/id_rsa)...
[+] Key Authentication Successful!

Store Sudo password for privileged commands? (Y/n): Y
Enter Sudo password for analyst: ********

  Remote System:
    ubuntu-server
    Linux ubuntu-server 5.15.0-91-generic #101-Ubuntu SMP

[+] Session ready
```

**Authentication Methods:**
1. **SSH Key** (recommended) - No repeated prompts
2. **Password** - Interactive password prompt

**Setting Up SSH Key Authentication:**
```powershell
# On Windows analyst workstation:
ssh-keygen -t rsa -b 4096
ssh-copy-id analyst@target-linux
```

### Linux Remote Menu

```
LINUX REMOTE HUNTING - SSH

Connected to: analyst@192.168.1.100

AUTOMATED COLLECTION
[1] Full System Triage      - Deploy script, collect, retrieve
[2] AVML Memory Capture     - Deploy AVML, capture, retrieve
[3] Quick Triage            - Run live triage commands

HUNTING & SEARCH
[4] Hash Search (Remote)    - Search for SHA256 on target
[5] Hash Search (Local)     - Search for SHA256 locally
[6] Custom Command          - Run command on target

FILE TRANSFER
[7] Upload File             - SCP file to target
[8] Download File           - SCP file from target
[9] Interactive SSH         - Open SSH session

[C] Change Target
[D] Disconnect
[0] Back
```

### Linux Triage Collection

**[1] Full System Triage:**
1. Uploads `Custodian-linux.sh` to `/tmp/`
2. Executes with sudo
3. Retrieves the output archive
4. Saves to `Output\Collection\Linux_{hostname}_{timestamp}\`

**[3] Quick Triage Commands:**
Executes 19 forensic commands:
- System info, hostname, uptime
- Current users, failed logins
- Running processes, network connections
- Cron jobs, services
- User accounts, sudo users
- SSH configuration
- Recent temp files, SUID/SGID binaries
- Bash history, environment variables
- Kernel modules, mount points, firewall rules

---

## KAPE Collection

**Menu Path:** Main Menu → [K] KAPE Collection

### Local KAPE Collection

```
KAPE COLLECTION

LOCAL COLLECTION
[1] Triage Collection      - !SANS_Triage targets + EZParser
[2] Full Collection        - All artifacts + registry + logs
[3] Custom Collection      - Select targets and modules

REMOTE COLLECTION
[4] Deploy to Remote       - Deploy KAPE to remote system

[0] Back to Main Menu
```

**Collection Modes:**

| Mode | Targets | Use Case |
|------|---------|----------|
| **Triage** | !SANS_Triage | Quick incident response |
| **Full** | !BasicCollection, RegistryHives, EventLogs | Comprehensive forensics |
| **Custom** | User-selected | Targeted collection |

### Remote KAPE Deployment

1. Copies KAPE to remote system via WinRM
2. Executes collection on remote
3. Compresses results
4. Retrieves archive to local system
5. Cleans up remote files

**Output:** `Output\Collection\KAPE_{ComputerName}_{timestamp}.zip`

---

## Memory Capture

**Menu Path:** Main Menu → [M] Memory Capture

### Local Memory Capture

Supports:
- **DumpIt** - Standard systems
- **Magnet RAM Capture** - Secure Boot enabled systems

```
=== LOCAL MEMORY CAPTURE ===

[*] Checking for Secure Boot...
[*] Using DumpIt
[*] Starting DumpIt...
[*] Output: C:\Custodian-HT\Output\Memory\MemoryDump_WORKSTATION_20260118.dmp

[+] Memory capture complete!
    File: MemoryDump_WORKSTATION_20260118.dmp
    Size: 16.23 GB
    SHA256: abc123...
```

### Remote Memory Capture

For remote Windows systems:
1. Deploys DumpIt/MagnetRAM to target
2. Executes memory capture
3. Retrieves dump file
4. Cleans up remote files

### AVML for Linux

For Linux systems via SSH:
1. Uploads AVML binary to `/tmp/`
2. Executes: `sudo /tmp/avml /tmp/memory.lime`
3. Downloads the LiME format memory dump
4. Provides Volatility3 analysis commands

---

## Analysis Tools

**Menu Path:** Main Menu → [4] Analysis Tools

### Hayabusa

Windows Event Log timeline analysis using Sigma-based detection rules.

```
EVTX directory path: C:\Evidence\EventLogs

[*] Running Hayabusa analysis...
[*] Output: C:\Custodian-HT\Output\Analysis\Hayabusa_20260118\
```

### Chainsaw

Sigma-based event log hunting with additional detection capabilities.

```
EVTX directory path: C:\Evidence\EventLogs

[*] Running Chainsaw analysis...
```

### YARA Scanning

Pattern-based malware scanning.

```
Path to scan: C:\Users\Public

[*] Running YARA scan...
[*] Rules: Tools\yara\rules\
```

### EZTools

Eric Zimmerman's forensic parsers:

| Tool | Purpose |
|------|---------|
| AmcacheParser | Application execution artifacts |
| LECmd | LNK file parser |
| PECmd | Prefetch parser |
| RBCmd | Recycle Bin parser |
| SBECmd | ShellBags explorer |
| JLECmd | Jump lists parser |
| RecentFileCacheParser | RecentFileCache.bcf parser |
| SrumECmd | SRUM database parser |
| RegistryExplorer | Registry hive viewer |

### Volatility3

Memory dump analysis.

```
Memory dump path: C:\Evidence\memory.dmp
Plugin (e.g., windows.pslist, windows.netscan): windows.pslist

[*] Running Volatility3...
```

---

## OSINT & Threat Intelligence

**Menu Path:** Main Menu → [6] OSINT

### Available Lookups

| Service | Lookup Type | API Key Required |
|---------|-------------|------------------|
| VirusTotal | Hash, URL, IP, Domain | Yes |
| AbuseIPDB | IP Address | Yes |
| URLhaus | URL | No |
| AlienVault OTX | Hash, IP, Domain | No |

### Bulk Hash Lookup

Process multiple hashes from a CSV file:

```
CSV file path (must have Hash column): C:\Evidence\hashes.csv

[*] Processing hashes...
[*] Results saved to: C:\Custodian-HT\Output\Analysis\ThreatIntel_20260118.csv
```

**CSV Format:**
```csv
Hash,Source
abc123...,malware.exe
def456...,suspicious.dll
```

---

## Scanning Tools

**Menu Path:** Main Menu → [S] Scanning Tools

### Loki-RS Scanner

IOC scanning with YARA rules, filename patterns, and hash lists.

```
SCANNING TOOLS

[1] Quick Scan (Local)    - Fast scan with default paths
[2] Intense Scan (Local)  - Deep scan with all checks
[3] Remote Scan (Windows) - Deploy Loki to remote
[4] Remote Scan (Linux)   - Deploy Loki via SSH
[5] View Scan Results     - Parse and display Loki log file

[0] Back
```

**Scan Modes:**
- **Quick Scan**: Common paths, essential checks
- **Intense Scan**: Full filesystem, all detection methods

---

## Hunt Playbooks

**Menu Path:** Main Menu → [3] Hunt Playbooks

### Ransomware Hunt

**Indicators Searched:**
- Encrypted file extensions (.encrypted, .locked, .crypt)
- Ransom notes (README.txt, DECRYPT*.txt)
- Volume Shadow Copy deletion
- vssadmin.exe execution
- bcdedit.exe modifications
- wbadmin.exe execution (backup deletion)

### Lateral Movement Hunt

**Indicators Searched:**
- RDP connections (Event ID 4624 Type 10)
- SMB connections (Event ID 5140)
- WMI activity
- PsExec execution
- Remote service creation
- Named pipe connections

### Persistence Hunt

**Artifacts Checked:**
- Registry Run/RunOnce keys
- Scheduled tasks
- Services with unusual paths
- WMI Event Subscriptions
- Startup folder items
- BITS jobs

### Credential Access Hunt

**Indicators Searched:**
- LSASS process access (Event ID 4663)
- SAM/SECURITY hive access
- Mimikatz patterns
- DCSync activity (Event ID 4662)
- Kerberoasting (Event ID 4769)
- Password spray attempts

---

## Troubleshooting

### WinRM Connection Failures

**Error:** "Access is denied"

**Solutions:**
1. Enable WinRM on target:
   ```powershell
   Enable-PSRemoting -Force
   winrm quickconfig
   ```

2. Check credential format:
   - Domain: `DOMAIN\user` or `user@domain.fqdn`
   - Local: `.\user`

3. Add user to Remote Management Users:
   ```powershell
   Add-LocalGroupMember -Group "Remote Management Users" -Member "DOMAIN\user"
   ```

4. For non-domain systems, disable UAC remote restrictions:
   ```powershell
   Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
     -Name "LocalAccountTokenFilterPolicy" -Value 1 -Type DWord
   ```

### PSExec Connection Failures

**Error:** "SMB authentication failed"

**Solutions:**
1. Verify admin share access:
   ```powershell
   dir \\target\C$
   ```

2. Check credentials manually:
   ```powershell
   net use \\target\IPC$ /user:DOMAIN\user *
   ```

3. Ensure TCP 445 is open

### SSH Connection Failures

**Error:** "Connection refused" or "Permission denied"

**Solutions:**
1. Verify SSH service:
   ```bash
   sudo systemctl status sshd
   ```

2. Check firewall:
   ```bash
   sudo ufw status
   ```

3. Test manually:
   ```powershell
   ssh user@target
   ```

4. Set up key authentication:
   ```powershell
   ssh-keygen -t rsa -b 4096
   ssh-copy-id user@target
   ```

### Module Load Failures

**Error:** "Custodian-HT modules not loaded"

**Solution:**
```powershell
# Re-run initialization
.\Initialize-CustodianHT.ps1

# Or manually import
Import-Module .\Custodian-HT.psm1 -Force
```

### External Tool Not Found

**Error:** "KAPE not found" / "Hayabusa not found"

**Solution:**
Place tools in the correct directory:
```
Tools\
├── kape\
│   └── kape.exe
├── hayabusa\
│   └── hayabusa.exe
├── chainsaw\
│   └── chainsaw.exe
├── PSTools\
│   └── PsExec.exe
└── DumpIt\
    └── DumpIt.exe
```

---

## Best Practices

### Evidence Handling

1. **Document everything**: Use meaningful case names
2. **Preserve originals**: Work on copies when possible
3. **Chain of custody**: Note timestamps and hash values
4. **Secure storage**: Encrypt sensitive collections

### Remote Operations

1. **Test connectivity first**: Use ping and port checks
2. **Use SSH keys for Linux**: Avoid repeated password prompts
3. **Monitor bandwidth**: Large collections over slow links
4. **Clean up after**: Remove deployed tools from targets

### Analysis Workflow

1. **Triage first**: Quick triage before deep dive
2. **Timeline early**: Establish activity timeline
3. **Correlate sources**: Cross-reference multiple artifacts
4. **Document findings**: Update case notes continuously

---

## Support

For issues, questions, or feature requests:
- GitHub Issues: [Create an issue](https://github.com/yourusername/Custodian-HT/issues)
- Documentation: [Wiki](https://github.com/yourusername/Custodian-HT/wiki)

---

*Custodian-HT - RootGuard Cyber Defence*