# Tools Directory

This directory contains external forensic and threat hunting tools integrated with Custodian-HT.

## Directory Structure

- **Hayabusa/** - Windows Event Log Fast Forensics Timeline Generator
- **Chainsaw/** - Rapidly search and hunt through Windows Event Logs
- **YARA/** - Pattern matching tool for malware researchers
- **Sigma/** - Generic signature format for SIEM systems
- **EZTools/** - Eric Zimmerman's forensic tools suite
- **AVML/** - Acquire Volatile Memory for Linux (Microsoft)
- **PuTTY/** - SSH and Telnet client for remote connections
- **KAPE/** - Kroll Artifact Parser and Extractor (manual download)
- **DumpIt/** - Memory acquisition tool (manual download)
- **MagnetRAM/** - Free memory imaging tool (manual download)
- **Sysmon/** - System Monitor for Windows (manual download)
- **CyberChef/** - The Cyber Swiss Army Knife
- **Sysinternals/** - Microsoft Sysinternals Suite
- **Hindsight/** - Browser forensics tool
- **Volatility3/** - Memory forensics framework

## Automated Downloads

Run `Setup-CustodianHT.ps1` to automatically download:
- Hayabusa
- Chainsaw
- YARA
- Sigma rules
- EZTools (via Get-ZimmermanTools)
- AVML
- PuTTY
- CyberChef
- Sysinternals Suite
- Hindsight

## Manual Downloads Required

1. **KAPE** - https://www.kroll.com/kape
2. **DumpIt** - https://www.magnetforensics.com/resources/magnet-dumpit-for-windows
3. **MagnetRAM** - https://www.magnetforensics.com/resources/magnet-ram-capture
4. **Sysmon** - https://learn.microsoft.com/sysinternals/downloads/sysmon

Download and extract to the respective subdirectories.

## Tool Versions

Custodian-HT uses intelligent tool discovery that can detect versioned executables:
- `hayabusa-3.7.0-win-x64.exe` â†’ Auto-detected as "Hayabusa"
- `chainsaw_x86_64-pc-windows-msvc.exe` â†’ Auto-detected as "Chainsaw"

No need to rename executables!
