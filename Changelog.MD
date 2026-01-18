# Changelog

All notable changes to Custodian-HT will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Planned
- MacOS remote hunting support
- Cloud artifact collection (Azure AD, M365)
- Automated IOC extraction from memory dumps
- Integration with MISP threat intelligence platform

---

## [2.2.18] - 2026-01-18

### Added
- PSExec connection method for Windows remote hunting
- Smart SSH authentication fallback (key → password)
- Sudo password caching for Linux remote operations
- PowerShell 7 compatibility for WinRM connections
- FQDN auto-detection for domain environments
- Credential format guidance in connection prompts

### Fixed
- WinRM connection failures in domain environments
- SSH ControlMaster socket errors on Windows (removed incompatible feature)
- Error suppression for SMB cleanup commands
- Missing `Connect-WindowsRemote` function

### Changed
- Windows remote menu now offers WinRM or PSExec choice
- Improved error messages with troubleshooting guidance
- Linux SSH uses `SecureString` for sudo password storage

---

## [2.2.0] - 2026-01-15

### Added
- Linux Remote Hunting module via SSH
- Automated Linux triage deployment (`Custodian-linux.sh`)
- AVML memory capture for Linux systems
- Remote hash search for Linux filesystems
- SCP file transfer integration
- CustodianPatchTuesday module for vulnerability intelligence
- CustodianScanning module with Loki-RS integration

### Changed
- Restructured launcher for modular remote operations
- Improved session state management
- Enhanced banner to show connection status

### Fixed
- Event log collection parameter handling
- UTF-8 encoding for output files

---

## [2.1.0] - 2026-01-10

### Added
- Hunt Playbooks menu with 8 pre-built scenarios
- Ransomware Hunt playbook
- Lateral Movement Hunt playbook
- Persistence Hunt playbook
- Credential Access Hunt playbook
- Data Exfiltration Hunt playbook
- LOLBins Hunt playbook
- Webshell Hunt playbook
- BEC Investigation playbook

### Changed
- Reorganized main menu structure
- Improved playbook output formatting

---

## [2.0.0] - 2026-01-01

### Added
- Complete rewrite of module architecture
- Modular design with separate `.psm1` files
- Configuration file support (`Custodian-HT.json`)
- OSINT integration (VirusTotal, AbuseIPDB, URLhaus, AlienVault)
- EZTools integration
- Volatility3 integration
- YARA scanning capabilities
- Hayabusa integration
- Chainsaw integration

### Changed
- New interactive menu system
- Standardized output paths
- Consistent function naming (`Get-Custodian*`)

### Removed
- Legacy monolithic script
- Deprecated collection methods

---

## [1.5.0] - 2025-11-15

### Added
- Remote KAPE deployment
- Memory capture with DumpIt
- Magnet RAM Capture for Secure Boot systems
- HTML triage report generation

### Fixed
- KAPE target path handling
- Remote session cleanup

---

## [1.4.0] - 2025-10-01

### Added
- KAPE integration (local collection)
- Custom KAPE target selection
- Event log collection with time filtering

### Changed
- Improved error handling throughout
- Better progress indicators

---

## [1.3.0] - 2025-08-15

### Added
- Windows Remote Hunting via WinRM
- Remote triage capabilities
- Interactive remote PowerShell session

### Fixed
- TrustedHosts handling for workgroup environments

---

## [1.2.0] - 2025-07-01

### Added
- Browser extension collection (Chrome, Edge, Firefox)
- WMI persistence detection
- BITS job enumeration
- Print monitor detection

### Changed
- Expanded persistence checks
- More detailed service information

---

## [1.1.0] - 2025-05-15

### Added
- Quick Triage function
- Autoruns collection
- Scheduled task enumeration
- Service enumeration
- Certificate store inspection

---

## [1.0.0] - 2025-04-01

### Added
- Initial release
- Network connection collection
- Process enumeration
- Event log collection (basic)
- DNS cache collection
- ARP cache collection

---

## Version History Summary

| Version | Date | Highlights |
|---------|------|------------|
| 2.2.18 | 2026-01-18 | PSExec support, PS7 compatibility |
| 2.2.0 | 2026-01-15 | Linux SSH hunting, Patch Tuesday |
| 2.1.0 | 2026-01-10 | Hunt playbooks |
| 2.0.0 | 2026-01-01 | Major rewrite, modular architecture |
| 1.5.0 | 2025-11-15 | KAPE remote, memory capture |
| 1.0.0 | 2025-04-01 | Initial release |

---

*Custodian-HT - RootGuard Cyber Defence*