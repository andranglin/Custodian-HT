@{
    # Script module or binary module file associated with this manifest
    RootModule = 'Custodian-HT.psm1'

    # Version number of this module
    ModuleVersion = '1.0.0'

    # ID used to uniquely identify this module
    GUID = '7d4e5f6a-8b9c-4d1e-2f3a-5b6c7d8e9f0a'

    # Author of this module
    Author = 'RootGuard'

    # Company or vendor of this module
    CompanyName = 'RootGuard'

    # Copyright statement for this module
    Copyright = '(c) 2026 RootGuard Cyber Defence. All rights reserved.'

    # Description of the functionality provided by this module
    Description = 'Custodian-HT - A comprehensive, modular threat hunting and DFIR toolkit for SOC analysts and incident responders. Integrates Sysmon, YARA, Sigma, Hayabusa, Chainsaw, Eric Zimmerman tools, KAPE, Volatility3, and OSINT capabilities for rapid forensic analysis, threat hunting, and incident response.'

    # Minimum version of the PowerShell engine required by this module
    PowerShellVersion = '5.1'

    # Minimum version of the PowerShell host required by this module
    PowerShellHostVersion = '5.1'

    # Minimum version of Microsoft .NET Framework required by this module
    DotNetFrameworkVersion = '4.7.2'

    # Minimum version of the common language runtime (CLR) required by this module
    CLRVersion = '4.0'

    # Processor architecture (None, X86, Amd64) required by this module
    ProcessorArchitecture = 'None'

    # Modules that must be imported into the global environment prior to importing this module
    RequiredModules = @()

    # Assemblies that must be loaded prior to importing this module
    RequiredAssemblies = @()

    # Script files (.ps1) that are run in the caller's environment prior to importing this module
    ScriptsToProcess = @()

    # Type files (.ps1xml) to be loaded when importing this module
    TypesToProcess = @()

    # Format files (.ps1xml) to be loaded when importing this module
    FormatsToProcess = @()

    # Modules to import as nested modules of the module specified in RootModule/ModuleToProcess
    NestedModules = @(
        '.\Modules\CustodianCollection.psm1',
        '.\Modules\CustodianNetwork.psm1',
        '.\Modules\CustodianLogs.psm1',
        '.\Modules\CustodianSystem.psm1',
        '.\Modules\CustodianAnalysis.psm1',
        '.\Modules\CustodianOSINT.psm1',
        '.\Modules\CustodianReporting.psm1',
        '.\Modules\CustodianPlaybooks.psm1',
        '.\Modules\CustodianAdditional.psm1'
    )

    # Functions to export from this module (filled by root module)
    FunctionsToExport = @(
        # Root module helper functions
        'Write-CustodianLog',
        'Get-CustodianLogPath',
        'Get-CustodianPath',
        'Get-CustodianToolPath',
        'Get-CustodianConfig',
        'Set-CustodianConfig',
        'Test-CustodianRemoteConnection',
        'Get-CustodianRemoteTarget',
        'Invoke-CustodianCommand',
        'Export-CustodianData',
        
        # Collection Module
        'Get-CustodianUSBHistory',
        'Get-CustodianMemory',
        'Get-CustodianFileHashes',
        'Get-CustodianMFT',
        'Get-CustodianProcesses',
        'Get-CustodianHandles',
        'Get-CustodianPrefetch',
        
        # Network Module
        'Get-CustodianNetworkConnections',
        'Get-CustodianARPCache',
        'Get-CustodianDNSCache',
        'Get-CustodianSMBSessions',
        'Get-CustodianFirewallRules',
        'Get-CustodianRoutingTable',
        
        # Logs Module
        'Get-CustodianEventLogs',
        'Get-CustodianAppCompatCache',
        'Get-CustodianUserAssist',
        'Get-CustodianSysmonLogs',
        'Get-CustodianPowerShellLogs',
        'Get-CustodianRDPLogs',
        
        # System Module
        'Get-CustodianAutoruns',
        'Get-CustodianScheduledTasks',
        'Get-CustodianServices',
        'Get-CustodianPersistence',
        'Get-CustodianInstalledSoftware',
        'Get-CustodianCertificates',
        'Get-CustodianDrivers',
        
        # Analysis Module
        'Invoke-HayabusaAnalysis',
        'Invoke-ChainsawAnalysis',
        'Invoke-YaraScan',
        'Invoke-SigmaConversion',
        'Invoke-EZToolParser',
        'Invoke-KAPECollection',
        'Invoke-VolatilityAnalysis',
        
        # OSINT Module
        'Search-VirusTotal',
        'Search-AbuseIPDB',
        'Search-URLhaus',
        'Search-AlienVault',
        'Search-Malshare',
        'Get-ThreatIntel',
        
        # Reporting Module
        'New-CustodianTriageReport',
        'New-CustodianHTMLReport',
        'Export-CustodianIOCs',
        'Export-CustodianTimeline',
        'New-CustodianExecutiveSummary',
        
        # Playbooks Module
        'Start-RansomwareHunt',
        'Start-LateralMovementHunt',
        'Start-PersistenceHunt',
        'Start-DataExfilHunt',
        'Start-CredentialAccessHunt',
        'Start-LOLBinsHunt',
        'Start-WebshellHunt',
        'Start-BECInvestigation',
        
        # Additional Module
        'Get-CustodianDDEAnalysis',
        'Get-CustodianPrintMonitors',
        'Get-CustodianIFEO',
        'Get-CustodianNetshHelpers',
        'Get-CustodianWDigest',
        'Get-CustodianWSLDetection',
        'Get-CustodianBrowserExtensions',
        'Get-CustodianOfficeAddins'
    )

    # Cmdlets to export from this module
    CmdletsToExport = @()

    # Variables to export from this module
    VariablesToExport = @()

    # Aliases to export from this module
    AliasesToExport = @()

    # List of all modules packaged with this module
    ModuleList = @()

    # List of all files packaged with this module
    FileList = @()

    # Private data to pass to the module specified in RootModule/ModuleToProcess
    PrivateData = @{
        PSData = @{
            # Tags applied to this module for module discovery
            Tags = @(
                'Security',
                'ThreatHunting',
                'DFIR',
                'Forensics',
                'IncidentResponse',
                'Malware',
                'SOC',
                'BlueTeam',
                'Sysmon',
                'YARA',
                'Sigma',
                'OSINT',
                'Windows',
                'Linux',
                'CrossPlatform',
                'Hayabusa',
                'Chainsaw',
                'EZTools',
                'KAPE',
                'Volatility',
                'MemoryForensics',
                'EventLogAnalysis',
                'ThreatIntelligence'
            )

            # A URL to the license for this module
            LicenseUri = 'https://github.com/ridgeline-cyber/custodian-ht/blob/main/LICENSE'

            # A URL to the main website for this project
            ProjectUri = 'https://github.com/ridgeline-cyber/custodian-ht'

            # A URL to an icon representing this module
            IconUri = 'https://raw.githubusercontent.com/ridgeline-cyber/custodian-ht/main/Docs/images/icon.png'

            # ReleaseNotes of this module
            ReleaseNotes = @'
# Custodian-HT v1.0.0 Release Notes

## Initial Release Features

### Core Capabilities
- 9 specialized PowerShell modules for comprehensive DFIR operations
- Cross-platform support (Windows native, Linux via SSH/scripts)
- Remote collection capabilities (WinRM and SSH)
- Automated dependency installation
- Modular architecture for extensibility

### Collection Modules
- **CustodianCollection**: Registry, memory, disk, process artifacts
- **CustodianNetwork**: Network connections, ARP, DNS, SMB, firewall
- **CustodianLogs**: Event logs, AppCompatCache, UserAssist, Sysmon
- **CustodianSystem**: Autoruns, tasks, services, persistence mechanisms
- **CustodianAdditional**: DDE, IFEO, print monitors, browser extensions

### Analysis & Intelligence
- **CustodianAnalysis**: Hayabusa, Chainsaw, YARA, Sigma, EZTools, KAPE, Volatility3
- **CustodianOSINT**: VirusTotal, AbuseIPDB, URLhaus, AlienVault OTX, Malshare

### Reporting & Playbooks
- **CustodianReporting**: HTML/JSON/CSV reports, IOC extraction (STIX/OpenIOC)
- **CustodianPlaybooks**: Guided hunts for ransomware, lateral movement, persistence, etc.

### Integrated Tools
- Hayabusa - Windows Event Log forensics
- Chainsaw - SIGMA-based event log hunting
- YARA - Pattern matching for malware
- Sigma - Generic SIEM signatures
- EZTools - Eric Zimmerman's forensic tools
- KAPE - Artifact parser and extractor
- Volatility3 - Memory forensics
- AVML - Linux memory acquisition
- PuTTY - SSH client suite

### Interactive Launcher
- Menu-driven interface for all operations
- Quick triage collection with HTML reporting
- Windows remote hunting (WinRM)
- Linux remote hunting (SSH)
- EZTools integration menu
- OSINT lookup interface
- Analysis tools menu

### Documentation
- Comprehensive README with examples
- Module-specific documentation
- Investigation playbooks
- Troubleshooting guides

## Requirements
- PowerShell 5.1+ (Windows PowerShell or PowerShell 7+)
- .NET Framework 4.7.2+
- Administrator privileges for some collection functions
- Internet connection for OSINT features and tool downloads

## Installation
```powershell
.\Initialize-CustodianHT.ps1
.\Setup-CustodianHT.ps1
.\Custodian-HTLauncher.ps1
```

## Known Issues
- Memory capture requires manual download of DumpIt/MagnetRAM
- KAPE requires license/registration
- API keys needed for full OSINT functionality
- Linux AVML deployment requires sudo permissions

## Roadmap
- Enhanced memory analysis workflows
- Additional OSINT integrations
- Cloud forensics modules
- Container security analysis
- Expanded playbook library

---

**Author:** Ridgeline Cyber Defence - Ady  
**License:** MIT  
**Support:** https://github.com/ridgeline-cyber/custodian-ht/issues
'@

            # Prerelease string of this module
            # Prerelease = 'alpha'

            # Flag to indicate whether the module requires explicit user acceptance for install/update/save
            RequireLicenseAcceptance = $false

            # External dependent modules of this module
            # ExternalModuleDependencies = @()
        }
    }

    # HelpInfo URI of this module
    HelpInfoURI = 'https://github.com/ridgeline-cyber/custodian-ht/wiki'

    # Default prefix for commands exported from this module
    # DefaultCommandPrefix = 'Custodian'
}