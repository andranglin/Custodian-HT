#Requires -Version 5.1
<#
.SYNOPSIS
    Custodian-HT Main Launcher - Remote & Local Threat Hunting Platform
.DESCRIPTION
    Interactive launcher for Custodian-HT threat hunting toolkit supporting:
    - Local threat hunting and triage
    - Windows remote hunting (WinRM + deployment)
    - Linux remote hunting (SSH + deployment)
    - KAPE collection (local and remote)
    - OSINT and analysis tool integration
.AUTHOR
    RootGuard Cyber Defence
.VERSION
    2.2.18 - Fixed Missing Windows Connect Function
#>

[CmdletBinding()]
param()

#region Initialize
$ErrorActionPreference = "Stop"
$Script:Version = "2.2.18"
$Script:BasePath = $PSScriptRoot

# Set Encoding to handle Linux output banners correctly
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# Import Custodian-HT modules
try {
    # Check if the module file actually exists before importing to prevent hard crash if missing
    $modulePath = Join-Path $Script:BasePath "Custodian-HT.psm1"
    if (Test-Path $modulePath) {
        Import-Module $modulePath -Force -ErrorAction Stop
        Write-Host "[+] Custodian-HT modules loaded successfully" -ForegroundColor Green
    } else {
        # Fallback for standalone mode if module is missing
        Write-Host "[!] Custodian-HT.psm1 not found. Some functions may be limited." -ForegroundColor Yellow
    }
} catch {
    Write-Host "[-] Failed to load Custodian-HT modules: $_" -ForegroundColor Red
    Write-Host "[!] Run Initialize-CustodianHT.ps1 first to set up the environment" -ForegroundColor Yellow
    # We don't exit here to allow the launcher to run in "repair" or "setup" contexts if needed
}

# Import CustodianPatchTuesday module (optional - for vulnerability intelligence)
$patchTuesdayModule = Join-Path $Script:BasePath "Modules\CustodianPatchTuesday.psm1"
if (Test-Path $patchTuesdayModule) {
    try {
        Import-Module $patchTuesdayModule -Force -ErrorAction Stop
        Write-Host "[+] CustodianPatchTuesday module loaded" -ForegroundColor Green
    } catch {
        Write-Host "[!] CustodianPatchTuesday module failed to load: $_" -ForegroundColor Yellow
    }
}

# Session state - Windows (WinRM)
$Script:RemoteSession = $null
$Script:RemoteCredential = $null
$Script:RemoteType = $null  # "Windows" or "Linux" or "PSExec"
$Script:RemoteHost = $null
$Script:PSExecPath = $null   # Path to PsExec.exe for PSExec connections

# Session state - Linux (SSH)
$Script:SSHHost = $null          # user@hostname format
$Script:SSHUser = $null          # username only
$Script:SSHHostname = $null      # hostname/IP only
$Script:SSHKeyPath = $null       # optional SSH key path
$Script:SSHConnected = $false
$Script:SSHSudoPass = $null      # Sudo password (SecureString)
#endregion

#region Display Functions
function Show-Banner {
    Clear-Host
    Write-Host ""
    Write-Host "  ██████╗██╗   ██╗███████╗████████╗ ██████╗ ██████╗ ██╗ █████╗ ███╗   ██╗       ██╗  ██╗████████╗" -ForegroundColor Cyan
    Write-Host " ██╔════╝██║   ██║██╔════╝╚══██╔══╝██╔═══██╗██╔══██╗██║██╔══██╗████╗  ██║       ██║  ██║╚══██╔══╝" -ForegroundColor Cyan
    Write-Host " ██║     ██║   ██║███████╗   ██║   ██║   ██║██║  ██║██║███████║██╔██╗ ██║█████╗███████║   ██║   " -ForegroundColor Green
    Write-Host " ██║     ██║   ██║╚════██║   ██║   ██║   ██║██║  ██║██║██╔══██║██║╚██╗██║╚════╝██╔══██║   ██║   " -ForegroundColor Green
    Write-Host " ╚██████╗╚██████╔╝███████║   ██║   ╚██████╔╝██████╔╝██║██║  ██║██║ ╚████║       ██║  ██║   ██║   " -ForegroundColor Yellow
    Write-Host "  ╚═════╝ ╚═════╝ ╚══════╝   ╚═╝      ╚═════╝ ╚═════╝ ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝       ╚═╝  ╚═╝   ╚═╝   " -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  Threat Hunting and DFIR Toolkit v$Script:Version" -ForegroundColor White
    Write-Host "  RootGuard Cyber Defence" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Target: " -NoNewline -ForegroundColor Gray
    if ($Script:RemoteSession) {
        Write-Host "$Script:RemoteHost (Windows/WinRM)" -ForegroundColor Green
    } elseif ($Script:RemoteType -eq "PSExec" -and $Script:RemoteHost) {
        Write-Host "$Script:RemoteHost (Windows/PSExec)" -ForegroundColor Green
    } elseif ($Script:SSHConnected) {
        Write-Host "$Script:SSHHost (Linux/SSH)" -ForegroundColor Green
    } else {
        Write-Host "localhost" -ForegroundColor Cyan
    }
    Write-Host ""
}

function Show-MainMenu {
    Write-Host "  LOCAL OPERATIONS" -ForegroundColor Cyan
    Write-Host "  [1] Quick Triage            - Comprehensive system triage + HTML report"
    Write-Host "  [2] Collection Modules      - Network, Logs, System, Persistence"
    Write-Host "  [3] Hunt Playbooks          - Guided threat hunting scenarios"
    Write-Host "  [4] Analysis Tools          - Hayabusa, Chainsaw, YARA, Sigma"
    Write-Host "  [5] EZTools                 - Eric Zimmerman's forensic tools"
    Write-Host "  [6] OSINT                   - Threat intelligence lookups"
    Write-Host ""
    Write-Host "  REMOTE OPERATIONS" -ForegroundColor Yellow
    Write-Host "  [7] Windows Remote          - WinRM hunting (hybrid: modules + deployment)"
    Write-Host "  [8] Linux Remote            - SSH hunting (deployment-based)"
    Write-Host ""
    Write-Host "  KAPE & MEMORY" -ForegroundColor Magenta
    Write-Host "  [K] KAPE Collection         - Local and remote KAPE acquisition"
    Write-Host "  [M] Memory Capture          - Local memory dump (DumpIt/MagnetRAM)"
    Write-Host ""
    Write-Host "  SCANNING & DETECTION" -ForegroundColor Magenta
    Write-Host "  [S] Scanning Tools          - Loki-RS IOC scanner, yarGen rule generator"
    Write-Host ""
    Write-Host "  VULNERABILITY INTELLIGENCE" -ForegroundColor Magenta
    Write-Host "  [P] Patch Tuesday           - Microsoft monthly vulnerability analysis"
    Write-Host ""
    Write-Host "  [0] Exit" -ForegroundColor Red
    Write-Host ""
}
#endregion

#region Quick Triage
function Start-QuickTriage {
    Write-Host ""
    Write-Host "=== QUICK TRIAGE ===" -ForegroundColor Cyan
    Write-Host ""
    
    $caseName = Read-Host "Case Name (default: Triage-$(Get-Date -Format 'yyyyMMdd'))"
    if (-not $caseName) { $caseName = "Triage-$(Get-Date -Format 'yyyyMMdd')" }
    
    $outputPath = Join-Path (Get-CustodianPath -PathType "Triage") $caseName
    New-Item -ItemType Directory -Path $outputPath -Force | Out-Null
    
    Write-Host ""
    Write-Host "Starting comprehensive triage collection..." -ForegroundColor Cyan
    Write-Host "    Output: $outputPath" -ForegroundColor Gray
    Write-Host ""
    
    Write-Host "[1/8] Network connections..." -ForegroundColor Yellow
    Get-CustodianNetworkConnections -OutputPath $outputPath -IncludeUDP | Out-Null
    
    Write-Host "[2/8] System information..." -ForegroundColor Yellow
    Get-CustodianProcesses -OutputPath $outputPath | Out-Null
    
    Write-Host "[3/8] Autoruns and persistence..." -ForegroundColor Yellow
    Get-CustodianAutoruns -OutputPath $outputPath | Out-Null
    Get-CustodianScheduledTasks -OutputPath $outputPath | Out-Null
    
    Write-Host "[4/8] Services..." -ForegroundColor Yellow
    Get-CustodianServices -OutputPath $outputPath | Out-Null
    
    Write-Host "[5/8] Event logs (last 24 hours)..." -ForegroundColor Yellow
    Get-CustodianEventLogs -OutputPath $outputPath -LogName "Security","System","Application" -Days 1 -MaxEvents 500 | Out-Null
    
    Write-Host "[6/8] Network configuration..." -ForegroundColor Yellow
    Get-CustodianNetworkAdapters -OutputPath $outputPath | Out-Null
    Get-CustodianDNSCache -OutputPath $outputPath | Out-Null
    
    Write-Host "[7/8] SMB sessions..." -ForegroundColor Yellow
    Get-CustodianSMBSessions -OutputPath $outputPath | Out-Null
    
    Write-Host "[8/8] Generating HTML report..." -ForegroundColor Yellow
    New-CustodianTriageReport -InputPath $outputPath -CaseName $caseName -Analyst $env:USERNAME | Out-Null
    
    Write-Host ""
    Write-Host "Quick Triage Complete!" -ForegroundColor Green
    Write-Host "    Location: $outputPath" -ForegroundColor Gray
    Write-Host ""
    
    Read-Host "Press Enter to continue"
}
#endregion

#region Collection Modules Menu
function Show-CollectionMenu {
    while ($true) {
        Show-Banner
        Write-Host "  COLLECTION MODULES" -ForegroundColor Cyan
        Write-Host "  [1] Network Collection    - Connections, ARP, DNS, SMB, Firewall"
        Write-Host "  [2] Event Logs            - Security, System, PowerShell, Sysmon"
        Write-Host "  [3] System Artifacts      - Autoruns, Services, Drivers, Certificates"
        Write-Host "  [4] Persistence           - Registry, WMI, Scheduled Tasks"
        Write-Host "  [5] Browser Extensions    - Chrome, Edge, Firefox"
        Write-Host "  [6] Additional Forensics  - IFEO, WDigest, Print Monitors, WSL"
        Write-Host ""
        Write-Host "  [0] Back to Main Menu"
        Write-Host ""
        
        $choice = Read-Host "Select option"
        
        switch ($choice) {
            "1" { 
                Get-CustodianNetworkConnections -IncludeUDP
                Get-CustodianARPCache
                Get-CustodianDNSCache
                Get-CustodianSMBSessions
                Get-CustodianFirewallRules
                Read-Host "Press Enter to continue"
            }
            "2" {
                $days = Read-Host "Days to collect (default: 7)"
                if (-not $days) { $days = 7 }
                Get-CustodianEventLogs -LogName "Security","System","Application" -Days $days
                Get-CustodianPowerShellLogs -Days $days
                Get-CustodianSysmonLogs -Days $days
                Read-Host "Press Enter to continue"
            }
            "3" {
                Get-CustodianAutoruns
                Get-CustodianServices
                Get-CustodianDrivers
                Get-CustodianCertificates
                Get-CustodianInstalledSoftware
                Read-Host "Press Enter to continue"
            }
            "4" {
                Get-CustodianPersistence
                Get-CustodianScheduledTasks
                Read-Host "Press Enter to continue"
            }
            "5" {
                Get-CustodianBrowserExtensions
                Read-Host "Press Enter to continue"
            }
            "6" {
                Get-CustodianIFEO
                Get-CustodianWDigest
                Get-CustodianPrintMonitors
                Get-CustodianWSLDetection
                Read-Host "Press Enter to continue"
            }
            "0" { return }
        }
    }
}
#endregion

#region Playbooks Menu
function Show-PlaybooksMenu {
    while ($true) {
        Show-Banner
        Write-Host "  HUNT PLAYBOOKS" -ForegroundColor Cyan
        Write-Host "  [1] Ransomware Hunt           - Encryption activity, shadow copy deletion"
        Write-Host "  [2] Lateral Movement Hunt     - RDP, SMB, WMI, PsExec indicators"
        Write-Host "  [3] Persistence Hunt          - Autoruns, tasks, services, WMI"
        Write-Host "  [4] Credential Access Hunt    - LSASS, SAM, Kerberos activity"
        Write-Host "  [5] Data Exfiltration Hunt    - Large files, archives, cloud storage"
        Write-Host "  [6] LOLBins Hunt              - PowerShell, WMIC, CertUtil abuse"
        Write-Host "  [7] Webshell Hunt             - Web directories, IIS logs"
        Write-Host "  [8] BEC Investigation         - Email client, Outlook files"
        Write-Host ""
        Write-Host "  [0] Back to Main Menu"
        Write-Host ""
        
        $choice = Read-Host "Select playbook"
        
        switch ($choice) {
            "1" { Start-RansomwareHunt; Read-Host "Press Enter to continue" }
            "2" { Start-LateralMovementHunt; Read-Host "Press Enter to continue" }
            "3" { Start-PersistenceHunt; Read-Host "Press Enter to continue" }
            "4" { Start-CredentialAccessHunt; Read-Host "Press Enter to continue" }
            "5" { Start-DataExfilHunt; Read-Host "Press Enter to continue" }
            "6" { Start-LOLBinsHunt; Read-Host "Press Enter to continue" }
            "7" { Start-WebshellHunt; Read-Host "Press Enter to continue" }
            "8" { Start-BECInvestigation; Read-Host "Press Enter to continue" }
            "0" { return }
        }
    }
}
#endregion

#region Analysis Tools Menu
function Show-AnalysisMenu {
    while ($true) {
        Show-Banner
        Write-Host "  ANALYSIS TOOLS" -ForegroundColor Cyan
        Write-Host "  [1] Hayabusa             - Windows Event Log timeline"
        Write-Host "  [2] Chainsaw             - Sigma-based event log hunting"
        Write-Host "  [3] YARA                 - Malware pattern scanning"
        Write-Host "  [4] Sigma                - Rule conversion"
        Write-Host "  [5] EZTools Parser       - AmcacheParser, LECmd, PECmd, etc."
        Write-Host "  [6] Volatility3          - Memory analysis"
        Write-Host ""
        Write-Host "  [0] Back to Main Menu"
        Write-Host ""
        
        $choice = Read-Host "Select tool"
        
        switch ($choice) {
            "1" {
                $evtxPath = Read-Host "EVTX directory path"
                if (Test-Path $evtxPath) {
                    Invoke-HayabusaAnalysis -EvtxPath $evtxPath
                }
                Read-Host "Press Enter to continue"
            }
            "2" {
                $evtxPath = Read-Host "EVTX directory path"
                if (Test-Path $evtxPath) {
                    Invoke-ChainsawAnalysis -EvtxPath $evtxPath
                }
                Read-Host "Press Enter to continue"
            }
            "3" {
                $scanPath = Read-Host "Path to scan"
                if (Test-Path $scanPath) {
                    Invoke-YaraScan -Path $scanPath -Recurse
                }
                Read-Host "Press Enter to continue"
            }
            "4" {
                Write-Host "Sigma conversion requires sigma-cli (pip install sigma-cli)" -ForegroundColor Yellow
                Read-Host "Press Enter to continue"
            }
            "5" { Show-EZToolsMenu }
            "6" {
                $dumpPath = Read-Host "Memory dump path"
                $plugin = Read-Host "Plugin (e.g., windows.pslist, windows.netscan)"
                if (Test-Path $dumpPath) {
                    Invoke-VolatilityAnalysis -MemoryDump $dumpPath -Plugin $plugin
                }
                Read-Host "Press Enter to continue"
            }
            "0" { return }
        }
    }
}
#endregion

#region EZTools Menu
function Show-EZToolsMenu {
    $tools = @(
        "AmcacheParser", "LECmd", "PECmd", "RBCmd", "SBECmd", 
        "JLECmd", "RecentFileCacheParser", "SrumECmd", "RegistryExplorer"
    )
    
    while ($true) {
        Show-Banner
        Write-Host "  EZTOOLS - Eric Zimmerman's Forensic Tools" -ForegroundColor Cyan
        Write-Host ""
        for ($i = 0; $i -lt $tools.Count; $i++) {
            Write-Host "  [$($i+1)] $($tools[$i])"
        }
        Write-Host ""
        Write-Host "  [0] Back"
        Write-Host ""
        
        $choice = Read-Host "Select tool"
        
        if ($choice -eq "0") { return }
        
        $toolIndex = [int]$choice - 1
        if ($toolIndex -ge 0 -and $toolIndex -lt $tools.Count) {
            $tool = $tools[$toolIndex]
            $target = Read-Host "Target file/directory"
            if (Test-Path $target) {
                Invoke-EZToolParser -Tool $tool -Target $target
            } else {
                Write-Host "Target not found: $target" -ForegroundColor Red
            }
            Read-Host "Press Enter to continue"
        }
    }
}
#endregion

#region OSINT Menu
function Show-OSINTMenu {
    while ($true) {
        Show-Banner
        Write-Host "  OSINT and THREAT INTELLIGENCE" -ForegroundColor Cyan
        Write-Host "  [1] VirusTotal Lookup"
        Write-Host "  [2] AbuseIPDB Lookup"
        Write-Host "  [3] URLhaus Lookup"
        Write-Host "  [4] AlienVault OTX Lookup"
        Write-Host "  [5] Bulk Hash Lookup (from CSV)"
        Write-Host "  [6] Open Microsoft Copilot"
        Write-Host "  [7] Open ChatGPT"
        Write-Host ""
        Write-Host "  [0] Back to Main Menu"
        Write-Host ""
        
        $choice = Read-Host "Select option"
        
        $config = Get-CustodianConfig
        
        switch ($choice) {
            "1" {
                $hash = Read-Host "Hash/URL/IP/Domain"
                if ($config.APIKeys.VirusTotal) {
                    Search-VirusTotal -Indicator $hash -APIKey $config.APIKeys.VirusTotal
                } else {
                    Write-Host "VirusTotal API key not configured in Config\Custodian-HT.json" -ForegroundColor Red
                }
                Read-Host "Press Enter to continue"
            }
            "2" {
                $ip = Read-Host "IP Address"
                if ($config.APIKeys.AbuseIPDB) {
                    Search-AbuseIPDB -IPAddress $ip -APIKey $config.APIKeys.AbuseIPDB
                } else {
                    Write-Host "AbuseIPDB API key not configured" -ForegroundColor Red
                }
                Read-Host "Press Enter to continue"
            }
            "3" {
                $url = Read-Host "URL"
                Search-URLhaus -URL $url
                Read-Host "Press Enter to continue"
            }
            "4" {
                $indicator = Read-Host "Indicator (hash/IP/domain)"
                Search-AlienVault -Indicator $indicator
                Read-Host "Press Enter to continue"
            }
            "5" {
                $csvPath = Read-Host "CSV file path (must have Hash column)"
                if (Test-Path $csvPath) {
                    Write-Host "Processing hashes..." -ForegroundColor Cyan
                    Search-BulkThreatIntel -CSVPath $csvPath
                } else {
                    Write-Host "File not found" -ForegroundColor Red
                }
                Read-Host "Press Enter to continue"
            }
            "6" { Start-Process "https://copilot.microsoft.com" }
            "7" { Start-Process "https://chatgpt.com" }
            "0" { return }
        }
    }
}
#endregion

#region KAPE Functions
function Show-KAPEMenu {
    while ($true) {
        Show-Banner
        Write-Host "  KAPE COLLECTION" -ForegroundColor Magenta
        Write-Host ""
        Write-Host "  LOCAL COLLECTION" -ForegroundColor Cyan
        Write-Host "  [1] Triage Collection      - !SANS_Triage targets + EZParser"
        Write-Host "  [2] Full Collection        - All artifacts + registry + logs"
        Write-Host "  [3] Custom Collection      - Select targets and modules"
        Write-Host ""
        Write-Host "  REMOTE COLLECTION" -ForegroundColor Yellow
        Write-Host "  [4] Remote KAPE (WinRM)    - Deploy and run KAPE on remote system"
        Write-Host ""
        Write-Host "  UTILITIES" -ForegroundColor Gray
        Write-Host "  [5] Parse KAPE Output      - Run EZTools on existing KAPE collection"
        Write-Host "  [6] List Available Targets"
        Write-Host "  [7] List Available Modules"
        Write-Host ""
        Write-Host "  [0] Back to Main Menu"
        Write-Host ""
        
        $choice = Read-Host "Select option"
        
        switch ($choice) {
            "1" { Invoke-LocalKAPE -Mode "Triage"; Read-Host "Press Enter to continue" }
            "2" { Invoke-LocalKAPE -Mode "Full"; Read-Host "Press Enter to continue" }
            "3" { Invoke-LocalKAPE -Mode "Custom"; Read-Host "Press Enter to continue" }
            "4" { 
                $target = Read-Host "Target hostname/IP"
                $cred = Get-Credential -Message "Enter credentials for $target"
                Invoke-RemoteKAPE -ComputerName $target -Credential $cred
                Read-Host "Press Enter to continue"
            }
            "5" {
                $kapeOutput = Read-Host "Path to KAPE output folder"
                if (Test-Path $kapeOutput) {
                    Write-Host "Running EZTools parsers on KAPE output..." -ForegroundColor Cyan
                    $targetDir = Join-Path $kapeOutput "Targets"
                    if (Test-Path $targetDir) {
                        $amcache = Get-ChildItem $targetDir -Recurse -Filter "Amcache.hve" -ErrorAction SilentlyContinue | Select-Object -First 1
                        if ($amcache) { Invoke-EZToolParser -Tool "AmcacheParser" -Target $amcache.FullName }
                    }
                } else {
                    Write-Host "Path not found" -ForegroundColor Red
                }
                Read-Host "Press Enter to continue"
            }
            "6" {
                $kapePath = Join-Path $Script:BasePath "Tools\kape\kape.exe"
                if (Test-Path $kapePath) {
                    & $kapePath --tlist
                } else {
                    Write-Host "KAPE not found. Download from https://www.kroll.com/kape" -ForegroundColor Red
                }
                Read-Host "Press Enter to continue"
            }
            "7" {
                $kapePath = Join-Path $Script:BasePath "Tools\kape\kape.exe"
                if (Test-Path $kapePath) {
                    & $kapePath --mlist
                } else {
                    Write-Host "KAPE not found. Download from https://www.kroll.com/kape" -ForegroundColor Red
                }
                Read-Host "Press Enter to continue"
            }
            "0" { return }
        }
    }
}

function Invoke-LocalKAPE {
    param(
        [ValidateSet("Triage","Full","Custom")][string]$Mode = "Triage"
    )
    
    $kapePath = Join-Path $Script:BasePath "Tools\kape\kape.exe"
    
    if (-not (Test-Path $kapePath)) {
        Write-Host "[-] KAPE not found at: $kapePath" -ForegroundColor Red
        Write-Host "[*] Download from: https://www.kroll.com/en/services/cyber-risk/incident-response-litigation-support/kroll-artifact-parser-extractor-kape" -ForegroundColor Yellow
        return $null
    }
    
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $outputPath = Get-CustodianPath -PathType "Collection"
    $kapeOutput = Join-Path $outputPath "KAPE_$timestamp"
    New-Item -ItemType Directory -Path $kapeOutput -Force | Out-Null
    
    Write-Host ""
    Write-Host "=== KAPE LOCAL COLLECTION ===" -ForegroundColor Cyan
    Write-Host "[*] Output: $kapeOutput" -ForegroundColor Gray
    
    switch ($Mode) {
        "Triage" {
            $targets = "!SANS_Triage"
            $modules = "!EZParser"
        }
        "Full" {
            $targets = "!BasicCollection,RegistryHives,EventLogs,FileSystem,WebBrowsers"
            $modules = "!EZParser,EvtxECmd,RECmd"
        }
        "Custom" {
            Write-Host ""
            Write-Host "Common targets: !SANS_Triage, !BasicCollection, RegistryHives, EventLogs, WebBrowsers, Antivirus, FileSystem" -ForegroundColor Yellow
            $targets = Read-Host "Enter targets (comma-separated)"
            
            Write-Host "Common modules: !EZParser, EvtxECmd, RECmd, AmcacheParser, PECmd, SBECmd" -ForegroundColor Yellow
            $modules = Read-Host "Enter modules (comma-separated, or blank for targets only)"
        }
    }
    
    Write-Host "[*] Mode: $Mode" -ForegroundColor Cyan
    Write-Host "[*] Targets: $targets" -ForegroundColor Cyan
    if ($modules) { Write-Host "[*] Modules: $modules" -ForegroundColor Cyan }
    Write-Host ""
    
    try {
        $kapeArgs = @(
            "--tsource", "C:",
            "--tdest", (Join-Path $kapeOutput "Targets"),
            "--target", $targets
        )
        
        if ($modules) {
            $kapeArgs += @(
                "--msource", (Join-Path $kapeOutput "Targets"),
                "--mdest", (Join-Path $kapeOutput "Modules"),
                "--module", $modules
            )
        }
        
        Write-Host "[*] Running KAPE collection (this may take several minutes)..." -ForegroundColor Yellow
        $process = Start-Process -FilePath $kapePath -ArgumentList $kapeArgs -NoNewWindow -Wait -PassThru
        
        if ($process.ExitCode -eq 0) {
            Write-Host "[+] KAPE collection complete: $kapeOutput" -ForegroundColor Green
        } else {
            Write-Host "[!] KAPE completed with exit code: $($process.ExitCode)" -ForegroundColor Yellow
        }
        
        return $kapeOutput
        
    } catch {
        Write-Host "[-] KAPE collection failed: $_" -ForegroundColor Red
        return $null
    }
}

function Invoke-RemoteKAPE {
    param(
        [Parameter(Mandatory)][string]$ComputerName,
        [Parameter(Mandatory)][PSCredential]$Credential,
        [ValidateSet("Triage","Full")][string]$Mode = "Triage"
    )
    
    $localKapePath = Join-Path $Script:BasePath "Tools\kape"
    
    if (-not (Test-Path (Join-Path $localKapePath "kape.exe"))) {
        Write-Host "[-] KAPE not found locally. Cannot deploy to remote." -ForegroundColor Red
        return $null
    }
    
    Write-Host ""
    Write-Host "=== KAPE REMOTE COLLECTION ===" -ForegroundColor Cyan
    Write-Host "[*] Target: $ComputerName" -ForegroundColor Gray
    Write-Host "[*] Mode: $Mode" -ForegroundColor Gray
    
    # Configure TrustedHosts if needed
    try {
        $currentTrusted = (Get-Item WSMan:\localhost\Client\TrustedHosts -ErrorAction SilentlyContinue).Value
        if ($currentTrusted -notmatch [regex]::Escape($ComputerName)) {
            Write-Host "[*] Adding $ComputerName to TrustedHosts..." -ForegroundColor Yellow
            if ([string]::IsNullOrEmpty($currentTrusted)) {
                Set-Item WSMan:\localhost\Client\TrustedHosts -Value $ComputerName -Force
            } else {
                Set-Item WSMan:\localhost\Client\TrustedHosts -Value "$currentTrusted,$ComputerName" -Force
            }
        }
    } catch {
        Write-Host "[!] Could not configure TrustedHosts (run as Admin): $_" -ForegroundColor Yellow
    }
    
    try {
        Write-Host "[*] Connecting to $ComputerName..." -ForegroundColor Yellow
        $session = New-PSSession -ComputerName $ComputerName -Credential $Credential -ErrorAction Stop
        
        $remotePath = "C:\Windows\Temp\CustodianKAPE"
        
        Write-Host "[*] Creating remote staging directory..." -ForegroundColor Yellow
        Invoke-Command -Session $session -ScriptBlock {
            param($path)
            if (Test-Path $path) { Remove-Item $path -Recurse -Force }
            New-Item -ItemType Directory -Path $path -Force | Out-Null
        } -ArgumentList $remotePath
        
        Write-Host "[*] Copying KAPE to remote system (this may take a minute)..." -ForegroundColor Yellow
        Copy-Item -Path "$localKapePath\*" -Destination $remotePath -ToSession $session -Recurse -Force
        
        Write-Host "[*] Executing KAPE on remote system..." -ForegroundColor Yellow
        
        $targets = if ($Mode -eq "Triage") { "!SANS_Triage" } else { "!BasicCollection,RegistryHives,EventLogs" }
        
        $remoteResult = Invoke-Command -Session $session -ScriptBlock {
            param($kapePath, $targets)
            
            $outputDir = "C:\Windows\Temp\CustodianKAPE_Output"
            if (Test-Path $outputDir) { Remove-Item $outputDir -Recurse -Force }
            New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
            
            $kapeExe = Join-Path $kapePath "kape.exe"
            $args = "--tsource C: --tdest `"$outputDir\Targets`" --target $targets --zip CustodianKAPE"
            
            Start-Process -FilePath $kapeExe -ArgumentList $args -NoNewWindow -Wait
            
            $zipFile = Get-ChildItem "$outputDir\Targets" -Filter "*.zip" -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($zipFile) {
                return $zipFile.FullName
            } else {
                $zipPath = "$outputDir\CustodianKAPE.zip"
                Compress-Archive -Path "$outputDir\Targets\*" -DestinationPath $zipPath -Force
                return $zipPath
            }
        } -ArgumentList $remotePath, $targets
        
        Write-Host "[*] Retrieving KAPE archive from remote..." -ForegroundColor Yellow
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $outputPath = Get-CustodianPath -PathType "Collection"
        $localOutput = Join-Path $outputPath "KAPE_${ComputerName}_$timestamp.zip"
        Copy-Item -Path $remoteResult -Destination $localOutput -FromSession $session
        
        Write-Host "[*] Cleaning up remote system..." -ForegroundColor Yellow
        Invoke-Command -Session $session -ScriptBlock {
            Remove-Item -Path "C:\Windows\Temp\CustodianKAPE*" -Recurse -Force -ErrorAction SilentlyContinue
        }
        
		Write-Host "    4. On target: Set LocalAccountTokenFilterPolicy=1 (for local accounts)" -ForegroundColor Gray
        Remove-PSSession $session
        
        Write-Host "[+] KAPE collection complete: $localOutput" -ForegroundColor Green
        return $localOutput
        
    } catch {
        Write-Host "[-] Remote KAPE collection failed: $_" -ForegroundColor Red
        if ($session) { Remove-PSSession $session -ErrorAction SilentlyContinue }
        return $null
    }
}
#endregion

#region Memory Capture
function Invoke-LocalMemoryCapture {
    Write-Host ""
    Write-Host "=== LOCAL MEMORY CAPTURE ===" -ForegroundColor Cyan
    
    $dumpitPath = Join-Path $Script:BasePath "Tools\DumpIt\DumpIt.exe"
    $magnetPath = Join-Path $Script:BasePath "Tools\MagnetRAMCapture\MagnetRAMCapture.exe"
    
    $outputPath = Get-CustodianPath -PathType "Memory"
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $dumpFile = Join-Path $outputPath "MemoryDump_${env:COMPUTERNAME}_$timestamp.dmp"
    
    # Check for Secure Boot
    $secureBoot = $false
    try {
        $secureBoot = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
    } catch {}
    
    if ($secureBoot) {
        Write-Host "[*] Secure Boot detected - using Magnet RAM Capture" -ForegroundColor Yellow
        if (Test-Path $magnetPath) {
            Write-Host "[*] Starting Magnet RAM Capture..." -ForegroundColor Cyan
            Write-Host "[*] Output: $dumpFile" -ForegroundColor Gray
            Start-Process -FilePath $magnetPath -ArgumentList "/accepteula /go /output `"$dumpFile`"" -Wait
        } else {
            Write-Host "[-] Magnet RAM Capture not found at: $magnetPath" -ForegroundColor Red
            Write-Host "[*] Download from: https://www.magnetforensics.com/resources/magnet-ram-capture/" -ForegroundColor Yellow
            return
        }
    } else {
        Write-Host "[*] Using DumpIt" -ForegroundColor Cyan
        if (Test-Path $dumpitPath) {
            Write-Host "[*] Starting DumpIt..." -ForegroundColor Cyan
            Write-Host "[*] Output: $dumpFile" -ForegroundColor Gray
            Start-Process -FilePath $dumpitPath -ArgumentList "/OUTPUT `"$dumpFile`" /QUIET" -Wait
        } else {
            Write-Host "[-] DumpIt not found at: $dumpitPath" -ForegroundColor Red
            Write-Host "[*] Download from: https://www.magnetforensics.com/resources/magnet-dumpit-for-windows/" -ForegroundColor Yellow
            return
        }
    }
    
    if (Test-Path $dumpFile) {
        $fileInfo = Get-Item $dumpFile
        $hash = (Get-FileHash $dumpFile -Algorithm SHA256).Hash
        
        Write-Host ""
        Write-Host "[+] Memory capture complete!" -ForegroundColor Green
        Write-Host "    File: $dumpFile" -ForegroundColor Gray
        Write-Host "    Size: $([math]::Round($fileInfo.Length / 1GB, 2)) GB" -ForegroundColor Gray
        Write-Host "    SHA256: $hash" -ForegroundColor Gray
        
        $metadata = [PSCustomObject]@{
            ComputerName = $env:COMPUTERNAME
            DumpFile = $dumpFile
            SizeBytes = $fileInfo.Length
            SHA256 = $hash
            Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        }
        $metadata | Export-Csv -Path (Join-Path $outputPath "MemoryDump_Metadata.csv") -NoTypeInformation -Append
    } else {
        Write-Host "[-] Memory dump file not created" -ForegroundColor Red
    }
    
    Read-Host "Press Enter to continue"
}
#endregion

#region Windows Remote

# [FIX] Connect-WindowsRemote with WinRM and PSExec options
function Connect-WindowsRemote {
    <#
    .SYNOPSIS
        Establish remote session to Windows host via WinRM or PSExec
        Compatible with PowerShell 5.1 and PowerShell 7+
    #>
    Write-Host ""
    Write-Host "=== WINDOWS REMOTE CONNECTION ===" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  Connection Method:" -ForegroundColor Cyan
    Write-Host "  [1] WinRM (PowerShell Remoting) - Requires WinRM enabled"
    Write-Host "  [2] PSExec (SMB-based)          - Uses admin shares, more reliable"
    Write-Host "  [0] Cancel"
    Write-Host ""
    
    $method = Read-Host "Select method"
    
    switch ($method) {
        "1" { Connect-WindowsWinRM }
        "2" { Connect-WindowsPSExec }
        "0" { return }
        default { 
            Write-Host "Invalid option" -ForegroundColor Red
            return 
        }
    }
}

function Connect-WindowsWinRM {
    <#
    .SYNOPSIS
        Establish WinRM session to remote Windows host
    #>
    Write-Host ""
    Write-Host "=== WinRM CONNECTION ===" -ForegroundColor Yellow
    Write-Host ""

    # Detect PowerShell version
    $isPowerShell7 = $PSVersionTable.PSVersion.Major -ge 7
    if ($isPowerShell7) {
        Write-Host "[*] Running PowerShell $($PSVersionTable.PSVersion) - will target Windows PowerShell endpoint" -ForegroundColor Cyan
    }

    # 1. Get Target
    $target = Read-Host "Target Hostname or IP (e.g., lab-pc02 or lab-pc02.lab.local)"
    if (-not $target) { return }

    # 2. Detect if this looks like a domain environment
    $isDomain = $false
    if ($target -match '\.') {
        $isDomain = $true
        Write-Host "[*] Detected FQDN - using domain authentication" -ForegroundColor Cyan
    } else {
        # Check if current machine is domain-joined
        try {
            $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
            if ($cs.PartOfDomain) {
                $isDomain = $true
                $domain = $cs.Domain
                Write-Host "[*] Current machine is domain-joined ($domain)" -ForegroundColor Cyan
                
                # Offer to use FQDN
                $useFQDN = Read-Host "Use FQDN? ($target.$domain) (Y/n)"
                if ($useFQDN -ne 'n' -and $useFQDN -ne 'N') {
                    $target = "$target.$domain"
                    Write-Host "[*] Using: $target" -ForegroundColor Cyan
                }
            }
        } catch {}
    }

    # 3. Get Credentials with proper format hint
    Write-Host ""
    if ($isDomain) {
        Write-Host "[*] Domain authentication - use format: DOMAIN\username or user@domain.local" -ForegroundColor Yellow
    } else {
        Write-Host "[*] Workgroup authentication - use format: username or .\username" -ForegroundColor Yellow
    }
    
    try {
        $cred = Get-Credential -Message "Enter Admin Credentials for $target"
        if (-not $cred) { return }
    } catch {
        return
    }

    # 4. Connection Attempt
    Write-Host ""
    Write-Host "[*] Connecting to $target via WinRM..." -ForegroundColor Cyan

    try {
        # For non-domain or IP targets, may need TrustedHosts
        if (-not $isDomain -or $target -match '^\d+\.\d+\.\d+\.\d+$') {
            try {
                $trustedHosts = (Get-Item WSMan:\localhost\Client\TrustedHosts -ErrorAction SilentlyContinue).Value
                if ($trustedHosts -ne "*" -and $trustedHosts -notmatch [regex]::Escape($target)) {
                    Write-Host "[*] Adding to TrustedHosts for NTLM auth..." -ForegroundColor Yellow
                    if ($trustedHosts) {
                        Set-Item WSMan:\localhost\Client\TrustedHosts -Value "$trustedHosts,$target" -Force -ErrorAction SilentlyContinue
                    } else {
                        Set-Item WSMan:\localhost\Client\TrustedHosts -Value $target -Force -ErrorAction SilentlyContinue
                    }
                }
            } catch {
                Write-Host "[!] Could not modify TrustedHosts (need Admin)" -ForegroundColor Yellow
            }
        }

        # Create session with appropriate authentication
        $sessionOptions = New-PSSessionOption -OperationTimeout 30000 -OpenTimeout 30000
        
        # Build session parameters
        $sessionParams = @{
            ComputerName = $target
            Credential = $cred
            SessionOption = $sessionOptions
            ErrorAction = 'Stop'
        }
        
        # PowerShell 7+ must explicitly target Windows PowerShell endpoint
        if ($isPowerShell7) {
            $sessionParams['ConfigurationName'] = 'Microsoft.PowerShell'
            Write-Host "[*] Targeting Windows PowerShell endpoint (Microsoft.PowerShell)" -ForegroundColor Cyan
        }
        
        if ($isDomain -and $target -match '\.') {
            Write-Host "[*] Attempting Kerberos authentication..." -ForegroundColor Cyan
        } else {
            Write-Host "[*] Attempting NTLM authentication..." -ForegroundColor Cyan
            $sessionParams['Authentication'] = 'Negotiate'
        }
        
        # Create the session
        $session = New-PSSession @sessionParams
        
        # 5. Set Global State
        $Script:RemoteSession = $session
        $Script:RemoteCredential = $cred
        $Script:RemoteHost = $target
        $Script:RemoteType = "Windows"

        # Get remote system info
        $remoteInfo = Invoke-Command -Session $session -ScriptBlock {
            "$env:COMPUTERNAME ($env:USERDOMAIN) - PS $($PSVersionTable.PSVersion)"
        } -ErrorAction SilentlyContinue

        Write-Host "[+] Connected successfully!" -ForegroundColor Green
        if ($remoteInfo) {
            Write-Host "    Remote: $remoteInfo" -ForegroundColor Gray
        }
        Start-Sleep -Seconds 1
        
        # 6. Transition to Menu
        Show-WindowsRemoteMenu

    } catch {
        Write-Host "[-] Connection Failed: $_" -ForegroundColor Red
        Write-Host ""
        Write-Host "Troubleshooting:" -ForegroundColor Yellow
        
        if ($isPowerShell7) {
            Write-Host "  PowerShell 7 Note:" -ForegroundColor Magenta
            Write-Host "  - Target must have Windows PowerShell remoting enabled" -ForegroundColor White
            Write-Host "  - On TARGET, run in Windows PowerShell (powershell.exe) as Admin:" -ForegroundColor White
            Write-Host "    Enable-PSRemoting -Force" -ForegroundColor Cyan
            Write-Host ""
        }
        
        if ($isDomain) {
            Write-Host "  Domain Environment:" -ForegroundColor Cyan
            Write-Host "  1. Use FQDN: $target (not short name)" -ForegroundColor White
            Write-Host "  2. Credential format: LAB\admin82 or admin82@lab.local" -ForegroundColor White
            Write-Host "  3. User must be in Domain Admins or Remote Management Users" -ForegroundColor White
            Write-Host "  4. Check: Get-ADGroupMember 'Remote Management Users'" -ForegroundColor White
            Write-Host "  5. On target run: winrm quickconfig" -ForegroundColor White
        } else {
            Write-Host "  Workgroup Environment:" -ForegroundColor Cyan
            Write-Host "  1. On target: Enable-PSRemoting -Force" -ForegroundColor White
            Write-Host "  2. On target: winrm quickconfig" -ForegroundColor White
            Write-Host "  3. Firewall: TCP 5985 (HTTP) or 5986 (HTTPS)" -ForegroundColor White
            Write-Host "  4. Run this script as Administrator" -ForegroundColor White
        }
        
        $Script:RemoteSession = $null
        Write-Host ""
        Read-Host "Press Enter to continue"
    }
}

function Connect-WindowsPSExec {
    <#
    .SYNOPSIS
        Connect to remote Windows host using PSExec (SMB-based)
        UPDATED: Removed auto-context switching in favor of explicit user input.
    #>
    Write-Host ""
    Write-Host "=== PSEXEC CONNECTION ===" -ForegroundColor Yellow
    Write-Host ""
    
    # Check for PsExec
    $psexecPath = $null
    $searchPaths = @(
        (Join-Path $Script:BasePath "Tools\PSTools\PsExec.exe"),
        (Join-Path $Script:BasePath "Tools\PsExec.exe"),
        (Join-Path $Script:BasePath "Tools\Sysinternals\PsExec.exe"),
        "C:\Tools\PSTools\PsExec.exe",
        "C:\Sysinternals\PsExec.exe"
    )
    
    foreach ($path in $searchPaths) {
        if (Test-Path $path) {
            $psexecPath = $path
            break
        }
    }
    
    # Also check PATH
    if (-not $psexecPath) {
        $psexecCmd = Get-Command PsExec.exe -ErrorAction SilentlyContinue
        if ($psexecCmd) {
            $psexecPath = $psexecCmd.Source
        }
    }
    
    if (-not $psexecPath) {
        Write-Host "[-] PsExec.exe not found" -ForegroundColor Red
        Write-Host ""
        Write-Host "Download PSTools from:" -ForegroundColor Yellow
        Write-Host "  https://docs.microsoft.com/en-us/sysinternals/downloads/psexec" -ForegroundColor Cyan
        Write-Host ""
        Read-Host "Press Enter to continue"
        return
    }
    
    Write-Host "[+] Found PsExec: $psexecPath" -ForegroundColor Green
    
    # Get target
    $target = Read-Host "Target Hostname or IP"
    if (-not $target) { return }
    
    # Get credentials with CLEAR instructions
    Write-Host ""
    Write-Host "[*] Credentials Required:" -ForegroundColor Cyan
    Write-Host "    - For DOMAIN accounts : " -NoNewline; Write-Host "LAB\username" -ForegroundColor Green
    Write-Host "    - For LOCAL accounts  : " -NoNewline; Write-Host ".\username" -ForegroundColor Yellow -NoNewline; Write-Host " (Don't forget the dot!)"
    
    try {
        $cred = Get-Credential -Message "Enter Admin Credentials for $target"
        if (-not $cred) { return }
    } catch {
        return
    }
    
    $username = $cred.UserName
    $password = $cred.GetNetworkCredential().Password

    # [REMOVED] The "Context Sanitization" block was removed here.
    # We now rely on the user providing the correct prefix (.\ or DOMAIN\)
    # rather than guessing, which prevents conflicts on domain-joined machines.

    # Test SMB connectivity with credentials
    Write-Host ""
    Write-Host "[*] Establishing authenticated SMB connection..." -ForegroundColor Cyan
    Write-Host "    User: $username" -ForegroundColor Gray
    
    # First, clear any existing connections to target (suppress all output/errors)
    try {
        Remove-SmbMapping -RemotePath "\\$target\IPC$" -Force -ErrorAction SilentlyContinue
        Remove-SmbMapping -RemotePath "\\$target\C$" -Force -ErrorAction SilentlyContinue
    } catch {}
    
    # Also try net use in case Remove-SmbMapping isn't available
    $null = cmd /c "net use `"\\$target\IPC$`" /delete /y 2>nul" 2>$null
    $null = cmd /c "net use `"\\$target\C$`" /delete /y 2>nul" 2>$null
    Start-Sleep -Milliseconds 500
    
    # Establish SMB connection using New-SmbMapping (handles credentials properly)
    Write-Host "[*] Authenticating to \\$target..." -ForegroundColor Cyan
    
    $authSuccess = $false
    $authError = ""
    
    # Method 1: Try New-SmbMapping (Windows 8+/Server 2012+)
    try {
        $mapping = New-SmbMapping -RemotePath "\\$target\C$" -UserName $username -Password $password -ErrorAction Stop
        $authSuccess = $true
        Write-Host "[+] SMB authentication successful (New-SmbMapping)" -ForegroundColor Green
    } catch {
        $authError = $_.Exception.Message
        
        # Method 2: Try New-PSDrive as fallback
        try {
            $driveName = "CustodianTemp"
            Remove-PSDrive -Name $driveName -Force -ErrorAction SilentlyContinue
            $null = New-PSDrive -Name $driveName -PSProvider FileSystem -Root "\\$target\C$" -Credential $cred -ErrorAction Stop
            Remove-PSDrive -Name $driveName -Force -ErrorAction SilentlyContinue
            $authSuccess = $true
            Write-Host "[+] SMB authentication successful (PSDrive)" -ForegroundColor Green
        } catch {
            $authError = $_.Exception.Message
        }
    }
    
    if (-not $authSuccess) {
        Write-Host "[-] SMB authentication failed" -ForegroundColor Red
        Write-Host ""
        
        # Parse common errors with helpful hints
        if ($authError -match "password is incorrect|1326|logon failure|credentials") {
            Write-Host "    Cause: Invalid username or password (Error 1326)" -ForegroundColor Yellow
            Write-Host "    Hint:  If trying to use a LOCAL account, did you use '.\username'?" -ForegroundColor White
            Write-Host "           Current Attempt: $username" -ForegroundColor Gray
        } elseif ($authError -match "network path|53|host is down") {
            Write-Host "    Cause: Cannot reach target (Error 53)" -ForegroundColor Yellow
            Write-Host "    Try:   ping $target" -ForegroundColor White
        } elseif ($authError -match "access is denied|5") {
            Write-Host "    Cause: Access denied (Error 5) - User lacks Admin rights on target" -ForegroundColor Yellow
        } else {
            Write-Host "    Error: $authError" -ForegroundColor Gray
        }
        
        Write-Host ""
        Read-Host "Press Enter to continue"
        return
    }
    
    # Verify admin share access
    Write-Host "[*] Verifying admin share (C$) access..." -ForegroundColor Cyan
    try {
        $testAccess = Get-ChildItem "\\$target\C$" -ErrorAction Stop | Select-Object -First 1
        Write-Host "[+] Admin share access confirmed" -ForegroundColor Green
    } catch {
        Write-Host "[-] Cannot access C$ admin share" -ForegroundColor Red
        Write-Host "    User authenticated but may lack admin rights on target" -ForegroundColor Yellow
        try { Remove-SmbMapping -RemotePath "\\$target\C$" -Force -ErrorAction SilentlyContinue } catch {}
        Read-Host "Press Enter to continue"
        return
    }
    
    # Store connection info
    $Script:RemoteHost = $target
    $Script:RemoteType = "PSExec"
    $Script:RemoteSession = $null
    $Script:RemoteCredential = $cred
    $Script:PSExecPath = $psexecPath
    
    Write-Host ""
    Write-Host "[+] PSExec connection ready!" -ForegroundColor Green
    Write-Host "    Target: $target" -ForegroundColor Gray
    Write-Host "    User: $username" -ForegroundColor Gray
    Write-Host "    Method: PSExec (SMB)" -ForegroundColor Gray
    Write-Host ""
    Write-Host "[!] Note: PSExec runs commands on-demand (no persistent session)" -ForegroundColor Yellow
    Start-Sleep -Seconds 1
    
    Show-WindowsPSExecMenu
}

function Invoke-PSExecCommand {
    <#
    .SYNOPSIS
        Execute command on remote host via PSExec
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Command,
        [switch]$PowerShell,
        [switch]$System,
        [switch]$Interactive
    )
    
    if (-not $Script:RemoteHost -or -not $Script:PSExecPath) {
        Write-Host "[-] Not connected via PSExec" -ForegroundColor Red
        return $null
    }
    
    $psexecArgs = @()
    $psexecArgs += "\\$($Script:RemoteHost)"
    $psexecArgs += "-accepteula"
    
    # Add credentials if available
    if ($Script:RemoteCredential) {
        $username = $Script:RemoteCredential.UserName
        $password = $Script:RemoteCredential.GetNetworkCredential().Password
        $psexecArgs += "-u", $username
        $psexecArgs += "-p", $password
    }
    
    if ($System) {
        $psexecArgs += "-s"  # Run as SYSTEM
    }
    
    if ($Interactive) {
        $psexecArgs += "-i"  # Interactive
    }
    
    if ($PowerShell) {
        $psexecArgs += "powershell.exe"
        $psexecArgs += "-NoProfile"
        $psexecArgs += "-ExecutionPolicy", "Bypass"
        $psexecArgs += "-Command", $Command
    } else {
        $psexecArgs += "cmd.exe"
        $psexecArgs += "/c"
        $psexecArgs += $Command
    }
    
    try {
        $output = & $Script:PSExecPath @psexecArgs 2>&1
        # Filter out PsExec banner
        $output = $output | Where-Object { 
            $_ -notmatch "PsExec v" -and 
            $_ -notmatch "Copyright" -and 
            $_ -notmatch "Sysinternals" -and
            $_ -notmatch "Starting .* on" -and
            $_ -notmatch "Connecting to" -and
            $_ -notmatch "error code 0"
        }
        return $output
    } catch {
        Write-Host "[-] PSExec command failed: $_" -ForegroundColor Red
        return $null
    }
}

function Show-WindowsPSExecMenu {
    <#
    .SYNOPSIS
        Menu for PSExec-based remote operations
    #>
    while ($true) {
        Show-Banner
        Write-Host "  WINDOWS REMOTE (PSEXEC) - $Script:RemoteHost" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  QUICK COLLECTION" -ForegroundColor Cyan
        Write-Host "  [1] Quick Triage          - System info, processes, connections"
        Write-Host "  [2] Process List          - Get running processes"
        Write-Host "  [3] Network Connections   - Get netstat output"
        Write-Host "  [4] Scheduled Tasks       - List scheduled tasks"
        Write-Host "  [5] Services              - List services"
        Write-Host ""
        Write-Host "  DEPLOYMENT" -ForegroundColor Cyan
        Write-Host "  [6] Copy & Run Script     - Deploy and execute PS script"
        Write-Host "  [7] Run Command           - Execute custom command"
        Write-Host "  [8] PowerShell Command    - Execute PowerShell command"
        Write-Host ""
        Write-Host "  FILE OPERATIONS" -ForegroundColor Yellow
        Write-Host "  [C] Copy File TO Target   - Copy file to remote system"
        Write-Host "  [G] Get File FROM Target  - Copy file from remote system"
        Write-Host "  [D] Browse Remote         - List remote directory"
        Write-Host ""
        Write-Host "  [0] Disconnect & Back"
        Write-Host ""
        
        $choice = Read-Host "Select option"
        
        switch ($choice.ToUpper()) {
            "1" { Invoke-PSExecQuickTriage }
            "2" { Invoke-PSExecProcessList }
            "3" { Invoke-PSExecNetstat }
            "4" { Invoke-PSExecScheduledTasks }
            "5" { Invoke-PSExecServices }
            "6" { Invoke-PSExecDeployScript }
            "7" { Invoke-PSExecCustomCommand }
            "8" { Invoke-PSExecPowerShell }
            "C" { Invoke-PSExecCopyTo }
            "G" { Invoke-PSExecCopyFrom }
            "D" { Invoke-PSExecBrowse }
            "0" {
                # Cleanup SMB connections (suppress errors for non-existent connections)
                if ($Script:RemoteHost) {
                    try { Remove-SmbMapping -RemotePath "\\$($Script:RemoteHost)\C$" -Force -ErrorAction SilentlyContinue } catch {}
                    try { Remove-SmbMapping -RemotePath "\\$($Script:RemoteHost)\IPC$" -Force -ErrorAction SilentlyContinue } catch {}
                    $null = cmd /c "net use `"\\$($Script:RemoteHost)\IPC$`" /delete /y 2>nul" 2>$null
                    $null = cmd /c "net use `"\\$($Script:RemoteHost)\C$`" /delete /y 2>nul" 2>$null
                }
                $Script:RemoteHost = $null
                $Script:RemoteType = $null
                $Script:RemoteCredential = $null
                $Script:PSExecPath = $null
                Write-Host "[+] Disconnected and SMB sessions cleared" -ForegroundColor Green
                return
            }
            default {
                Write-Host "Invalid option" -ForegroundColor Red
                Start-Sleep -Milliseconds 500
            }
        }
    }
}

function Invoke-PSExecQuickTriage {
    Write-Host ""
    Write-Host "=== QUICK TRIAGE (PSExec) ===" -ForegroundColor Cyan
    Write-Host "[*] Target: $Script:RemoteHost" -ForegroundColor White
    Write-Host ""
    
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $outputDir = Join-Path (Get-CustodianPath -PathType "Triage") "PSExec_${Script:RemoteHost}_${timestamp}"
    New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
    
    $commands = @(
        @{ Name = "System Info"; Cmd = "systeminfo"; File = "systeminfo.txt" },
        @{ Name = "Process List"; Cmd = "Get-Process | Select-Object ProcessName, Id, CPU, WorkingSet, Path | Sort-Object CPU -Descending | Format-Table -AutoSize"; PS = $true; File = "processes.txt" },
        @{ Name = "Network Connections"; Cmd = "netstat -ano"; File = "netstat.txt" },
        @{ Name = "Network Config"; Cmd = "ipconfig /all"; File = "ipconfig.txt" },
        @{ Name = "Logged On Users"; Cmd = "query user"; File = "users.txt" },
        @{ Name = "Services"; Cmd = "Get-Service | Where-Object Status -eq 'Running' | Format-Table -AutoSize"; PS = $true; File = "services.txt" },
        @{ Name = "Scheduled Tasks"; Cmd = "schtasks /query /fo LIST"; File = "schtasks.txt" },
        @{ Name = "Autoruns"; Cmd = "Get-CimInstance Win32_StartupCommand | Select-Object Name, Command, Location | Format-Table -AutoSize"; PS = $true; File = "autoruns.txt" }
    )
    
    $total = $commands.Count
    $current = 0
    
    foreach ($cmd in $commands) {
        $current++
        Write-Host "[$current/$total] $($cmd.Name)..." -ForegroundColor Yellow
        
        try {
            if ($cmd.PS) {
                $result = Invoke-PSExecCommand -Command $cmd.Cmd -PowerShell
            } else {
                $result = Invoke-PSExecCommand -Command $cmd.Cmd
            }
            
            if ($result) {
                $outFile = Join-Path $outputDir $cmd.File
                $result | Out-File -FilePath $outFile -Encoding UTF8
            }
        } catch {
            Write-Host "    [!] Failed: $_" -ForegroundColor Red
        }
    }
    
    Write-Host ""
    Write-Host "[+] TRIAGE COMPLETE" -ForegroundColor Green
    Write-Host "    Output: $outputDir" -ForegroundColor White
    Write-Host ""
    Read-Host "Press Enter to continue"
}

function Invoke-PSExecProcessList {
    Write-Host ""
    Write-Host "[*] Getting process list from $Script:RemoteHost..." -ForegroundColor Cyan
    $result = Invoke-PSExecCommand -Command "Get-Process | Select-Object ProcessName, Id, CPU, WorkingSet, Path | Sort-Object CPU -Descending | Format-Table -AutoSize" -PowerShell
    if ($result) {
        $result | ForEach-Object { Write-Host $_ }
    }
    Write-Host ""
    Read-Host "Press Enter to continue"
}

function Invoke-PSExecNetstat {
    Write-Host ""
    Write-Host "[*] Getting network connections from $Script:RemoteHost..." -ForegroundColor Cyan
    $result = Invoke-PSExecCommand -Command "netstat -ano"
    if ($result) {
        $result | ForEach-Object { Write-Host $_ }
    }
    Write-Host ""
    Read-Host "Press Enter to continue"
}

function Invoke-PSExecScheduledTasks {
    Write-Host ""
    Write-Host "[*] Getting scheduled tasks from $Script:RemoteHost..." -ForegroundColor Cyan
    $result = Invoke-PSExecCommand -Command "schtasks /query /fo LIST /v"
    if ($result) {
        $result | ForEach-Object { Write-Host $_ }
    }
    Write-Host ""
    Read-Host "Press Enter to continue"
}

function Invoke-PSExecServices {
    Write-Host ""
    Write-Host "[*] Getting services from $Script:RemoteHost..." -ForegroundColor Cyan
    $result = Invoke-PSExecCommand -Command "Get-Service | Where-Object Status -eq 'Running' | Select-Object Name, DisplayName, Status | Format-Table -AutoSize" -PowerShell
    if ($result) {
        $result | ForEach-Object { Write-Host $_ }
    }
    Write-Host ""
    Read-Host "Press Enter to continue"
}

function Invoke-PSExecCustomCommand {
    Write-Host ""
    $cmd = Read-Host "Enter command (cmd.exe)"
    if ($cmd) {
        Write-Host ""
        Write-Host "[*] Executing: $cmd" -ForegroundColor Cyan
        $result = Invoke-PSExecCommand -Command $cmd
        if ($result) {
            $result | ForEach-Object { Write-Host $_ }
        }
    }
    Write-Host ""
    Read-Host "Press Enter to continue"
}

function Invoke-PSExecPowerShell {
    Write-Host ""
    $cmd = Read-Host "Enter PowerShell command"
    if ($cmd) {
        Write-Host ""
        Write-Host "[*] Executing: $cmd" -ForegroundColor Cyan
        $result = Invoke-PSExecCommand -Command $cmd -PowerShell
        if ($result) {
            $result | ForEach-Object { Write-Host $_ }
        }
    }
    Write-Host ""
    Read-Host "Press Enter to continue"
}

function Invoke-PSExecDeployScript {
    Write-Host ""
    $localScript = Read-Host "Local script path"
    
    if (-not (Test-Path $localScript)) {
        Write-Host "[-] Script not found: $localScript" -ForegroundColor Red
        Read-Host "Press Enter to continue"
        return
    }
    
    $scriptName = Split-Path $localScript -Leaf
    $remotePath = "C:\Windows\Temp\$scriptName"
    
    Write-Host "[*] Copying script to target..." -ForegroundColor Cyan
    try {
        Copy-Item -Path $localScript -Destination "\\$($Script:RemoteHost)\C$\Windows\Temp\$scriptName" -Force
        Write-Host "[+] Script copied to $remotePath" -ForegroundColor Green
        
        Write-Host "[*] Executing script..." -ForegroundColor Cyan
        $result = Invoke-PSExecCommand -Command "& '$remotePath'" -PowerShell
        if ($result) {
            $result | ForEach-Object { Write-Host $_ }
        }
        
        # Cleanup
        Remove-Item "\\$($Script:RemoteHost)\C$\Windows\Temp\$scriptName" -Force -ErrorAction SilentlyContinue
        
    } catch {
        Write-Host "[-] Failed: $_" -ForegroundColor Red
    }
    Write-Host ""
    Read-Host "Press Enter to continue"
}

function Invoke-PSExecCopyTo {
    Write-Host ""
    $localPath = Read-Host "Local file path"
    if (-not (Test-Path $localPath)) {
        Write-Host "[-] File not found" -ForegroundColor Red
        Read-Host "Press Enter to continue"
        return
    }
    
    $remotePath = Read-Host "Remote path (e.g., C:\Temp\file.txt)"
    $uncPath = $remotePath -replace '^([A-Za-z]):', "\\$($Script:RemoteHost)\`$1$"
    
    Write-Host "[*] Copying to $uncPath..." -ForegroundColor Cyan
    try {
        Copy-Item -Path $localPath -Destination $uncPath -Force
        Write-Host "[+] File copied successfully" -ForegroundColor Green
    } catch {
        Write-Host "[-] Copy failed: $_" -ForegroundColor Red
    }
    Write-Host ""
    Read-Host "Press Enter to continue"
}

function Invoke-PSExecCopyFrom {
    Write-Host ""
    $remotePath = Read-Host "Remote file path (e.g., C:\Windows\System32\config\SAM)"
    $uncPath = $remotePath -replace '^([A-Za-z]):', "\\$($Script:RemoteHost)\`$1$"
    
    $localPath = Read-Host "Local destination path"
    
    Write-Host "[*] Copying from $uncPath..." -ForegroundColor Cyan
    try {
        Copy-Item -Path $uncPath -Destination $localPath -Force
        Write-Host "[+] File copied to $localPath" -ForegroundColor Green
    } catch {
        Write-Host "[-] Copy failed: $_" -ForegroundColor Red
    }
    Write-Host ""
    Read-Host "Press Enter to continue"
}

function Invoke-PSExecBrowse {
    Write-Host ""
    $remotePath = Read-Host "Remote path to list (e.g., C:\Users)"
    $uncPath = $remotePath -replace '^([A-Za-z]):', "\\$($Script:RemoteHost)\`$1$"
    
    Write-Host ""
    Write-Host "[*] Listing: $uncPath" -ForegroundColor Cyan
    Write-Host ""
    
    try {
        Get-ChildItem -Path $uncPath | Format-Table Mode, LastWriteTime, Length, Name -AutoSize
    } catch {
        Write-Host "[-] Cannot list directory: $_" -ForegroundColor Red
    }
    Write-Host ""
    Read-Host "Press Enter to continue"
}

function Show-WindowsRemoteMenu {
    if (-not $Script:RemoteSession) {
        Write-Host "Not connected to remote Windows system" -ForegroundColor Red
        Read-Host "Press Enter to continue"
        return
    }
    
    while ($true) {
        Show-Banner
        Write-Host "  WINDOWS REMOTE HUNTING - $Script:RemoteHost" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  QUICK OPERATIONS (via WinRM + Modules)" -ForegroundColor Cyan
        Write-Host "  [1] Quick Triage          - Fast collection via module functions"
        Write-Host "  [2] Run Playbook          - Execute hunt playbook remotely"
        Write-Host "  [3] Network Collection    - Get-CustodianNetworkConnections"
        Write-Host "  [4] Persistence Check     - Get-CustodianPersistence"
        Write-Host ""
        Write-Host "  COMPREHENSIVE OPERATIONS (Deployment)" -ForegroundColor Cyan
        Write-Host "  [5] Deploy Invoke-ThreatHunt.ps1 - Full Windows DFIR collection"
        Write-Host "  [6] Remote KAPE Collection - Deploy and run KAPE"
        Write-Host "  [7] Memory Capture        - Deploy DumpIt/MagnetRAM"
        Write-Host ""
        Write-Host "  UTILITIES" -ForegroundColor Cyan
        Write-Host "  [8] Hash Search           - Search files by hash"
        Write-Host "  [9] Interactive PowerShell - Enter-PSSession"
        Write-Host "  [R] RDP Connection        - Open mstsc.exe"
        Write-Host ""
        Write-Host "  [D] Disconnect"
        Write-Host "  [0] Back to Main Menu"
        Write-Host ""
        
        $choice = Read-Host "Select option"
        
        switch ($choice.ToUpper()) {
            "1" {
                Write-Host "Running Quick Triage on $Script:RemoteHost..." -ForegroundColor Cyan
                $outputPath = Join-Path (Get-CustodianPath -PathType "Collection") "RemoteTriage_${Script:RemoteHost}_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
                New-Item -ItemType Directory -Path $outputPath -Force | Out-Null
                
                Get-CustodianNetworkConnections -ComputerName $Script:RemoteHost -Credential $Script:RemoteCredential -OutputPath $outputPath
                Get-CustodianProcesses -ComputerName $Script:RemoteHost -Credential $Script:RemoteCredential -OutputPath $outputPath
                Get-CustodianAutoruns -ComputerName $Script:RemoteHost -Credential $Script:RemoteCredential -OutputPath $outputPath
                Get-CustodianServices -ComputerName $Script:RemoteHost -Credential $Script:RemoteCredential -OutputPath $outputPath
                Get-CustodianScheduledTasks -ComputerName $Script:RemoteHost -Credential $Script:RemoteCredential -OutputPath $outputPath
                
                Write-Host "[+] Quick Triage complete: $outputPath" -ForegroundColor Green
                Read-Host "Press Enter to continue"
            }
            "2" {
                Write-Host ""
                Write-Host "Available Playbooks:"
                Write-Host "  [1] Ransomware Hunt"
                Write-Host "  [2] Persistence Hunt"
                Write-Host "  [3] Lateral Movement Hunt"
                $pb = Read-Host "Select playbook"
                
                switch ($pb) {
                    "1" { Start-RansomwareHunt -ComputerName $Script:RemoteHost -Credential $Script:RemoteCredential }
                    "2" { Start-PersistenceHunt -ComputerName $Script:RemoteHost -Credential $Script:RemoteCredential }
                    "3" { Start-LateralMovementHunt -ComputerName $Script:RemoteHost -Credential $Script:RemoteCredential }
                }
                Read-Host "Press Enter to continue"
            }
            "3" {
                Get-CustodianNetworkConnections -ComputerName $Script:RemoteHost -Credential $Script:RemoteCredential -IncludeUDP
                Read-Host "Press Enter to continue"
            }
            "4" {
                Get-CustodianPersistence -ComputerName $Script:RemoteHost -Credential $Script:RemoteCredential
                Read-Host "Press Enter to continue"
            }
            "5" {
                Write-Host "Deploying Invoke-ThreatHunt.ps1 to $Script:RemoteHost..." -ForegroundColor Cyan
                $scriptPath = Join-Path $Script:BasePath "Invoke-ThreatHunt.ps1"
                
                if (Test-Path $scriptPath) {
                    Copy-Item -Path $scriptPath -Destination "C:\Temp\Invoke-ThreatHunt.ps1" -ToSession $Script:RemoteSession -Force
                    
                    Write-Host "Executing Invoke-ThreatHunt.ps1..." -ForegroundColor Cyan
                    Invoke-Command -Session $Script:RemoteSession -ScriptBlock {
                        & "C:\Temp\Invoke-ThreatHunt.ps1" -OutputPath "C:\Custodian_ThreatHunt" -Quick
                    }
                    
                    Write-Host "[+] Collection complete on remote system" -ForegroundColor Green
                    Write-Host "[*] Data saved to: C:\Custodian_ThreatHunt on $Script:RemoteHost" -ForegroundColor Cyan
                } else {
                    Write-Host "[-] Invoke-ThreatHunt.ps1 not found" -ForegroundColor Red
                }
                Read-Host "Press Enter to continue"
            }
            "6" {
                Invoke-RemoteKAPE -ComputerName $Script:RemoteHost -Credential $Script:RemoteCredential
                Read-Host "Press Enter to continue"
            }
            "7" {
                Write-Host "Memory capture requires DumpIt.exe or MagnetRAM.exe in Tools\DumpIt\" -ForegroundColor Yellow
                Read-Host "Press Enter to continue"
            }
            "8" {
                $hash = Read-Host "Hash to search (SHA256)"
                Write-Host "Searching for hash on $Script:RemoteHost..." -ForegroundColor Cyan
                $results = Invoke-Command -Session $Script:RemoteSession -ScriptBlock {
                    param($h)
                    Get-ChildItem C:\Users,C:\Windows\Temp,C:\ProgramData -Recurse -File -ErrorAction SilentlyContinue |
                        Where-Object { $_.Length -lt 100MB } |
                        ForEach-Object {
                            $fileHash = (Get-FileHash $_.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
                            if ($fileHash -eq $h) {
                                [PSCustomObject]@{
                                    Path = $_.FullName
                                    Hash = $fileHash
                                    Size = $_.Length
                                    Modified = $_.LastWriteTime
                                }
                            }
                        }
                } -ArgumentList $hash
                
                if ($results) {
                    Write-Host "[+] Matches found:" -ForegroundColor Green
                    $results | Format-Table -AutoSize
                } else {
                    Write-Host "[*] No matches found" -ForegroundColor Yellow
                }
                Read-Host "Press Enter to continue"
            }
            "9" {
                Write-Host "Opening interactive PowerShell session..." -ForegroundColor Cyan
                Write-Host "Type 'exit' to return to launcher" -ForegroundColor Yellow
                Enter-PSSession -Session $Script:RemoteSession
            }
            "R" {
                Write-Host "Opening RDP connection to $Script:RemoteHost..." -ForegroundColor Cyan
                Start-Process "mstsc.exe" -ArgumentList "/v:$Script:RemoteHost"
            }
            "D" {
                Remove-PSSession $Script:RemoteSession -ErrorAction SilentlyContinue
                $Script:RemoteSession = $null
                $Script:RemoteHost = $null
                $Script:RemoteType = $null
                $Script:RemoteCredential = $null
                Write-Host "[+] Disconnected" -ForegroundColor Green
                Start-Sleep -Seconds 1
                return
            }
            "0" { return }
        }
    }
}
#endregion

#region Linux Remote Hunting - SSH Session Management

function Test-SSHAvailable {
    <#
    .SYNOPSIS
        Check if SSH client is available on the system
    #>
    $sshCmd = Get-Command ssh -ErrorAction SilentlyContinue
    $scpCmd = Get-Command scp -ErrorAction SilentlyContinue
    
    if (-not $sshCmd -or -not $scpCmd) {
        Write-Host "[-] OpenSSH client not found" -ForegroundColor Red
        Write-Host ""
        Write-Host "Install OpenSSH Client:" -ForegroundColor Yellow
        Write-Host "  Settings > Apps > Optional Features > Add OpenSSH Client" -ForegroundColor White
        Write-Host "  Or: Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0" -ForegroundColor White
        return $false
    }
    return $true
}

function Invoke-SSHCommand {
    <#
    .SYNOPSIS
        Execute command on remote Linux host via SSH with improved Sudo handling
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Command,
        [switch]$UseSudo,
        [int]$TimeoutSeconds = 300
    )
    
    if (-not $Script:SSHConnected) {
        Write-Host "[-] No SSH session. Connect first." -ForegroundColor Red
        return $null
    }
    
    # Improved Sudo Logic: Wraps in 'sh -c' to handle complex strings/redirects
    if ($UseSudo -and $Script:SSHSudoPass) {
        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Script:SSHSudoPass)
        $sudoPlain = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
        
        # Escape single quotes in the inner command for the outer sh -c
        $safeCommand = $Command -replace "'", "'\''"
        $fullCommand = "echo '$sudoPlain' | sudo -S -p '' sh -c '$safeCommand' 2>/dev/null"
    } elseif ($UseSudo) {
        $fullCommand = "sudo $Command"
    } else {
        $fullCommand = $Command
    }
    
    $sshArgs = @()
    if ($Script:SSHKeyPath) {
        $sshArgs += "-i", $Script:SSHKeyPath
        $sshArgs += "-o", "BatchMode=yes"
    }
    $sshArgs += "-o", "StrictHostKeyChecking=no"
    $sshArgs += "-o", "ConnectTimeout=30"
    $sshArgs += $Script:SSHHost
    $sshArgs += $fullCommand
    
    try {
        $output = $null | & ssh @sshArgs 2>&1
        return $output
    } catch {
        Write-Host "[-] SSH command failed: $_" -ForegroundColor Red
        return $null
    }
}

function Invoke-SCPUpload {
    <#
    .SYNOPSIS
        Upload file to remote Linux host via SCP
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$LocalPath,
        [Parameter(Mandatory)][string]$RemotePath
    )
    
    if (-not $Script:SSHConnected) {
        Write-Host "[-] No SSH session. Connect first." -ForegroundColor Red
        return $false
    }
    
    if (-not (Test-Path $LocalPath)) {
        Write-Host "[-] Local file not found: $LocalPath" -ForegroundColor Red
        return $false
    }
    
    $scpArgs = @()
    if ($Script:SSHKeyPath) {
        $scpArgs += "-i", $Script:SSHKeyPath
        $scpArgs += "-o", "BatchMode=yes"
    }
    $scpArgs += "-o", "StrictHostKeyChecking=no"
    $scpArgs += "-o", "ConnectTimeout=30"
    $scpArgs += $LocalPath
    $scpArgs += "${Script:SSHHost}:${RemotePath}"
    
    try {
        Write-Host "[*] Uploading $(Split-Path $LocalPath -Leaf)..." -ForegroundColor Cyan
        $result = $null | & scp @scpArgs 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Host "[+] Upload complete" -ForegroundColor Green
            return $true
        } else {
            Write-Host "[-] Upload failed: $result" -ForegroundColor Red
            return $false
        }
    } catch {
        Write-Host "[-] SCP failed: $_" -ForegroundColor Red
        return $false
    }
}

function Invoke-SCPDownload {
    <#
    .SYNOPSIS
        Download file from remote Linux host via SCP
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$RemotePath,
        [Parameter(Mandatory)][string]$LocalPath
    )
    
    if (-not $Script:SSHConnected) {
        Write-Host "[-] No SSH session. Connect first." -ForegroundColor Red
        return $false
    }
    
    $localDir = Split-Path $LocalPath -Parent
    if ($localDir -and -not (Test-Path $localDir)) {
        New-Item -ItemType Directory -Path $localDir -Force | Out-Null
    }
    
    $scpArgs = @()
    if ($Script:SSHKeyPath) {
        $scpArgs += "-i", $Script:SSHKeyPath
        $scpArgs += "-o", "BatchMode=yes"
    }
    $scpArgs += "-o", "StrictHostKeyChecking=no"
    $scpArgs += "-o", "ConnectTimeout=30"
    $scpArgs += "${Script:SSHHost}:${RemotePath}"
    $scpArgs += $LocalPath
    
    try {
        Write-Host "[*] Downloading $RemotePath..." -ForegroundColor Cyan
        $result = $null | & scp @scpArgs 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Host "[+] Download complete: $LocalPath" -ForegroundColor Green
            return $true
        } else {
            Write-Host "[-] Download failed: $result" -ForegroundColor Red
            return $false
        }
    } catch {
        Write-Host "[-] SCP failed: $_" -ForegroundColor Red
        return $false
    }
}

function Connect-LinuxRemote {
    <#
    .SYNOPSIS
        Establish SSH connection to Linux target with smart fallback
    #>
    
    # 1. Clear invalid SSH Agent sockets to prevent "getsockname failed"
    if (Test-Path Env:\SSH_AUTH_SOCK) {
        Remove-Item Env:\SSH_AUTH_SOCK -ErrorAction SilentlyContinue
    }
    
    if (-not (Test-SSHAvailable)) {
        Read-Host "Press Enter to continue"
        return
    }
    
    Write-Host ""
    Write-Host "=== LINUX REMOTE CONNECTION ===" -ForegroundColor Yellow
    Write-Host ""
    
    # 2. Get Connection Target
    $sshHost = Read-Host "SSH Target (user@hostname or user@IP)"
    if (-not $sshHost -or $sshHost -notmatch '@') {
        Write-Host "[-] Invalid format. Use: user@hostname" -ForegroundColor Red
        Read-Host "Press Enter to continue"
        return
    }
    
    $parts = $sshHost -split '@'
    $Script:SSHUser = $parts[0]
    $Script:SSHHostname = $parts[1]
    $Script:SSHHost = $sshHost
    
    # 3. Configure Key (Optional)
    $Script:SSHKeyPath = $null
    $defaultKey = "$env:USERPROFILE\.ssh\id_rsa"
    
    # Check if a default key exists to be smart about prompts
    if (Test-Path $defaultKey) {
        $useKey = Read-Host "SSH Key detected at default location. Use it? (Y/n)"
        if ($useKey -ne 'n') { $Script:SSHKeyPath = $defaultKey }
    } else {
        $hasKey = Read-Host "Do you have a specific SSH key to use? (y/N)"
        if ($hasKey -eq 'y') {
            $keyPath = Read-Host "Path to SSH private key"
            if (Test-Path $keyPath) {
                $Script:SSHKeyPath = $keyPath
            } else {
                Write-Host "[!] Key not found. Will default to password auth." -ForegroundColor Yellow
            }
        }
    }

    # 4. Attempt Connection (Smart Fallback Logic)
    Write-Host ""
    $Script:SSHConnected = $false
    
    # Attempt 1: Try Key (if configured)
    if ($Script:SSHKeyPath) {
        Write-Host "[*] Attempting Key Authentication ($($Script:SSHKeyPath))..." -ForegroundColor Cyan
        
        # Test with BatchMode=yes. If key fails, SSH dies immediately (good)
        $sshArgs = @("-i", $Script:SSHKeyPath, "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=10", $Script:SSHHost, "echo 'CONNECTION_OK'")
        
        try {
            $testResult = $null | & ssh @sshArgs 2>&1
            if ($testResult -match 'CONNECTION_OK') {
                $Script:SSHConnected = $true
                Write-Host "[+] Key Authentication Successful!" -ForegroundColor Green
            } else {
                Write-Host "[-] Key Authentication Failed." -ForegroundColor Yellow
                # Clear key path so subsequent commands don't use the bad key
                $Script:SSHKeyPath = $null
            }
        } catch {
            $Script:SSHKeyPath = $null
        }
    }

    # Attempt 2: Try Password (if Key failed or wasn't provided)
    if (-not $Script:SSHConnected) {
        Write-Host "[*] Attempting Password Authentication..." -ForegroundColor Cyan
        if ($Script:SSHKeyPath) { Write-Host "    (Falling back from failed key)" -ForegroundColor Gray }
        
        # No BatchMode here - strictly interactive
        $sshArgs = @("-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=15", $Script:SSHHost, "echo 'CONNECTION_OK'")
        
        try {
            # Standard SSH, will prompt user for password in terminal
            $testResult = & ssh @sshArgs 2>&1
            
            if ($testResult -match 'CONNECTION_OK') {
                $Script:SSHConnected = $true
                Write-Host "[+] Password Authentication Successful!" -ForegroundColor Green
            } else {
                Write-Host "[-] Password Authentication Failed." -ForegroundColor Red
            }
        } catch {
             Write-Host "[-] Connection Error: $_" -ForegroundColor Red
        }
    }

    # 5. Post-Connection Setup (Only runs if connected)
    if ($Script:SSHConnected) {
        # NOW we ask for Sudo password, not before
        Write-Host ""
        $sudoChoice = Read-Host "Store Sudo password for privileged commands? (Y/n)"
        if ($sudoChoice -ne 'n') {
            $Script:SSHSudoPass = Read-Host "Enter Sudo password for $Script:SSHUser" -AsSecureString
        } else {
            $Script:SSHSudoPass = $null
        }

        # Remote Info
        $sysInfo = Invoke-SSHCommand -Command "hostname; uname -a"
        if ($sysInfo) {
            Write-Host ""
            Write-Host "  Remote System:" -ForegroundColor White
            $sysInfo | ForEach-Object { Write-Host "    $_" -ForegroundColor Gray }
        }
        
        Start-Sleep -Seconds 1
        Show-LinuxRemoteMenu
    } else {
        Write-Host ""
        Write-Host "[-] All authentication methods failed." -ForegroundColor Red
        Read-Host "Press Enter to continue"
    }
}

function Disconnect-LinuxRemote {
    $Script:SSHHost = $null
    $Script:SSHUser = $null
    $Script:SSHHostname = $null
    $Script:SSHKeyPath = $null
    $Script:SSHConnected = $false
    $Script:SSHSudoPass = $null
    Write-Host "[+] SSH session cleared" -ForegroundColor Green
}

function Show-LinuxRemoteMenu {
    while ($true) {
        Show-Banner
        
        Write-Host "  LINUX REMOTE HUNTING - SSH" -ForegroundColor Yellow
        Write-Host ""
        if ($Script:SSHConnected) {
            Write-Host "  Connected to: " -NoNewline -ForegroundColor Gray
            Write-Host "$Script:SSHHost" -ForegroundColor Green
        } else {
            Write-Host "  Status: " -NoNewline -ForegroundColor Gray
            Write-Host "Not connected" -ForegroundColor Red
        }
        Write-Host ""
        
        Write-Host "  AUTOMATED COLLECTION" -ForegroundColor Cyan
        Write-Host "  [1] Full System Triage      - Deploy script, collect, retrieve"
        Write-Host "  [2] AVML Memory Capture     - Deploy AVML, capture, retrieve"
        Write-Host "  [3] Quick Triage            - Run live triage commands"
        Write-Host ""
        Write-Host "  HUNTING & SEARCH" -ForegroundColor Cyan
        Write-Host "  [4] Hash Search (Remote)    - Search for SHA256 on target"
        Write-Host "  [5] Hash Search (Local)     - Search for SHA256 locally"
        Write-Host "  [6] Custom Command          - Run command on target"
        Write-Host ""
        Write-Host "  FILE TRANSFER" -ForegroundColor Yellow
        Write-Host "  [7] Upload File             - SCP to target"
        Write-Host "  [8] Download File           - SCP from target"
        Write-Host "  [9] Interactive SSH         - Open terminal session"
        Write-Host ""
        Write-Host "  [C] Change Target           - Connect to different host"
        Write-Host "  [D] Disconnect              - Clear session"
        Write-Host "  [0] Back to Main Menu"
        Write-Host ""
        
        $choice = Read-Host "Select option"
        
        switch ($choice.ToUpper()) {
            "1" { Invoke-LinuxFullTriage }
            "2" { Invoke-LinuxMemoryCapture }
            "3" { Invoke-LinuxQuickTriage }
            "4" { Invoke-LinuxHashSearch }
            "5" { Invoke-LocalHashSearch }
            "6" { Invoke-LinuxCustomCommand }
            "7" { Invoke-LinuxUpload }
            "8" { Invoke-LinuxDownload }
            "9" { Invoke-LinuxInteractiveSSH }
            "C" { Connect-LinuxRemote }
            "D" { Disconnect-LinuxRemote; return }
            "0" { return }
            default {
                Write-Host "Invalid option" -ForegroundColor Red
                Start-Sleep -Milliseconds 500
            }
        }
    }
}

function Invoke-LinuxFullTriage {
    if (-not $Script:SSHConnected) {
        Write-Host "[-] Not connected. Select [C] to connect first." -ForegroundColor Red
        Read-Host "Press Enter to continue"
        return
    }
    
    Write-Host ""
    Write-Host "=== LINUX FULL SYSTEM TRIAGE ===" -ForegroundColor Cyan
    Write-Host ""
    
    $linuxScript = Join-Path $Script:BasePath "Custodian-linux.sh"
    if (-not (Test-Path $linuxScript)) {
        Write-Host "[-] Custodian-linux.sh not found at: $linuxScript" -ForegroundColor Red
        Read-Host "Press Enter to continue"
        return
    }
    
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $outputDir = Join-Path (Get-CustodianPath -PathType "Collection") "Linux_${Script:SSHHostname}_${timestamp}"
    New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
    
    Write-Host "[*] Target: $Script:SSHHost" -ForegroundColor White
    Write-Host "[*] Output: $outputDir" -ForegroundColor White
    Write-Host ""
    
    # 1. Sanitize Locally (Local Fix)
    Write-Host "[1/4] Preparing script..." -ForegroundColor Yellow
    try {
        $content = Get-Content $linuxScript -Raw
        $content = $content -replace "`r", ""
        $tempScript = [System.IO.Path]::GetTempFileName()
        # Write back without BOM, forcing Linux LF
        [System.IO.File]::WriteAllText($tempScript, $content)
    } catch {
        Write-Host "[-] Local sanitization failed. Uploading original." -ForegroundColor Yellow
        $tempScript = $linuxScript
    }

    # 2. Upload (Prompt 1)
    Write-Host "[2/4] Uploading..." -ForegroundColor Yellow
    if (-not (Invoke-SCPUpload -LocalPath $tempScript -RemotePath "/tmp/Custodian-linux.sh")) {
        Read-Host "Press Enter to continue"
        return
    }
    
    # 3. Exec + Fix Permissions (Prompt 2)
    Write-Host "[3/4] Executing triage script (may take several minutes)..." -ForegroundColor Yellow
    
    # Combined command: 
    # 1. Make executable (chmod)
    # 2. Run script using bash LOGIN shell (-l) to fix environment vars
    # 3. Fix permissions on ANY resulting tar file so we can download it (chown)
    # 4. List the file to prove it exists (ls)
    # 5. [FIX] Explicit PATH injection for Sudo context with PS-safe variable escaping
    $chainedCmd = "chmod +x /tmp/Custodian-linux.sh; sudo -E bash -l -c 'export PATH=`$PATH:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; /tmp/Custodian-linux.sh' 2>&1; chown $Script:SSHUser /tmp/custodian_*.tar.gz 2>/dev/null; ls -t /tmp/custodian_*.tar.gz 2>/dev/null | head -1"
    
    $runResult = Invoke-SSHCommand -Command $chainedCmd -UseSudo
    
    # Check if the last line of output is a file path
    $remoteArchive = $null
    if ($runResult) {
        $lastLine = $runResult[-1].Trim()
        if ($lastLine -match "\.tar\.gz$") {
            $remoteArchive = $lastLine
        }
    }
    
    if (-not $remoteArchive) {
        Write-Host "[-] No output archive found." -ForegroundColor Red
        Write-Host "    Script Output (Tail):" -ForegroundColor Gray
        $runResult | Select-Object -Last 10 | ForEach-Object { Write-Host "    $_" -ForegroundColor Gray }
        Read-Host "Press Enter to continue"
        return
    }
    
    $localArchive = Join-Path $outputDir (Split-Path $remoteArchive -Leaf)
    Write-Host "    Found: $remoteArchive" -ForegroundColor Gray
    
    # 4. Download (Prompt 3)
    Write-Host "[4/4] Downloading results..." -ForegroundColor Yellow
    if (Invoke-SCPDownload -RemotePath $remoteArchive -LocalPath $localArchive) {
        Write-Host ""
        Write-Host "[+] TRIAGE COMPLETE" -ForegroundColor Green
        Write-Host "    Archive: $localArchive" -ForegroundColor White
        
        $extract = Read-Host "Extract archive? (Y/n)"
        if ($extract -ne 'n' -and $extract -ne 'N') {
            try {
                tar -xzf $localArchive -C $outputDir 2>$null
                Write-Host "[+] Extracted to: $outputDir" -ForegroundColor Green
            } catch {
                Write-Host "[!] Extraction failed (requires 'tar' on Windows or use 7-Zip manually)" -ForegroundColor Yellow
            }
        }
        
        # Cleanup (Prompt 4 - Optional)
        $cleanup = Read-Host "Cleanup remote files? (Y/n)"
        if ($cleanup -ne 'n' -and $cleanup -ne 'N') {
            Invoke-SSHCommand -Command "rm -f /tmp/Custodian-linux*.sh /tmp/custodian_*.tar.gz" -UseSudo | Out-Null
            Write-Host "[+] Remote cleanup complete" -ForegroundColor Green
        }
    }
    
    # Cleanup local temp if created
    if ($tempScript -ne $linuxScript) {
        Remove-Item $tempScript -Force -ErrorAction SilentlyContinue
    }
    
    Write-Host ""
    Read-Host "Press Enter to continue"
}

function Invoke-LinuxMemoryCapture {
    if (-not $Script:SSHConnected) {
        Write-Host "[-] Not connected. Select [C] to connect first." -ForegroundColor Red
        Read-Host "Press Enter to continue"
        return
    }
    
    Write-Host ""
    Write-Host "=== LINUX MEMORY CAPTURE (AVML) ===" -ForegroundColor Cyan
    Write-Host ""
    
    # 1. Check for AVML Tool
    $avmlPath = Join-Path $Script:BasePath "Tools\AVML\avml"
    if (-not (Test-Path $avmlPath)) {
        $altPaths = @(
            (Join-Path $Script:BasePath "Tools\avml"),
            (Join-Path $Script:BasePath "Tools\AVML\avml-linux")
        )
        foreach ($alt in $altPaths) {
            if (Test-Path $alt) { $avmlPath = $alt; break }
        }
    }
    
    if (-not (Test-Path $avmlPath)) {
        Write-Host "[-] AVML not found at: Tools\AVML\avml" -ForegroundColor Red
        Write-Host "    Download from: https://github.com/microsoft/avml/releases" -ForegroundColor Yellow
        Read-Host "Press Enter to continue"
        return
    }
    
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $memoryDir = Get-CustodianPath -PathType "Memory"
    $localMemFile = Join-Path $memoryDir "memory_${Script:SSHHostname}_${timestamp}.lime"
    
    # 2. Pre-Flight Disk Check - FIXED Parsing to use Powershell Regex
    Write-Host "[*] Checking remote disk space..." -ForegroundColor Yellow
    
    $targetPath = $null
    
    # Get RAM size
    $ramRaw = Invoke-SSHCommand -Command "cat /proc/meminfo"
    $ramTotalLine = $ramRaw | Where-Object { $_ -match "MemTotal:" }
    if ($ramTotalLine -match "(\d+)") {
        $ramKB = [int64]$matches[1]
        $ramGB = [math]::Round($ramKB / 1MB, 2)
        Write-Host "    Remote RAM: $ramGB GB" -ForegroundColor Gray
    } else {
        Write-Host "[-] Could not detect RAM size. Defaulting to /tmp/" -ForegroundColor Red
        $ramKB = 0
    }

    # Check potential paths for space
    $pathsToCheck = @("/tmp", "/var/tmp", "/home/$($Script:SSHUser)")
    
    foreach ($path in $pathsToCheck) {
        # Simple df command, no fancy formatting to break things
        $dfRaw = Invoke-SSHCommand -Command "df -k $path"
        # Parse last line in PowerShell
        if ($dfRaw) {
            $lastLine = $dfRaw[-1] -split "\s+"
            # Available space is usually the 4th column (index 3) on standard Linux df
            # Filesystem     1K-blocks    Used Available Use% Mounted on
            if ($lastLine.Count -ge 4) {
                try {
                    $spaceKB = [int64]$lastLine[3]
                    if ($spaceKB -gt ($ramKB + 500000)) { # RAM + 500MB buffer
                        $targetPath = $path
                        $freeGB = [math]::Round($spaceKB / 1MB, 2)
                        Write-Host "    [+] Found suitable path: $path ($freeGB GB free)" -ForegroundColor Green
                        break
                    }
                } catch {}
            }
        }
    }
    
    if (-not $targetPath) {
        Write-Host "[-] WARNING: Could not verify sufficient disk space." -ForegroundColor Red
        if ($ramKB -gt 0) {
            Write-Host "    Needed: $ramGB GB + buffer" -ForegroundColor Yellow
        }
        
        $force = Read-Host "Attempt capture anyway? (y/N)"
        if ($force -ne 'y') { return }
        $targetPath = "/tmp"
    }

    $remoteAvml = "$targetPath/avml"
    $remoteDump = "$targetPath/memory.lime"

    $confirm = Read-Host "Capture memory to $targetPath? (y/N)"
    if ($confirm -ne 'y' -and $confirm -ne 'Y') { return }
    
    Write-Host ""
    # 3. Upload (Prompt 1)
    Write-Host "[1/3] Uploading AVML to $targetPath..." -ForegroundColor Yellow
    if (-not (Invoke-SCPUpload -LocalPath $avmlPath -RemotePath $remoteAvml)) {
        Read-Host "Press Enter to continue"
        return
    }
    
    # 4. Capture (Prompt 2)
    Write-Host "[2/3] Capturing memory (may take 10-30 minutes)..." -ForegroundColor Yellow
    
    # Combined command: Executable -> Capture -> Chown -> Verify
    # Use 'wc -c' instead of awk
    $chainedCmd = "chmod +x $remoteAvml; $remoteAvml $remoteDump 2>&1; chown $Script:SSHUser $remoteDump; ls -l $remoteDump"
    
    $runResult = Invoke-SSHCommand -Command $chainedCmd -UseSudo
    
    # Parse output for verification
    $sizeBytes = 0
    $captureSuccess = $false
    
    if ($runResult) {
        foreach ($line in $runResult) {
            if ($line -match "memory\.lime" -and $line -match "^\-") {
                try {
                    $parts = $line -split "\s+"
                    if ($parts.Count -ge 5) {
                        $sizeBytes = [int64]$parts[4]
                        $captureSuccess = $true
                    }
                } catch {}
            }
        }
    }
    
    if (-not $captureSuccess -or $sizeBytes -lt 1000) {
        Write-Host "[-] Memory capture failed." -ForegroundColor Red
        if ($runResult) {
            Write-Host "    Output Log:" -ForegroundColor Gray
            $runResult | Select-Object -Last 10 | ForEach-Object { Write-Host "    $_" -ForegroundColor Gray }
        }
        
        # Cleanup
        Invoke-SSHCommand -Command "rm -f $remoteAvml $remoteDump" -UseSudo | Out-Null
        Read-Host "Press Enter to continue"
        return
    }
    
    Write-Host "[+] Capture successful. Size: $([math]::Round($sizeBytes / 1GB, 2)) GB" -ForegroundColor Green
    
    # 5. Download (Prompt 3)
    Write-Host "[3/3] Downloading memory dump..." -ForegroundColor Yellow
    if (Invoke-SCPDownload -RemotePath $remoteDump -LocalPath $localMemFile) {
        Write-Host ""
        Write-Host "[+] MEMORY CAPTURE COMPLETE" -ForegroundColor Green
        Write-Host "    File: $localMemFile" -ForegroundColor White
        
        $cleanup = Read-Host "Cleanup remote files? (Y/n)"
        if ($cleanup -ne 'n' -and $cleanup -ne 'N') {
            Invoke-SSHCommand -Command "rm -f $remoteAvml $remoteDump" -UseSudo | Out-Null
            Write-Host "[+] Remote cleanup complete" -ForegroundColor Green
        }
        
        Write-Host ""
        Write-Host "Volatility3 analysis commands:" -ForegroundColor Cyan
        Write-Host "  vol -f `"$localMemFile`" linux.pslist" -ForegroundColor White
        Write-Host "  vol -f `"$localMemFile`" linux.bash" -ForegroundColor White
    }
    
    Write-Host ""
    Read-Host "Press Enter to continue"
}

function Invoke-LinuxQuickTriage {
    if (-not $Script:SSHConnected) {
        Write-Host "[-] Not connected. Select [C] to connect first." -ForegroundColor Red
        Read-Host "Press Enter to continue"
        return
    }
    
    Write-Host ""
    Write-Host "=== LINUX QUICK TRIAGE ===" -ForegroundColor Cyan
    Write-Host "[*] Target: $Script:SSHHost" -ForegroundColor White
    Write-Host "[*] Strategy: Batch Execution (Reduces password prompts)" -ForegroundColor Gray
    Write-Host ""
    
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $localOutDir = Join-Path (Get-CustodianPath -PathType "Triage") "LinuxQuick_${Script:SSHHostname}_${timestamp}"
    New-Item -ItemType Directory -Path $localOutDir -Force | Out-Null
    
    # Generate a single shell script to run all commands remotely
    $remoteScriptContent = @"
#!/bin/bash
mkdir -p /tmp/custodian_triage
echo "[*] Collecting System Info..."
hostname > /tmp/custodian_triage/system_info.txt
uname -a >> /tmp/custodian_triage/system_info.txt
cat /etc/os-release >> /tmp/custodian_triage/system_info.txt 2>/dev/null
echo "[*] Collecting Users..."
who -a > /tmp/custodian_triage/current_users.txt
w >> /tmp/custodian_triage/current_users.txt
cat /etc/passwd > /tmp/custodian_triage/user_accounts.txt
echo "[*] Collecting Network..."
netstat -tulpn > /tmp/custodian_triage/network_connections.txt 2>/dev/null || ss -tulpn > /tmp/custodian_triage/network_connections.txt
ip addr > /tmp/custodian_triage/network_interfaces.txt
echo "[*] Collecting Processes..."
ps auxwww --forest > /tmp/custodian_triage/processes.txt
echo "[*] Collecting Persistence..."
crontab -l > /tmp/custodian_triage/cron_jobs.txt 2>/dev/null
ls -la /etc/cron.* > /tmp/custodian_triage/cron_dirs.txt 2>/dev/null
echo "[*] Collecting Configs..."
cat /etc/ssh/sshd_config > /tmp/custodian_triage/ssh_config.txt 2>/dev/null
cat /etc/sudoers > /tmp/custodian_triage/sudo_users.txt 2>/dev/null
echo "[*] Collecting Security Info..."
find / -type f \( -perm -4000 -o -perm -2000 \) -ls 2>/dev/null | head -100 > /tmp/custodian_triage/suid_sgid.txt
find /tmp /var/tmp -type f -mtime -7 -ls 2>/dev/null | head -100 > /tmp/custodian_triage/recent_temp_files.txt
echo "[*] Compressing results..."
tar -czf /tmp/custodian_quick_${timestamp}.tar.gz -C /tmp custodian_triage
rm -rf /tmp/custodian_triage
"@

    # Save script locally
    $tempScript = Join-Path $env:TEMP "custodian_quick.sh"
    $remoteScript = "/tmp/custodian_quick.sh"
    $remoteArchive = "/tmp/custodian_quick_${timestamp}.tar.gz"
    
    $remoteScriptContent | Out-File -FilePath $tempScript -Encoding ascii -Force

    # 1. Upload (Prompt #1)
    Write-Host "[1/3] Uploading batch script..." -ForegroundColor Yellow
    if (-not (Invoke-SCPUpload -LocalPath $tempScript -RemotePath $remoteScript)) { return }

    # 2. Execute (Prompt #2)
    Write-Host "[2/3] Executing triage commands..." -ForegroundColor Yellow
    # [FIX] Sanitize line endings and execute with 'bash' explicitly
    Invoke-SSHCommand -Command "sed -i 's/\r$//' $remoteScript && chmod +x $remoteScript && bash $remoteScript" -UseSudo | Out-Null
    
    # 3. Fix Permissions & Download (Prompt #3)
    Write-Host "[3/3] Retrieving results..." -ForegroundColor Yellow
    # [FIX] Ensure we own the file so we can download it
    Invoke-SSHCommand -Command "chown $Script:SSHUser $remoteArchive" -UseSudo | Out-Null
    
    $localArchive = Join-Path $localOutDir "triage_data.tar.gz"
    if (Invoke-SCPDownload -RemotePath $remoteArchive -LocalPath $localArchive) {
        Write-Host ""
        Write-Host "[+] QUICK TRIAGE COMPLETE" -ForegroundColor Green
        Write-Host "    Output: $localOutDir" -ForegroundColor White
        
        # Cleanup remote
        Invoke-SSHCommand -Command "rm -f $remoteScript $remoteArchive" -UseSudo | Out-Null
    }
    
    # Cleanup local temp
    Remove-Item $tempScript -Force -ErrorAction SilentlyContinue
    Read-Host "Press Enter to continue"
}

function Invoke-LinuxHashSearch {
    if (-not $Script:SSHConnected) {
        Write-Host "[-] Not connected. Select [C] to connect first." -ForegroundColor Red
        Read-Host "Press Enter to continue"
        return
    }
    
    Write-Host ""
    Write-Host "=== REMOTE HASH SEARCH ===" -ForegroundColor Cyan
    Write-Host ""
    
    $hash = Read-Host "Enter SHA256 hash (64 characters)"
    if (-not $hash -or $hash.Length -ne 64) {
        Write-Host "[-] Invalid SHA256 hash" -ForegroundColor Red
        Read-Host "Press Enter to continue"
        return
    }
    
    $searchPath = Read-Host "Search path (default: /)"
    if (-not $searchPath) { $searchPath = "/" }
    
    Write-Host ""
    Write-Host "[*] Searching $searchPath on $Script:SSHHost..." -ForegroundColor Yellow
    Write-Host "[*] This may take a long time..." -ForegroundColor Gray
    
    $searchCmd = "find $searchPath -type f -readable 2>/dev/null | while read f; do sha256sum `"`$f`" 2>/dev/null; done | grep -i '$hash'"
    
    try {
        $results = Invoke-SSHCommand -Command $searchCmd -UseSudo
        if ($results) {
            Write-Host ""
            Write-Host "[+] MATCH FOUND!" -ForegroundColor Green
            $results | ForEach-Object { Write-Host "    $_" -ForegroundColor Yellow }
        } else {
            Write-Host "[-] No files matching hash found" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "[-] Search failed: $_" -ForegroundColor Red
    }
    
    Write-Host ""
    Read-Host "Press Enter to continue"
}

function Invoke-LocalHashSearch {
    Write-Host ""
    Write-Host "=== LOCAL HASH SEARCH ===" -ForegroundColor Cyan
    Write-Host ""
    
    $hash = Read-Host "Enter SHA256 hash (64 characters)"
    if (-not $hash -or $hash.Length -ne 64) {
        Write-Host "[-] Invalid SHA256 hash" -ForegroundColor Red
        Read-Host "Press Enter to continue"
        return
    }
    
    $searchPath = Read-Host "Search path (default: C:\)"
    if (-not $searchPath) { $searchPath = "C:\" }
    
    Write-Host ""
    Write-Host "[*] Searching locally in $searchPath..." -ForegroundColor Yellow
    
    $found = $false
    $count = 0
    
    try {
        Get-ChildItem -Path $searchPath -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
            $count++
            if ($count % 1000 -eq 0) {
                Write-Host "`r[*] Scanned $count files..." -NoNewline -ForegroundColor Gray
            }
            try {
                $fileHash = (Get-FileHash -Path $_.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
                if ($fileHash -eq $hash.ToUpper()) {
                    Write-Host ""
                    Write-Host "[+] MATCH FOUND!" -ForegroundColor Green
                    Write-Host "    Path: $($_.FullName)" -ForegroundColor Yellow
                    Write-Host "    Size: $($_.Length) bytes" -ForegroundColor Gray
                    $found = $true
                }
            } catch {}
        }
        
        Write-Host ""
        if (-not $found) {
            Write-Host "[-] No files matching hash found" -ForegroundColor Yellow
        }
        Write-Host "[*] Scanned $count files" -ForegroundColor Gray
    } catch {
        Write-Host "[-] Search error: $_" -ForegroundColor Red
    }
    
    Write-Host ""
    Read-Host "Press Enter to continue"
}

function Invoke-LinuxCustomCommand {
    if (-not $Script:SSHConnected) {
        Write-Host "[-] Not connected. Select [C] to connect first." -ForegroundColor Red
        Read-Host "Press Enter to continue"
        return
    }
    
    Write-Host ""
    Write-Host "=== CUSTOM COMMAND ===" -ForegroundColor Cyan
    Write-Host "Connected to: $Script:SSHHost" -ForegroundColor White
    Write-Host ""
    
    $useSudo = Read-Host "Run with sudo? (y/N)"
    $command = Read-Host "Command"
    
    if (-not $command) { return }
    
    Write-Host ""
    if ($useSudo -eq 'y' -or $useSudo -eq 'Y') {
        $result = Invoke-SSHCommand -Command $command -UseSudo
    } else {
        $result = Invoke-SSHCommand -Command $command
    }
    
    if ($result) {
        Write-Host "=== OUTPUT ===" -ForegroundColor Green
        $result | ForEach-Object { Write-Host $_ }
    }
    
    Write-Host ""
    Read-Host "Press Enter to continue"
}

function Invoke-LinuxUpload {
    if (-not $Script:SSHConnected) {
        Write-Host "[-] Not connected. Select [C] to connect first." -ForegroundColor Red
        Read-Host "Press Enter to continue"
        return
    }
    
    Write-Host ""
    $localPath = Read-Host "Local file path"
    if (-not (Test-Path $localPath)) {
        Write-Host "[-] File not found" -ForegroundColor Red
        Read-Host "Press Enter to continue"
        return
    }
    
    $remotePath = Read-Host "Remote destination (default: /tmp/)"
    if (-not $remotePath) { $remotePath = "/tmp/" }
    
    Invoke-SCPUpload -LocalPath $localPath -RemotePath $remotePath
    Read-Host "Press Enter to continue"
}

function Invoke-LinuxDownload {
    if (-not $Script:SSHConnected) {
        Write-Host "[-] Not connected. Select [C] to connect first." -ForegroundColor Red
        Read-Host "Press Enter to continue"
        return
    }
    
    Write-Host ""
    $remotePath = Read-Host "Remote file path"
    if (-not $remotePath) { return }
    
    $defaultLocal = Join-Path (Get-CustodianPath -PathType "Collection") (Split-Path $remotePath -Leaf)
    $localPath = Read-Host "Local destination (default: $defaultLocal)"
    if (-not $localPath) { $localPath = $defaultLocal }
    
    Invoke-SCPDownload -RemotePath $remotePath -LocalPath $localPath
    Read-Host "Press Enter to continue"
}

function Invoke-LinuxInteractiveSSH {
    if (-not $Script:SSHConnected) {
        Write-Host "[-] Not connected. Select [C] to connect first." -ForegroundColor Red
        Read-Host "Press Enter to continue"
        return
    }
    
    Write-Host ""
    Write-Host "[*] Opening interactive SSH session to $Script:SSHHost" -ForegroundColor Cyan
    Write-Host "[*] Type 'exit' to return" -ForegroundColor Yellow
    Write-Host ""
    
    $sshArgs = @()
    if ($Script:SSHKeyPath) {
        $sshArgs += "-i", $Script:SSHKeyPath
    }
    $sshArgs += "-o", "StrictHostKeyChecking=no"
    $sshArgs += $Script:SSHHost
    
    & ssh @sshArgs
    
    Write-Host ""
    Write-Host "[*] Returned to Custodian-HT" -ForegroundColor Cyan
    Read-Host "Press Enter to continue"
}
#endregion

#region Scanning Menu
function Show-ScanningMenu {
    while ($true) {
        Show-Banner
        Write-Host "  SCANNING & DETECTION TOOLS" -ForegroundColor Magenta
        Write-Host ""
        Write-Host "  LOKI-RS IOC SCANNER" -ForegroundColor Cyan
        Write-Host "  [1] Local Scan            - Scan local system for IOCs"
        Write-Host "  [2] Local Scan (Intense)  - Deep scan (slower, more thorough)"
        Write-Host "  [3] Remote Scan (WinRM)    - Deploy and scan remote Windows system"
        Write-Host "  [4] Remote Scan (SSH)      - Deploy and scan remote Linux system"
        Write-Host "  [5] View Scan Results      - Parse and display Loki log file"
        Write-Host ""
        Write-Host "  YARGEN-GO RULE GENERATOR" -ForegroundColor Yellow
        Write-Host "  [6] Generate Rule          - Create YARA rule from sample"
        Write-Host "  [7] Batch Generate         - Create rules from sample directory"
        Write-Host "  [8] Test Rule              - Test generated rule against samples"
        Write-Host ""
        Write-Host "  [0] Back to Main Menu"
        Write-Host ""
        
        $choice = Read-Host "Select option"
        
        switch ($choice) {
            "1" {
                $scanPath = Read-Host "Path to scan (default: C:\Users)"
                if (-not $scanPath) { $scanPath = "C:\Users" }
                Invoke-LokiScan -Path $scanPath
                Read-Host "Press Enter to continue"
            }
            "2" {
                $scanPath = Read-Host "Path to scan (default: C:\)"
                if (-not $scanPath) { $scanPath = "C:\" }
                Write-Host ""
                Write-Host "[!] Intense mode will take significantly longer" -ForegroundColor Yellow
                Invoke-LokiScan -Path $scanPath -Intense
                Read-Host "Press Enter to continue"
            }
            "3" {
                $target = Read-Host "Target hostname/IP"
                $scanPath = Read-Host "Path to scan on target (default: C:\Users)"
                if (-not $scanPath) { $scanPath = "C:\Users" }
                $cred = Get-Credential -Message "Enter credentials for $target"
                Invoke-RemoteLokiScan -ComputerName $target -Credential $cred -ScanPath $scanPath
                Read-Host "Press Enter to continue"
            }
            "4" {
                $remoteHost = Read-Host "Remote host (user@hostname)"
                $scanPath = Read-Host "Path to scan (default: /home)"
                if (-not $scanPath) { $scanPath = "/home" }
                Invoke-LinuxLokiScan -RemoteHost $remoteHost -ScanPath $scanPath
                Read-Host "Press Enter to continue"
            }
            "5" {
                $logFile = Read-Host "Path to Loki log file"
                if (Test-Path $logFile) {
                    Show-LokiResults -LogFile $logFile
                } else {
                    Write-Host "File not found" -ForegroundColor Red
                }
                Read-Host "Press Enter to continue"
            }
            "6" {
                $samplePath = Read-Host "Path to malware sample"
                if (Test-Path $samplePath) {
                    $ruleName = Read-Host "Rule name (optional, press Enter for auto)"
                    if ($ruleName) {
                        New-YaraRule -Path $samplePath -RuleName $ruleName
                    } else {
                        New-YaraRule -Path $samplePath
                    }
                } else {
                    Write-Host "File not found" -ForegroundColor Red
                }
                Read-Host "Press Enter to continue"
            }
            "7" {
                $sampleDir = Read-Host "Directory containing malware samples"
                if (Test-Path $sampleDir) {
                    $goodwareDir = Read-Host "Goodware directory for exclusions (optional)"
                    if ($goodwareDir -and (Test-Path $goodwareDir)) {
                        New-YaraRuleFromDirectory -SampleDirectory $sampleDir -GoodwareDirectory $goodwareDir
                    } else {
                        New-YaraRuleFromDirectory -SampleDirectory $sampleDir
                    }
                } else {
                    Write-Host "Directory not found" -ForegroundColor Red
                }
                Read-Host "Press Enter to continue"
            }
            "8" {
                $ruleFile = Read-Host "Path to YARA rule file"
                $testPath = Read-Host "Path to test against"
                if ((Test-Path $ruleFile) -and (Test-Path $testPath)) {
                    Test-YaraRule -RuleFile $ruleFile -TestPath $testPath
                } else {
                    Write-Host "Path not found" -ForegroundColor Red
                }
                Read-Host "Press Enter to continue"
            }
            "0" { return }
        }
    }
}
#endregion

#region Patch Tuesday Menu
function Show-PatchTuesdayMenu {
    while ($true) {
        Show-Banner
        Write-Host "  PATCH TUESDAY VULNERABILITY ANALYSIS" -ForegroundColor Magenta
        Write-Host ""
        Write-Host "  MICROSOFT PATCH TUESDAY" -ForegroundColor Cyan
        Write-Host "  [1] Current Month Overview    - Get this month's vulnerability summary"
        Write-Host "  [2] Actively Exploited CVEs   - Show CVEs being exploited in the wild"
        Write-Host "  [3] Priority Patches          - CVEs requiring immediate attention"
        Write-Host "  [4] Custom Date Query         - Query specific month (YYYY-MMM)"
        Write-Host ""
        Write-Host "  EXPORT & COMPARE" -ForegroundColor Yellow
        Write-Host "  [5] Export Report (CSV)       - Export full vulnerability data"
        Write-Host "  [6] Export Report (Markdown)  - Export formatted Markdown report"
        Write-Host "  [7] Export Report (HTML)      - Export interactive HTML report"
        Write-Host "  [8] Compare Two Months        - Compare vulnerability trends"
        Write-Host ""
        Write-Host "  [0] Back to Main Menu"
        Write-Host ""
        
        $choice = Read-Host "Select option"
        
        switch ($choice) {
            "1" {
                Write-Host ""
                Write-Host "Fetching current month Patch Tuesday data..." -ForegroundColor Cyan
                try {
                    $results = Get-CustodianPatchTuesday
                    if ($results) {
                        Write-Host ""
                        Write-Host "  Summary:" -ForegroundColor White
                        Write-Host "    Total CVEs: $($results.Count)" -ForegroundColor Cyan
                        Write-Host "    Actively Exploited: $(($results | Where-Object Exploited).Count)" -ForegroundColor Red
                        Write-Host "    Exploitation Likely: $(($results | Where-Object ExploitationLikely).Count)" -ForegroundColor Yellow
                        Write-Host "    High Rated (CVSS >= 8.0): $(($results | Where-Object HighRated).Count)" -ForegroundColor Cyan
                    }
                } catch {
                    Write-Host "[-] Error: $($_.Exception.Message)" -ForegroundColor Red
                }
                Write-Host ""
                Read-Host "Press Enter to continue"
            }
            "2" {
                Write-Host ""
                Write-Host "Fetching actively exploited CVEs..." -ForegroundColor Cyan
                try {
                    $exploited = Get-CustodianExploitedCVEs
                    if ($exploited -and $exploited.Count -gt 0) {
                        Write-Host ""
                        Write-Host "  ACTIVELY EXPLOITED - PATCH IMMEDIATELY" -ForegroundColor Red
                        Write-Host "  =======================================" -ForegroundColor Red
                        foreach ($cve in $exploited) {
                            Write-Host "    $($cve.CVE) | CVSS: $($cve.CvssScore) | $($cve.Title)" -ForegroundColor Red
                        }
                    } else {
                        Write-Host ""
                        Write-Host "[+] No actively exploited CVEs found this month" -ForegroundColor Green
                    }
                } catch {
                    Write-Host "[-] Error: $($_.Exception.Message)" -ForegroundColor Red
                }
                Write-Host ""
                Read-Host "Press Enter to continue"
            }
            "3" {
                Write-Host ""
                $threshold = Read-Host "CVSS threshold (default: 8.0)"
                if (-not $threshold) { $threshold = "8.0" }
                try {
                    Get-CustodianPriorityPatches -BaseScore ([float]$threshold)
                } catch {
                    Write-Host "[-] Error: $($_.Exception.Message)" -ForegroundColor Red
                }
                Write-Host ""
                Read-Host "Press Enter to continue"
            }
            "4" {
                Write-Host ""
                $reportDate = Read-Host "Enter date (YYYY-MMM or YYYY-MM, e.g., 2025-Jan or 2025-01)"
                if ($reportDate) {
                    try {
                        $results = Get-CustodianPatchTuesday -ReportDate $reportDate
                        if ($results) {
                            Write-Host ""
                            Write-Host "  Summary for $reportDate :" -ForegroundColor White
                            Write-Host "    Total CVEs: $($results.Count)" -ForegroundColor Cyan
                            Write-Host "    Actively Exploited: $(($results | Where-Object Exploited).Count)" -ForegroundColor Red
                            Write-Host "    Exploitation Likely: $(($results | Where-Object ExploitationLikely).Count)" -ForegroundColor Yellow
                            Write-Host "    High Rated: $(($results | Where-Object HighRated).Count)" -ForegroundColor Cyan
                        }
                    } catch {
                        Write-Host "[-] Error: $($_.Exception.Message)" -ForegroundColor Red
                    }
                }
                Write-Host ""
                Read-Host "Press Enter to continue"
            }
            "5" {
                Write-Host ""
                $reportDate = Read-Host "Enter date (YYYY-MMM, leave blank for current)"
                try {
                    if ($reportDate) {
                        Export-CustodianPatchReport -ReportDate $reportDate -Format CSV
                    } else {
                        Export-CustodianPatchReport -Format CSV
                    }
                } catch {
                    Write-Host "[-] Error: $($_.Exception.Message)" -ForegroundColor Red
                }
                Write-Host ""
                Read-Host "Press Enter to continue"
            }
            "6" {
                Write-Host ""
                $reportDate = Read-Host "Enter date (YYYY-MMM, leave blank for current)"
                try {
                    if ($reportDate) {
                        Export-CustodianPatchReport -ReportDate $reportDate -Format Markdown
                    } else {
                        Export-CustodianPatchReport -Format Markdown
                    }
                } catch {
                    Write-Host "[-] Error: $($_.Exception.Message)" -ForegroundColor Red
                }
                Write-Host ""
                Read-Host "Press Enter to continue"
            }
            "7" {
                Write-Host ""
                $reportDate = Read-Host "Enter date (YYYY-MMM, leave blank for current)"
                try {
                    if ($reportDate) {
                        Export-CustodianPatchReport -ReportDate $reportDate -Format HTML
                    } else {
                        Export-CustodianPatchReport -Format HTML
                    }
                    Write-Host "[+] HTML report opened in browser" -ForegroundColor Green
                } catch {
                    Write-Host "[-] Error: $($_.Exception.Message)" -ForegroundColor Red
                }
                Write-Host ""
                Read-Host "Press Enter to continue"
            }
            "8" {
                Write-Host ""
                $month1 = Read-Host "First month (YYYY-MMM, e.g., 2024-Dec)"
                $month2 = Read-Host "Second month (YYYY-MMM, leave blank for current)"
                if ($month1) {
                    try {
                        if ($month2) {
                            Compare-CustodianPatchTuesday -Month1 $month1 -Month2 $month2
                        } else {
                            Compare-CustodianPatchTuesday -Month1 $month1
                        }
                    } catch {
                        Write-Host "[-] Error: $($_.Exception.Message)" -ForegroundColor Red
                    }
                }
                Write-Host ""
                Read-Host "Press Enter to continue"
            }
            "0" { return }
            default {
                Write-Host "Invalid option" -ForegroundColor Red
                Start-Sleep -Milliseconds 500
            }
        }
    }
}
#endregion

#region Main Loop
function Start-Launcher {
    while ($true) {
        Show-Banner
        Show-MainMenu
        
        $choice = Read-Host "Select option"
        
        switch ($choice.ToUpper()) {
            "1" { Start-QuickTriage }
            "2" { Show-CollectionMenu }
            "3" { Show-PlaybooksMenu }
            "4" { Show-AnalysisMenu }
            "5" { Show-EZToolsMenu }
            "6" { Show-OSINTMenu }
            "7" { Connect-WindowsRemote }
            "8" { Connect-LinuxRemote }
            "K" { Show-KAPEMenu }
            "M" { Invoke-LocalMemoryCapture }
            "S" { Show-ScanningMenu }
            "P" { Show-PatchTuesdayMenu }
            "0" { 
                Write-Host ""
                Write-Host "Cleaning up..." -ForegroundColor Cyan
                
                # Close Windows WinRM session
                if ($Script:RemoteSession) {
                    Remove-PSSession $Script:RemoteSession -ErrorAction SilentlyContinue
                }
                
                # Close Windows PSExec/SMB session
                if ($Script:RemoteType -eq "PSExec" -and $Script:RemoteHost) {
                    try { Remove-SmbMapping -RemotePath "\\$($Script:RemoteHost)\C$" -Force -ErrorAction SilentlyContinue } catch {}
                    try { Remove-SmbMapping -RemotePath "\\$($Script:RemoteHost)\IPC$" -Force -ErrorAction SilentlyContinue } catch {}
                    $null = cmd /c "net use `"\\$($Script:RemoteHost)\IPC$`" /delete /y 2>nul" 2>$null
                    $null = cmd /c "net use `"\\$($Script:RemoteHost)\C$`" /delete /y 2>nul" 2>$null
                    Write-Host "[+] SMB sessions cleared" -ForegroundColor Green
                }
                
                # Clear Linux SSH session
                if ($Script:SSHConnected) {
                    $Script:SSHSudoPass = $null
                    Write-Host "[+] SSH credentials cleared" -ForegroundColor Green
                }
                
                Write-Host "Goodbye!" -ForegroundColor Green
                exit 0
            }
            default {
                Write-Host "Invalid option" -ForegroundColor Red
                Start-Sleep -Seconds 1
            }
        }
    }
}

Start-Launcher
#endregion