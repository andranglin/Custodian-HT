#Requires -Version 5.1
<#
.SYNOPSIS
    Custodian-HT Scanning Module - Loki-RS and yarGen-Go Integration
.DESCRIPTION
    Provides IOC scanning with Loki-RS and YARA rule generation with yarGen-Go
    Supports local and remote execution (Windows/Linux)
.AUTHOR
    RootGuard Cyber Defence
.VERSION
    1.1.0 - Added local helper functions
#>

#region Helpers

function Write-CustodianLog {
    param([string]$Message, [ValidateSet("INFO","SUCCESS","WARN","ERROR")][string]$Level = "INFO")
    $c = @{ INFO = "Cyan"; SUCCESS = "Green"; WARN = "Yellow"; ERROR = "Red" }
    $p = @{ INFO = "[*]"; SUCCESS = "[+]"; WARN = "[!]"; ERROR = "[-]" }
    Write-Host "$($p[$Level]) $Message" -ForegroundColor $c[$Level]
}

function Get-CustodianPath {
    param([string]$PathType = "Collection")
    $base = if ($PSScriptRoot) { Split-Path $PSScriptRoot -Parent } else { $PWD.Path }
    $out = Join-Path $base "Output\$PathType"
    if (-not (Test-Path $out)) { New-Item -ItemType Directory -Path $out -Force | Out-Null }
    return $out
}

#endregion

#region Loki-RS Functions

function Get-LokiPath {
    <#
    .SYNOPSIS
        Get path to Loki-RS executable
    #>
    [CmdletBinding()]
    param(
        [ValidateSet("Windows","Linux")][string]$Platform = "Windows"
    )
    
    $basePath = Split-Path $PSScriptRoot -Parent
    $lokiFolder = Join-Path $basePath "Tools\Loki"
    
    if ($Platform -eq "Windows") {
        $exePath = Join-Path $lokiFolder "loki-rs.exe"
    } else {
        $exePath = Join-Path $lokiFolder "loki-rs"
    }
    
    if (Test-Path $exePath) {
        return $exePath
    }
    
    # Try alternative naming
    $altPath = Get-ChildItem -Path $lokiFolder -Filter "loki*" -ErrorAction SilentlyContinue | 
               Where-Object { $_.Extension -eq ".exe" -or $_.Extension -eq "" } |
               Select-Object -First 1
    
    if ($altPath) { return $altPath.FullName }
    
    return $null
}

function Invoke-LokiScan {
    <#
    .SYNOPSIS
        Run Loki-RS IOC scanner locally
    .DESCRIPTION
        Scans specified path for IOCs using Loki-RS with YARA rules,
        hash checks, filename patterns, and C2 indicators
    .PARAMETER Path
        Path to scan (default: C:\)
    .PARAMETER OutputPath
        Output directory for results
    .PARAMETER Intense
        Enable intense mode (slower, more thorough)
    .PARAMETER NoLog
        Disable file logging
    .EXAMPLE
        Invoke-LokiScan -Path "C:\Users" -OutputPath "C:\Evidence"
    #>
    [CmdletBinding()]
    param(
        [string]$Path = "C:\",
        [string]$OutputPath = (Get-CustodianPath -PathType "Analysis"),
        [switch]$Intense,
        [switch]$NoLog,
        [string]$CustomRules
    )
    
    $lokiPath = Get-LokiPath -Platform "Windows"
    
    if (-not $lokiPath) {
        Write-CustodianLog "Loki-RS not found. Run Setup-CustodianHT.ps1 to install." -Level "ERROR"
        return $null
    }
    
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $outputDir = Join-Path $OutputPath "Loki_$timestamp"
    New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
    
    Write-CustodianLog "Starting Loki-RS scan on $Path" -Level "INFO"
    Write-CustodianLog "Output: $outputDir" -Level "INFO"
    
    # Build arguments
    $lokiArgs = @(
        "--path", $Path,
        "--csv",
        "--logfile", (Join-Path $outputDir "loki_scan.log")
    )
    
    if ($Intense) {
        $lokiArgs += "--intense"
        Write-CustodianLog "Intense mode enabled (this will take longer)" -Level "WARN"
    }
    
    if ($CustomRules) {
        if (Test-Path $CustomRules) {
            $lokiArgs += @("--rules", $CustomRules)
            Write-CustodianLog "Using custom rules: $CustomRules" -Level "INFO"
        }
    }
    
    try {
        Write-CustodianLog "Executing Loki-RS..." -Level "INFO"
        
        # Run Loki and capture output
        $process = Start-Process -FilePath $lokiPath -ArgumentList $lokiArgs -NoNewWindow -Wait -PassThru -RedirectStandardOutput (Join-Path $outputDir "loki_stdout.txt") -RedirectStandardError (Join-Path $outputDir "loki_stderr.txt")
        
        # Parse results
        $logFile = Join-Path $outputDir "loki_scan.log"
        if (Test-Path $logFile) {
            $logContent = Get-Content $logFile -Raw
            
            # Count findings
            $warnings = ([regex]::Matches($logContent, "WARNING")).Count
            $alerts = ([regex]::Matches($logContent, "ALERT")).Count
            
            $results = [PSCustomObject]@{
                ScanPath = $Path
                OutputDirectory = $outputDir
                Timestamp = Get-Date
                Warnings = $warnings
                Alerts = $alerts
                ExitCode = $process.ExitCode
                LogFile = $logFile
            }
            
            # Export summary
            $results | Export-Csv -Path (Join-Path $outputDir "scan_summary.csv") -NoTypeInformation
            
            Write-CustodianLog "Loki-RS scan complete" -Level "SUCCESS"
            Write-CustodianLog "  Warnings: $warnings" -Level $(if ($warnings -gt 0) { "WARN" } else { "INFO" })
            Write-CustodianLog "  Alerts: $alerts" -Level $(if ($alerts -gt 0) { "ERROR" } else { "INFO" })
            Write-CustodianLog "  Results: $outputDir" -Level "INFO"
            
            return $results
        }
        
    } catch {
        Write-CustodianLog "Loki-RS scan failed: $_" -Level "ERROR"
        return $null
    }
}

function Invoke-RemoteLokiScan {
    <#
    .SYNOPSIS
        Deploy and run Loki-RS on remote Windows system via WinRM
    .PARAMETER ComputerName
        Target computer name or IP
    .PARAMETER Credential
        PSCredential for remote authentication
    .PARAMETER ScanPath
        Path to scan on remote system (default: C:\Users)
    .PARAMETER OutputPath
        Local path to store retrieved results
    .EXAMPLE
        Invoke-RemoteLokiScan -ComputerName "WKS01" -Credential $cred -ScanPath "C:\Users"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ComputerName,
        [Parameter(Mandatory)][PSCredential]$Credential,
        [string]$ScanPath = "C:\Users",
        [string]$OutputPath = (Get-CustodianPath -PathType "Analysis"),
        [switch]$Intense
    )
    
    $lokiPath = Get-LokiPath -Platform "Windows"
    
    if (-not $lokiPath) {
        Write-CustodianLog "Loki-RS not found locally. Cannot deploy." -Level "ERROR"
        return $null
    }
    
    $basePath = Split-Path $PSScriptRoot -Parent
    $lokiFolder = Join-Path $basePath "Tools\Loki"
    
    Write-CustodianLog "Deploying Loki-RS to $ComputerName" -Level "INFO"
    
    try {
        # Create session
        $session = New-PSSession -ComputerName $ComputerName -Credential $Credential -ErrorAction Stop
        
        # Create remote staging directory
        $remotePath = "C:\Windows\Temp\CustodianLoki"
        $remoteOutput = "C:\Windows\Temp\CustodianLoki_Output"
        
        Invoke-Command -Session $session -ScriptBlock {
            param($path, $output)
            if (Test-Path $path) { Remove-Item $path -Recurse -Force }
            if (Test-Path $output) { Remove-Item $output -Recurse -Force }
            New-Item -ItemType Directory -Path $path -Force | Out-Null
            New-Item -ItemType Directory -Path $output -Force | Out-Null
        } -ArgumentList $remotePath, $remoteOutput
        
        # Copy Loki-RS and rules to remote
        Write-CustodianLog "Copying Loki-RS to remote system..." -Level "INFO"
        Copy-Item -Path "$lokiFolder\*" -Destination $remotePath -ToSession $session -Recurse -Force
        
        # Execute scan remotely
        Write-CustodianLog "Executing Loki-RS on $ComputerName (scanning $ScanPath)..." -Level "INFO"
        
        $scanResult = Invoke-Command -Session $session -ScriptBlock {
            param($lokiPath, $scanPath, $outputPath, $intense)
            
            $lokiExe = Get-ChildItem -Path $lokiPath -Filter "loki*.exe" | Select-Object -First 1
            if (-not $lokiExe) { return @{ Error = "Loki executable not found" } }
            
            $args = @(
                "--path", $scanPath,
                "--csv",
                "--logfile", "$outputPath\loki_scan.log"
            )
            
            if ($intense) { $args += "--intense" }
            
            $process = Start-Process -FilePath $lokiExe.FullName -ArgumentList $args -NoNewWindow -Wait -PassThru
            
            # Count findings in log
            $logFile = "$outputPath\loki_scan.log"
            $warnings = 0
            $alerts = 0
            
            if (Test-Path $logFile) {
                $content = Get-Content $logFile -Raw
                $warnings = ([regex]::Matches($content, "WARNING")).Count
                $alerts = ([regex]::Matches($content, "ALERT")).Count
            }
            
            return @{
                ExitCode = $process.ExitCode
                Warnings = $warnings
                Alerts = $alerts
                OutputPath = $outputPath
            }
        } -ArgumentList $remotePath, $ScanPath, $remoteOutput, $Intense.IsPresent
        
        if ($scanResult.Error) {
            Write-CustodianLog "Remote scan failed: $($scanResult.Error)" -Level "ERROR"
            Remove-PSSession $session
            return $null
        }
        
        # Retrieve results
        Write-CustodianLog "Retrieving results from $ComputerName..." -Level "INFO"
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $localOutput = Join-Path $OutputPath "Loki_${ComputerName}_$timestamp"
        New-Item -ItemType Directory -Path $localOutput -Force | Out-Null
        
        Copy-Item -Path "$remoteOutput\*" -Destination $localOutput -FromSession $session -Recurse
        
        # Cleanup remote
        Invoke-Command -Session $session -ScriptBlock {
            Remove-Item -Path "C:\Windows\Temp\CustodianLoki*" -Recurse -Force -ErrorAction SilentlyContinue
        }
        
        Remove-PSSession $session
        
        Write-CustodianLog "Remote Loki-RS scan complete" -Level "SUCCESS"
        Write-CustodianLog "  Target: $ComputerName" -Level "INFO"
        Write-CustodianLog "  Warnings: $($scanResult.Warnings)" -Level $(if ($scanResult.Warnings -gt 0) { "WARN" } else { "INFO" })
        Write-CustodianLog "  Alerts: $($scanResult.Alerts)" -Level $(if ($scanResult.Alerts -gt 0) { "ERROR" } else { "INFO" })
        Write-CustodianLog "  Results: $localOutput" -Level "INFO"
        
        return [PSCustomObject]@{
            ComputerName = $ComputerName
            ScanPath = $ScanPath
            OutputDirectory = $localOutput
            Warnings = $scanResult.Warnings
            Alerts = $scanResult.Alerts
            Timestamp = Get-Date
        }
        
    } catch {
        Write-CustodianLog "Remote Loki-RS deployment failed: $_" -Level "ERROR"
        if ($session) { Remove-PSSession $session -ErrorAction SilentlyContinue }
        return $null
    }
}

function Invoke-LinuxLokiScan {
    <#
    .SYNOPSIS
        Deploy and run Loki-RS on remote Linux system via SSH
    .DESCRIPTION
        Copies Loki-RS Linux binary to target, executes scan, retrieves results
    .PARAMETER RemoteHost
        SSH target (user@hostname)
    .PARAMETER ScanPath
        Path to scan on remote system
    .PARAMETER OutputPath
        Local path to store retrieved results
    .EXAMPLE
        Invoke-LinuxLokiScan -RemoteHost "root@192.168.1.100" -ScanPath "/home"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$RemoteHost,
        [string]$ScanPath = "/home",
        [string]$OutputPath = (Get-CustodianPath -PathType "Analysis"),
        [switch]$Intense
    )
    
    $basePath = Split-Path $PSScriptRoot -Parent
    $lokiLinux = Join-Path $basePath "Tools\Loki\loki-rs"
    
    if (-not (Test-Path $lokiLinux)) {
        Write-CustodianLog "Loki-RS Linux binary not found at: $lokiLinux" -Level "ERROR"
        return $null
    }
    
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $localOutput = Join-Path $OutputPath "Loki_Linux_$timestamp"
    New-Item -ItemType Directory -Path $localOutput -Force | Out-Null
    
    Write-CustodianLog "Deploying Loki-RS to $RemoteHost" -Level "INFO"
    
    try {
        # Copy Loki to remote
        $scpResult = & scp $lokiLinux "${RemoteHost}:/tmp/loki-rs" 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-CustodianLog "SCP failed: $scpResult" -Level "ERROR"
            return $null
        }
        
        # Make executable and run
        $intenseFlag = if ($Intense) { "--intense" } else { "" }
        $sshCommand = "chmod +x /tmp/loki-rs && /tmp/loki-rs --path $ScanPath --csv --logfile /tmp/loki_scan.log $intenseFlag; cat /tmp/loki_scan.log"
        
        Write-CustodianLog "Executing Loki-RS on $RemoteHost..." -Level "INFO"
        $scanOutput = & ssh $RemoteHost $sshCommand 2>&1
        $scanOutput | Out-File -FilePath (Join-Path $localOutput "loki_scan.log") -Encoding UTF8
        
        # Retrieve log file
        & scp "${RemoteHost}:/tmp/loki_scan.log" $localOutput 2>&1 | Out-Null
        
        # Cleanup remote
        & ssh $RemoteHost "rm -f /tmp/loki-rs /tmp/loki_scan.log" 2>&1 | Out-Null
        
        # Count findings
        $logContent = Get-Content (Join-Path $localOutput "loki_scan.log") -Raw -ErrorAction SilentlyContinue
        $warnings = if ($logContent) { ([regex]::Matches($logContent, "WARNING")).Count } else { 0 }
        $alerts = if ($logContent) { ([regex]::Matches($logContent, "ALERT")).Count } else { 0 }
        
        Write-CustodianLog "Linux Loki-RS scan complete" -Level "SUCCESS"
        Write-CustodianLog "  Warnings: $warnings" -Level $(if ($warnings -gt 0) { "WARN" } else { "INFO" })
        Write-CustodianLog "  Alerts: $alerts" -Level $(if ($alerts -gt 0) { "ERROR" } else { "INFO" })
        Write-CustodianLog "  Results: $localOutput" -Level "INFO"
        
        return [PSCustomObject]@{
            RemoteHost = $RemoteHost
            ScanPath = $ScanPath
            OutputDirectory = $localOutput
            Warnings = $warnings
            Alerts = $alerts
            Timestamp = Get-Date
        }
        
    } catch {
        Write-CustodianLog "Linux Loki-RS scan failed: $_" -Level "ERROR"
        return $null
    }
}

#endregion

#region yarGen-Go Functions

function Get-YarGenPath {
    <#
    .SYNOPSIS
        Get path to yarGen-Go executable
    #>
    [CmdletBinding()]
    param(
        [ValidateSet("Windows","Linux")][string]$Platform = "Windows"
    )
    
    $basePath = Split-Path $PSScriptRoot -Parent
    $yargenFolder = Join-Path $basePath "Tools\yarGen"
    
    if ($Platform -eq "Windows") {
        $exePath = Join-Path $yargenFolder "yargen-go.exe"
    } else {
        $exePath = Join-Path $yargenFolder "yargen-go"
    }
    
    if (Test-Path $exePath) {
        return $exePath
    }
    
    # Try alternative naming
    $altPath = Get-ChildItem -Path $yargenFolder -Filter "yargen*" -ErrorAction SilentlyContinue | 
               Where-Object { $_.Extension -eq ".exe" -or $_.Extension -eq "" } |
               Select-Object -First 1
    
    if ($altPath) { return $altPath.FullName }
    
    return $null
}

function New-YaraRule {
    <#
    .SYNOPSIS
        Generate YARA rule from malware sample using yarGen-Go
    .DESCRIPTION
        Analyzes a file or directory and generates YARA rules based on
        unique strings and byte patterns
    .PARAMETER Path
        Path to malware sample file or directory
    .PARAMETER OutputPath
        Output directory for generated rules
    .PARAMETER RuleName
        Name for the generated rule (default: derived from filename)
    .PARAMETER Author
        Author name for rule metadata
    .PARAMETER MinStringLength
        Minimum string length to consider (default: 6)
    .EXAMPLE
        New-YaraRule -Path "C:\Malware\sample.exe" -RuleName "Malware_Sample_2026"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [string]$OutputPath = (Get-CustodianPath -PathType "Analysis"),
        [string]$RuleName,
        [string]$Author = "Custodian-HT",
        [int]$MinStringLength = 6,
        [switch]$Opcodes
    )
    
    $yargenPath = Get-YarGenPath -Platform "Windows"
    
    if (-not $yargenPath) {
        Write-CustodianLog "yarGen-Go not found. Run Setup-CustodianHT.ps1 to install." -Level "ERROR"
        return $null
    }
    
    if (-not (Test-Path $Path)) {
        Write-CustodianLog "Sample path not found: $Path" -Level "ERROR"
        return $null
    }
    
    # Generate rule name from filename if not provided
    if (-not $RuleName) {
        $sampleName = (Get-Item $Path).BaseName -replace '[^a-zA-Z0-9]', '_'
        $RuleName = "MAL_$sampleName"
    }
    
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $outputDir = Join-Path $OutputPath "yarGen_$timestamp"
    New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
    
    $ruleFile = Join-Path $outputDir "$RuleName.yar"
    
    Write-CustodianLog "Generating YARA rule from: $Path" -Level "INFO"
    Write-CustodianLog "Rule name: $RuleName" -Level "INFO"
    
    # Build arguments
    $yargenArgs = @(
        "-m", $Path,
        "-o", $ruleFile,
        "--author", $Author,
        "--min-string-length", $MinStringLength
    )
    
    if ($Opcodes) {
        $yargenArgs += "--opcodes"
    }
    
    try {
        $process = Start-Process -FilePath $yargenPath -ArgumentList $yargenArgs -NoNewWindow -Wait -PassThru -RedirectStandardOutput (Join-Path $outputDir "yargen_stdout.txt") -RedirectStandardError (Join-Path $outputDir "yargen_stderr.txt")
        
        if (Test-Path $ruleFile) {
            $ruleContent = Get-Content $ruleFile -Raw
            $stringCount = ([regex]::Matches($ruleContent, '\$')).Count
            
            Write-CustodianLog "YARA rule generated successfully" -Level "SUCCESS"
            Write-CustodianLog "  Rule file: $ruleFile" -Level "INFO"
            Write-CustodianLog "  Strings extracted: ~$stringCount" -Level "INFO"
            
            # Calculate hash of sample for reference
            $sampleHash = (Get-FileHash $Path -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
            
            $result = [PSCustomObject]@{
                SamplePath = $Path
                SampleHash = $sampleHash
                RuleName = $RuleName
                RuleFile = $ruleFile
                OutputDirectory = $outputDir
                StringCount = $stringCount
                Timestamp = Get-Date
            }
            
            # Export metadata
            $result | Export-Csv -Path (Join-Path $outputDir "rule_metadata.csv") -NoTypeInformation
            
            return $result
        } else {
            Write-CustodianLog "YARA rule file not created. Check yargen_stderr.txt for errors." -Level "ERROR"
            return $null
        }
        
    } catch {
        Write-CustodianLog "yarGen-Go failed: $_" -Level "ERROR"
        return $null
    }
}

function New-YaraRuleFromDirectory {
    <#
    .SYNOPSIS
        Generate YARA rules from multiple samples in a directory
    .PARAMETER SampleDirectory
        Directory containing malware samples
    .PARAMETER GoodwareDirectory
        Directory containing known-good files for exclusion (optional)
    .PARAMETER OutputPath
        Output directory for generated rules
    .EXAMPLE
        New-YaraRuleFromDirectory -SampleDirectory "C:\Malware" -GoodwareDirectory "C:\Windows\System32"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$SampleDirectory,
        [string]$GoodwareDirectory,
        [string]$OutputPath = (Get-CustodianPath -PathType "Analysis"),
        [string]$Author = "Custodian-HT"
    )
    
    $yargenPath = Get-YarGenPath -Platform "Windows"
    
    if (-not $yargenPath) {
        Write-CustodianLog "yarGen-Go not found. Run Setup-CustodianHT.ps1 to install." -Level "ERROR"
        return $null
    }
    
    if (-not (Test-Path $SampleDirectory)) {
        Write-CustodianLog "Sample directory not found: $SampleDirectory" -Level "ERROR"
        return $null
    }
    
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $outputDir = Join-Path $OutputPath "yarGen_Batch_$timestamp"
    New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
    
    $ruleFile = Join-Path $outputDir "generated_rules.yar"
    
    Write-CustodianLog "Generating YARA rules from directory: $SampleDirectory" -Level "INFO"
    
    $yargenArgs = @(
        "-m", $SampleDirectory,
        "-o", $ruleFile,
        "--author", $Author
    )
    
    if ($GoodwareDirectory -and (Test-Path $GoodwareDirectory)) {
        $yargenArgs += @("-g", $GoodwareDirectory)
        Write-CustodianLog "Using goodware exclusions from: $GoodwareDirectory" -Level "INFO"
    }
    
    try {
        $process = Start-Process -FilePath $yargenPath -ArgumentList $yargenArgs -NoNewWindow -Wait -PassThru -RedirectStandardOutput (Join-Path $outputDir "yargen_stdout.txt") -RedirectStandardError (Join-Path $outputDir "yargen_stderr.txt")
        
        if (Test-Path $ruleFile) {
            $ruleContent = Get-Content $ruleFile -Raw
            $ruleCount = ([regex]::Matches($ruleContent, "rule\s+\w+")).Count
            
            Write-CustodianLog "YARA rules generated successfully" -Level "SUCCESS"
            Write-CustodianLog "  Rules file: $ruleFile" -Level "INFO"
            Write-CustodianLog "  Rules generated: $ruleCount" -Level "INFO"
            
            return [PSCustomObject]@{
                SampleDirectory = $SampleDirectory
                RuleFile = $ruleFile
                OutputDirectory = $outputDir
                RuleCount = $ruleCount
                Timestamp = Get-Date
            }
        } else {
            Write-CustodianLog "YARA rules not created. Check yargen_stderr.txt" -Level "ERROR"
            return $null
        }
        
    } catch {
        Write-CustodianLog "yarGen-Go batch processing failed: $_" -Level "ERROR"
        return $null
    }
}

function Test-YaraRule {
    <#
    .SYNOPSIS
        Test a generated YARA rule against samples
    .PARAMETER RuleFile
        Path to YARA rule file
    .PARAMETER TestPath
        Path to test against
    .EXAMPLE
        Test-YaraRule -RuleFile "C:\Rules\malware.yar" -TestPath "C:\Samples"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$RuleFile,
        [Parameter(Mandatory)][string]$TestPath
    )
    
    if (-not (Test-Path $RuleFile)) {
        Write-CustodianLog "Rule file not found: $RuleFile" -Level "ERROR"
        return $null
    }
    
    # Use existing YARA scan function if available
    if (Get-Command Invoke-YaraScan -ErrorAction SilentlyContinue) {
        return Invoke-YaraScan -Path $TestPath -RulesPath $RuleFile
    }
    
    # Fallback to direct YARA execution
    $basePath = Split-Path $PSScriptRoot -Parent
    $yaraPath = Join-Path $basePath "Tools\YARA\yara64.exe"
    
    if (-not (Test-Path $yaraPath)) {
        Write-CustodianLog "YARA not found. Cannot test rules." -Level "ERROR"
        return $null
    }
    
    Write-CustodianLog "Testing YARA rule against: $TestPath" -Level "INFO"
    
    try {
        $results = & $yaraPath -r $RuleFile $TestPath 2>&1
        
        if ($results) {
            Write-CustodianLog "Matches found:" -Level "SUCCESS"
            $results | ForEach-Object { Write-Host "  $_" -ForegroundColor Yellow }
            return $results
        } else {
            Write-CustodianLog "No matches found" -Level "INFO"
            return @()
        }
    } catch {
        Write-CustodianLog "YARA test failed: $_" -Level "ERROR"
        return $null
    }
}

#endregion

#region Helper Functions

function Show-LokiResults {
    <#
    .SYNOPSIS
        Parse and display Loki-RS scan results
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$LogFile
    )
    
    if (-not (Test-Path $LogFile)) {
        Write-CustodianLog "Log file not found: $LogFile" -Level "ERROR"
        return
    }
    
    $content = Get-Content $LogFile
    
    Write-Host ""
    Write-Host "=== LOKI-RS SCAN RESULTS ===" -ForegroundColor Cyan
    Write-Host ""
    
    $warnings = $content | Where-Object { $_ -match "WARNING" }
    $alerts = $content | Where-Object { $_ -match "ALERT" }
    
    if ($alerts) {
        Write-Host "ALERTS ($($alerts.Count)):" -ForegroundColor Red
        $alerts | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
        Write-Host ""
    }
    
    if ($warnings) {
        Write-Host "WARNINGS ($($warnings.Count)):" -ForegroundColor Yellow
        $warnings | ForEach-Object { Write-Host "  $_" -ForegroundColor Yellow }
        Write-Host ""
    }
    
    if (-not $alerts -and -not $warnings) {
        Write-Host "No threats detected." -ForegroundColor Green
    }
}

#endregion

# Export module members
Export-ModuleMember -Function @(
    # Loki-RS
    'Get-LokiPath',
    'Invoke-LokiScan',
    'Invoke-RemoteLokiScan',
    'Invoke-LinuxLokiScan',
    'Show-LokiResults',
    # yarGen-Go
    'Get-YarGenPath',
    'New-YaraRule',
    'New-YaraRuleFromDirectory',
    'Test-YaraRule'
)