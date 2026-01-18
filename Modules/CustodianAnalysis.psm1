#Requires -Version 5.1
<#
.SYNOPSIS
    Custodian-HT Analysis Tool Integration Module
.DESCRIPTION
    Integration with external forensic tools: Hayabusa, Chainsaw, YARA, Sigma,
    EZTools, KAPE, and Volatility3 for advanced analysis.
.AUTHOR
    RootGuard Cyber Defence
.VERSION
    1.0.0
#>

#region Hayabusa
function Invoke-HayabusaAnalysis {
    <#
    .SYNOPSIS
        Run Hayabusa Windows Event Log analysis
    .PARAMETER EvtxPath
        Path to EVTX files or directory
    .PARAMETER OutputFormat
        Output format: csv, json (default: csv)
    .PARAMETER Profile
        Analysis profile: standard, verbose, all-field-info
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$EvtxPath,
        [string]$OutputPath = (Get-CustodianPath -PathType "Analysis"),
        [ValidateSet("csv","json")][string]$OutputFormat = "csv",
        [ValidateSet("standard","verbose","all-field-info")][string]$Profile = "standard"
    )
    
    try {
        $hayabusaPath = Get-CustodianToolPath -ToolName "hayabusa" -Subfolder "Hayabusa"
        
        if (-not $hayabusaPath) {
            Write-CustodianLog "Hayabusa not found. Run Setup-CustodianHT.ps1 to install." -Level "ERROR"
            return $null
        }
        
        Write-CustodianLog "Running Hayabusa analysis on $EvtxPath..." -Level "INFO"
        
        $outputFile = Join-Path $OutputPath "Hayabusa_$(Get-Date -Format 'yyyyMMdd_HHmmss').$OutputFormat"
        
        $args = @(
            "csv-timeline",
            "-d", $EvtxPath,
            "-o", $outputFile,
            "-p", $Profile
        )
        
        if ($OutputFormat -eq "json") {
            $args[0] = "json-timeline"
        }
        
        $process = Start-Process -FilePath $hayabusaPath -ArgumentList $args -NoNewWindow -Wait -PassThru
        
        if ($process.ExitCode -eq 0 -and (Test-Path $outputFile)) {
            Write-CustodianLog "Hayabusa analysis complete: $outputFile" -Level "SUCCESS"
            return $outputFile
        } else {
            Write-CustodianLog "Hayabusa analysis failed with exit code: $($process.ExitCode)" -Level "ERROR"
            return $null
        }
        
    } catch {
        Write-CustodianLog "Failed to run Hayabusa: $_" -Level "ERROR"
        return $null
    }
}
#endregion

#region Chainsaw
function Invoke-ChainsawAnalysis {
    <#
    .SYNOPSIS
        Run Chainsaw SIGMA-based event log hunting
    .PARAMETER EvtxPath
        Path to EVTX files or directory
    .PARAMETER RulesPath
        Path to Sigma rules (default: Tools\Sigma\rules)
    .PARAMETER MappingFile
        Path to Sigma mapping file
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$EvtxPath,
        [string]$OutputPath = (Get-CustodianPath -PathType "Analysis"),
        [string]$RulesPath,
        [string]$MappingFile
    )
    
    try {
        $chainsawPath = Get-CustodianToolPath -ToolName "chainsaw" -Subfolder "Chainsaw"
        
        if (-not $chainsawPath) {
            Write-CustodianLog "Chainsaw not found. Run Setup-CustodianHT.ps1 to install." -Level "ERROR"
            return $null
        }
        
        if (-not $RulesPath) {
            $RulesPath = Join-Path (Get-CustodianPath -PathType "Tools") "Sigma\rules"
        }
        
        Write-CustodianLog "Running Chainsaw analysis on $EvtxPath..." -Level "INFO"
        
        $outputFile = Join-Path $OutputPath "Chainsaw_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
        
        $args = @(
            "hunt", $EvtxPath,
            "-s", $RulesPath,
            "--csv", $outputFile
        )
        
        if ($MappingFile -and (Test-Path $MappingFile)) {
            $args += @("--mapping", $MappingFile)
        }
        
        $process = Start-Process -FilePath $chainsawPath -ArgumentList $args -NoNewWindow -Wait -PassThru
        
        if ($process.ExitCode -eq 0 -and (Test-Path $outputFile)) {
            Write-CustodianLog "Chainsaw analysis complete: $outputFile" -Level "SUCCESS"
            return $outputFile
        } else {
            Write-CustodianLog "Chainsaw analysis completed with exit code: $($process.ExitCode)" -Level "WARN"
            return $outputFile
        }
        
    } catch {
        Write-CustodianLog "Failed to run Chainsaw: $_" -Level "ERROR"
        return $null
    }
}
#endregion

#region YARA
function Invoke-YaraScan {
    <#
    .SYNOPSIS
        Run YARA malware scanning
    .PARAMETER Path
        Path to scan (file or directory)
    .PARAMETER RulesPath
        Path to YARA rules
    .PARAMETER Recurse
        Scan recursively
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [string]$OutputPath = (Get-CustodianPath -PathType "Analysis"),
        [string]$RulesPath,
        [switch]$Recurse
    )
    
    try {
        $yaraPath = Get-CustodianToolPath -ToolName "yara" -Subfolder "YARA" -Extensions @(".exe", "")
        
        if (-not $yaraPath) {
            Write-CustodianLog "YARA not found. Run Setup-CustodianHT.ps1 to install." -Level "ERROR"
            return $null
        }
        
        if (-not $RulesPath) {
            $RulesPath = Join-Path (Get-CustodianPath -PathType "Tools") "YARA\rules"
        }
        
        # Find all .yar rule files
        $ruleFiles = Get-ChildItem -Path $RulesPath -Filter "*.yar*" -Recurse -File -ErrorAction SilentlyContinue
        
        if ($ruleFiles.Count -eq 0) {
            Write-CustodianLog "No YARA rules found in $RulesPath" -Level "ERROR"
            return $null
        }
        
        Write-CustodianLog "Running YARA scan on $Path with $($ruleFiles.Count) rule files..." -Level "INFO"
        
        $outputFile = Join-Path $OutputPath "YARAScan_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
        $results = @()
        
        foreach ($ruleFile in $ruleFiles) {
            $args = @($ruleFile.FullName)
            if ($Recurse) { $args += "-r" }
            $args += $Path
            
            try {
                $output = & $yaraPath $args 2>&1
                if ($output) {
                    $results += "=== Rules: $($ruleFile.Name) ==="
                    $results += $output
                    $results += ""
                }
            } catch {
                Write-CustodianLog "  Failed with rule $($ruleFile.Name): $_" -Level "WARN"
            }
        }
        
        if ($results) {
            $results | Out-File -FilePath $outputFile -Encoding UTF8
            Write-CustodianLog "YARA scan complete: $outputFile" -Level "SUCCESS"
            return $outputFile
        } else {
            Write-CustodianLog "YARA scan found no matches" -Level "INFO"
            return $null
        }
        
    } catch {
        Write-CustodianLog "Failed to run YARA: $_" -Level "ERROR"
        return $null
    }
}
#endregion

#region Sigma Conversion
function Invoke-SigmaConversion {
    <#
    .SYNOPSIS
        Convert Sigma rules to target SIEM format
    .PARAMETER RulePath
        Path to Sigma rule file or directory
    .PARAMETER Target
        Target SIEM: splunk, qradar, elasticsearch, sentinel
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$RulePath,
        [string]$OutputPath = (Get-CustodianPath -PathType "Analysis"),
        [ValidateSet("splunk","qradar","elasticsearch","sentinel")][string]$Target = "splunk"
    )
    
    try {
        # Sigma conversion requires sigma-cli (Python package)
        $sigmaCmd = Get-Command sigma -ErrorAction SilentlyContinue
        
        if (-not $sigmaCmd) {
            Write-CustodianLog "sigma-cli not found. Install with: pip install sigma-cli" -Level "ERROR"
            return $null
        }
        
        Write-CustodianLog "Converting Sigma rules to $Target format..." -Level "INFO"
        
        $outputFile = Join-Path $OutputPath "SigmaRules_${Target}_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
        
        $args = @("convert", "-t", $Target, $RulePath, "-o", $outputFile)
        
        $process = Start-Process -FilePath "sigma" -ArgumentList $args -NoNewWindow -Wait -PassThru
        
        if ($process.ExitCode -eq 0 -and (Test-Path $outputFile)) {
            Write-CustodianLog "Sigma conversion complete: $outputFile" -Level "SUCCESS"
            return $outputFile
        } else {
            Write-CustodianLog "Sigma conversion failed" -Level "ERROR"
            return $null
        }
        
    } catch {
        Write-CustodianLog "Failed to convert Sigma rules: $_" -Level "ERROR"
        return $null
    }
}
#endregion

#region EZTools
function Invoke-EZToolParser {
    <#
    .SYNOPSIS
        Run Eric Zimmerman tool parsers
    .PARAMETER Tool
        Tool name: AmcacheParser, LECmd, PECmd, RBCmd, SBECmd, etc.
    .PARAMETER Target
        Target file or directory to parse
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet("AmcacheParser","LECmd","PECmd","RBCmd","SBECmd","JLECmd",
                     "RecentFileCacheParser","SrumECmd","SumECmd","RegistryExplorer")]
        [string]$Tool,
        [Parameter(Mandatory)][string]$Target,
        [string]$OutputPath = (Get-CustodianPath -PathType "Analysis")
    )
    
    try {
        $toolPath = Get-CustodianToolPath -ToolName $Tool -Subfolder "EZTools"
        
        if (-not $toolPath) {
            Write-CustodianLog "$Tool not found in EZTools directory" -Level "ERROR"
            return $null
        }
        
        Write-CustodianLog "Running $Tool on $Target..." -Level "INFO"
        
        $outputDir = Join-Path $OutputPath "${Tool}_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
        New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
        
        # Common arguments for most EZ tools
        $args = @()
        
        switch ($Tool) {
            "AmcacheParser" { $args = @("-f", $Target, "--csv", $outputDir) }
            "LECmd"         { $args = @("-f", $Target, "--csv", $outputDir) }
            "PECmd"         { $args = @("-f", $Target, "--csv", $outputDir) }
            "RBCmd"         { $args = @("-d", $Target, "--csv", $outputDir) }
            "SBECmd"        { $args = @("-d", $Target, "--csv", $outputDir) }
            "JLECmd"        { $args = @("-d", $Target, "--csv", $outputDir) }
            "SrumECmd"      { $args = @("-f", $Target, "--csv", $outputDir) }
            "RecentFileCacheParser" { $args = @("-f", $Target, "--csv", $outputDir) }
            default         { $args = @($Target, $outputDir) }
        }
        
        $process = Start-Process -FilePath $toolPath -ArgumentList $args -NoNewWindow -Wait -PassThru
        
        if (Test-Path $outputDir) {
            Write-CustodianLog "$Tool parsing complete: $outputDir" -Level "SUCCESS"
            return $outputDir
        } else {
            Write-CustodianLog "$Tool parsing may have failed (exit code: $($process.ExitCode))" -Level "WARN"
            return $null
        }
        
    } catch {
        Write-CustodianLog "Failed to run $Tool : $_" -Level "ERROR"
        return $null
    }
}
#endregion

#region KAPE
function Invoke-KAPECollection {
    <#
    .SYNOPSIS
        Run KAPE collection
    .PARAMETER Target
        KAPE target (e.g., "KapeTriage", "!SANS_Triage")
    .PARAMETER Source
        Source drive or directory (default: C:\)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Target,
        [string]$Source = "C:\",
        [string]$OutputPath = (Get-CustodianPath -PathType "Collection")
    )
    
    try {
        $kapePath = Get-CustodianToolPath -ToolName "kape" -Subfolder "KAPE"
        
        if (-not $kapePath) {
            Write-CustodianLog "KAPE not found. Download from https://www.kroll.com/kape" -Level "ERROR"
            return $null
        }
        
        Write-CustodianLog "Running KAPE collection: $Target..." -Level "INFO"
        
        $outputDir = Join-Path $OutputPath "KAPE_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
        
        $args = @(
            "--tsource", $Source,
            "--tdest", $outputDir,
            "--target", $Target,
            "--vhdx", $Target
        )
        
        $process = Start-Process -FilePath $kapePath -ArgumentList $args -NoNewWindow -Wait -PassThru
        
        if (Test-Path $outputDir) {
            Write-CustodianLog "KAPE collection complete: $outputDir" -Level "SUCCESS"
            return $outputDir
        } else {
            Write-CustodianLog "KAPE collection failed" -Level "ERROR"
            return $null
        }
        
    } catch {
        Write-CustodianLog "Failed to run KAPE: $_" -Level "ERROR"
        return $null
    }
}
#endregion

#region Volatility3
function Invoke-VolatilityAnalysis {
    <#
    .SYNOPSIS
        Run Volatility3 memory analysis
    .PARAMETER MemoryDump
        Path to memory dump file
    .PARAMETER Plugin
        Volatility plugin to run (e.g., windows.pslist, windows.netscan)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$MemoryDump,
        [Parameter(Mandatory)][string]$Plugin,
        [string]$OutputPath = (Get-CustodianPath -PathType "Analysis")
    )
    
    try {
        # Volatility3 requires Python
        $vol3Cmd = Get-Command vol -ErrorAction SilentlyContinue
        if (-not $vol3Cmd) {
            $vol3Cmd = Get-Command python -ErrorAction SilentlyContinue
            if (-not $vol3Cmd) {
                Write-CustodianLog "Python not found. Install Python and Volatility3." -Level "ERROR"
                return $null
            }
        }
        
        Write-CustodianLog "Running Volatility3 plugin: $Plugin..." -Level "INFO"
        
        $outputFile = Join-Path $OutputPath "Volatility_${Plugin}_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
        
        $args = @("-f", $MemoryDump, $Plugin)
        
        $output = & vol @args 2>&1
        $output | Out-File -FilePath $outputFile -Encoding UTF8
        
        Write-CustodianLog "Volatility analysis complete: $outputFile" -Level "SUCCESS"
        return $outputFile
        
    } catch {
        Write-CustodianLog "Failed to run Volatility: $_" -Level "ERROR"
        return $null
    }
}
#endregion

#region Export Module Members
Export-ModuleMember -Function `
    Invoke-HayabusaAnalysis,
    Invoke-ChainsawAnalysis,
    Invoke-YaraScan,
    Invoke-SigmaConversion,
    Invoke-EZToolParser,
    Invoke-KAPECollection,
    Invoke-VolatilityAnalysis
#endregion