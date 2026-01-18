#Requires -Version 5.1
<#
.SYNOPSIS
    Custodian-HT Root Module
.DESCRIPTION
    Root module that imports all 9 Custodian-HT child modules and provides
    common helper functions for logging, path management, and remote operations.
.AUTHOR
    RootGuard
.VERSION
    1.0.0
#>

#region Module Variables
$Script:CustodianVersion = "1.0.0"
$Script:ModuleRoot = $PSScriptRoot
$Script:ModulesPath = Join-Path $ModuleRoot "Modules"
$Script:ToolsPath = Join-Path $ModuleRoot "Tools"
$Script:ConfigPath = Join-Path $ModuleRoot "Config"
$Script:OutputPath = Join-Path $ModuleRoot "Output"
$Script:LogPath = Join-Path $OutputPath "Logs"

# Current session state
$Script:RemoteSession = $null
$Script:CurrentTarget = "localhost"
$Script:Config = $null
#endregion

#region Helper Functions - Logging
function Write-CustodianLog {
    <#
    .SYNOPSIS
        Centralized logging function for Custodian-HT
    .PARAMETER Message
        Log message
    .PARAMETER Level
        Log level: INFO, SUCCESS, WARN, ERROR, DEBUG
    .PARAMETER NoConsole
        Skip console output (log to file only)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet("INFO","SUCCESS","WARN","ERROR","DEBUG")][string]$Level = "INFO",
        [switch]$NoConsole
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logFile = Join-Path $Script:LogPath "Custodian-$(Get-Date -Format 'yyyyMMdd').log"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    # Ensure log directory exists
    if (-not (Test-Path $Script:LogPath)) {
        New-Item -ItemType Directory -Path $Script:LogPath -Force | Out-Null
    }
    
    # Write to log file
    try {
        Add-Content -Path $logFile -Value $logEntry -ErrorAction SilentlyContinue
    } catch {
        Write-Warning "Failed to write to log file: $_"
    }
    
    # Console output
    if (-not $NoConsole) {
        $colors = @{
            INFO = "Cyan"
            SUCCESS = "Green"
            WARN = "Yellow"
            ERROR = "Red"
            DEBUG = "Gray"
        }
        
        $symbols = @{
            INFO = "[*]"
            SUCCESS = "[+]"
            WARN = "[!]"
            ERROR = "[-]"
            DEBUG = "[?]"
        }
        
        Write-Host "$($symbols[$Level]) $Message" -ForegroundColor $colors[$Level]
    }
}

function Get-CustodianLogPath {
    <#
    .SYNOPSIS
        Returns the current log file path
    #>
    [CmdletBinding()]
    param()
    
    return (Join-Path $Script:LogPath "Custodian-$(Get-Date -Format 'yyyyMMdd').log")
}
#endregion

#region Helper Functions - Path Management
function Get-CustodianPath {
    <#
    .SYNOPSIS
        Get standardized paths for Custodian-HT components
    .PARAMETER PathType
        Type of path: Root, Tools, Config, Output, Logs, Modules, Temp, Cache, Reports
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet("Root","Tools","Config","Output","Logs","Modules","Temp","Cache","Reports","Evidence","Analysis","Collection","Memory","Triage")]
        [string]$PathType
    )
    
    $paths = @{
        Root = $Script:ModuleRoot
        Tools = Join-Path $Script:ModuleRoot "Tools"
        Config = Join-Path $Script:ModuleRoot "Config"
        Output = Join-Path $Script:ModuleRoot "Output"
        Logs = Join-Path $Script:ModuleRoot "Output\Logs"
        Modules = Join-Path $Script:ModuleRoot "Modules"
        Temp = Join-Path $Script:ModuleRoot "Output\Temp"
        Cache = Join-Path $Script:ModuleRoot "Output\Cache"
        Reports = Join-Path $Script:ModuleRoot "Output\Reports"
        Evidence = Join-Path $Script:ModuleRoot "Output\Evidence"
        Analysis = Join-Path $Script:ModuleRoot "Output\Analysis"
        Collection = Join-Path $Script:ModuleRoot "Output\Collection"
        Memory = Join-Path $Script:ModuleRoot "Output\Memory"
        Triage = Join-Path $Script:ModuleRoot "Output\Triage"
    }
    
    $path = $paths[$PathType]
    
    # Ensure directory exists
    if (-not (Test-Path $path)) {
        try {
            New-Item -ItemType Directory -Path $path -Force -ErrorAction Stop | Out-Null
            Write-CustodianLog "Created directory: $PathType" -Level "INFO"
        } catch {
            Write-CustodianLog "Failed to create directory $PathType : $_" -Level "ERROR"
        }
    }
    
    return $path
}

function Resolve-CustodianPath {
    <#
    .SYNOPSIS
        Resolve paths relative to Custodian-HT root (not current directory)
    .PARAMETER Path
        Path to resolve (can be relative or absolute)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path
    )
    
    # If already absolute, return as-is
    if ([System.IO.Path]::IsPathRooted($Path)) {
        return $Path
    }
    
    # Resolve relative to module root
    $resolvedPath = Join-Path $Script:ModuleRoot $Path
    
    # Normalize the path
    return [System.IO.Path]::GetFullPath($resolvedPath)
}

function Get-CustodianToolPath {
    <#
    .SYNOPSIS
        Find tool executable with intelligent version detection
    .PARAMETER ToolName
        Tool name (e.g., "hayabusa", "chainsaw")
    .PARAMETER Subfolder
        Optional subfolder within Tools directory
    .PARAMETER Extensions
        File extensions to search for (default: .exe, .ps1, "")
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ToolName,
        [string]$Subfolder = "",
        [string[]]$Extensions = @(".exe", ".ps1", "")
    )
    
    $searchPath = if ($Subfolder) {
        Join-Path (Get-CustodianPath -PathType "Tools") $Subfolder
    } else {
        Get-CustodianPath -PathType "Tools"
    }
    
    if (-not (Test-Path $searchPath)) {
        Write-CustodianLog "Tool path not found: $searchPath" -Level "WARN"
        return $null
    }
    
    foreach ($ext in $Extensions) {
        $pattern = if ($ext) { "${ToolName}*${ext}" } else { "${ToolName}*" }
        $found = Get-ChildItem -Path $searchPath -Filter $pattern -Recurse -File -ErrorAction SilentlyContinue |
            Select-Object -First 1
        
        if ($found) {
            Write-CustodianLog "Found tool: $($found.Name)" -Level "DEBUG" -NoConsole
            return $found.FullName
        }
    }
    
    Write-CustodianLog "Tool not found: $ToolName in $searchPath" -Level "WARN"
    return $null
}
#endregion

#region Helper Functions - Configuration
function Get-CustodianConfig {
    <#
    .SYNOPSIS
        Load Custodian-HT configuration from JSON file
    #>
    [CmdletBinding()]
    param()
    
    if ($Script:Config) {
        return $Script:Config
    }
    
    $configFile = Join-Path (Get-CustodianPath -PathType "Config") "Custodian-HT.json"
    
    if (-not (Test-Path $configFile)) {
        Write-CustodianLog "Configuration file not found: $configFile" -Level "ERROR"
        return $null
    }
    
    try {
        $Script:Config = Get-Content -Path $configFile -Raw | ConvertFrom-Json
        Write-CustodianLog "Configuration loaded successfully" -Level "SUCCESS"
        return $Script:Config
    } catch {
        Write-CustodianLog "Failed to load configuration: $_" -Level "ERROR"
        return $null
    }
}

function Set-CustodianConfig {
    <#
    .SYNOPSIS
        Update Custodian-HT configuration
    .PARAMETER Config
        Configuration object to save
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][PSCustomObject]$Config
    )
    
    $configFile = Join-Path (Get-CustodianPath -PathType "Config") "Custodian-HT.json"
    
    try {
        $Config | ConvertTo-Json -Depth 10 | Out-File -FilePath $configFile -Encoding UTF8 -Force
        $Script:Config = $Config
        Write-CustodianLog "Configuration saved successfully" -Level "SUCCESS"
        return $true
    } catch {
        Write-CustodianLog "Failed to save configuration: $_" -Level "ERROR"
        return $false
    }
}
#endregion

#region Helper Functions - Remote Operations
function Test-CustodianRemoteConnection {
    <#
    .SYNOPSIS
        Test if remote session is active
    #>
    [CmdletBinding()]
    param()
    
    if ($Script:RemoteSession -and $Script:RemoteSession.State -eq "Opened") {
        return $true
    }
    return $false
}

function Get-CustodianRemoteTarget {
    <#
    .SYNOPSIS
        Get current remote target
    #>
    [CmdletBinding()]
    param()
    
    return $Script:CurrentTarget
}

function Invoke-CustodianCommand {
    <#
    .SYNOPSIS
        Execute command locally or remotely based on current session
    .PARAMETER ScriptBlock
        Script block to execute
    .PARAMETER ArgumentList
        Arguments to pass to script block
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][scriptblock]$ScriptBlock,
        [object[]]$ArgumentList
    )
    
    if (Test-CustodianRemoteConnection) {
        Write-CustodianLog "Executing remotely on $Script:CurrentTarget" -Level "DEBUG" -NoConsole
        return Invoke-Command -Session $Script:RemoteSession -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList
    } else {
        Write-CustodianLog "Executing locally" -Level "DEBUG" -NoConsole
        return Invoke-Command -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList
    }
}
#endregion

#region Helper Functions - Data Export
function Export-CustodianData {
    <#
    .SYNOPSIS
        Export data to file with multiple format support
    .PARAMETER Data
        Data to export
    .PARAMETER FileName
        Output file name
    .PARAMETER OutputPath
        Output directory path (resolved relative to Custodian-HT root if relative)
    .PARAMETER Format
        Export format: CSV, JSON, XML, TXT
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Data,
        [Parameter(Mandatory)][string]$FileName,
        [Parameter(Mandatory)][string]$OutputPath,
        [ValidateSet("CSV","JSON","XML","TXT")][string]$Format = "CSV"
    )
    
    # Resolve path relative to module root if relative
    $OutputPath = Resolve-CustodianPath -Path $OutputPath
    
    # Ensure output directory exists
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }
    
    $filePath = Join-Path $OutputPath $FileName
    
    try {
        switch ($Format.ToUpper()) {
            "CSV" {
                $Data | Export-Csv -Path $filePath -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
            }
            "JSON" {
                $Data | ConvertTo-Json -Depth 10 | Out-File -FilePath $filePath -Encoding UTF8 -ErrorAction Stop
            }
            "XML" {
                $Data | Export-Clixml -Path $filePath -ErrorAction Stop
            }
            "TXT" {
                $Data | Out-File -FilePath $filePath -Encoding UTF8 -ErrorAction Stop
            }
        }
        
        Write-CustodianLog "Exported: $FileName" -Level "SUCCESS"
        return $filePath
    } catch {
        Write-CustodianLog "Failed to export $FileName : $_" -Level "ERROR"
        return $null
    }
}
#endregion

#region Module Import
Write-CustodianLog "Custodian-HT v$Script:CustodianVersion - Loading modules..." -Level "INFO"

# List of all child modules
$childModules = @(
    "CustodianCollection.psm1",
    "CustodianNetwork.psm1",
    "CustodianLogs.psm1",
    "CustodianSystem.psm1",
    "CustodianAnalysis.psm1",
    "CustodianOSINT.psm1",
    "CustodianReporting.psm1",
    "CustodianPlaybooks.psm1",
    "CustodianAdditional.psm1",
    "CustodianScanning.psm1",
    "CustodianPatchTuesday.psm1"
)

$loadedCount = 0
$failedModules = @()

foreach ($moduleName in $childModules) {
    $modulePath = Join-Path $Script:ModulesPath $moduleName
    
    if (Test-Path $modulePath) {
        try {
            Import-Module $modulePath -Force -DisableNameChecking -ErrorAction Stop
            Write-CustodianLog "  Loaded: $moduleName" -Level "SUCCESS" -NoConsole
            $loadedCount++
        } catch {
            Write-CustodianLog "  Failed to load: $moduleName - $_" -Level "ERROR"
            $failedModules += $moduleName
        }
    } else {
        Write-CustodianLog "  Not found: $moduleName" -Level "WARN"
        $failedModules += $moduleName
    }
}

Write-CustodianLog "Module loading complete: $loadedCount/$($childModules.Count) loaded" -Level "SUCCESS"

if ($failedModules.Count -gt 0) {
    Write-CustodianLog "Failed/missing modules: $($failedModules -join ', ')" -Level "WARN"
}
#endregion

#region Function Export
# Export all helper functions
Export-ModuleMember -Function `
    Write-CustodianLog,
    Get-CustodianLogPath,
    Get-CustodianPath,
    Resolve-CustodianPath,
    Get-CustodianToolPath,
    Get-CustodianConfig,
    Set-CustodianConfig,
    Test-CustodianRemoteConnection,
    Get-CustodianRemoteTarget,
    Invoke-CustodianCommand,
    Export-CustodianData

# Export all functions from loaded child modules
foreach ($moduleName in $childModules) {
    $module = Get-Module | Where-Object { $_.Path -like "*$moduleName" }
    if ($module) {
        $exportedCommands = Get-Command -Module $module.Name
        if ($exportedCommands) {
            Export-ModuleMember -Function $exportedCommands.Name
        }
    }
}
#endregion