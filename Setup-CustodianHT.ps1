#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Custodian-HT Setup and Tool Management Script
.DESCRIPTION
    Installs, updates, and manages forensic tools for Custodian-HT
    Self-contained toolkit - all tools install into Custodian-HT\Tools\
.AUTHOR
    RootGuard Cyber Defence
.VERSION
    2.2.18
#>

[CmdletBinding()]
param(
    [switch]$Install,
    [switch]$CheckStatus,
    [switch]$Update,
    [switch]$Force,
    [string]$ToolsPath
)

$Script:Version = "2.2.18"
$Script:BasePath = $PSScriptRoot
if (-not $ToolsPath) { $ToolsPath = Join-Path $Script:BasePath "Tools" }

#region Tool Definitions
$Script:ToolDefinitions = [ordered]@{
    
    #--- Log Analysis ---
    Hayabusa = @{
        Name = "Hayabusa"
        Description = "Windows Event Log fast forensics timeline generator"
        Category = "Log Analysis"
        GitHubRepo = "Yamato-Security/hayabusa"
        AssetPattern = "hayabusa-.*-win-x64\.zip$"
        Subfolder = "Hayabusa"
        Executable = "hayabusa*.exe"
        VersionArg = "--version"
        Required = $true
    }
    Chainsaw = @{
        Name = "Chainsaw"
        Description = "Rapidly search and hunt through Windows forensic artefacts"
        Category = "Log Analysis"
        GitHubRepo = "WithSecureLabs/chainsaw"
        AssetPattern = "chainsaw_x86_64-pc-windows-msvc\.zip$"
        Subfolder = "Chainsaw"
        Executable = "chainsaw.exe"
        VersionArg = "--version"
        Required = $true
    }
    
    #--- IOC Scanning ---
    YARA = @{
        Name = "YARA"
        Description = "Pattern matching swiss knife for malware researchers"
        Category = "IOC Scanning"
        GitHubRepo = "VirusTotal/yara"
        AssetPattern = "yara-.*-win64\.zip$"
        Subfolder = "YARA"
        Executable = "yara64.exe"
        VersionArg = "--version"
        Required = $true
    }
    Loki = @{
        Name = "Loki"
        Description = "IOC and YARA scanner for threat hunting"
        Category = "IOC Scanning"
        GitHubRepo = "Neo23x0/Loki"
        Subfolder = "Loki"
        Executable = "loki.py"
        PythonRequired = $true
        CustomInstall = "Loki"
        Required = $true
    }
    
    #--- Memory Forensics ---
    Volatility3 = @{
        Name = "Volatility 3"
        Description = "Memory forensics framework with Windows/Linux plugins"
        Category = "Memory Forensics"
        Subfolder = "Volatility3"
        PythonRequired = $true
        CustomInstall = "Volatility3"
        Required = $true
    }
    AVML = @{
        Name = "AVML"
        Description = "Acquire Volatile Memory for Linux"
        Category = "Memory Forensics"
        GitHubRepo = "microsoft/avml"
        AssetPattern = "avml$"
        Subfolder = "AVML"
        Executable = "avml"
        LinuxOnly = $true
        Required = $false
    }
    DumpIt = @{
        Name = "DumpIt"
        Description = "Windows memory acquisition tool"
        Category = "Memory Forensics"
        DownloadURL = "https://github.com/thimbleweed/All-In-USB/raw/master/utilities/DumpIt/DumpIt.exe"
        Subfolder = "DumpIt"
        Executable = "DumpIt.exe"
        Required = $true
    }
    MagnetRAM = @{
        Name = "Magnet RAM Capture"
        Description = "Free Windows memory acquisition tool (Secure Boot compatible)"
        Category = "Memory Forensics"
        ManualDownload = $true
        ManualURL = "https://www.magnetforensics.com/resources/magnet-ram-capture/"
        Subfolder = "MagnetRAMCapture"           # Fixed: matches launcher path
        Executable = "MagnetRAMCapture.exe"       # Fixed: matches launcher expectation
        Required = $false
        Note = "Requires manual download from Magnet Forensics website"
    }
    
    #--- Artifact Collection ---
    KAPE = @{
        Name = "KAPE"
        Description = "Kroll Artifact Parser and Extractor"
        Category = "Artifact Collection"
        ManualDownload = $true
        ManualURL = "https://www.kroll.com/en/services/cyber-risk/incident-response-litigation-support/kroll-artifact-parser-extractor-kape"
        Subfolder = "kape"                        # Fixed: lowercase to match launcher
        Executable = "kape.exe"
        Required = $true
        Note = "Requires free registration at Kroll website to download"
    }
    
    #--- Artifact Analysis ---
    EZTools = @{
        Name = "Eric Zimmerman Tools"
        Description = "Forensic tools by Eric Zimmerman (AmcacheParser, LECmd, PECmd, etc.)"
        Category = "Artifact Analysis"
        Subfolder = "EZTools"
        Executable = "AmcacheParser.exe"
        CustomInstall = "EZTools"
        Required = $true
    }
    Hindsight = @{
        Name = "Hindsight"
        Description = "Chrome/Chromium browser forensics"
        Category = "Artifact Analysis"
        GitHubRepo = "obsidianforensics/hindsight"
        AssetPattern = "hindsight.*\.exe$"
        Subfolder = "Hindsight"
        Executable = "hindsight*.exe"
        Required = $true
    }
    
    #--- Remote Execution ---
    PSTools = @{
        Name = "PSTools (PsExec)"
        Description = "Sysinternals PsExec for remote command execution"
        Category = "Remote Execution"
        DownloadURL = "https://download.sysinternals.com/files/PSTools.zip"
        Subfolder = "PSTools"                     # Added: dedicated PSTools folder
        Executable = "PsExec.exe"
        Required = $true
    }
    Sysinternals = @{
        Name = "Sysinternals Suite"
        Description = "Full Microsoft Sysinternals utilities suite"
        Category = "Utilities"
        DownloadURL = "https://download.sysinternals.com/files/SysinternalsSuite.zip"
        Subfolder = "Sysinternals"
        Executable = "procexp64.exe"
        Required = $false
    }
    
    #--- Utilities ---
    CyberChef = @{
        Name = "CyberChef"
        Description = "Data transformation and analysis tool"
        Category = "Utilities"
        GitHubRepo = "gchq/CyberChef"
        AssetPattern = "CyberChef.*\.zip$"
        Subfolder = "CyberChef"
        Executable = "CyberChef*.html"
        Required = $true
    }
    PuTTY = @{
        Name = "PuTTY"
        Description = "SSH and telnet client"
        Category = "Utilities"
        DownloadURL = "https://the.earth.li/~sgtatham/putty/latest/w64/putty.zip"
        Subfolder = "PuTTY"
        Executable = "putty.exe"
        Required = $false
    }
    
    #--- Rule Sets ---
    SigmaCLI = @{
        Name = "Sigma CLI"
        Description = "Sigma rule converter"
        Category = "Rules"
        PipPackage = "sigma-cli"
        Subfolder = "Sigma"
        PythonRequired = $true
        Required = $false
    }
    yarGen = @{
        Name = "yarGen"
        Description = "YARA rule generator from malware samples"
        Category = "Rules"
        GitHubRepo = "Neo23x0/yarGen"
        Subfolder = "yarGen"
        Executable = "yarGen.py"
        PythonRequired = $true
        CustomInstall = "yarGen"
        Required = $false
    }
}
#endregion

#region Helper Functions
function Show-Banner {
    Clear-Host
    Write-Host ""
    Write-Host "  +-----------------------------------------------------------+" -ForegroundColor Cyan
    Write-Host "  |         CUSTODIAN-HT SETUP v$Script:Version                      |" -ForegroundColor Cyan
    Write-Host "  |              Ridgeline Cyber Defence                      |" -ForegroundColor Cyan
    Write-Host "  +-----------------------------------------------------------+" -ForegroundColor Cyan
    Write-Host ""
}

function Write-SetupLog {
    param(
        [string]$Message,
        [ValidateSet("INFO","SUCCESS","WARN","ERROR")][string]$Level = "INFO"
    )
    $colors = @{ INFO = "Cyan"; SUCCESS = "Green"; WARN = "Yellow"; ERROR = "Red" }
    $prefix = @{ INFO = "[*]"; SUCCESS = "[+]"; WARN = "[!]"; ERROR = "[-]" }
    Write-Host "$($prefix[$Level]) $Message" -ForegroundColor $colors[$Level]
}

function Initialize-ToolsDirectory {
    Write-SetupLog "Initializing directory structure..." -Level INFO
    $dirs = @(
        "Tools", 
        "Tools\PSTools",
        "Tools\kape",
        "Tools\DumpIt",
        "Tools\MagnetRAMCapture",
        "Output", 
        "Output\Collection", 
        "Output\Analysis", 
        "Output\Triage", 
        "Output\Reports",
        "Output\Memory",
        "Config", 
        "Modules",
        "Scripts",
        "Rules"
    )
    foreach ($dir in $dirs) {
        $fullPath = Join-Path $Script:BasePath $dir
        if (-not (Test-Path $fullPath)) {
            New-Item -ItemType Directory -Path $fullPath -Force | Out-Null
        }
    }
    Write-SetupLog "Directory structure ready" -Level SUCCESS
}

function Test-ToolInstalled {
    param([string]$ToolName)
    
    $tool = $Script:ToolDefinitions[$ToolName]
    if (-not $tool) { return $false }
    
    $toolPath = Join-Path $ToolsPath $tool.Subfolder
    if (-not (Test-Path $toolPath)) { return $false }
    
    if ($tool.Executable) {
        $exePath = Join-Path $toolPath $tool.Executable
        # Handle wildcards in executable name
        $found = Get-ChildItem -Path $toolPath -Filter $tool.Executable -ErrorAction SilentlyContinue
        return ($found.Count -gt 0)
    }
    
    return $true
}

function Get-ToolStatus {
    param([string]$ToolName)
    
    $tool = $Script:ToolDefinitions[$ToolName]
    $status = @{
        Name = $tool.Name
        Installed = (Test-ToolInstalled -ToolName $ToolName)
        Required = $tool.Required
        Category = $tool.Category
        ManualDownload = $tool.ManualDownload
        InstalledVersion = "Unknown"
        LatestVersion = "Unknown"
        UpdateAvailable = $false
    }
    
    return $status
}

function Show-AllToolStatus {
    Write-Host ""
    Write-Host "  TOOL STATUS" -ForegroundColor Cyan
    Write-Host "  ============================================================" -ForegroundColor Cyan
    Write-Host ""
    
    $categories = $Script:ToolDefinitions.Values | Select-Object -ExpandProperty Category -Unique
    
    foreach ($category in $categories) {
        Write-Host "  $category" -ForegroundColor Yellow
        Write-Host "  ------------------------------------------------------------" -ForegroundColor Gray
        
        foreach ($toolName in $Script:ToolDefinitions.Keys) {
            $tool = $Script:ToolDefinitions[$toolName]
            if ($tool.Category -eq $category) {
                $installed = Test-ToolInstalled -ToolName $toolName
                $status = if ($installed) { "[OK]" } else { "[--]" }
                $color = if ($installed) { "Green" } elseif ($tool.Required) { "Red" } else { "Yellow" }
                $required = if ($tool.Required) { "*" } else { " " }
                $manual = if ($tool.ManualDownload) { "(manual)" } else { "" }
                
                Write-Host "  $status " -NoNewline -ForegroundColor $color
                Write-Host "$required$($tool.Name) $manual" -ForegroundColor White
            }
        }
        Write-Host ""
    }
    
    Write-Host "  Legend: [OK] = Installed, [--] = Not installed, * = Required" -ForegroundColor Gray
    Write-Host "  (manual) = Requires manual download" -ForegroundColor Gray
    Write-Host ""
}
#endregion

#region Installation Functions
function Install-ToolFromGitHub {
    param(
        [string]$ToolName,
        [switch]$Force
    )
    
    $tool = $Script:ToolDefinitions[$ToolName]
    $toolPath = Join-Path $ToolsPath $tool.Subfolder
    
    if ((Test-ToolInstalled -ToolName $ToolName) -and -not $Force) {
        Write-SetupLog "$($tool.Name) already installed" -Level INFO
        return $true
    }
    
    Write-SetupLog "Installing $($tool.Name) from GitHub..." -Level INFO
    
    try {
        # Get latest release
        $apiUrl = "https://api.github.com/repos/$($tool.GitHubRepo)/releases/latest"
        $headers = @{ "User-Agent" = "Custodian-HT-Setup" }
        
        try {
            $release = Invoke-RestMethod -Uri $apiUrl -Headers $headers -ErrorAction Stop
        } catch {
            Write-SetupLog "Failed to get release info: $($_.Exception.Message)" -Level ERROR
            return $false
        }
        
        # Find matching asset
        $asset = $release.assets | Where-Object { $_.name -match $tool.AssetPattern } | Select-Object -First 1
        
        if (-not $asset) {
            Write-SetupLog "No matching asset found for pattern: $($tool.AssetPattern)" -Level ERROR
            return $false
        }
        
        # Download
        $downloadPath = Join-Path $env:TEMP $asset.name
        Write-SetupLog "  Downloading: $($asset.name)" -Level INFO
        
        Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $downloadPath -Headers $headers
        
        # Create tool directory
        if (Test-Path $toolPath) { Remove-Item $toolPath -Recurse -Force }
        New-Item -ItemType Directory -Path $toolPath -Force | Out-Null
        
        # Extract or copy
        if ($asset.name -match '\.zip$') {
            Write-SetupLog "  Extracting..." -Level INFO
            Expand-Archive -Path $downloadPath -DestinationPath $toolPath -Force
        } else {
            Copy-Item -Path $downloadPath -Destination $toolPath -Force
        }
        
        # Cleanup
        Remove-Item $downloadPath -Force -ErrorAction SilentlyContinue
        
        Write-SetupLog "$($tool.Name) installed successfully" -Level SUCCESS
        return $true
        
    } catch {
        Write-SetupLog "Failed to install $($tool.Name): $($_.Exception.Message)" -Level ERROR
        return $false
    }
}

function Install-ToolFromURL {
    param(
        [string]$ToolName,
        [switch]$Force
    )
    
    $tool = $Script:ToolDefinitions[$ToolName]
    $toolPath = Join-Path $ToolsPath $tool.Subfolder
    
    if ((Test-ToolInstalled -ToolName $ToolName) -and -not $Force) {
        Write-SetupLog "$($tool.Name) already installed" -Level INFO
        return $true
    }
    
    Write-SetupLog "Installing $($tool.Name)..." -Level INFO
    
    try {
        $fileName = Split-Path $tool.DownloadURL -Leaf
        $downloadPath = Join-Path $env:TEMP $fileName
        
        Write-SetupLog "  Downloading: $fileName" -Level INFO
        Invoke-WebRequest -Uri $tool.DownloadURL -OutFile $downloadPath
        
        # Create tool directory
        if (-not (Test-Path $toolPath)) {
            New-Item -ItemType Directory -Path $toolPath -Force | Out-Null
        }
        
        # Extract or copy
        if ($fileName -match '\.zip$') {
            Write-SetupLog "  Extracting..." -Level INFO
            Expand-Archive -Path $downloadPath -DestinationPath $toolPath -Force
        } else {
            Copy-Item -Path $downloadPath -Destination (Join-Path $toolPath $fileName) -Force
        }
        
        # Cleanup
        Remove-Item $downloadPath -Force -ErrorAction SilentlyContinue
        
        Write-SetupLog "$($tool.Name) installed successfully" -Level SUCCESS
        return $true
        
    } catch {
        Write-SetupLog "Failed to install $($tool.Name): $($_.Exception.Message)" -Level ERROR
        return $false
    }
}

function Install-EZTools {
    param([switch]$Force)
    
    $toolPath = Join-Path $ToolsPath "EZTools"
    
    if ((Test-Path (Join-Path $toolPath "AmcacheParser.exe")) -and -not $Force) {
        Write-SetupLog "EZTools already installed" -Level INFO
        return $true
    }
    
    Write-SetupLog "Installing Eric Zimmerman Tools..." -Level INFO
    
    try {
        # Download Get-ZimmermanTools.ps1
        $zimScript = Join-Path $env:TEMP "Get-ZimmermanTools.ps1"
        $zimUrl = "https://raw.githubusercontent.com/EricZimmerman/Get-ZimmermanTools/master/Get-ZimmermanTools.ps1"
        
        Invoke-WebRequest -Uri $zimUrl -OutFile $zimScript
        
        # Create directory
        if (-not (Test-Path $toolPath)) {
            New-Item -ItemType Directory -Path $toolPath -Force | Out-Null
        }
        
        # Run the download script
        Write-SetupLog "  Downloading tools (this may take a few minutes)..." -Level INFO
        & $zimScript -Dest $toolPath -NetVersion 6 2>&1 | Out-Null
        
        # Cleanup
        Remove-Item $zimScript -Force -ErrorAction SilentlyContinue
        
        if (Test-Path (Join-Path $toolPath "AmcacheParser.exe")) {
            Write-SetupLog "EZTools installed successfully" -Level SUCCESS
            return $true
        } else {
            Write-SetupLog "EZTools installation may be incomplete" -Level WARN
            return $false
        }
        
    } catch {
        Write-SetupLog "Failed to install EZTools: $($_.Exception.Message)" -Level ERROR
        return $false
    }
}

function Install-Volatility3 {
    param([switch]$Force)
    
    $toolPath = Join-Path $ToolsPath "Volatility3"
    
    # Check if Python is available
    $python = Get-Command python -ErrorAction SilentlyContinue
    if (-not $python) {
        $python = Get-Command python3 -ErrorAction SilentlyContinue
    }
    
    if (-not $python) {
        Write-SetupLog "Python not found - Volatility3 requires Python 3.x" -Level ERROR
        Write-SetupLog "  Install Python from: https://www.python.org/downloads/" -Level INFO
        return $false
    }
    
    Write-SetupLog "Installing Volatility3..." -Level INFO
    
    try {
        # Install via pip
        & $python.Source -m pip install volatility3 --quiet 2>&1 | Out-Null
        
        # Create marker directory
        if (-not (Test-Path $toolPath)) {
            New-Item -ItemType Directory -Path $toolPath -Force | Out-Null
        }
        
        # Create info file
        "Volatility3 installed via pip`nRun: vol -h" | Out-File (Join-Path $toolPath "README.txt") -Force
        
        Write-SetupLog "Volatility3 installed successfully" -Level SUCCESS
        Write-SetupLog "  Run 'vol -h' to verify" -Level INFO
        return $true
        
    } catch {
        Write-SetupLog "Failed to install Volatility3: $($_.Exception.Message)" -Level ERROR
        return $false
    }
}

function Install-Loki {
    param([switch]$Force)
    
    $toolPath = Join-Path $ToolsPath "Loki"
    
    if ((Test-Path (Join-Path $toolPath "loki.py")) -and -not $Force) {
        Write-SetupLog "Loki already installed" -Level INFO
        return $true
    }
    
    Write-SetupLog "Installing Loki IOC Scanner..." -Level INFO
    
    try {
        # Clone from GitHub
        $zipUrl = "https://github.com/Neo23x0/Loki/archive/refs/heads/master.zip"
        $downloadPath = Join-Path $env:TEMP "loki.zip"
        
        Invoke-WebRequest -Uri $zipUrl -OutFile $downloadPath
        
        # Extract
        $extractPath = Join-Path $env:TEMP "loki-extract"
        if (Test-Path $extractPath) { Remove-Item $extractPath -Recurse -Force }
        Expand-Archive -Path $downloadPath -DestinationPath $extractPath -Force
        
        # Move to final location
        if (Test-Path $toolPath) { Remove-Item $toolPath -Recurse -Force }
        Move-Item -Path (Join-Path $extractPath "Loki-master") -Destination $toolPath -Force
        
        # Install Python requirements
        $python = Get-Command python -ErrorAction SilentlyContinue
        if ($python) {
            $reqFile = Join-Path $toolPath "requirements.txt"
            if (Test-Path $reqFile) {
                & $python.Source -m pip install -r $reqFile --quiet 2>&1 | Out-Null
            }
        }
        
        # Cleanup
        Remove-Item $downloadPath -Force -ErrorAction SilentlyContinue
        Remove-Item $extractPath -Recurse -Force -ErrorAction SilentlyContinue
        
        Write-SetupLog "Loki installed successfully" -Level SUCCESS
        return $true
        
    } catch {
        Write-SetupLog "Failed to install Loki: $($_.Exception.Message)" -Level ERROR
        return $false
    }
}

function Install-yarGen {
    param([switch]$Force)
    
    $toolPath = Join-Path $ToolsPath "yarGen"
    
    if ((Test-Path (Join-Path $toolPath "yarGen.py")) -and -not $Force) {
        Write-SetupLog "yarGen already installed" -Level INFO
        return $true
    }
    
    Write-SetupLog "Installing yarGen..." -Level INFO
    
    try {
        $zipUrl = "https://github.com/Neo23x0/yarGen/archive/refs/heads/master.zip"
        $downloadPath = Join-Path $env:TEMP "yargen.zip"
        
        Invoke-WebRequest -Uri $zipUrl -OutFile $downloadPath
        
        $extractPath = Join-Path $env:TEMP "yargen-extract"
        if (Test-Path $extractPath) { Remove-Item $extractPath -Recurse -Force }
        Expand-Archive -Path $downloadPath -DestinationPath $extractPath -Force
        
        if (Test-Path $toolPath) { Remove-Item $toolPath -Recurse -Force }
        Move-Item -Path (Join-Path $extractPath "yarGen-master") -Destination $toolPath -Force
        
        # Cleanup
        Remove-Item $downloadPath -Force -ErrorAction SilentlyContinue
        Remove-Item $extractPath -Recurse -Force -ErrorAction SilentlyContinue
        
        Write-SetupLog "yarGen installed successfully" -Level SUCCESS
        return $true
        
    } catch {
        Write-SetupLog "Failed to install yarGen: $($_.Exception.Message)" -Level ERROR
        return $false
    }
}

function Install-PythonTool {
    param(
        [string]$ToolName,
        [switch]$Force
    )
    
    $tool = $Script:ToolDefinitions[$ToolName]
    
    $python = Get-Command python -ErrorAction SilentlyContinue
    if (-not $python) {
        Write-SetupLog "Python not found - $($tool.Name) requires Python" -Level ERROR
        return $false
    }
    
    Write-SetupLog "Installing $($tool.Name) via pip..." -Level INFO
    
    try {
        & $python.Source -m pip install $tool.PipPackage --quiet 2>&1 | Out-Null
        Write-SetupLog "$($tool.Name) installed successfully" -Level SUCCESS
        return $true
    } catch {
        Write-SetupLog "Failed to install $($tool.Name): $($_.Exception.Message)" -Level ERROR
        return $false
    }
}

function Install-YARARules {
    Write-SetupLog "Downloading YARA rules..." -Level INFO
    
    $rulesFolder = Join-Path $ToolsPath "YARA\rules"
    if (-not (Test-Path $rulesFolder)) {
        New-Item -ItemType Directory -Path $rulesFolder -Force | Out-Null
    }
    
    try {
        # Download signature-base rules
        $zipUrl = "https://github.com/Neo23x0/signature-base/archive/refs/heads/master.zip"
        $zipFile = Join-Path $env:TEMP "signature-base.zip"
        
        Invoke-WebRequest -Uri $zipUrl -OutFile $zipFile
        Expand-Archive -Path $zipFile -DestinationPath $rulesFolder -Force
        Remove-Item $zipFile -Force -ErrorAction SilentlyContinue
        
        Write-SetupLog "YARA rules downloaded" -Level SUCCESS
    } catch {
        Write-SetupLog "Failed to download YARA rules: $($_.Exception.Message)" -Level WARN
    }
}

function Install-SigmaRules {
    Write-SetupLog "Downloading Sigma rules..." -Level INFO
    
    $rulesFolder = Join-Path $ToolsPath "Sigma\rules"
    if (-not (Test-Path $rulesFolder)) {
        New-Item -ItemType Directory -Path $rulesFolder -Force | Out-Null
    }
    
    try {
        $zipUrl = "https://github.com/SigmaHQ/sigma/archive/refs/heads/master.zip"
        $zipFile = Join-Path $env:TEMP "sigma-rules.zip"
        
        Invoke-WebRequest -Uri $zipUrl -OutFile $zipFile
        Expand-Archive -Path $zipFile -DestinationPath $rulesFolder -Force
        Remove-Item $zipFile -Force -ErrorAction SilentlyContinue
        
        Write-SetupLog "Sigma rules downloaded" -Level SUCCESS
    } catch {
        Write-SetupLog "Failed to download Sigma rules: $($_.Exception.Message)" -Level WARN
    }
}

function Install-Tool {
    param(
        [string]$ToolName,
        [switch]$Force
    )
    $tool = $Script:ToolDefinitions[$ToolName]
    if (-not $tool) { return $false }
    
    # Skip Linux-only tools on Windows
    if ($tool.LinuxOnly -and $env:OS -eq "Windows_NT") {
        Write-SetupLog "Skipping $($tool.Name) (Linux only)" -Level INFO
        return $true
    }
    
    # Skip manual download tools
    if ($tool.ManualDownload) {
        Write-SetupLog "$($tool.Name) requires manual download" -Level WARN
        Write-SetupLog "  Download from: $($tool.ManualURL)" -Level INFO
        if ($tool.Note) {
            Write-SetupLog "  Note: $($tool.Note)" -Level INFO
        }
        Write-SetupLog "  Install to: Tools\$($tool.Subfolder)\" -Level INFO
        return $false
    }
    
    # Route to custom installers
    switch ($tool.CustomInstall) {
        "EZTools" { return Install-EZTools -Force:$Force }
        "Volatility3" { return Install-Volatility3 -Force:$Force }
        "Loki" { return Install-Loki -Force:$Force }
        "yarGen" { return Install-yarGen -Force:$Force }
    }
    
    # Standard installers
    if ($tool.PythonRequired -and $tool.PipPackage) { 
        return Install-PythonTool -ToolName $ToolName -Force:$Force 
    }
    if ($tool.GitHubRepo) { 
        return Install-ToolFromGitHub -ToolName $ToolName -Force:$Force 
    }
    if ($tool.DownloadURL) { 
        return Install-ToolFromURL -ToolName $ToolName -Force:$Force 
    }
    
    return $false
}
#endregion

#region Update Functions
function Update-AllTools {
    Write-Host ""
    Write-SetupLog "Checking for updates..." -Level INFO
    Write-Host ""
    
    $updates = @()
    foreach ($toolName in $Script:ToolDefinitions.Keys) {
        $tool = $Script:ToolDefinitions[$toolName]
        if (-not $tool.ManualDownload -and (Test-ToolInstalled -ToolName $toolName)) {
            # For simplicity, offer to reinstall all installed tools
            $updates += $toolName
        }
    }
    
    if ($updates.Count -eq 0) {
        Write-SetupLog "No installed tools found to update" -Level INFO
        return
    }
    
    Write-Host "  Installed tools that can be updated:" -ForegroundColor Yellow
    foreach ($update in $updates) {
        $tool = $Script:ToolDefinitions[$update]
        Write-Host "    - $($tool.Name)" -ForegroundColor White
    }
    Write-Host ""
    
    $confirm = Read-Host "  Reinstall/update all? (Y/N)"
    if ($confirm -eq 'Y') {
        foreach ($update in $updates) {
            Install-Tool -ToolName $update -Force
        }
    }
}
#endregion

#region Menu System
function Show-MainMenu {
    while ($true) {
        Show-Banner
        Write-Host "  MAIN MENU" -ForegroundColor Cyan
        Write-Host "  ----------------------------------------" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "  [1] Check Tool Status"
        Write-Host "  [2] Install Required Tools"
        Write-Host "  [3] Install All Tools"
        Write-Host "  [4] Install Individual Tool"
        Write-Host "  [5] Update Tools"
        Write-Host "  [6] Download YARA Rules"
        Write-Host "  [7] Download Sigma Rules"
        Write-Host "  [8] Reinstall Tool (Force)"
        Write-Host ""
        Write-Host "  [M] Show Manual Download Instructions"
        Write-Host "  [Q] Quit"
        Write-Host ""
        
        $choice = Read-Host "  Select option"
        
        switch ($choice.ToUpper()) {
            "1" {
                Show-Banner
                Show-AllToolStatus
                Read-Host "  Press Enter to continue"
            }
            "2" {
                Show-Banner
                Write-Host ""
                Initialize-ToolsDirectory
                foreach ($toolName in $Script:ToolDefinitions.Keys) {
                    $tool = $Script:ToolDefinitions[$toolName]
                    if ($tool.Required) { 
                        Install-Tool -ToolName $toolName 
                    }
                }
                Write-Host ""
                Read-Host "  Press Enter to continue"
            }
            "3" {
                Show-Banner
                Write-Host ""
                Initialize-ToolsDirectory
                foreach ($toolName in $Script:ToolDefinitions.Keys) {
                    Install-Tool -ToolName $toolName
                }
                Install-YARARules
                Install-SigmaRules
                Write-Host ""
                Read-Host "  Press Enter to continue"
            }
            "4" {
                Show-Banner
                Write-Host ""
                Write-Host "  Available Tools:" -ForegroundColor Cyan
                $toolList = @($Script:ToolDefinitions.Keys)
                for ($i = 0; $i -lt $toolList.Count; $i++) {
                    $tool = $Script:ToolDefinitions[$toolList[$i]]
                    $installed = if (Test-ToolInstalled -ToolName $toolList[$i]) { "[OK]" } else { "[--]" }
                    $color = if (Test-ToolInstalled -ToolName $toolList[$i]) { "Green" } else { "Yellow" }
                    $manual = if ($tool.ManualDownload) { " (manual)" } else { "" }
                    Write-Host "  [$($i+1)] " -NoNewline
                    Write-Host "$installed " -NoNewline -ForegroundColor $color
                    Write-Host "$($tool.Name)$manual"
                }
                Write-Host ""
                $selection = Read-Host "  Enter number (or Q to cancel)"
                if ($selection -ne 'Q') {
                    $toolIndex = [int]$selection - 1
                    if ($toolIndex -ge 0 -and $toolIndex -lt $toolList.Count) {
                        Initialize-ToolsDirectory
                        Install-Tool -ToolName $toolList[$toolIndex]
                    }
                }
                Write-Host ""
                Read-Host "  Press Enter to continue"
            }
            "5" {
                Show-Banner
                Update-AllTools
                Read-Host "  Press Enter to continue"
            }
            "6" {
                Show-Banner
                Initialize-ToolsDirectory
                Install-YARARules
                Read-Host "  Press Enter to continue"
            }
            "7" {
                Show-Banner
                Initialize-ToolsDirectory
                Install-SigmaRules
                Read-Host "  Press Enter to continue"
            }
            "8" {
                Show-Banner
                Write-Host ""
                Write-Host "  Reinstall Tool (Force):" -ForegroundColor Cyan
                $toolList = @($Script:ToolDefinitions.Keys)
                for ($i = 0; $i -lt $toolList.Count; $i++) {
                    $tool = $Script:ToolDefinitions[$toolList[$i]]
                    Write-Host "  [$($i+1)] $($tool.Name)"
                }
                Write-Host ""
                $selection = Read-Host "  Enter number (or Q to cancel)"
                if ($selection -ne 'Q') {
                    $toolIndex = [int]$selection - 1
                    if ($toolIndex -ge 0 -and $toolIndex -lt $toolList.Count) {
                        Initialize-ToolsDirectory
                        Install-Tool -ToolName $toolList[$toolIndex] -Force
                    }
                }
                Write-Host ""
                Read-Host "  Press Enter to continue"
            }
            "M" {
                Show-Banner
                Write-Host ""
                Write-Host "  MANUAL DOWNLOAD INSTRUCTIONS" -ForegroundColor Cyan
                Write-Host "  ============================================================" -ForegroundColor Cyan
                Write-Host ""
                
                foreach ($toolName in $Script:ToolDefinitions.Keys) {
                    $tool = $Script:ToolDefinitions[$toolName]
                    if ($tool.ManualDownload) {
                        Write-Host "  $($tool.Name)" -ForegroundColor Yellow
                        Write-Host "    URL: $($tool.ManualURL)" -ForegroundColor White
                        Write-Host "    Install to: Tools\$($tool.Subfolder)\" -ForegroundColor Gray
                        Write-Host "    Expected file: $($tool.Executable)" -ForegroundColor Gray
                        if ($tool.Note) {
                            Write-Host "    Note: $($tool.Note)" -ForegroundColor Cyan
                        }
                        Write-Host ""
                    }
                }
                
                Read-Host "  Press Enter to continue"
            }
            "Q" { return }
        }
    }
}

function Install-AllRequired {
    Initialize-ToolsDirectory
    foreach ($toolName in $Script:ToolDefinitions.Keys) {
        $tool = $Script:ToolDefinitions[$toolName]
        if ($tool.Required -or $Force) { 
            Install-Tool -ToolName $toolName -Force:$Force 
        }
    }
    if ($Force) {
        Install-YARARules
        Install-SigmaRules
    }
}
#endregion

#region Main Entry Point
if ($Install) {
    Show-Banner
    Install-AllRequired
} elseif ($CheckStatus) {
    Show-Banner
    Show-AllToolStatus
} elseif ($Update) {
    Show-Banner
    Update-AllTools
} else {
    Show-MainMenu
}
#endregion