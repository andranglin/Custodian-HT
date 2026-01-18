#Requires -Version 5.1
<#
.SYNOPSIS
    Custodian-HT Core Collection Module
.DESCRIPTION
    Core artifact collection including USB forensics, memory acquisition, disk analysis,
    file hashing, prefetch files, and registry forensics.
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

function Export-CustodianData {
    param(
        [AllowNull()][AllowEmptyCollection()]$Data,
        [string]$OutputPath,
        [string]$FileName,
        [ValidateSet("CSV","JSON")][string]$Format = "CSV",
        [switch]$Append
    )
    
    if ($null -eq $Data -or @($Data).Count -eq 0) {
        Write-CustodianLog "No data for $FileName" -Level "WARN"
        return $null
    }
    
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }
    
    $filePath = Join-Path $OutputPath $FileName
    
    try {
        if ($Format -eq "JSON") {
            $Data | ConvertTo-Json -Depth 5 | Out-File $filePath -Encoding UTF8 -Force
        } else {
            if ($Append -and (Test-Path $filePath)) {
                @($Data) | Export-Csv -Path $filePath -NoTypeInformation -Append
            } else {
                @($Data) | Export-Csv -Path $filePath -NoTypeInformation -Force
            }
        }
        Write-CustodianLog "Exported: $FileName ($(@($Data).Count) records)" -Level "SUCCESS"
        return $filePath
    } catch {
        Write-CustodianLog "Failed to export $FileName : $_" -Level "ERROR"
        return $null
    }
}

#endregion

#region USB Forensics
function Get-CustodianUSBHistory {
    <#
    .SYNOPSIS
        Collect USB device connection history from registry
    #>
    [CmdletBinding()]
    param(
        [string]$ComputerName = "localhost",
        [PSCredential]$Credential,
        [string]$OutputPath = (Get-CustodianPath -PathType "Collection")
    )
    
    $scriptBlock = {
        $usbDevices = @()
        
        # USBSTOR - USB Storage devices
        $usbStorPath = "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR"
        if (Test-Path $usbStorPath) {
            Get-ChildItem $usbStorPath -ErrorAction SilentlyContinue | ForEach-Object {
                $deviceClass = $_
                Get-ChildItem $_.PSPath -ErrorAction SilentlyContinue | ForEach-Object {
                    $device = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
                    $usbDevices += [PSCustomObject]@{
                        Type = "USBSTOR"
                        DeviceClass = $deviceClass.PSChildName
                        SerialNumber = $_.PSChildName
                        FriendlyName = $device.FriendlyName
                        HardwareID = ($device.HardwareID -join "; ")
                        Manufacturer = $device.Mfg
                        Service = $device.Service
                        ContainerID = $device.ContainerID
                        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                    }
                }
            }
        }
        
        # USB - All USB devices
        $usbPath = "HKLM:\SYSTEM\CurrentControlSet\Enum\USB"
        if (Test-Path $usbPath) {
            Get-ChildItem $usbPath -ErrorAction SilentlyContinue | ForEach-Object {
                $vid = $_.PSChildName
                Get-ChildItem $_.PSPath -ErrorAction SilentlyContinue | ForEach-Object {
                    $device = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
                    if ($device.FriendlyName -or $device.DeviceDesc) {
                        $usbDevices += [PSCustomObject]@{
                            Type = "USB"
                            DeviceClass = $vid
                            SerialNumber = $_.PSChildName
                            FriendlyName = $device.FriendlyName
                            DeviceDesc = $device.DeviceDesc
                            Manufacturer = $device.Mfg
                            Service = $device.Service
                            ContainerID = $device.ContainerID
                            Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                        }
                    }
                }
            }
        }
        
        return $usbDevices
    }
    
    try {
        Write-CustodianLog "Collecting USB history from $ComputerName..." -Level "INFO"
        
        if ($ComputerName -eq "localhost") {
            $data = Invoke-Command -ScriptBlock $scriptBlock
        } else {
            $data = Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock $scriptBlock
        }
        
        Export-CustodianData -Data $data -FileName "USBHistory.csv" -OutputPath $OutputPath -Format CSV
        Write-CustodianLog "USB history collected: $($data.Count) devices" -Level "SUCCESS"
        return $data
        
    } catch {
        Write-CustodianLog "Failed to collect USB history: $_" -Level "ERROR"
        return $null
    }
}
#endregion

#region Memory Acquisition
function Get-CustodianMemory {
    <#
    .SYNOPSIS
        Acquire memory dump using DumpIt or MagnetRAM
    .PARAMETER Tool
        Memory acquisition tool: DumpIt, MagnetRAM, WinPMEM
    .PARAMETER OutputPath
        Path to save memory dump
    #>
    [CmdletBinding()]
    param(
        [ValidateSet("DumpIt","MagnetRAM","WinPMEM")][string]$Tool = "DumpIt",
        [string]$OutputPath = (Get-CustodianPath -PathType "Memory")
    )
    
    try {
        Write-CustodianLog "Starting memory acquisition using $Tool..." -Level "INFO"
        
        $toolPath = Get-CustodianToolPath -ToolName $Tool -Subfolder "DumpIt"
        
        if (-not $toolPath) {
            Write-CustodianLog "$Tool not found in Tools folder. Please download manually." -Level "ERROR"
            Write-Host ""
            Write-Host "Memory acquisition tools require manual download:" -ForegroundColor Yellow
            Write-Host "  - DumpIt: https://www.magnetforensics.com/resources/magnet-dumpit-for-windows/" -ForegroundColor White
            Write-Host "  - MagnetRAM: https://www.magnetforensics.com/resources/magnet-ram-capture/" -ForegroundColor White
            Write-Host "  - WinPMEM: https://github.com/Velocidex/WinPmem/releases" -ForegroundColor White
            return $null
        }
        
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $dumpFile = Join-Path $OutputPath "MemoryDump_${env:COMPUTERNAME}_$timestamp.dmp"
        
        switch ($Tool) {
            "DumpIt" {
                & $toolPath /OUTPUT $dumpFile /QUIET
            }
            "MagnetRAM" {
                & $toolPath /go /accepteula /o $dumpFile
            }
            "WinPMEM" {
                & $toolPath $dumpFile
            }
        }
        
        if (Test-Path $dumpFile) {
            $fileInfo = Get-Item $dumpFile
            $hash = (Get-FileHash $dumpFile -Algorithm SHA256).Hash
            
            $result = [PSCustomObject]@{
                Tool = $Tool
                DumpFile = $dumpFile
                SizeGB = [math]::Round($fileInfo.Length / 1GB, 2)
                SHA256 = $hash
                ComputerName = $env:COMPUTERNAME
                Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            }
            
            # Save metadata
            $result | Export-Csv -Path (Join-Path $OutputPath "MemoryDump_Metadata.csv") -NoTypeInformation -Append
            
            Write-CustodianLog "Memory dump complete: $dumpFile ($($result.SizeGB) GB)" -Level "SUCCESS"
            return $result
        } else {
            Write-CustodianLog "Memory dump file not created" -Level "ERROR"
            return $null
        }
        
    } catch {
        Write-CustodianLog "Memory acquisition failed: $_" -Level "ERROR"
        return $null
    }
}
#endregion

#region File Hashing
function Get-CustodianFileHashes {
    <#
    .SYNOPSIS
        Calculate hashes for files in a directory
    .PARAMETER Path
        Directory path to scan
    .PARAMETER Algorithm
        Hash algorithm: MD5, SHA1, SHA256 (default: SHA256)
    .PARAMETER Recurse
        Scan subdirectories
    .PARAMETER Extensions
        File extensions to include (e.g., ".exe", ".dll")
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [string]$OutputPath = (Get-CustodianPath -PathType "Collection"),
        [ValidateSet("MD5","SHA1","SHA256")][string]$Algorithm = "SHA256",
        [switch]$Recurse,
        [string[]]$Extensions
    )
    
    try {
        Write-CustodianLog "Calculating file hashes in $Path..." -Level "INFO"
        
        $params = @{
            Path = $Path
            File = $true
            ErrorAction = "SilentlyContinue"
        }
        
        if ($Recurse) { $params.Recurse = $true }
        
        $files = Get-ChildItem @params
        
        if ($Extensions) {
            $files = $files | Where-Object { $Extensions -contains $_.Extension }
        }
        
        $results = @()
        $total = $files.Count
        $current = 0
        
        foreach ($file in $files) {
            $current++
            if ($current % 100 -eq 0) {
                Write-Host "  Progress: $current / $total" -ForegroundColor Gray
            }
            
            try {
                $hash = Get-FileHash -Path $file.FullName -Algorithm $Algorithm -ErrorAction Stop
                
                $results += [PSCustomObject]@{
                    FileName = $file.Name
                    FullPath = $file.FullName
                    $Algorithm = $hash.Hash
                    SizeBytes = $file.Length
                    Created = $file.CreationTime
                    Modified = $file.LastWriteTime
                    Accessed = $file.LastAccessTime
                    Extension = $file.Extension
                    Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                }
            } catch {
                # Skip files that can't be hashed (locked, etc.)
            }
        }
        
        Export-CustodianData -Data $results -FileName "FileHashes_$Algorithm.csv" -OutputPath $OutputPath -Format CSV
        Write-CustodianLog "File hashes collected: $($results.Count) files" -Level "SUCCESS"
        return $results
        
    } catch {
        Write-CustodianLog "Failed to calculate file hashes: $_" -Level "ERROR"
        return $null
    }
}
#endregion

#region Hash Search
function Search-CustodianFileByHash {
    <#
    .SYNOPSIS
        Search for files matching a specific hash
    .PARAMETER Hash
        Hash value to search for
    .PARAMETER Path
        Starting path for search
    .PARAMETER Algorithm
        Hash algorithm used
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Hash,
        [string]$Path = "C:\",
        [ValidateSet("MD5","SHA1","SHA256")][string]$Algorithm = "SHA256",
        [string]$OutputPath = (Get-CustodianPath -PathType "Collection")
    )
    
    try {
        Write-CustodianLog "Searching for files with hash: $Hash" -Level "INFO"
        
        $matches = @()
        
        Get-ChildItem -Path $Path -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
            try {
                $fileHash = (Get-FileHash -Path $_.FullName -Algorithm $Algorithm -ErrorAction Stop).Hash
                if ($fileHash -eq $Hash) {
                    $matches += [PSCustomObject]@{
                        FileName = $_.Name
                        FullPath = $_.FullName
                        Hash = $fileHash
                        SizeBytes = $_.Length
                        Modified = $_.LastWriteTime
                        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                    }
                    Write-Host "  MATCH: $($_.FullName)" -ForegroundColor Red
                }
            } catch {}
        }
        
        if ($matches) {
            Export-CustodianData -Data $matches -FileName "HashSearch_$Hash.csv" -OutputPath $OutputPath -Format CSV
        }
        
        Write-CustodianLog "Hash search complete: $($matches.Count) matches found" -Level "SUCCESS"
        return $matches
        
    } catch {
        Write-CustodianLog "Hash search failed: $_" -Level "ERROR"
        return $null
    }
}
#endregion

#region Prefetch Files
function Get-CustodianPrefetch {
    <#
    .SYNOPSIS
        Collect Windows Prefetch files metadata
    #>
    [CmdletBinding()]
    param(
        [string]$ComputerName = "localhost",
        [PSCredential]$Credential,
        [string]$OutputPath = (Get-CustodianPath -PathType "Collection")
    )
    
    $scriptBlock = {
        $prefetchPath = "$env:SystemRoot\Prefetch"
        $prefetch = @()
        
        if (Test-Path $prefetchPath) {
            Get-ChildItem -Path $prefetchPath -Filter "*.pf" -ErrorAction SilentlyContinue | ForEach-Object {
                $prefetch += [PSCustomObject]@{
                    FileName = $_.Name
                    ExecutableName = ($_.BaseName -split '-')[0]
                    Hash = ($_.BaseName -split '-')[-1]
                    SizeBytes = $_.Length
                    Created = $_.CreationTime
                    Modified = $_.LastWriteTime
                    Accessed = $_.LastAccessTime
                    FullPath = $_.FullName
                    Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                }
            }
        }
        
        return $prefetch | Sort-Object Modified -Descending
    }
    
    try {
        Write-CustodianLog "Collecting Prefetch files from $ComputerName..." -Level "INFO"
        
        if ($ComputerName -eq "localhost") {
            $data = Invoke-Command -ScriptBlock $scriptBlock
        } else {
            $data = Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock $scriptBlock
        }
        
        Export-CustodianData -Data $data -FileName "PrefetchFiles.csv" -OutputPath $OutputPath -Format CSV
        Write-CustodianLog "Prefetch files collected: $($data.Count) files" -Level "SUCCESS"
        return $data
        
    } catch {
        Write-CustodianLog "Failed to collect Prefetch files: $_" -Level "ERROR"
        return $null
    }
}
#endregion

#region Recent Files
function Get-CustodianRecentFiles {
    <#
    .SYNOPSIS
        Collect recently accessed files from user profiles
    .PARAMETER Hours
        Number of hours to look back (default: 24)
    #>
    [CmdletBinding()]
    param(
        [string]$ComputerName = "localhost",
        [PSCredential]$Credential,
        [string]$OutputPath = (Get-CustodianPath -PathType "Collection"),
        [int]$Hours = 24
    )
    
    $scriptBlock = {
        param($Hours)
        
        $cutoff = (Get-Date).AddHours(-$Hours)
        $recentFiles = @()
        
        # Scan common user directories
        $userPaths = @(
            "$env:USERPROFILE\Desktop",
            "$env:USERPROFILE\Downloads",
            "$env:USERPROFILE\Documents",
            "$env:APPDATA",
            "$env:LOCALAPPDATA\Temp"
        )
        
        foreach ($path in $userPaths) {
            if (Test-Path $path) {
                Get-ChildItem -Path $path -Recurse -File -ErrorAction SilentlyContinue |
                    Where-Object { $_.LastWriteTime -gt $cutoff } |
                    ForEach-Object {
                        $recentFiles += [PSCustomObject]@{
                            FileName = $_.Name
                            FullPath = $_.FullName
                            Extension = $_.Extension
                            SizeBytes = $_.Length
                            Created = $_.CreationTime
                            Modified = $_.LastWriteTime
                            Accessed = $_.LastAccessTime
                            Directory = $_.DirectoryName
                            Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                        }
                    }
            }
        }
        
        return $recentFiles | Sort-Object Modified -Descending
    }
    
    try {
        Write-CustodianLog "Collecting recent files (last $Hours hours) from $ComputerName..." -Level "INFO"
        
        if ($ComputerName -eq "localhost") {
            $data = Invoke-Command -ScriptBlock $scriptBlock -ArgumentList $Hours
        } else {
            $data = Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock $scriptBlock -ArgumentList $Hours
        }
        
        Export-CustodianData -Data $data -FileName "RecentFiles_${Hours}h.csv" -OutputPath $OutputPath -Format CSV
        Write-CustodianLog "Recent files collected: $($data.Count) files" -Level "SUCCESS"
        return $data
        
    } catch {
        Write-CustodianLog "Failed to collect recent files: $_" -Level "ERROR"
        return $null
    }
}
#endregion

#region Temp Directory
function Get-CustodianTempFiles {
    <#
    .SYNOPSIS
        Collect files from temporary directories
    #>
    [CmdletBinding()]
    param(
        [string]$ComputerName = "localhost",
        [PSCredential]$Credential,
        [string]$OutputPath = (Get-CustodianPath -PathType "Collection")
    )
    
    $scriptBlock = {
        $tempFiles = @()
        
        $tempPaths = @(
            "$env:TEMP",
            "$env:TMP",
            "$env:SystemRoot\Temp",
            "$env:LOCALAPPDATA\Temp"
        )
        
        foreach ($path in $tempPaths | Select-Object -Unique) {
            if (Test-Path $path) {
                Get-ChildItem -Path $path -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
                    $tempFiles += [PSCustomObject]@{
                        FileName = $_.Name
                        FullPath = $_.FullName
                        Extension = $_.Extension
                        SizeBytes = $_.Length
                        Created = $_.CreationTime
                        Modified = $_.LastWriteTime
                        TempLocation = $path
                        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                    }
                }
            }
        }
        
        return $tempFiles | Sort-Object Modified -Descending
    }
    
    try {
        Write-CustodianLog "Collecting temp files from $ComputerName..." -Level "INFO"
        
        if ($ComputerName -eq "localhost") {
            $data = Invoke-Command -ScriptBlock $scriptBlock
        } else {
            $data = Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock $scriptBlock
        }
        
        Export-CustodianData -Data $data -FileName "TempFiles.csv" -OutputPath $OutputPath -Format CSV
        Write-CustodianLog "Temp files collected: $($data.Count) files" -Level "SUCCESS"
        return $data
        
    } catch {
        Write-CustodianLog "Failed to collect temp files: $_" -Level "ERROR"
        return $null
    }
}
#endregion

#region System Info
function Get-CustodianSystemInfo {
    <#
    .SYNOPSIS
        Collect comprehensive system information
    #>
    [CmdletBinding()]
    param(
        [string]$ComputerName = "localhost",
        [PSCredential]$Credential,
        [string]$OutputPath = (Get-CustodianPath -PathType "Collection")
    )
    
    $scriptBlock = {
        $os = Get-CimInstance Win32_OperatingSystem
        $cs = Get-CimInstance Win32_ComputerSystem
        $bios = Get-CimInstance Win32_BIOS
        $cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
        
        [PSCustomObject]@{
            ComputerName = $env:COMPUTERNAME
            Domain = $cs.Domain
            Workgroup = $cs.Workgroup
            OSName = $os.Caption
            OSVersion = $os.Version
            OSBuild = $os.BuildNumber
            OSArchitecture = $os.OSArchitecture
            InstallDate = $os.InstallDate
            LastBootTime = $os.LastBootUpTime
            Uptime = (Get-Date) - $os.LastBootUpTime
            Manufacturer = $cs.Manufacturer
            Model = $cs.Model
            SerialNumber = $bios.SerialNumber
            BIOSVersion = $bios.SMBIOSBIOSVersion
            CPUName = $cpu.Name
            CPUCores = $cpu.NumberOfCores
            TotalMemoryGB = [math]::Round($cs.TotalPhysicalMemory / 1GB, 2)
            FreeMemoryGB = [math]::Round($os.FreePhysicalMemory / 1MB, 2)
            SystemDrive = $env:SystemDrive
            WindowsDirectory = $env:SystemRoot
            CurrentUser = "$env:USERDOMAIN\$env:USERNAME"
            TimeZone = (Get-TimeZone).DisplayName
            Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        }
    }
    
    try {
        Write-CustodianLog "Collecting system information from $ComputerName..." -Level "INFO"
        
        if ($ComputerName -eq "localhost") {
            $data = Invoke-Command -ScriptBlock $scriptBlock
        } else {
            $data = Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock $scriptBlock
        }
        
        Export-CustodianData -Data $data -FileName "SystemInfo.json" -OutputPath $OutputPath -Format JSON
        Export-CustodianData -Data $data -FileName "SystemInfo.csv" -OutputPath $OutputPath -Format CSV
        Write-CustodianLog "System information collected" -Level "SUCCESS"
        return $data
        
    } catch {
        Write-CustodianLog "Failed to collect system information: $_" -Level "ERROR"
        return $null
    }
}
#endregion

#region Export Module Members
Export-ModuleMember -Function `
    Get-CustodianUSBHistory,
    Get-CustodianMemory,
    Get-CustodianFileHashes,
    Search-CustodianFileByHash,
    Get-CustodianPrefetch,
    Get-CustodianRecentFiles,
    Get-CustodianTempFiles,
    Get-CustodianSystemInfo
#endregion