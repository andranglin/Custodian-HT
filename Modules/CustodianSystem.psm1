#Requires -Version 5.1
<#
.SYNOPSIS
    Custodian-HT System Artifacts Collection Module
.DESCRIPTION
    System configuration and persistence mechanism collection including Autoruns,
    scheduled tasks, services, drivers, certificates, and registry persistence.
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

#region Autoruns
function Get-CustodianAutoruns {
    <#
    .SYNOPSIS
        Collect autorun entries from registry and startup folders
    #>
    [CmdletBinding()]
    param(
        [string]$ComputerName = "localhost",
        [PSCredential]$Credential,
        [string]$OutputPath = (Get-CustodianPath -PathType "Collection")
    )
    
    $scriptBlock = {
        $autoruns = @()
        
        # Registry Run keys
        $runKeys = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
        )
        
        foreach ($key in $runKeys) {
            if (Test-Path $key) {
                $items = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
                $items.PSObject.Properties | Where-Object {$_.Name -notlike 'PS*'} | ForEach-Object {
                    $autoruns += [PSCustomObject]@{
                        Location = $key
                        Name = $_.Name
                        Command = $_.Value
                        Type = "RegistryRun"
                        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                    }
                }
            }
        }
        
        # Startup folders
        $startupFolders = @(
            "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
            "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
        )
        
        foreach ($folder in $startupFolders) {
            if (Test-Path $folder) {
                Get-ChildItem $folder -File -ErrorAction SilentlyContinue | ForEach-Object {
                    $autoruns += [PSCustomObject]@{
                        Location = $folder
                        Name = $_.Name
                        Command = $_.FullName
                        Type = "StartupFolder"
                        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                    }
                }
            }
        }
        
        return $autoruns
    }
    
    try {
        Write-CustodianLog "Collecting autoruns from $ComputerName..." -Level "INFO"
        
        if ($ComputerName -eq "localhost") {
            $data = Invoke-Command -ScriptBlock $scriptBlock
        } else {
            $data = Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock $scriptBlock
        }
        
        if ($data) {
            Export-CustodianData -Data $data -FileName "Autoruns.csv" -OutputPath $OutputPath -Format CSV
            Write-CustodianLog "Autoruns collected: $($data.Count) entries" -Level "SUCCESS"
        }
        
        return $data
        
    } catch {
        Write-CustodianLog "Failed to collect autoruns: $_" -Level "ERROR"
        return $null
    }
}
#endregion

#region Scheduled Tasks
function Get-CustodianScheduledTasks {
    <#
    .SYNOPSIS
        Collect scheduled tasks
    #>
    [CmdletBinding()]
    param(
        [string]$ComputerName = "localhost",
        [PSCredential]$Credential,
        [string]$OutputPath = (Get-CustodianPath -PathType "Collection"),
        [switch]$IncludeDisabled
    )
    
    $scriptBlock = {
        param($IncludeDisabled)
        
        $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue
        
        if (-not $IncludeDisabled) {
            $tasks = $tasks | Where-Object {$_.State -ne 'Disabled'}
        }
        
        $tasks | Select-Object TaskName, TaskPath, State, Author, Description,
            @{Name="Actions"; Expression={($_.Actions | ForEach-Object {"$($_.Execute) $($_.Arguments)"}) -join "; "}},
            @{Name="Triggers"; Expression={($_.Triggers | ForEach-Object {$_.StartBoundary}) -join "; "}},
            @{Name="Principal"; Expression={$_.Principal.UserId}},
            @{Name="RunLevel"; Expression={$_.Principal.RunLevel}},
            @{Name="LastRunTime"; Expression={$_.LastRunTime}},
            @{Name="NextRunTime"; Expression={$_.NextRunTime}},
            @{Name="Timestamp"; Expression={Get-Date -Format "yyyy-MM-dd HH:mm:ss"}}
    }
    
    try {
        Write-CustodianLog "Collecting scheduled tasks from $ComputerName..." -Level "INFO"
        
        if ($ComputerName -eq "localhost") {
            $data = Invoke-Command -ScriptBlock $scriptBlock -ArgumentList $IncludeDisabled
        } else {
            $data = Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock $scriptBlock -ArgumentList $IncludeDisabled
        }
        
        Export-CustodianData -Data $data -FileName "ScheduledTasks.csv" -OutputPath $OutputPath -Format CSV
        Write-CustodianLog "Scheduled tasks collected: $($data.Count) tasks" -Level "SUCCESS"
        return $data
        
    } catch {
        Write-CustodianLog "Failed to collect scheduled tasks: $_" -Level "ERROR"
        return $null
    }
}
#endregion

#region Services
function Get-CustodianServices {
    <#
    .SYNOPSIS
        Collect Windows services
    #>
    [CmdletBinding()]
    param(
        [string]$ComputerName = "localhost",
        [PSCredential]$Credential,
        [string]$OutputPath = (Get-CustodianPath -PathType "Collection")
    )
    
    $scriptBlock = {
        Get-WmiObject Win32_Service -ErrorAction SilentlyContinue |
            Select-Object Name, DisplayName, State, Status, StartMode, PathName,
                ServiceType, StartName, ProcessId, Description, DesktopInteract,
                ErrorControl, @{Name="Timestamp"; Expression={Get-Date -Format "yyyy-MM-dd HH:mm:ss"}}
    }
    
    try {
        Write-CustodianLog "Collecting services from $ComputerName..." -Level "INFO"
        
        if ($ComputerName -eq "localhost") {
            $data = Invoke-Command -ScriptBlock $scriptBlock
        } else {
            $data = Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock $scriptBlock
        }
        
        Export-CustodianData -Data $data -FileName "Services.csv" -OutputPath $OutputPath -Format CSV
        
        # Identify suspicious services (non-standard paths)
        $suspicious = $data | Where-Object {
            $_.PathName -notmatch '(?i)^[a-z]:\\windows\\' -and
            $_.PathName -notmatch '(?i)^[a-z]:\\program files' -and
            $_.PathName -ne $null
        }
        
        if ($suspicious) {
            Export-CustodianData -Data $suspicious -FileName "Services_NonStandard.csv" -OutputPath $OutputPath -Format CSV
        }
        
        Write-CustodianLog "Services collected: $($data.Count) total, $($suspicious.Count) non-standard" -Level "SUCCESS"
        return $data
        
    } catch {
        Write-CustodianLog "Failed to collect services: $_" -Level "ERROR"
        return $null
    }
}
#endregion

#region Drivers
function Get-CustodianDrivers {
    <#
    .SYNOPSIS
        Collect system drivers
    #>
    [CmdletBinding()]
    param(
        [string]$ComputerName = "localhost",
        [PSCredential]$Credential,
        [string]$OutputPath = (Get-CustodianPath -PathType "Collection")
    )
    
    $scriptBlock = {
        Get-WmiObject Win32_SystemDriver -ErrorAction SilentlyContinue |
            Select-Object Name, DisplayName, State, Status, PathName, StartMode,
                ServiceType, Description, @{Name="Timestamp"; Expression={Get-Date -Format "yyyy-MM-dd HH:mm:ss"}}
    }
    
    try {
        Write-CustodianLog "Collecting drivers from $ComputerName..." -Level "INFO"
        
        if ($ComputerName -eq "localhost") {
            $data = Invoke-Command -ScriptBlock $scriptBlock
        } else {
            $data = Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock $scriptBlock
        }
        
        Export-CustodianData -Data $data -FileName "Drivers.csv" -OutputPath $OutputPath -Format CSV
        Write-CustodianLog "Drivers collected: $($data.Count) drivers" -Level "SUCCESS"
        return $data
        
    } catch {
        Write-CustodianLog "Failed to collect drivers: $_" -Level "ERROR"
        return $null
    }
}
#endregion

#region Persistence
function Get-CustodianPersistence {
    <#
    .SYNOPSIS
        Comprehensive persistence mechanism detection
    #>
    [CmdletBinding()]
    param(
        [string]$ComputerName = "localhost",
        [PSCredential]$Credential,
        [string]$OutputPath = (Get-CustodianPath -PathType "Collection")
    )
    
    $scriptBlock = {
        $persistence = @()
        
        # WMI Event Subscriptions
        $wmiFilters = Get-WmiObject -Namespace root\subscription -Class __EventFilter -ErrorAction SilentlyContinue |
            Select-Object Name, Query, QueryLanguage, __PATH
        
        foreach ($filter in $wmiFilters) {
            $persistence += [PSCustomObject]@{
                Type = "WMI_EventFilter"
                Name = $filter.Name
                Details = $filter.Query
                Path = $filter.__PATH
                Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            }
        }
        
        $wmiConsumers = Get-WmiObject -Namespace root\subscription -Class __EventConsumer -ErrorAction SilentlyContinue |
            Select-Object Name, __CLASS, __PATH
        
        foreach ($consumer in $wmiConsumers) {
            $persistence += [PSCustomObject]@{
                Type = "WMI_EventConsumer"
                Name = $consumer.Name
                Details = $consumer.__CLASS
                Path = $consumer.__PATH
                Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            }
        }
        
        # Winlogon keys
        $winlogonPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
        if (Test-Path $winlogonPath) {
            $winlogon = Get-ItemProperty -Path $winlogonPath -ErrorAction SilentlyContinue
            
            @('Userinit', 'Shell', 'Notify', 'TaskMan') | ForEach-Object {
                if ($winlogon.$_) {
                    $persistence += [PSCustomObject]@{
                        Type = "Winlogon"
                        Name = $_
                        Details = $winlogon.$_
                        Path = $winlogonPath
                        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                    }
                }
            }
        }
        
        # AppInit_DLLs
        $appInitPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"
        if (Test-Path $appInitPath) {
            $appInit = Get-ItemProperty -Path $appInitPath -Name AppInit_DLLs -ErrorAction SilentlyContinue
            if ($appInit.AppInit_DLLs) {
                $persistence += [PSCustomObject]@{
                    Type = "AppInit_DLLs"
                    Name = "AppInit_DLLs"
                    Details = $appInit.AppInit_DLLs
                    Path = $appInitPath
                    Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                }
            }
        }
        
        return $persistence
    }
    
    try {
        Write-CustodianLog "Detecting persistence mechanisms on $ComputerName..." -Level "INFO"
        
        if ($ComputerName -eq "localhost") {
            $data = Invoke-Command -ScriptBlock $scriptBlock
        } else {
            $data = Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock $scriptBlock
        }
        
        if ($data) {
            Export-CustodianData -Data $data -FileName "PersistenceMechanisms.csv" -OutputPath $OutputPath -Format CSV
            Write-CustodianLog "Persistence mechanisms detected: $($data.Count) items" -Level "SUCCESS"
        }
        
        return $data
        
    } catch {
        Write-CustodianLog "Failed to detect persistence: $_" -Level "ERROR"
        return $null
    }
}
#endregion

#region Installed Software
function Get-CustodianInstalledSoftware {
    <#
    .SYNOPSIS
        Collect installed software from registry
    #>
    [CmdletBinding()]
    param(
        [string]$ComputerName = "localhost",
        [PSCredential]$Credential,
        [string]$OutputPath = (Get-CustodianPath -PathType "Collection")
    )
    
    $scriptBlock = {
        $software = @()
        
        $uninstallPaths = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
        )
        
        foreach ($path in $uninstallPaths) {
            $software += Get-ItemProperty -Path $path -ErrorAction SilentlyContinue |
                Where-Object {$_.DisplayName} |
                Select-Object DisplayName, DisplayVersion, Publisher, InstallDate,
                    InstallLocation, UninstallString, @{Name="RegistryPath"; Expression={$_.PSPath}},
                    @{Name="Timestamp"; Expression={Get-Date -Format "yyyy-MM-dd HH:mm:ss"}}
        }
        
        return $software | Sort-Object DisplayName -Unique
    }
    
    try {
        Write-CustodianLog "Collecting installed software from $ComputerName..." -Level "INFO"
        
        if ($ComputerName -eq "localhost") {
            $data = Invoke-Command -ScriptBlock $scriptBlock
        } else {
            $data = Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock $scriptBlock
        }
        
        Export-CustodianData -Data $data -FileName "InstalledSoftware.csv" -OutputPath $OutputPath -Format CSV
        Write-CustodianLog "Installed software collected: $($data.Count) applications" -Level "SUCCESS"
        return $data
        
    } catch {
        Write-CustodianLog "Failed to collect installed software: $_" -Level "ERROR"
        return $null
    }
}
#endregion

#region Certificates
function Get-CustodianCertificates {
    <#
    .SYNOPSIS
        Collect certificates from certificate stores
    #>
    [CmdletBinding()]
    param(
        [string]$ComputerName = "localhost",
        [PSCredential]$Credential,
        [string]$OutputPath = (Get-CustodianPath -PathType "Collection")
    )
    
    $scriptBlock = {
        $certs = @()
        
        $stores = @("My", "Root", "CA", "TrustedPublisher", "AuthRoot")
        
        foreach ($store in $stores) {
            try {
                Get-ChildItem "Cert:\LocalMachine\$store" -ErrorAction SilentlyContinue | ForEach-Object {
                    $certs += [PSCustomObject]@{
                        Store = $store
                        Subject = $_.Subject
                        Issuer = $_.Issuer
                        Thumbprint = $_.Thumbprint
                        NotBefore = $_.NotBefore
                        NotAfter = $_.NotAfter
                        HasPrivateKey = $_.HasPrivateKey
                        SerialNumber = $_.SerialNumber
                        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                    }
                }
            } catch {}
        }
        
        return $certs
    }
    
    try {
        Write-CustodianLog "Collecting certificates from $ComputerName..." -Level "INFO"
        
        if ($ComputerName -eq "localhost") {
            $data = Invoke-Command -ScriptBlock $scriptBlock
        } else {
            $data = Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock $scriptBlock
        }
        
        Export-CustodianData -Data $data -FileName "Certificates.csv" -OutputPath $OutputPath -Format CSV
        Write-CustodianLog "Certificates collected: $($data.Count) certificates" -Level "SUCCESS"
        return $data
        
    } catch {
        Write-CustodianLog "Failed to collect certificates: $_" -Level "ERROR"
        return $null
    }
}
#endregion

#region Processes
function Get-CustodianProcesses {
    <#
    .SYNOPSIS
        Collect running processes with detailed information
    #>
    [CmdletBinding()]
    param(
        [string]$ComputerName = "localhost",
        [PSCredential]$Credential,
        [string]$OutputPath = (Get-CustodianPath -PathType "Collection")
    )
    
    $scriptBlock = {
        Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | ForEach-Object {
            $owner = Invoke-CimMethod -InputObject $_ -MethodName GetOwner -ErrorAction SilentlyContinue
            
            [PSCustomObject]@{
                ProcessName = $_.Name
                PID = $_.ProcessId
                ParentPID = $_.ParentProcessId
                ExecutablePath = $_.ExecutablePath
                CommandLine = $_.CommandLine
                Owner = if ($owner.User) { "$($owner.Domain)\$($owner.User)" } else { "N/A" }
                CreationDate = $_.CreationDate
                ThreadCount = $_.ThreadCount
                HandleCount = $_.HandleCount
                WorkingSetMB = [math]::Round($_.WorkingSetSize / 1MB, 2)
                Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            }
        }
    }
    
    try {
        Write-CustodianLog "Collecting processes from $ComputerName..." -Level "INFO"
        
        if ($ComputerName -eq "localhost") {
            $data = Invoke-Command -ScriptBlock $scriptBlock
        } else {
            $data = Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock $scriptBlock
        }
        
        Export-CustodianData -Data $data -FileName "Processes.csv" -OutputPath $OutputPath -Format CSV
        
        # Identify suspicious processes (non-standard paths)
        $suspicious = $data | Where-Object {
            $_.ExecutablePath -and
            $_.ExecutablePath -notmatch '(?i)^[a-z]:\\windows\\' -and
            $_.ExecutablePath -notmatch '(?i)^[a-z]:\\program files'
        }
        
        if ($suspicious) {
            Export-CustodianData -Data $suspicious -FileName "Processes_NonStandard.csv" -OutputPath $OutputPath -Format CSV
        }
        
        Write-CustodianLog "Processes collected: $($data.Count) total, $($suspicious.Count) non-standard" -Level "SUCCESS"
        return $data
        
    } catch {
        Write-CustodianLog "Failed to collect processes: $_" -Level "ERROR"
        return $null
    }
}
#endregion

#region Export Module Members
Export-ModuleMember -Function `
    Get-CustodianAutoruns,
    Get-CustodianScheduledTasks,
    Get-CustodianServices,
    Get-CustodianDrivers,
    Get-CustodianPersistence,
    Get-CustodianInstalledSoftware,
    Get-CustodianCertificates,
    Get-CustodianProcesses
#endregion