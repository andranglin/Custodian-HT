#Requires -Version 5.1
<#
.SYNOPSIS
    Custodian-HT Hunt Playbooks Module
.DESCRIPTION
    Guided threat hunting playbooks for common attack scenarios including ransomware,
    lateral movement, persistence, data exfiltration, and credential access.
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

#region Ransomware Hunt
function Start-RansomwareHunt {
    <#
    .SYNOPSIS
        Execute ransomware detection playbook
    .PARAMETER ComputerName
        Target computer
    .PARAMETER OutputPath
        Path to save results
    #>
    [CmdletBinding()]
    param(
        [string]$ComputerName = "localhost",
        [PSCredential]$Credential,
        [string]$OutputPath = (Get-CustodianPath -PathType "Collection")
    )
    
    try {
        Write-CustodianLog "=== Starting Ransomware Hunt Playbook ===" -Level "INFO"
        
        $huntPath = Join-Path $OutputPath "RansomwareHunt_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
        New-Item -ItemType Directory -Path $huntPath -Force | Out-Null
        
        # 1. Check for mass file encryption activity
        Write-CustodianLog "[1/6] Checking for suspicious file modifications..." -Level "INFO"
        $recentFiles = Invoke-Command -ScriptBlock {
            Get-ChildItem -Path "C:\Users" -Recurse -File -ErrorAction SilentlyContinue |
                Where-Object {$_.LastWriteTime -gt (Get-Date).AddHours(-24)} |
                Group-Object Extension | Sort-Object Count -Descending | Select-Object -First 20
        }
        Export-CustodianData -Data $recentFiles -FileName "RecentFileModifications.csv" -OutputPath $huntPath -Format CSV
        
        # 2. Shadow copy deletion detection
        Write-CustodianLog "[2/6] Checking for shadow copy deletion..." -Level "INFO"
        try {
            $shadowEvents = Get-WinEvent -FilterHashtable @{LogName='System'; Id=524; StartTime=(Get-Date).AddDays(-7)} -ErrorAction SilentlyContinue |
                Select-Object TimeCreated, Id, Message
            if ($shadowEvents) {
                Export-CustodianData -Data $shadowEvents -FileName "ShadowCopyDeletion.csv" -OutputPath $huntPath -Format CSV
                Write-CustodianLog "  Found $($shadowEvents.Count) shadow copy deletion events!" -Level "WARN"
            } else {
                Write-CustodianLog "  No shadow copy deletion events found" -Level "INFO"
            }
        } catch {
            Write-CustodianLog "  Could not query System log: $_" -Level "WARN"
        }
        
        # 3. Check for ransom notes
        Write-CustodianLog "[3/6] Scanning for ransom notes..." -Level "INFO"
        $ransomNotes = Invoke-Command -ScriptBlock {
            Get-ChildItem -Path "C:\" -Recurse -File -ErrorAction SilentlyContinue |
                Where-Object {$_.Name -match '(README|DECRYPT|RANSOM|RECOVERY|HOW_TO).*\.(txt|html)$'} |
                Select-Object FullName, Length, LastWriteTime
        }
        if ($ransomNotes) {
            Export-CustodianData -Data $ransomNotes -FileName "PossibleRansomNotes.csv" -OutputPath $huntPath -Format CSV
        }
        
        # 4. Check for encryption tools in memory
        Write-CustodianLog "[4/6] Checking running processes..." -Level "INFO"
        $processes = Get-CustodianProcesses -ComputerName $ComputerName -Credential $Credential -OutputPath $huntPath
        
        # 5. Network connections to known ransomware C2
        Write-CustodianLog "[5/6] Checking network connections..." -Level "INFO"
        Get-CustodianNetworkConnections -ComputerName $ComputerName -Credential $Credential -OutputPath $huntPath
        
        # 6. Check for disabled security services
        Write-CustodianLog "[6/6] Checking security services..." -Level "INFO"
        $services = Get-CustodianServices -ComputerName $ComputerName -Credential $Credential -OutputPath $huntPath
        
        Write-CustodianLog "=== Ransomware Hunt Complete ===" -Level "SUCCESS"
        Write-CustodianLog "Results saved to: $huntPath" -Level "SUCCESS"
        
        return $huntPath
        
    } catch {
        Write-CustodianLog "Ransomware hunt failed: $_" -Level "ERROR"
        return $null
    }
}
#endregion

#region Lateral Movement Hunt
function Start-LateralMovementHunt {
    <#
    .SYNOPSIS
        Execute lateral movement detection playbook
    #>
    [CmdletBinding()]
    param(
        [string]$ComputerName = "localhost",
        [PSCredential]$Credential,
        [string]$OutputPath = (Get-CustodianPath -PathType "Collection")
    )
    
    try {
        Write-CustodianLog "=== Starting Lateral Movement Hunt Playbook ===" -Level "INFO"
        
        $huntPath = Join-Path $OutputPath "LateralMovementHunt_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
        New-Item -ItemType Directory -Path $huntPath -Force | Out-Null
        
        # 1. RDP connections
        Write-CustodianLog "[1/5] Checking RDP connections..." -Level "INFO"
        Get-CustodianRDPLogs -ComputerName $ComputerName -Credential $Credential -OutputPath $huntPath -Days 30
        
        # 2. SMB sessions
        Write-CustodianLog "[2/5] Checking SMB sessions..." -Level "INFO"
        Get-CustodianSMBSessions -ComputerName $ComputerName -Credential $Credential -OutputPath $huntPath
        
        # 3. WMI activity
        Write-CustodianLog "[3/5] Checking WMI event logs..." -Level "INFO"
        Get-CustodianEventLogs -ComputerName $ComputerName -Credential $Credential -OutputPath $huntPath -LogName "Microsoft-Windows-WMI-Activity/Operational" -Days 7
        
        # 4. PsExec/RemCom indicators
        Write-CustodianLog "[4/5] Checking for PsExec indicators..." -Level "INFO"
        $services = Invoke-Command -ScriptBlock {
            Get-WmiObject Win32_Service | Where-Object {
                $_.Name -match 'psexe|remcom|paexec' -or
                $_.PathName -match 'psexe|remcom|paexec'
            } | Select-Object Name, PathName, State, StartMode
        }
        if ($services) {
            Export-CustodianData -Data $services -FileName "SuspiciousServices_PsExec.csv" -OutputPath $huntPath -Format CSV
        }
        
        # 5. Network connections
        Write-CustodianLog "[5/5] Checking network connections..." -Level "INFO"
        Get-CustodianNetworkConnections -ComputerName $ComputerName -Credential $Credential -OutputPath $huntPath
        
        Write-CustodianLog "=== Lateral Movement Hunt Complete ===" -Level "SUCCESS"
        Write-CustodianLog "Results saved to: $huntPath" -Level "SUCCESS"
        
        return $huntPath
        
    } catch {
        Write-CustodianLog "Lateral movement hunt failed: $_" -Level "ERROR"
        return $null
    }
}
#endregion

#region Persistence Hunt
function Start-PersistenceHunt {
    <#
    .SYNOPSIS
        Execute persistence mechanism detection playbook
    #>
    [CmdletBinding()]
    param(
        [string]$ComputerName = "localhost",
        [PSCredential]$Credential,
        [string]$OutputPath = (Get-CustodianPath -PathType "Collection")
    )
    
    try {
        Write-CustodianLog "=== Starting Persistence Hunt Playbook ===" -Level "INFO"
        
        $huntPath = Join-Path $OutputPath "PersistenceHunt_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
        New-Item -ItemType Directory -Path $huntPath -Force | Out-Null
        
        # 1. Registry autoruns
        Write-CustodianLog "[1/5] Checking autoruns..." -Level "INFO"
        Get-CustodianAutoruns -ComputerName $ComputerName -Credential $Credential -OutputPath $huntPath
        
        # 2. Scheduled tasks
        Write-CustodianLog "[2/5] Checking scheduled tasks..." -Level "INFO"
        Get-CustodianScheduledTasks -ComputerName $ComputerName -Credential $Credential -OutputPath $huntPath
        
        # 3. Services
        Write-CustodianLog "[3/5] Checking services..." -Level "INFO"
        Get-CustodianServices -ComputerName $ComputerName -Credential $Credential -OutputPath $huntPath
        
        # 4. WMI persistence
        Write-CustodianLog "[4/5] Checking WMI persistence..." -Level "INFO"
        Get-CustodianPersistence -ComputerName $ComputerName -Credential $Credential -OutputPath $huntPath
        
        # 5. User profiles and recent activity
        Write-CustodianLog "[5/5] Checking user profiles..." -Level "INFO"
        $userProfiles = Invoke-Command -ScriptBlock {
            Get-WmiObject Win32_UserProfile | Where-Object {$_.Special -eq $false} |
                Select-Object LocalPath, LastUseTime, Loaded, @{Name="SID";Expression={$_.SID}}
        }
        Export-CustodianData -Data $userProfiles -FileName "UserProfiles.csv" -OutputPath $huntPath -Format CSV
        
        Write-CustodianLog "=== Persistence Hunt Complete ===" -Level "SUCCESS"
        Write-CustodianLog "Results saved to: $huntPath" -Level "SUCCESS"
        
        return $huntPath
        
    } catch {
        Write-CustodianLog "Persistence hunt failed: $_" -Level "ERROR"
        return $null
    }
}
#endregion

#region Credential Access Hunt
function Start-CredentialAccessHunt {
    <#
    .SYNOPSIS
        Execute credential access detection playbook
    #>
    [CmdletBinding()]
    param(
        [string]$ComputerName = "localhost",
        [PSCredential]$Credential,
        [string]$OutputPath = (Get-CustodianPath -PathType "Collection")
    )
    
    try {
        Write-CustodianLog "=== Starting Credential Access Hunt Playbook ===" -Level "INFO"
        
        $huntPath = Join-Path $OutputPath "CredentialAccessHunt_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
        New-Item -ItemType Directory -Path $huntPath -Force | Out-Null
        
        # 1. LSASS access detection
        Write-CustodianLog "[1/4] Checking for LSASS access..." -Level "INFO"
        Get-CustodianEventLogs -ComputerName $ComputerName -Credential $Credential -OutputPath $huntPath -LogName "Security" -EventID 4656,4663 -Days 7
        
        # 2. Credential dumping tools
        Write-CustodianLog "[2/4] Checking for credential dumping tools..." -Level "INFO"
        $processes = Invoke-Command -ScriptBlock {
            Get-Process | Where-Object {
                $_.Name -match 'mimikatz|procdump|dumpert|nanodump|sharpkatz'
            } | Select-Object Name, Id, Path, CommandLine
        }
        if ($processes) {
            Export-CustodianData -Data $processes -FileName "CredentialDumpingTools.csv" -OutputPath $huntPath -Format CSV
        }
        
        # 3. SAM/SYSTEM file access
        Write-CustodianLog "[3/4] Checking for SAM/SYSTEM file access..." -Level "INFO"
        $samAccess = Invoke-Command -ScriptBlock {
            Get-ChildItem "C:\Windows\System32\config" -File | Where-Object {
                $_.Name -match 'SAM|SYSTEM|SECURITY'
            } | Select-Object Name, LastAccessTime, LastWriteTime
        }
        Export-CustodianData -Data $samAccess -FileName "SAMSystemAccess.csv" -OutputPath $huntPath -Format CSV
        
        # 4. Kerberos activity
        Write-CustodianLog "[4/4] Checking Kerberos events..." -Level "INFO"
        Get-CustodianEventLogs -ComputerName $ComputerName -Credential $Credential -OutputPath $huntPath -LogName "Security" -EventID 4768,4769,4771 -Days 7
        
        Write-CustodianLog "=== Credential Access Hunt Complete ===" -Level "SUCCESS"
        Write-CustodianLog "Results saved to: $huntPath" -Level "SUCCESS"
        
        return $huntPath
        
    } catch {
        Write-CustodianLog "Credential access hunt failed: $_" -Level "ERROR"
        return $null
    }
}
#endregion

#region Data Exfiltration Hunt
function Start-DataExfilHunt {
    <#
    .SYNOPSIS
        Execute data exfiltration detection playbook
    #>
    [CmdletBinding()]
    param(
        [string]$ComputerName = "localhost",
        [PSCredential]$Credential,
        [string]$OutputPath = (Get-CustodianPath -PathType "Collection")
    )
    
    try {
        Write-CustodianLog "=== Starting Data Exfiltration Hunt Playbook ===" -Level "INFO"
        
        $huntPath = Join-Path $OutputPath "DataExfilHunt_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
        New-Item -ItemType Directory -Path $huntPath -Force | Out-Null
        
        # 1. Large file transfers
        Write-CustodianLog "[1/4] Checking for large file operations..." -Level "INFO"
        $largeFiles = Invoke-Command -ScriptBlock {
            Get-ChildItem -Path "C:\Users" -Recurse -File -ErrorAction SilentlyContinue |
                Where-Object {$_.Length -gt 100MB -and $_.LastWriteTime -gt (Get-Date).AddDays(-7)} |
                Select-Object FullName, Length, LastWriteTime, CreationTime
        }
        if ($largeFiles) {
            Export-CustodianData -Data $largeFiles -FileName "LargeFiles.csv" -OutputPath $huntPath -Format CSV
        }
        
        # 2. Archive creation
        Write-CustodianLog "[2/4] Checking for archive creation..." -Level "INFO"
        $archives = Invoke-Command -ScriptBlock {
            Get-ChildItem -Path "C:\Users" -Recurse -File -ErrorAction SilentlyContinue |
                Where-Object {$_.Extension -match '\.(zip|rar|7z|tar|gz)$' -and $_.LastWriteTime -gt (Get-Date).AddDays(-7)} |
                Select-Object FullName, Length, LastWriteTime
        }
        if ($archives) {
            Export-CustodianData -Data $archives -FileName "RecentArchives.csv" -OutputPath $huntPath -Format CSV
        }
        
        # 3. Network connections to external IPs
        Write-CustodianLog "[3/4] Checking external network connections..." -Level "INFO"
        Get-CustodianNetworkConnections -ComputerName $ComputerName -Credential $Credential -OutputPath $huntPath
        
        # 4. Cloud storage access
        Write-CustodianLog "[4/4] Checking for cloud storage activity..." -Level "INFO"
        $processes = Invoke-Command -ScriptBlock {
            Get-Process | Where-Object {
                $_.Name -match 'dropbox|onedrive|googledrive|box|mega'
            } | Select-Object Name, Id, Path
        }
        if ($processes) {
            Export-CustodianData -Data $processes -FileName "CloudStorageProcesses.csv" -OutputPath $huntPath -Format CSV
        }
        
        Write-CustodianLog "=== Data Exfiltration Hunt Complete ===" -Level "SUCCESS"
        Write-CustodianLog "Results saved to: $huntPath" -Level "SUCCESS"
        
        return $huntPath
        
    } catch {
        Write-CustodianLog "Data exfiltration hunt failed: $_" -Level "ERROR"
        return $null
    }
}
#endregion

#region LOLBins Hunt
function Start-LOLBinsHunt {
    <#
    .SYNOPSIS
        Execute Living-off-the-Land binaries detection playbook
    #>
    [CmdletBinding()]
    param(
        [string]$ComputerName = "localhost",
        [PSCredential]$Credential,
        [string]$OutputPath = (Get-CustodianPath -PathType "Collection")
    )
    
    try {
        Write-CustodianLog "=== Starting LOLBins Hunt Playbook ===" -Level "INFO"
        
        $huntPath = Join-Path $OutputPath "LOLBinsHunt_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
        New-Item -ItemType Directory -Path $huntPath -Force | Out-Null
        
        # 1. PowerShell execution
        Write-CustodianLog "[1/3] Checking PowerShell logs..." -Level "INFO"
        Get-CustodianPowerShellLogs -ComputerName $ComputerName -Credential $Credential -OutputPath $huntPath -Days 7
        
        # 2. WMIC/CertUtil/BITSAdmin usage (Process Creation events)
        Write-CustodianLog "[2/3] Checking for LOLBin usage..." -Level "INFO"
        try {
            $lolbinPatterns = 'wmic|certutil|bitsadmin|mshta|regsvr32|rundll32|msiexec|cscript|wscript'
            $processEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688; StartTime=(Get-Date).AddDays(-7)} -ErrorAction SilentlyContinue |
                Where-Object { $_.Message -match $lolbinPatterns } |
                Select-Object TimeCreated, Id, @{N='Process';E={($_.Message -split "`n" | Select-String "New Process Name" | Select-Object -First 1) -replace '.*:\s*',''}}
            if ($processEvents) {
                Export-CustodianData -Data $processEvents -FileName "LOLBin_ProcessCreation.csv" -OutputPath $huntPath -Format CSV
                Write-CustodianLog "  Found $($processEvents.Count) potential LOLBin executions!" -Level "WARN"
            } else {
                Write-CustodianLog "  No LOLBin usage detected in Security log" -Level "INFO"
            }
        } catch {
            Write-CustodianLog "  Could not query Security log (4688): $_" -Level "WARN"
        }
        
        # 3. Sysmon process creation events
        Write-CustodianLog "[3/3] Checking Sysmon logs..." -Level "INFO"
        Get-CustodianSysmonLogs -ComputerName $ComputerName -Credential $Credential -OutputPath $huntPath -Days 7
        
        Write-CustodianLog "=== LOLBins Hunt Complete ===" -Level "SUCCESS"
        Write-CustodianLog "Results saved to: $huntPath" -Level "SUCCESS"
        
        return $huntPath
        
    } catch {
        Write-CustodianLog "LOLBins hunt failed: $_" -Level "ERROR"
        return $null
    }
}
#endregion

#region Webshell Hunt
function Start-WebshellHunt {
    <#
    .SYNOPSIS
        Execute webshell detection playbook
    #>
    [CmdletBinding()]
    param(
        [string]$ComputerName = "localhost",
        [PSCredential]$Credential,
        [string]$OutputPath = (Get-CustodianPath -PathType "Collection")
    )
    
    try {
        Write-CustodianLog "=== Starting Webshell Hunt Playbook ===" -Level "INFO"
        
        $huntPath = Join-Path $OutputPath "WebshellHunt_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
        New-Item -ItemType Directory -Path $huntPath -Force | Out-Null
        
        # 1. Scan web directories
        Write-CustodianLog "[1/2] Scanning web directories..." -Level "INFO"
        $webshells = Invoke-Command -ScriptBlock {
            $webPaths = @("C:\inetpub\wwwroot", "C:\xampp\htdocs", "C:\wamp\www")
            $results = @()
            
            foreach ($path in $webPaths) {
                if (Test-Path $path) {
                    $results += Get-ChildItem -Path $path -Recurse -File -ErrorAction SilentlyContinue |
                        Where-Object {$_.Extension -match '\.(asp|aspx|php|jsp)$' -and $_.LastWriteTime -gt (Get-Date).AddDays(-30)} |
                        Select-Object FullName, Length, LastWriteTime, CreationTime
                }
            }
            return $results
        }
        if ($webshells) {
            Export-CustodianData -Data $webshells -FileName "RecentWebFiles.csv" -OutputPath $huntPath -Format CSV
        }
        
        # 2. Check IIS logs
        Write-CustodianLog "[2/2] Checking IIS logs..." -Level "INFO"
        $iisLogs = Invoke-Command -ScriptBlock {
            if (Test-Path "C:\inetpub\logs\LogFiles") {
                Get-ChildItem "C:\inetpub\logs\LogFiles" -Recurse -File -Filter "*.log" |
                    Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-7)} |
                    Select-Object FullName, Length, LastWriteTime
            }
        }
        if ($iisLogs) {
            Export-CustodianData -Data $iisLogs -FileName "IISLogs.csv" -OutputPath $huntPath -Format CSV
        }
        
        Write-CustodianLog "=== Webshell Hunt Complete ===" -Level "SUCCESS"
        Write-CustodianLog "Results saved to: $huntPath" -Level "SUCCESS"
        
        return $huntPath
        
    } catch {
        Write-CustodianLog "Webshell hunt failed: $_" -Level "ERROR"
        return $null
    }
}
#endregion

#region BEC Investigation
function Start-BECInvestigation {
    <#
    .SYNOPSIS
        Execute Business Email Compromise investigation playbook
    #>
    [CmdletBinding()]
    param(
        [string]$ComputerName = "localhost",
        [PSCredential]$Credential,
        [string]$OutputPath = (Get-CustodianPath -PathType "Collection")
    )
    
    try {
        Write-CustodianLog "=== Starting BEC Investigation Playbook ===" -Level "INFO"
        
        $huntPath = Join-Path $OutputPath "BECInvestigation_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
        New-Item -ItemType Directory -Path $huntPath -Force | Out-Null
        
        # 1. Email client processes
        Write-CustodianLog "[1/3] Checking email client activity..." -Level "INFO"
        $emailProcs = Invoke-Command -ScriptBlock {
            Get-Process | Where-Object {
                $_.Name -match 'outlook|thunderbird|mailclient'
            } | Select-Object Name, Id, Path, StartTime
        }
        if ($emailProcs) {
            Export-CustodianData -Data $emailProcs -FileName "EmailProcesses.csv" -OutputPath $huntPath -Format CSV
        }
        
        # 2. Recent Outlook PST/OST files
        Write-CustodianLog "[2/3] Locating Outlook data files..." -Level "INFO"
        $outlookFiles = Invoke-Command -ScriptBlock {
            Get-ChildItem -Path "C:\Users" -Recurse -File -ErrorAction SilentlyContinue |
                Where-Object {$_.Extension -match '\.(pst|ost)$'} |
                Select-Object FullName, Length, LastAccessTime, LastWriteTime
        }
        if ($outlookFiles) {
            Export-CustodianData -Data $outlookFiles -FileName "OutlookDataFiles.csv" -OutputPath $huntPath -Format CSV
        }
        
        # 3. Network connections (mail servers)
        Write-CustodianLog "[3/3] Checking mail server connections..." -Level "INFO"
        Get-CustodianNetworkConnections -ComputerName $ComputerName -Credential $Credential -OutputPath $huntPath
        
        Write-CustodianLog "=== BEC Investigation Complete ===" -Level "SUCCESS"
        Write-CustodianLog "Results saved to: $huntPath" -Level "SUCCESS"
        
        return $huntPath
        
    } catch {
        Write-CustodianLog "BEC investigation failed: $_" -Level "ERROR"
        return $null
    }
}
#endregion

#region Export Module Members
Export-ModuleMember -Function `
    Start-RansomwareHunt,
    Start-LateralMovementHunt,
    Start-PersistenceHunt,
    Start-CredentialAccessHunt,
    Start-DataExfilHunt,
    Start-LOLBinsHunt,
    Start-WebshellHunt,
    Start-BECInvestigation
#endregion