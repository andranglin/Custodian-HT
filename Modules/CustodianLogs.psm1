#Requires -Version 5.1
<#
.SYNOPSIS
    Custodian-HT Event Log Collection Module
.DESCRIPTION
    Event log collection: Security, System, Application, PowerShell, Sysmon, RDP
.AUTHOR
    RootGuard Cyber Defence
.VERSION
    1.0.0
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

#region Event Logs

function Get-CustodianEventLogs {
    <#
    .SYNOPSIS
        Collect Windows Event Logs
    .PARAMETER LogName
        Log names to collect (default: Security, System, Application)
    .PARAMETER Days
        Number of days to look back (default: 7)
    .PARAMETER MaxEvents
        Maximum events per log (default: 1000)
    #>
    [CmdletBinding()]
    param(
        [string]$ComputerName = "localhost",
        [PSCredential]$Credential,
        [string]$OutputPath,
        [string[]]$LogName = @("Security", "System", "Application"),
        [int]$Days = 7,
        [int]$MaxEvents = 1000
    )
    
    if (-not $OutputPath) { $OutputPath = Get-CustodianPath -PathType "Collection" }
    
    Write-CustodianLog "Collecting event logs from $ComputerName (last $Days days)..." -Level "INFO"
    
    $startTime = (Get-Date).AddDays(-$Days)
    $allEvents = @()
    
    foreach ($log in $LogName) {
        Write-CustodianLog "  Collecting $log log..." -Level "INFO"
        
        try {
            # Try Get-WinEvent first (works with newer logs)
            $events = $null
            
            if ($ComputerName -eq "localhost") {
                # Use XPath filter which is more reliable
                $xpathFilter = "*[System[TimeCreated[@SystemTime >= '$($startTime.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss"))']]]"
                try {
                    $events = Get-WinEvent -LogName $log -FilterXPath $xpathFilter -MaxEvents $MaxEvents -ErrorAction Stop
                } catch {
                    # Fallback: Get events without time filter, then filter in PS
                    try {
                        $events = Get-WinEvent -LogName $log -MaxEvents $MaxEvents -ErrorAction Stop | 
                                  Where-Object { $_.TimeCreated -ge $startTime }
                    } catch {
                        # Final fallback: try Get-EventLog for classic logs
                        if ($log -in @("Security", "System", "Application")) {
                            try {
                                $legacyEvents = Get-EventLog -LogName $log -After $startTime -Newest $MaxEvents -ErrorAction Stop
                                $events = $legacyEvents | ForEach-Object {
                                    [PSCustomObject]@{
                                        TimeCreated = $_.TimeGenerated
                                        Id = $_.EventID
                                        LevelDisplayName = $_.EntryType
                                        ProviderName = $_.Source
                                        Message = $_.Message
                                        TaskDisplayName = ""
                                        ProcessId = ""
                                        ThreadId = ""
                                        MachineName = $_.MachineName
                                    }
                                }
                            } catch {
                                Write-CustodianLog "    Cannot access $log log: $($_.Exception.Message)" -Level "ERROR"
                            }
                        }
                    }
                }
            } else {
                # Remote collection
                $scriptBlock = {
                    param($LogName, $MaxEvents, $StartTime)
                    Get-WinEvent -LogName $LogName -MaxEvents $MaxEvents -ErrorAction SilentlyContinue | 
                        Where-Object { $_.TimeCreated -ge $StartTime }
                }
                
                $params = @{
                    ScriptBlock = $scriptBlock
                    ArgumentList = @($log, $MaxEvents, $startTime)
                    ComputerName = $ComputerName
                }
                if ($Credential) { $params.Credential = $Credential }
                
                $events = Invoke-Command @params -ErrorAction SilentlyContinue
            }
            
            if ($events -and @($events).Count -gt 0) {
                foreach ($evt in $events) {
                    $msg = ""
                    if ($evt.Message) {
                        $msg = ($evt.Message -replace "`r`n", " " -replace "`n", " ")
                        if ($msg.Length -gt 500) { $msg = $msg.Substring(0, 500) + "..." }
                    }
                    
                    $allEvents += [PSCustomObject]@{
                        LogName = $log
                        TimeCreated = $evt.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
                        EventID = $evt.Id
                        Level = $evt.LevelDisplayName
                        Provider = $evt.ProviderName
                        Message = $msg
                        TaskCategory = $evt.TaskDisplayName
                        ProcessId = $evt.ProcessId
                        ThreadId = $evt.ThreadId
                        Computer = $evt.MachineName
                    }
                }
                Write-CustodianLog "    Collected $(@($events).Count) events from $log" -Level "SUCCESS"
            } else {
                Write-CustodianLog "    No events in $log (last $Days days) or access denied" -Level "WARN"
            }
        } catch {
            Write-CustodianLog "    Error collecting $log : $($_.Exception.Message)" -Level "ERROR"
        }
    }
    
    if ($allEvents.Count -gt 0) {
        Export-CustodianData -Data $allEvents -FileName "EventLogs.csv" -OutputPath $OutputPath -Format CSV
        Write-CustodianLog "Total: $($allEvents.Count) events collected" -Level "SUCCESS"
    } else {
        Write-CustodianLog "No events collected - ensure running as Administrator for Security log" -Level "WARN"
    }
    
    return $allEvents
}

#endregion

#region PowerShell Logs

function Get-CustodianPowerShellLogs {
    <#
    .SYNOPSIS
        Collect PowerShell execution logs
    #>
    [CmdletBinding()]
    param(
        [string]$ComputerName = "localhost",
        [PSCredential]$Credential,
        [string]$OutputPath,
        [int]$Days = 7,
        [int]$MaxEvents = 500
    )
    
    if (-not $OutputPath) { $OutputPath = Get-CustodianPath -PathType "Collection" }
    
    Write-CustodianLog "Collecting PowerShell logs from $ComputerName..." -Level "INFO"
    
    $startTime = (Get-Date).AddDays(-$Days)
    $allEvents = @()
    
    $psLogs = @(
        "Microsoft-Windows-PowerShell/Operational",
        "Windows PowerShell"
    )
    
    foreach ($log in $psLogs) {
        try {
            $events = $null
            
            if ($ComputerName -eq "localhost") {
                try {
                    $events = Get-WinEvent -LogName $log -MaxEvents $MaxEvents -ErrorAction Stop | 
                              Where-Object { $_.TimeCreated -ge $startTime }
                } catch {
                    # Log might not exist or be empty
                }
            } else {
                $scriptBlock = {
                    param($LogName, $MaxEvents, $StartTime)
                    Get-WinEvent -LogName $LogName -MaxEvents $MaxEvents -ErrorAction SilentlyContinue | 
                        Where-Object { $_.TimeCreated -ge $StartTime }
                }
                $params = @{
                    ScriptBlock = $scriptBlock
                    ArgumentList = @($log, $MaxEvents, $startTime)
                    ComputerName = $ComputerName
                }
                if ($Credential) { $params.Credential = $Credential }
                $events = Invoke-Command @params -ErrorAction SilentlyContinue
            }
            
            if ($events -and @($events).Count -gt 0) {
                foreach ($evt in $events) {
                    $msg = ""
                    if ($evt.Message) {
                        $msg = ($evt.Message -replace "`r`n", " " -replace "`n", " ")
                        if ($msg.Length -gt 1000) { $msg = $msg.Substring(0, 1000) + "..." }
                    }
                    
                    $allEvents += [PSCustomObject]@{
                        LogName = $log
                        TimeCreated = $evt.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
                        EventID = $evt.Id
                        Level = $evt.LevelDisplayName
                        Message = $msg
                        Computer = $evt.MachineName
                    }
                }
                Write-CustodianLog "  Collected $(@($events).Count) events from $log" -Level "SUCCESS"
            }
        } catch {
            # Silently continue - log might not exist
        }
    }
    
    if ($allEvents.Count -gt 0) {
        Export-CustodianData -Data $allEvents -FileName "PowerShellLogs.csv" -OutputPath $OutputPath -Format CSV
        Write-CustodianLog "Total: $($allEvents.Count) PowerShell events" -Level "SUCCESS"
    } else {
        Write-CustodianLog "No PowerShell events found in last $Days days" -Level "WARN"
    }
    
    return $allEvents
}

#endregion

#region Sysmon Logs

function Get-CustodianSysmonLogs {
    <#
    .SYNOPSIS
        Collect Sysmon logs
    #>
    [CmdletBinding()]
    param(
        [string]$ComputerName = "localhost",
        [PSCredential]$Credential,
        [string]$OutputPath,
        [int]$Days = 7,
        [int]$MaxEvents = 1000
    )
    
    if (-not $OutputPath) { $OutputPath = Get-CustodianPath -PathType "Collection" }
    
    Write-CustodianLog "Collecting Sysmon logs from $ComputerName..." -Level "INFO"
    
    $startTime = (Get-Date).AddDays(-$Days)
    $allEvents = @()
    
    try {
        $events = $null
        $logName = "Microsoft-Windows-Sysmon/Operational"
        
        if ($ComputerName -eq "localhost") {
            $events = Get-WinEvent -LogName $logName -MaxEvents $MaxEvents -ErrorAction Stop | 
                      Where-Object { $_.TimeCreated -ge $startTime }
        } else {
            $scriptBlock = {
                param($LogName, $MaxEvents, $StartTime)
                Get-WinEvent -LogName $LogName -MaxEvents $MaxEvents -ErrorAction Stop | 
                    Where-Object { $_.TimeCreated -ge $StartTime }
            }
            $params = @{
                ScriptBlock = $scriptBlock
                ArgumentList = @($logName, $MaxEvents, $startTime)
                ComputerName = $ComputerName
            }
            if ($Credential) { $params.Credential = $Credential }
            $events = Invoke-Command @params -ErrorAction Stop
        }
        
        if ($events -and @($events).Count -gt 0) {
            foreach ($evt in $events) {
                $msg = ""
                if ($evt.Message) {
                    $msg = ($evt.Message -replace "`r`n", " " -replace "`n", " ")
                    if ($msg.Length -gt 1000) { $msg = $msg.Substring(0, 1000) + "..." }
                }
                
                $allEvents += [PSCustomObject]@{
                    TimeCreated = $evt.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
                    EventID = $evt.Id
                    Message = $msg
                    Computer = $evt.MachineName
                }
            }
            
            Export-CustodianData -Data $allEvents -FileName "SysmonLogs.csv" -OutputPath $OutputPath -Format CSV
            Write-CustodianLog "Collected $($allEvents.Count) Sysmon events" -Level "SUCCESS"
        } else {
            Write-CustodianLog "No Sysmon events in last $Days days" -Level "WARN"
        }
        
    } catch {
        if ($_.Exception.Message -match "No events were found") {
            Write-CustodianLog "No Sysmon events found" -Level "WARN"
        } elseif ($_.Exception.Message -match "could not be found") {
            Write-CustodianLog "Sysmon not installed on this system" -Level "WARN"
        } else {
            Write-CustodianLog "Sysmon collection error: $($_.Exception.Message)" -Level "WARN"
        }
    }
    
    return $allEvents
}

#endregion

#region RDP Logs

function Get-CustodianRDPLogs {
    <#
    .SYNOPSIS
        Collect RDP connection logs
    #>
    [CmdletBinding()]
    param(
        [string]$ComputerName = "localhost",
        [PSCredential]$Credential,
        [string]$OutputPath,
        [int]$Days = 30
    )
    
    if (-not $OutputPath) { $OutputPath = Get-CustodianPath -PathType "Collection" }
    
    Write-CustodianLog "Collecting RDP logs from $ComputerName..." -Level "INFO"
    
    $startTime = (Get-Date).AddDays(-$Days)
    $rdpEvents = @()
    
    # RDP related logs and event IDs
    $rdpLogs = @(
        @{ Log = "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational"; IDs = @(1149) },
        @{ Log = "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"; IDs = @(21, 22, 23, 24, 25) }
    )
    
    foreach ($logInfo in $rdpLogs) {
        try {
            $events = $null
            
            if ($ComputerName -eq "localhost") {
                $events = Get-WinEvent -LogName $logInfo.Log -MaxEvents 500 -ErrorAction SilentlyContinue | 
                          Where-Object { $_.TimeCreated -ge $startTime -and $_.Id -in $logInfo.IDs }
            } else {
                $scriptBlock = {
                    param($LogName, $StartTime, $EventIDs)
                    Get-WinEvent -LogName $LogName -MaxEvents 500 -ErrorAction SilentlyContinue | 
                        Where-Object { $_.TimeCreated -ge $StartTime -and $_.Id -in $EventIDs }
                }
                $params = @{
                    ScriptBlock = $scriptBlock
                    ArgumentList = @($logInfo.Log, $startTime, $logInfo.IDs)
                    ComputerName = $ComputerName
                }
                if ($Credential) { $params.Credential = $Credential }
                $events = Invoke-Command @params -ErrorAction SilentlyContinue
            }
            
            if ($events -and @($events).Count -gt 0) {
                foreach ($evt in $events) {
                    $msg = ""
                    if ($evt.Message) {
                        $msg = ($evt.Message -replace "`r`n", " " -replace "`n", " ")
                        if ($msg.Length -gt 500) { $msg = $msg.Substring(0, 500) + "..." }
                    }
                    
                    $rdpEvents += [PSCustomObject]@{
                        TimeCreated = $evt.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
                        LogName = $logInfo.Log
                        EventID = $evt.Id
                        Message = $msg
                        Computer = $evt.MachineName
                    }
                }
            }
        } catch {
            # Log might not exist - continue
        }
    }
    
    if ($rdpEvents.Count -gt 0) {
        Export-CustodianData -Data $rdpEvents -FileName "RDPLogs.csv" -OutputPath $OutputPath -Format CSV
        Write-CustodianLog "Collected $($rdpEvents.Count) RDP events" -Level "SUCCESS"
    } else {
        Write-CustodianLog "No RDP events found in last $Days days" -Level "WARN"
    }
    
    return $rdpEvents
}

#endregion

#region Security Events Summary

function Get-CustodianSecuritySummary {
    <#
    .SYNOPSIS
        Generate security event summary (failed logins, account changes, etc.)
    #>
    [CmdletBinding()]
    param(
        [string]$ComputerName = "localhost",
        [PSCredential]$Credential,
        [string]$OutputPath,
        [int]$Days = 7
    )
    
    if (-not $OutputPath) { $OutputPath = Get-CustodianPath -PathType "Collection" }
    
    Write-CustodianLog "Generating security summary from $ComputerName..." -Level "INFO"
    
    $startTime = (Get-Date).AddDays(-$Days)
    $summary = @()
    
    # Important security event IDs
    $importantEvents = @{
        4624 = "Successful Logon"
        4625 = "Failed Logon"
        4634 = "Logoff"
        4648 = "Explicit Credentials"
        4672 = "Admin Logon"
        4720 = "User Created"
        4722 = "User Enabled"
        4723 = "Password Change Attempt"
        4724 = "Password Reset"
        4725 = "User Disabled"
        4726 = "User Deleted"
        4728 = "Member Added to Security Group"
        4732 = "Member Added to Local Group"
        4756 = "Member Added to Universal Group"
        4768 = "Kerberos TGT Request"
        4769 = "Kerberos Service Ticket"
        4771 = "Kerberos Pre-Auth Failed"
        4776 = "NTLM Authentication"
        7045 = "Service Installed"
    }
    
    try {
        $events = $null
        
        if ($ComputerName -eq "localhost") {
            $events = Get-WinEvent -LogName "Security" -MaxEvents 5000 -ErrorAction SilentlyContinue | 
                      Where-Object { $_.TimeCreated -ge $startTime -and $_.Id -in $importantEvents.Keys }
        } else {
            $scriptBlock = {
                param($StartTime, $EventIDs)
                Get-WinEvent -LogName "Security" -MaxEvents 5000 -ErrorAction SilentlyContinue | 
                    Where-Object { $_.TimeCreated -ge $StartTime -and $_.Id -in $EventIDs }
            }
            $params = @{
                ScriptBlock = $scriptBlock
                ArgumentList = @($startTime, @($importantEvents.Keys))
                ComputerName = $ComputerName
            }
            if ($Credential) { $params.Credential = $Credential }
            $events = Invoke-Command @params -ErrorAction SilentlyContinue
        }
        
        if ($events -and @($events).Count -gt 0) {
            $grouped = $events | Group-Object Id
            
            foreach ($group in $grouped) {
                $evtId = [int]$group.Name
                $summary += [PSCustomObject]@{
                    EventID = $group.Name
                    Description = $importantEvents[$evtId]
                    Count = $group.Count
                    FirstSeen = ($group.Group | Sort-Object TimeCreated | Select-Object -First 1).TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
                    LastSeen = ($group.Group | Sort-Object TimeCreated -Descending | Select-Object -First 1).TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
                }
            }
            
            Export-CustodianData -Data ($summary | Sort-Object Count -Descending) -FileName "SecuritySummary.csv" -OutputPath $OutputPath -Format CSV
            Write-CustodianLog "Security summary: $($summary.Count) event types, $(@($events).Count) total events" -Level "SUCCESS"
        } else {
            Write-CustodianLog "No security events found (requires Administrator)" -Level "WARN"
        }
        
    } catch {
        Write-CustodianLog "Security summary error: $($_.Exception.Message)" -Level "ERROR"
    }
    
    return $summary
}

#endregion

Export-ModuleMember -Function @(
    'Get-CustodianEventLogs',
    'Get-CustodianPowerShellLogs',
    'Get-CustodianSysmonLogs',
    'Get-CustodianRDPLogs',
    'Get-CustodianSecuritySummary'
)