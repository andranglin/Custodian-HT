#Requires -Version 5.1
<#
.SYNOPSIS
    Custodian-HT Network Collection Module
.DESCRIPTION
    Network artifact collection: connections, ARP, DNS, SMB, firewall
.AUTHOR
    RootGuard Cyber Defence
.VERSION
    1.2.0 - Fixed null handling and CSV exports
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

function Save-ToCSV {
    param([AllowNull()]$Data, [string]$Path, [string]$Name)
    
    if ($null -eq $Data -or @($Data).Count -eq 0) {
        Write-CustodianLog "No data for $Name" -Level "WARN"
        return @()
    }
    
    $file = Join-Path $Path $Name
    @($Data) | Export-Csv -Path $file -NoTypeInformation -Force
    Write-CustodianLog "Exported: $Name ($(@($Data).Count) records)" -Level "SUCCESS"
    return @($Data)
}

#endregion

#region Network Connections

function Get-CustodianNetworkConnections {
    [CmdletBinding()]
    param(
        [string]$ComputerName = "localhost",
        [PSCredential]$Credential,
        [string]$OutputPath,
        [switch]$IncludeUDP
    )
    
    if (-not $OutputPath) { $OutputPath = Get-CustodianPath -PathType "Collection" }
    
    Write-CustodianLog "Collecting network connections from $ComputerName..." -Level "INFO"
    
    $sb = {
        param($UDP)
        $conns = @()
        
        Get-NetTCPConnection -ErrorAction SilentlyContinue | ForEach-Object {
            $p = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
            $conns += [PSCustomObject]@{
                Protocol = "TCP"
                LocalAddress = $_.LocalAddress
                LocalPort = $_.LocalPort
                RemoteAddress = $_.RemoteAddress
                RemotePort = $_.RemotePort
                State = $_.State
                PID = $_.OwningProcess
                ProcessName = $p.ProcessName
                ProcessPath = $p.Path
                Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            }
        }
        
        if ($UDP) {
            Get-NetUDPEndpoint -ErrorAction SilentlyContinue | ForEach-Object {
                $p = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
                $conns += [PSCustomObject]@{
                    Protocol = "UDP"
                    LocalAddress = $_.LocalAddress
                    LocalPort = $_.LocalPort
                    RemoteAddress = "*"
                    RemotePort = "*"
                    State = "Listening"
                    PID = $_.OwningProcess
                    ProcessName = $p.ProcessName
                    ProcessPath = $p.Path
                    Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                }
            }
        }
        
        return $conns
    }
    
    try {
        if ($ComputerName -eq "localhost") {
            $data = & $sb $IncludeUDP.IsPresent
        } else {
            $params = @{ ComputerName = $ComputerName; ScriptBlock = $sb; ArgumentList = $IncludeUDP.IsPresent }
            if ($Credential) { $params.Credential = $Credential }
            $data = Invoke-Command @params
        }
        
        return Save-ToCSV -Data $data -Path $OutputPath -Name "NetworkConnections.csv"
    } catch {
        Write-CustodianLog "Failed: $_" -Level "ERROR"
        return @()
    }
}

#endregion

#region ARP Cache

function Get-CustodianARPCache {
    [CmdletBinding()]
    param(
        [string]$ComputerName = "localhost",
        [PSCredential]$Credential,
        [string]$OutputPath
    )
    
    if (-not $OutputPath) { $OutputPath = Get-CustodianPath -PathType "Collection" }
    
    Write-CustodianLog "Collecting ARP cache from $ComputerName..." -Level "INFO"
    
    $sb = {
        Get-NetNeighbor -ErrorAction SilentlyContinue | Where-Object { $_.State -ne "Unreachable" } | ForEach-Object {
            [PSCustomObject]@{
                InterfaceAlias = $_.InterfaceAlias
                IPAddress = $_.IPAddress
                MACAddress = $_.LinkLayerAddress
                State = $_.State
                AddressFamily = $_.AddressFamily
                Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            }
        }
    }
    
    try {
        if ($ComputerName -eq "localhost") {
            $data = & $sb
        } else {
            $params = @{ ComputerName = $ComputerName; ScriptBlock = $sb }
            if ($Credential) { $params.Credential = $Credential }
            $data = Invoke-Command @params
        }
        
        return Save-ToCSV -Data $data -Path $OutputPath -Name "ARPCache.csv"
    } catch {
        Write-CustodianLog "Failed: $_" -Level "ERROR"
        return @()
    }
}

#endregion

#region DNS Cache

function Get-CustodianDNSCache {
    [CmdletBinding()]
    param(
        [string]$ComputerName = "localhost",
        [PSCredential]$Credential,
        [string]$OutputPath
    )
    
    if (-not $OutputPath) { $OutputPath = Get-CustodianPath -PathType "Collection" }
    
    Write-CustodianLog "Collecting DNS cache from $ComputerName..." -Level "INFO"
    
    $sb = {
        $cache = @()
        
        try {
            Get-DnsClientCache -ErrorAction Stop | ForEach-Object {
                $cache += [PSCustomObject]@{
                    Name = $_.Entry
                    Type = $_.Type
                    TTL = $_.TimeToLive
                    Data = $_.Data
                    Section = $_.Section
                    Status = $_.Status
                    Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                }
            }
        } catch {
            # DNS cache might be empty or service unavailable
        }
        
        # Return empty array if no entries (not null)
        if ($cache.Count -eq 0) {
            $cache += [PSCustomObject]@{
                Name = "(No DNS cache entries)"
                Type = "N/A"
                TTL = 0
                Data = ""
                Section = ""
                Status = "Empty"
                Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            }
        }
        
        return $cache
    }
    
    try {
        if ($ComputerName -eq "localhost") {
            $data = & $sb
        } else {
            $params = @{ ComputerName = $ComputerName; ScriptBlock = $sb }
            if ($Credential) { $params.Credential = $Credential }
            $data = Invoke-Command @params
        }
        
        return Save-ToCSV -Data $data -Path $OutputPath -Name "DNSCache.csv"
    } catch {
        Write-CustodianLog "Failed: $_" -Level "ERROR"
        return @()
    }
}

#endregion

#region SMB Sessions

function Get-CustodianSMBSessions {
    [CmdletBinding()]
    param(
        [string]$ComputerName = "localhost",
        [PSCredential]$Credential,
        [string]$OutputPath
    )
    
    if (-not $OutputPath) { $OutputPath = Get-CustodianPath -PathType "Collection" }
    
    Write-CustodianLog "Collecting SMB data from $ComputerName..." -Level "INFO"
    
    $sb = {
        $results = @()
        
        # SMB Shares
        try {
            Get-SmbShare -ErrorAction Stop | ForEach-Object {
                $results += [PSCustomObject]@{
                    Type = "Share"
                    Name = $_.Name
                    Path = $_.Path
                    Description = $_.Description
                    ShareType = $_.ShareType
                    CurrentUsers = $_.CurrentUsers
                    Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                }
            }
        } catch {}
        
        # SMB Sessions
        try {
            Get-SmbSession -ErrorAction Stop | ForEach-Object {
                $results += [PSCustomObject]@{
                    Type = "Session"
                    Name = $_.ClientComputerName
                    Path = ""
                    Description = "User: $($_.ClientUserName)"
                    ShareType = ""
                    CurrentUsers = $_.NumOpens
                    Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                }
            }
        } catch {}
        
        # Return placeholder if empty
        if ($results.Count -eq 0) {
            $results += [PSCustomObject]@{
                Type = "Info"
                Name = "(No SMB data - may require admin)"
                Path = ""
                Description = ""
                ShareType = ""
                CurrentUsers = 0
                Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            }
        }
        
        return $results
    }
    
    try {
        if ($ComputerName -eq "localhost") {
            $data = & $sb
        } else {
            $params = @{ ComputerName = $ComputerName; ScriptBlock = $sb }
            if ($Credential) { $params.Credential = $Credential }
            $data = Invoke-Command @params
        }
        
        return Save-ToCSV -Data $data -Path $OutputPath -Name "SMBData.csv"
    } catch {
        Write-CustodianLog "Failed: $_" -Level "ERROR"
        return @()
    }
}

#endregion

#region Network Adapters

function Get-CustodianNetworkAdapters {
    [CmdletBinding()]
    param(
        [string]$ComputerName = "localhost",
        [PSCredential]$Credential,
        [string]$OutputPath
    )
    
    if (-not $OutputPath) { $OutputPath = Get-CustodianPath -PathType "Collection" }
    
    Write-CustodianLog "Collecting network adapters from $ComputerName..." -Level "INFO"
    
    $sb = {
        Get-NetAdapter -ErrorAction SilentlyContinue | ForEach-Object {
            $cfg = Get-NetIPConfiguration -InterfaceIndex $_.InterfaceIndex -ErrorAction SilentlyContinue
            [PSCustomObject]@{
                Name = $_.Name
                Description = $_.InterfaceDescription
                Status = $_.Status
                MacAddress = $_.MacAddress
                LinkSpeed = $_.LinkSpeed
                IPv4Address = ($cfg.IPv4Address.IPAddress -join ", ")
                IPv4Gateway = ($cfg.IPv4DefaultGateway.NextHop -join ", ")
                DNSServers = ($cfg.DNSServer.ServerAddresses -join ", ")
                Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            }
        }
    }
    
    try {
        if ($ComputerName -eq "localhost") {
            $data = & $sb
        } else {
            $params = @{ ComputerName = $ComputerName; ScriptBlock = $sb }
            if ($Credential) { $params.Credential = $Credential }
            $data = Invoke-Command @params
        }
        
        return Save-ToCSV -Data $data -Path $OutputPath -Name "NetworkAdapters.csv"
    } catch {
        Write-CustodianLog "Failed: $_" -Level "ERROR"
        return @()
    }
}

#endregion

#region Firewall Rules

function Get-CustodianFirewallRules {
    [CmdletBinding()]
    param(
        [string]$ComputerName = "localhost",
        [PSCredential]$Credential,
        [string]$OutputPath,
        [switch]$EnabledOnly
    )
    
    if (-not $OutputPath) { $OutputPath = Get-CustodianPath -PathType "Collection" }
    
    Write-CustodianLog "Collecting firewall rules from $ComputerName..." -Level "INFO"
    
    $sb = {
        param($EnabledOnly)
        
        $rules = Get-NetFirewallRule -ErrorAction SilentlyContinue
        if ($EnabledOnly) { $rules = $rules | Where-Object { $_.Enabled -eq "True" } }
        
        $rules | Select-Object -First 500 | ForEach-Object {
            $port = $_ | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
            [PSCustomObject]@{
                Name = $_.Name
                DisplayName = $_.DisplayName
                Direction = $_.Direction
                Action = $_.Action
                Enabled = $_.Enabled
                Profile = $_.Profile
                Protocol = $port.Protocol
                LocalPort = $port.LocalPort
                RemotePort = $port.RemotePort
                Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            }
        }
    }
    
    try {
        if ($ComputerName -eq "localhost") {
            $data = & $sb $EnabledOnly.IsPresent
        } else {
            $params = @{ ComputerName = $ComputerName; ScriptBlock = $sb; ArgumentList = $EnabledOnly.IsPresent }
            if ($Credential) { $params.Credential = $Credential }
            $data = Invoke-Command @params
        }
        
        return Save-ToCSV -Data $data -Path $OutputPath -Name "FirewallRules.csv"
    } catch {
        Write-CustodianLog "Failed: $_" -Level "ERROR"
        return @()
    }
}

#endregion

#region Hosts File

function Get-CustodianHostsFile {
    [CmdletBinding()]
    param(
        [string]$ComputerName = "localhost",
        [PSCredential]$Credential,
        [string]$OutputPath
    )
    
    if (-not $OutputPath) { $OutputPath = Get-CustodianPath -PathType "Collection" }
    
    Write-CustodianLog "Collecting hosts file from $ComputerName..." -Level "INFO"
    
    $sb = {
        $entries = @()
        $path = "$env:SystemRoot\System32\drivers\etc\hosts"
        
        if (Test-Path $path) {
            Get-Content $path -ErrorAction SilentlyContinue | ForEach-Object {
                $line = $_.Trim()
                if ($line -and -not $line.StartsWith("#")) {
                    $parts = $line -split '\s+', 2
                    if ($parts.Count -ge 2) {
                        $entries += [PSCustomObject]@{
                            IPAddress = $parts[0]
                            Hostname = $parts[1]
                            Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                        }
                    }
                }
            }
        }
        
        if ($entries.Count -eq 0) {
            $entries += [PSCustomObject]@{
                IPAddress = "(No custom entries)"
                Hostname = ""
                Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            }
        }
        
        return $entries
    }
    
    try {
        if ($ComputerName -eq "localhost") {
            $data = & $sb
        } else {
            $params = @{ ComputerName = $ComputerName; ScriptBlock = $sb }
            if ($Credential) { $params.Credential = $Credential }
            $data = Invoke-Command @params
        }
        
        return Save-ToCSV -Data $data -Path $OutputPath -Name "HostsFile.csv"
    } catch {
        Write-CustodianLog "Failed: $_" -Level "ERROR"
        return @()
    }
}

#endregion

#region Routing Table

function Get-CustodianRoutingTable {
    [CmdletBinding()]
    param(
        [string]$ComputerName = "localhost",
        [PSCredential]$Credential,
        [string]$OutputPath
    )
    
    if (-not $OutputPath) { $OutputPath = Get-CustodianPath -PathType "Collection" }
    
    Write-CustodianLog "Collecting routing table from $ComputerName..." -Level "INFO"
    
    $sb = {
        Get-NetRoute -ErrorAction SilentlyContinue | ForEach-Object {
            [PSCustomObject]@{
                InterfaceAlias = $_.InterfaceAlias
                DestinationPrefix = $_.DestinationPrefix
                NextHop = $_.NextHop
                RouteMetric = $_.RouteMetric
                Protocol = $_.Protocol
                Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            }
        }
    }
    
    try {
        if ($ComputerName -eq "localhost") {
            $data = & $sb
        } else {
            $params = @{ ComputerName = $ComputerName; ScriptBlock = $sb }
            if ($Credential) { $params.Credential = $Credential }
            $data = Invoke-Command @params
        }
        
        return Save-ToCSV -Data $data -Path $OutputPath -Name "RoutingTable.csv"
    } catch {
        Write-CustodianLog "Failed: $_" -Level "ERROR"
        return @()
    }
}

#endregion

Export-ModuleMember -Function @(
    'Get-CustodianNetworkConnections',
    'Get-CustodianARPCache',
    'Get-CustodianDNSCache',
    'Get-CustodianSMBSessions',
    'Get-CustodianNetworkAdapters',
    'Get-CustodianFirewallRules',
    'Get-CustodianHostsFile',
    'Get-CustodianRoutingTable'
)