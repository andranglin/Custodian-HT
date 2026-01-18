#Requires -Version 5.1
<#
.SYNOPSIS
    Custodian-HT OSINT and Threat Intelligence Module
.DESCRIPTION
    Threat intelligence lookups using VirusTotal, AbuseIPDB, URLhaus, AlienVault OTX,
    and other OSINT sources for IOC enrichment.
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

function Get-CustodianConfig {
    $base = if ($PSScriptRoot) { Split-Path $PSScriptRoot -Parent } else { $PWD.Path }
    $configPath = Join-Path $base "Config\Custodian-HT.json"
    if (Test-Path $configPath) {
        return Get-Content $configPath -Raw | ConvertFrom-Json
    }
    return $null
}

#endregion

#region VirusTotal
function Search-VirusTotal {
    <#
    .SYNOPSIS
        Search VirusTotal for hash, URL, IP, or domain
    .PARAMETER Indicator
        The IOC to search (hash, URL, IP, or domain)
    .PARAMETER APIKey
        VirusTotal API key
    .PARAMETER Type
        Indicator type: hash, url, ip, domain (auto-detected if not specified)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Indicator,
        [string]$APIKey,
        [ValidateSet("hash","url","ip","domain","auto")][string]$Type = "auto"
    )
    
    try {
        if (-not $APIKey) {
            $config = Get-CustodianConfig
            $APIKey = $config.APIKeys.VirusTotal
        }
        
        if (-not $APIKey) {
            Write-CustodianLog "VirusTotal API key not configured" -Level "ERROR"
            return $null
        }
        
        # Auto-detect indicator type
        if ($Type -eq "auto") {
            if ($Indicator -match '^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$') {
                $Type = "hash"
            } elseif ($Indicator -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') {
                $Type = "ip"
            } elseif ($Indicator -match '^https?://') {
                $Type = "url"
            } else {
                $Type = "domain"
            }
        }
        
        Write-CustodianLog "Searching VirusTotal for $Type : $Indicator" -Level "INFO"
        
        $headers = @{
            "x-apikey" = $APIKey
        }
        
        $baseUrl = "https://www.virustotal.com/api/v3"
        
        switch ($Type) {
            "hash" {
                $url = "$baseUrl/files/$Indicator"
            }
            "ip" {
                $url = "$baseUrl/ip_addresses/$Indicator"
            }
            "domain" {
                $url = "$baseUrl/domains/$Indicator"
            }
            "url" {
                $urlId = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Indicator)).TrimEnd('=')
                $url = "$baseUrl/urls/$urlId"
            }
        }
        
        $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Get -ErrorAction Stop
        
        $result = [PSCustomObject]@{
            Indicator = $Indicator
            Type = $Type
            Malicious = $response.data.attributes.last_analysis_stats.malicious
            Suspicious = $response.data.attributes.last_analysis_stats.suspicious
            Harmless = $response.data.attributes.last_analysis_stats.harmless
            Undetected = $response.data.attributes.last_analysis_stats.undetected
            LastAnalysisDate = if ($response.data.attributes.last_analysis_date) {
                [DateTimeOffset]::FromUnixTimeSeconds($response.data.attributes.last_analysis_date).DateTime
            } else { $null }
            Reputation = $response.data.attributes.reputation
            Link = "https://www.virustotal.com/gui/$Type/$Indicator"
            RawData = $response
            Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        }
        
        Write-CustodianLog "VirusTotal: $($result.Malicious) malicious, $($result.Suspicious) suspicious" -Level "SUCCESS"
        return $result
        
    } catch {
        Write-CustodianLog "VirusTotal search failed: $_" -Level "ERROR"
        return $null
    }
}
#endregion

#region AbuseIPDB
function Search-AbuseIPDB {
    <#
    .SYNOPSIS
        Search AbuseIPDB for IP reputation
    .PARAMETER IPAddress
        IP address to search
    .PARAMETER APIKey
        AbuseIPDB API key
    .PARAMETER MaxAge
        Maximum age of reports in days (default: 90)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$IPAddress,
        [string]$APIKey,
        [int]$MaxAge = 90
    )
    
    try {
        if (-not $APIKey) {
            $config = Get-CustodianConfig
            $APIKey = $config.APIKeys.AbuseIPDB
        }
        
        if (-not $APIKey) {
            Write-CustodianLog "AbuseIPDB API key not configured" -Level "ERROR"
            return $null
        }
        
        Write-CustodianLog "Searching AbuseIPDB for $IPAddress" -Level "INFO"
        
        $headers = @{
            "Key" = $APIKey
            "Accept" = "application/json"
        }
        
        $url = "https://api.abuseipdb.com/api/v2/check?ipAddress=$IPAddress&maxAgeInDays=$MaxAge&verbose=true"
        
        $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Get -ErrorAction Stop
        
        $result = [PSCustomObject]@{
            IPAddress = $response.data.ipAddress
            IsPublic = $response.data.isPublic
            AbuseConfidenceScore = $response.data.abuseConfidenceScore
            CountryCode = $response.data.countryCode
            ISP = $response.data.isp
            Domain = $response.data.domain
            TotalReports = $response.data.totalReports
            NumDistinctUsers = $response.data.numDistinctUsers
            LastReportedAt = $response.data.lastReportedAt
            IsWhitelisted = $response.data.isWhitelisted
            IsTor = $response.data.isTor
            Link = "https://www.abuseipdb.com/check/$IPAddress"
            Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        }
        
        Write-CustodianLog "AbuseIPDB: Confidence Score $($result.AbuseConfidenceScore)%, $($result.TotalReports) reports" -Level "SUCCESS"
        return $result
        
    } catch {
        Write-CustodianLog "AbuseIPDB search failed: $_" -Level "ERROR"
        return $null
    }
}
#endregion

#region URLhaus
function Search-URLhaus {
    <#
    .SYNOPSIS
        Search URLhaus for malicious URLs
    .PARAMETER URL
        URL to search
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$URL
    )
    
    try {
        Write-CustodianLog "Searching URLhaus for $URL" -Level "INFO"
        
        $body = @{
            url = $URL
        }
        
        $response = Invoke-RestMethod -Uri "https://urlhaus-api.abuse.ch/v1/url/" -Method Post -Body $body -ErrorAction Stop
        
        if ($response.query_status -eq "ok") {
            $result = [PSCustomObject]@{
                URL = $response.url
                Status = $response.url_status
                Threat = $response.threat
                DateAdded = $response.date_added
                LastOnline = $response.last_online
                Tags = ($response.tags -join ", ")
                Reporter = $response.reporter
                TakedownTime = $response.takedown_time_seconds
                Link = $response.urlhaus_reference
                Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            }
            
            Write-CustodianLog "URLhaus: Status=$($result.Status), Threat=$($result.Threat)" -Level "SUCCESS"
            return $result
        } else {
            Write-CustodianLog "URLhaus: URL not found in database" -Level "INFO"
            return [PSCustomObject]@{
                URL = $URL
                Status = "not_found"
                Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            }
        }
        
    } catch {
        Write-CustodianLog "URLhaus search failed: $_" -Level "ERROR"
        return $null
    }
}
#endregion

#region AlienVault OTX
function Search-AlienVault {
    <#
    .SYNOPSIS
        Search AlienVault OTX for threat intelligence
    .PARAMETER Indicator
        IOC to search (hash, IP, domain, URL)
    .PARAMETER Type
        Indicator type (auto-detected if not specified)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Indicator,
        [ValidateSet("hash","ip","domain","url","auto")][string]$Type = "auto"
    )
    
    try {
        # Auto-detect indicator type
        if ($Type -eq "auto") {
            if ($Indicator -match '^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$') {
                $Type = "hash"
            } elseif ($Indicator -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') {
                $Type = "ip"
            } elseif ($Indicator -match '^https?://') {
                $Type = "url"
            } else {
                $Type = "domain"
            }
        }
        
        Write-CustodianLog "Searching AlienVault OTX for $Type : $Indicator" -Level "INFO"
        
        $baseUrl = "https://otx.alienvault.com/api/v1/indicators"
        
        switch ($Type) {
            "hash" {
                $hashType = switch ($Indicator.Length) {
                    32 { "file/md5" }
                    40 { "file/sha1" }
                    64 { "file/sha256" }
                }
                $url = "$baseUrl/$hashType/$Indicator/general"
            }
            "ip" {
                $url = "$baseUrl/IPv4/$Indicator/general"
            }
            "domain" {
                $url = "$baseUrl/domain/$Indicator/general"
            }
            "url" {
                $url = "$baseUrl/url/$Indicator/general"
            }
        }
        
        $response = Invoke-RestMethod -Uri $url -Method Get -ErrorAction Stop
        
        $result = [PSCustomObject]@{
            Indicator = $Indicator
            Type = $Type
            PulseCount = $response.pulse_info.count
            Reputation = $response.reputation
            Country = $response.country_code
            ASN = $response.asn
            Validation = ($response.validation -join ", ")
            Link = "https://otx.alienvault.com/indicator/$Type/$Indicator"
            Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        }
        
        Write-CustodianLog "AlienVault: $($result.PulseCount) pulses found" -Level "SUCCESS"
        return $result
        
    } catch {
        Write-CustodianLog "AlienVault search failed: $_" -Level "ERROR"
        return $null
    }
}
#endregion

#region Bulk Lookup
function Search-BulkThreatIntel {
    <#
    .SYNOPSIS
        Perform bulk threat intelligence lookups from CSV
    .PARAMETER CSVPath
        Path to CSV file with indicators
    .PARAMETER IndicatorColumn
        Column name containing indicators (default: Hash)
    .PARAMETER OutputPath
        Path to save results
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$CSVPath,
        [string]$IndicatorColumn = "Hash",
        [string]$OutputPath = (Get-CustodianPath -PathType "Analysis")
    )
    
    try {
        if (-not (Test-Path $CSVPath)) {
            Write-CustodianLog "CSV file not found: $CSVPath" -Level "ERROR"
            return $null
        }
        
        $data = Import-Csv $CSVPath
        $results = @()
        $total = $data.Count
        $current = 0
        
        Write-CustodianLog "Starting bulk lookup of $total indicators..." -Level "INFO"
        
        foreach ($row in $data) {
            $current++
            $indicator = $row.$IndicatorColumn
            
            if ($indicator) {
                Write-Host "[$current/$total] Checking: $indicator" -ForegroundColor Cyan
                
                $vtResult = Search-VirusTotal -Indicator $indicator
                
                $results += [PSCustomObject]@{
                    Indicator = $indicator
                    VT_Malicious = $vtResult.Malicious
                    VT_Suspicious = $vtResult.Suspicious
                    VT_Link = $vtResult.Link
                    Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                }
                
                # Rate limiting - VT free API is 4 requests/minute
                Start-Sleep -Seconds 16
            }
        }
        
        $outputFile = Join-Path $OutputPath "BulkThreatIntel_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
        $results | Export-Csv -Path $outputFile -NoTypeInformation
        
        Write-CustodianLog "Bulk lookup complete: $outputFile" -Level "SUCCESS"
        return $results
        
    } catch {
        Write-CustodianLog "Bulk lookup failed: $_" -Level "ERROR"
        return $null
    }
}
#endregion

#region IOC Type Detection
function Get-IOCType {
    <#
    .SYNOPSIS
        Detect the type of an indicator
    .PARAMETER Indicator
        The indicator to analyze
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Indicator
    )
    
    if ($Indicator -match '^[a-fA-F0-9]{32}$') {
        return "MD5"
    } elseif ($Indicator -match '^[a-fA-F0-9]{40}$') {
        return "SHA1"
    } elseif ($Indicator -match '^[a-fA-F0-9]{64}$') {
        return "SHA256"
    } elseif ($Indicator -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') {
        return "IPv4"
    } elseif ($Indicator -match '^[a-fA-F0-9:]+$' -and $Indicator.Contains(':')) {
        return "IPv6"
    } elseif ($Indicator -match '^https?://') {
        return "URL"
    } elseif ($Indicator -match '^[a-zA-Z0-9][a-zA-Z0-9\-]*\.[a-zA-Z]{2,}') {
        return "Domain"
    } elseif ($Indicator -match '^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$') {
        return "Email"
    } else {
        return "Unknown"
    }
}
#endregion

#region Export Module Members
Export-ModuleMember -Function `
    Search-VirusTotal,
    Search-AbuseIPDB,
    Search-URLhaus,
    Search-AlienVault,
    Search-BulkThreatIntel,
    Get-IOCType
#endregion