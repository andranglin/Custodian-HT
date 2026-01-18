#Requires -Version 5.1
<#
.SYNOPSIS
    Custodian-HT Patch Tuesday Analysis Module
.DESCRIPTION
    Analyzes Microsoft Patch Tuesday vulnerability statistics from MSRC API.
    Identifies exploited, publicly disclosed, and high-rated vulnerabilities.
.AUTHOR
    RootGuard Cyber Defence
.VERSION
    1.0.0
#>

#region Local Helper Functions

function Write-CustodianLog {
    param(
        [string]$Message,
        [ValidateSet("INFO","SUCCESS","WARN","ERROR")][string]$Level = "INFO"
    )
    $colors = @{ INFO = "Cyan"; SUCCESS = "Green"; WARN = "Yellow"; ERROR = "Red" }
    $prefix = @{ INFO = "[*]"; SUCCESS = "[+]"; WARN = "[!]"; ERROR = "[-]" }
    Write-Host "$($prefix[$Level]) $Message" -ForegroundColor $colors[$Level]
}

function Get-CustodianPath {
    param([ValidateSet("Root","Tools","Output","Collection","Analysis","Config","Modules")][string]$PathType = "Output")
    $root = $PSScriptRoot
    if ($root -match '[\\/]Modules$') { $root = Split-Path $root -Parent }
    switch ($PathType) {
        "Root"       { return $root }
        "Tools"      { return Join-Path $root "Tools" }
        "Output"     { return Join-Path $root "Output" }
        "Collection" { return Join-Path $root "Output\Collection" }
        "Analysis"   { return Join-Path $root "Output\Analysis" }
        "Config"     { return Join-Path $root "Config" }
        "Modules"    { return Join-Path $root "Modules" }
    }
}

function Export-CustodianData {
    param(
        [Parameter(Mandatory=$false)][AllowNull()][AllowEmptyCollection()]$Data,
        [string]$OutputPath,
        [string]$FileName,
        [ValidateSet("CSV","JSON")][string]$Format = "CSV",
        [switch]$Append
    )
    if (-not $OutputPath) { $OutputPath = Get-CustodianPath -PathType "Analysis" }
    if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
    
    $dataArray = @($Data)
    if ($dataArray.Count -eq 0) {
        Write-CustodianLog "No data to export for $FileName" -Level WARN
        return
    }
    
    $filePath = Join-Path $OutputPath $FileName
    try {
        if ($Format -eq "CSV") {
            if ($Append -and (Test-Path $filePath)) {
                $dataArray | Export-Csv -Path $filePath -NoTypeInformation -Append
            } else {
                $dataArray | Export-Csv -Path $filePath -NoTypeInformation
            }
        } else {
            $dataArray | ConvertTo-Json -Depth 10 | Out-File $filePath -Encoding UTF8
        }
        Write-CustodianLog "Exported: $FileName ($($dataArray.Count) records)" -Level SUCCESS
    } catch {
        Write-CustodianLog "Failed to export $FileName : $_" -Level ERROR
    }
}

#endregion

#region Configuration

$Script:MSRCConfig = @{
    BaseUrl = 'https://api.msrc.microsoft.com/cvrf/v2.0/'
    Headers = @{ 'Accept' = 'application/json' }
    CVELinkUris = @{
        "MSRC"    = "https://msrc.microsoft.com/update-guide/vulnerability/"
        "CVE.org" = "https://www.cve.org/CVERecord?id="
    }
    VulnTypes = @(
        'Elevation of Privilege',
        'Security Feature Bypass',
        'Remote Code Execution',
        'Information Disclosure',
        'Denial of Service',
        'Spoofing',
        'Edge - Chromium'
    )
}

#endregion

#region Internal Functions

function ConvertTo-MonthName {
    param([string]$MonthNumber)
    $months = @{
        '01'='Jan'; '02'='Feb'; '03'='Mar'; '04'='Apr'; '05'='May'; '06'='Jun'
        '07'='Jul'; '08'='Aug'; '09'='Sep'; '10'='Oct'; '11'='Nov'; '12'='Dec'
    }
    return $months[$MonthNumber]
}

function Get-VulnerabilityCountByType {
    param([string]$SearchType, [array]$AllVulns)
    $counter = 0
    foreach ($vuln in $AllVulns) {
        foreach ($threat in $vuln.Threats) {
            if ($threat.Type -eq 0) {
                if ($SearchType -eq "Edge - Chromium") {
                    if ($threat.ProductID[0] -eq '11655') { $counter++; break }
                } elseif ($threat.Description.Value -eq $SearchType) {
                    if ($threat.ProductID[0] -eq '11655') { break }
                    $counter++; break
                }
            }
        }
    }
    return $counter
}

function Get-ExploitedVulnerabilities {
    param([array]$AllVulns)
    foreach ($vuln in $AllVulns) {
        foreach ($threat in $vuln.Threats) {
            if ($threat.Type -eq 1 -and $threat.Description.Value -match 'Exploited:Yes') {
                [PSCustomObject]@{ CVE = $vuln.CVE; Title = $vuln.Title.Value; Exploited = $true }
                break
            }
        }
    }
}

function Get-PubliclyDisclosedVulnerabilities {
    param([array]$AllVulns)
    foreach ($vuln in $AllVulns) {
        $desc = ($vuln.Threats.Description.Value) -split ";" | Select-Object -Unique
        if ($desc -contains 'Publicly Disclosed:Yes') {
            [PSCustomObject]@{ CVE = $vuln.CVE; Title = $vuln.Title.Value; PubliclyDisclosed = $true }
        }
    }
}

function Get-ExploitationLikelyVulnerabilities {
    param([array]$AllVulns)
    foreach ($vuln in $AllVulns) {
        foreach ($threat in $vuln.Threats) {
            if ($threat.Type -eq 1 -and $threat.Description.Value -match 'Exploitation More Likely') {
                [PSCustomObject]@{ CVE = $vuln.CVE; Title = $vuln.Title.Value; ExploitationLikely = $true }
                break
            }
        }
    }
}

function Get-VulnerabilityCriticality {
    param([array]$AllVulns)
    $validValues = @("Critical", "Important", "Moderate", "Low")
    foreach ($vuln in $AllVulns) {
        $threats = $vuln.Threats | Where-Object { $_.Type -eq 3 }
        foreach ($threat in $threats) {
            $desc = $threat.Description.Value -split ";" | Select-Object -Unique
            if ($validValues -contains $desc) {
                [PSCustomObject]@{ CVE = $vuln.CVE; Title = $vuln.Title.Value; Criticality = $desc }
                break
            }
        }
    }
}

function Get-CustomerActionRequired {
    param([array]$AllVulns)
    foreach ($vuln in $AllVulns) {
        $action = $vuln.Notes | Where-Object Title -eq "Customer Action Required" | Select-Object -ExpandProperty Value
        [PSCustomObject]@{
            CVE = $vuln.CVE
            Title = $vuln.Title.Value
            CustomerActionRequired = ($action -eq "Yes")
        }
    }
}

#endregion

#region Public Functions

function Get-CustodianPatchTuesday {
    [CmdletBinding()]
    param(
        [Parameter(Position=0)]
        [string]$ReportDate,
        
        [float]$BaseScore = 8.0,
        
        [ValidateSet("MSRC", "CVE.org", "None")]
        [string]$CVELinkFormat = "MSRC",
        
        [string]$OutputPath,
        
        [switch]$IncludeCriticality,
        
        [switch]$ExportResults
    )
    
    if (-not $OutputPath) { $OutputPath = Get-CustodianPath -PathType "Analysis" }
    
    if ([string]::IsNullOrWhiteSpace($ReportDate)) {
        $ReportDate = (Get-Date).ToString("yyyy-MMM", [System.Globalization.CultureInfo]::InvariantCulture)
    }
    
    if ($ReportDate -match '^\d{4}-\d{2}$') {
        $month = $ReportDate -replace '^\d{4}-(\d{2})$', '$1'
        $year = $ReportDate -replace '^(\d{4})-\d{2}$', '$1'
        $ReportDate = "$year-$(ConvertTo-MonthName -MonthNumber $month)"
    }
    
    if (-not ($ReportDate -match '^\d{4}-(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)$')) {
        Write-CustodianLog "Invalid date format. Use YYYY-MMM or YYYY-MM (e.g., 2025-Jan or 2025-01)" -Level ERROR
        return $null
    }
    
    $cveLinkUri = if ($CVELinkFormat -eq "None") { 
        $Script:MSRCConfig.CVELinkUris["MSRC"] 
    } else { 
        $Script:MSRCConfig.CVELinkUris[$CVELinkFormat] 
    }
    
    Write-CustodianLog "Fetching Patch Tuesday data for $ReportDate..." -Level INFO
    
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $response = Invoke-RestMethod -Uri "$($Script:MSRCConfig.BaseUrl)cvrf/$ReportDate" -Headers $Script:MSRCConfig.Headers -Method Get -ErrorAction Stop
        
        if ($null -eq $response) {
            Write-CustodianLog "No release notes found for $ReportDate" -Level ERROR
            return $null
        }
        
        $title = if ($response.DocumentTitle.Value) { $response.DocumentTitle.Value } else { "Release not found" }
        $allVulns = @($response.Vulnerability | Where-Object { -not [string]::IsNullOrWhiteSpace($_.Title) })
        
        Write-CustodianLog "$title" -Level SUCCESS
        Write-CustodianLog "Total vulnerabilities: $($allVulns.Count)" -Level INFO
        
        $exploited = @(Get-ExploitedVulnerabilities -AllVulns $allVulns)
        $publiclyDisclosed = @(Get-PubliclyDisclosedVulnerabilities -AllVulns $allVulns)
        $exploitationLikely = @(Get-ExploitationLikelyVulnerabilities -AllVulns $allVulns)
        $criticality = @(Get-VulnerabilityCriticality -AllVulns $allVulns)
        $customerAction = @(Get-CustomerActionRequired -AllVulns $allVulns)
        
        $results = foreach ($vuln in $allVulns) {
            $cvssScore = "N/A"
            if ($null -ne $vuln.CVSSScoreSets -and $vuln.CVSSScoreSets.Count -gt 0) {
                $cvssScore = $vuln.CVSSScoreSets[0].BaseScore
            }
            
            $vulnCriticality = ($criticality | Where-Object { $_.CVE -eq $vuln.CVE }).Criticality
            if (-not $vulnCriticality) { $vulnCriticality = "N/A" }
            
            $isHighRated = $false
            if ($cvssScore -ne "N/A") {
                if ($IncludeCriticality -and $vulnCriticality -eq "Critical") { $isHighRated = $true }
                if ([float]$cvssScore -ge $BaseScore) { $isHighRated = $true }
            }
            
            $custAction = ($customerAction | Where-Object { $_.CVE -eq $vuln.CVE }).CustomerActionRequired
            
            [PSCustomObject]@{
                CVE                    = $vuln.CVE
                Title                  = $vuln.Title.Value
                CvssScore              = $cvssScore
                Criticality            = $vulnCriticality
                Exploited              = ($exploited.CVE -contains $vuln.CVE)
                ExploitationLikely     = ($exploitationLikely.CVE -contains $vuln.CVE)
                PubliclyDisclosed      = ($publiclyDisclosed.CVE -contains $vuln.CVE)
                HighRated              = $isHighRated
                CustomerActionRequired = $custAction
                URL                    = "$cveLinkUri$($vuln.CVE)"
                ReportDate             = $ReportDate
            }
        }
        
        Write-Host ""
        Write-CustodianLog "VULNERABILITY SUMMARY" -Level INFO
        foreach ($vulnType in $Script:MSRCConfig.VulnTypes) {
            $count = Get-VulnerabilityCountByType -SearchType $vulnType -AllVulns $allVulns
            Write-Host "    $count $vulnType" -ForegroundColor Gray
        }
        Write-Host ""
        
        $exploitedCount = ($results | Where-Object Exploited).Count
        $disclosedCount = ($results | Where-Object PubliclyDisclosed).Count
        $likelyCount = ($results | Where-Object ExploitationLikely).Count
        $highRatedCount = ($results | Where-Object HighRated).Count
        
        if ($exploitedCount -gt 0) {
            Write-CustodianLog "ACTIVELY EXPLOITED: $exploitedCount" -Level ERROR
        }
        if ($disclosedCount -gt 0) {
            Write-CustodianLog "Publicly Disclosed: $disclosedCount" -Level WARN
        }
        Write-CustodianLog "Exploitation Likely: $likelyCount" -Level WARN
        Write-CustodianLog "High Rated (CVSS >= $BaseScore): $highRatedCount" -Level INFO
        
        if ($ExportResults) {
            $dateStr = $ReportDate -replace '-', ''
            Export-CustodianData -Data $results -FileName "PatchTuesday_${dateStr}.csv" -OutputPath $OutputPath -Format CSV
            
            $critical = $results | Where-Object { $_.Exploited -or $_.ExploitationLikely -or $_.HighRated }
            if ($critical.Count -gt 0) {
                Export-CustodianData -Data $critical -FileName "PatchTuesday_${dateStr}_Critical.csv" -OutputPath $OutputPath -Format CSV
            }
        }
        
        return $results
        
    } catch {
        if ($_.Exception.Response.StatusCode) {
            $statusCode = [int]$_.Exception.Response.StatusCode
            Write-CustodianLog "MSRC API returned $statusCode - no release notes yet for $ReportDate" -Level ERROR
        } else {
            Write-CustodianLog "Error fetching data: $($_.Exception.Message)" -Level ERROR
        }
        return $null
    }
}

function Get-CustodianExploitedCVEs {
    [CmdletBinding()]
    param(
        [Parameter(Position=0)]
        [string]$ReportDate
    )
    
    $allVulns = Get-CustodianPatchTuesday -ReportDate $ReportDate
    if ($null -eq $allVulns) { return $null }
    
    $exploited = $allVulns | Where-Object { $_.Exploited -eq $true } | Sort-Object CvssScore -Descending
    
    if ($exploited.Count -eq 0) {
        Write-CustodianLog "No actively exploited vulnerabilities this month" -Level SUCCESS
    } else {
        Write-Host ""
        Write-CustodianLog "ACTIVELY EXPLOITED VULNERABILITIES:" -Level ERROR
        foreach ($cve in $exploited) {
            $actionText = if ($cve.CustomerActionRequired) { "[ACTION REQUIRED]" } else { "[FIXED]" }
            $actionColor = if ($cve.CustomerActionRequired) { "Red" } else { "Green" }
            Write-Host "  $($cve.CVE) - CVSS $($cve.CvssScore) - $($cve.Title) " -ForegroundColor Red -NoNewline
            Write-Host $actionText -ForegroundColor $actionColor
        }
    }
    
    return $exploited
}

function Get-CustodianPriorityPatches {
    [CmdletBinding()]
    param(
        [Parameter(Position=0)]
        [string]$ReportDate,
        
        [float]$BaseScore = 8.0
    )
    
    $allVulns = Get-CustodianPatchTuesday -ReportDate $ReportDate -BaseScore $BaseScore
    if ($null -eq $allVulns) { return $null }
    
    $priority = $allVulns | Where-Object { 
        $_.Exploited -or 
        $_.ExploitationLikely -or 
        $_.HighRated -or
        ($_.CustomerActionRequired -and $_.CvssScore -ne "N/A" -and [float]$_.CvssScore -ge 7.0)
    } | Sort-Object @{Expression="Exploited";Descending=$true}, @{Expression="CvssScore";Descending=$true}
    
    Write-Host ""
    Write-CustodianLog "PRIORITY PATCHES ($($priority.Count) total):" -Level WARN
    Write-Host ""
    
    $exploitedList = $priority | Where-Object Exploited
    $likelyList = $priority | Where-Object { $_.ExploitationLikely -and -not $_.Exploited }
    $highList = $priority | Where-Object { $_.HighRated -and -not $_.Exploited -and -not $_.ExploitationLikely }
    
    if ($exploitedList.Count -gt 0) {
        Write-Host "  === ACTIVELY EXPLOITED ===" -ForegroundColor Red
        foreach ($cve in $exploitedList) {
            Write-Host "  $($cve.CVE) - CVSS $($cve.CvssScore) - $($cve.Title)" -ForegroundColor Red
        }
        Write-Host ""
    }
    
    if ($likelyList.Count -gt 0) {
        Write-Host "  === EXPLOITATION LIKELY ===" -ForegroundColor Yellow
        foreach ($cve in $likelyList) {
            Write-Host "  $($cve.CVE) - CVSS $($cve.CvssScore) - $($cve.Title)" -ForegroundColor Yellow
        }
        Write-Host ""
    }
    
    if ($highList.Count -gt 0) {
        Write-Host "  === HIGH CVSS (>= $BaseScore) ===" -ForegroundColor Cyan
        foreach ($cve in $highList) {
            Write-Host "  $($cve.CVE) - CVSS $($cve.CvssScore) - $($cve.Title)" -ForegroundColor Cyan
        }
    }
    
    return $priority
}

function Export-CustodianPatchReport {
    [CmdletBinding()]
    param(
        [Parameter(Position=0)]
        [string]$ReportDate,
        
        [ValidateSet("CSV", "JSON", "Markdown", "HTML")]
        [string]$Format = "Markdown",
        
        [string]$OutputPath,
        
        [float]$BaseScore = 8.0
    )
    
    if (-not $OutputPath) { $OutputPath = Join-Path (Get-CustodianPath -PathType "Output") "Reports" }
    if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
    
    $allVulns = Get-CustodianPatchTuesday -ReportDate $ReportDate -BaseScore $BaseScore -IncludeCriticality
    if ($null -eq $allVulns) { return }
    
    $dateStr = if ($ReportDate) { $ReportDate -replace '-', '' } else { (Get-Date).ToString("yyyyMMM") }
    $reportTitle = "Microsoft Patch Tuesday Analysis - $ReportDate"
    
    switch ($Format) {
        "CSV" {
            $filePath = Join-Path $OutputPath "PatchTuesday_${dateStr}.csv"
            $allVulns | Export-Csv -Path $filePath -NoTypeInformation
            Write-CustodianLog "Report exported: $filePath" -Level SUCCESS
        }
        
        "JSON" {
            $filePath = Join-Path $OutputPath "PatchTuesday_${dateStr}.json"
            $allVulns | ConvertTo-Json -Depth 5 | Out-File $filePath -Encoding UTF8
            Write-CustodianLog "Report exported: $filePath" -Level SUCCESS
        }
        
        "Markdown" {
            $filePath = Join-Path $OutputPath "PatchTuesday_${dateStr}.md"
            $md = [System.Text.StringBuilder]::new()
            
            [void]$md.AppendLine("# $reportTitle")
            [void]$md.AppendLine("")
            [void]$md.AppendLine("**Generated:** $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
            [void]$md.AppendLine("**Total Vulnerabilities:** $($allVulns.Count)")
            [void]$md.AppendLine("")
            
            [void]$md.AppendLine("## Summary")
            [void]$md.AppendLine("")
            [void]$md.AppendLine("| Category | Count |")
            [void]$md.AppendLine("|----------|-------|")
            [void]$md.AppendLine("| Actively Exploited | $(($allVulns | Where-Object Exploited).Count) |")
            [void]$md.AppendLine("| Publicly Disclosed | $(($allVulns | Where-Object PubliclyDisclosed).Count) |")
            [void]$md.AppendLine("| Exploitation Likely | $(($allVulns | Where-Object ExploitationLikely).Count) |")
            [void]$md.AppendLine("| High Rated (CVSS >= $BaseScore) | $(($allVulns | Where-Object HighRated).Count) |")
            [void]$md.AppendLine("")
            
            $exploited = $allVulns | Where-Object Exploited | Sort-Object CvssScore -Descending
            if ($exploited.Count -gt 0) {
                [void]$md.AppendLine("## Actively Exploited Vulnerabilities")
                [void]$md.AppendLine("")
                [void]$md.AppendLine("| CVE | CVSS | Criticality | Title |")
                [void]$md.AppendLine("|-----|------|-------------|-------|")
                foreach ($cve in $exploited) {
                    [void]$md.AppendLine("| [$($cve.CVE)]($($cve.URL)) | $($cve.CvssScore) | $($cve.Criticality) | $($cve.Title) |")
                }
                [void]$md.AppendLine("")
            }
            
            $likely = $allVulns | Where-Object { $_.ExploitationLikely -and -not $_.Exploited } | Sort-Object CvssScore -Descending
            if ($likely.Count -gt 0) {
                [void]$md.AppendLine("## Exploitation More Likely")
                [void]$md.AppendLine("")
                [void]$md.AppendLine("| CVE | CVSS | Criticality | Title |")
                [void]$md.AppendLine("|-----|------|-------------|-------|")
                foreach ($cve in $likely) {
                    [void]$md.AppendLine("| [$($cve.CVE)]($($cve.URL)) | $($cve.CvssScore) | $($cve.Criticality) | $($cve.Title) |")
                }
                [void]$md.AppendLine("")
            }
            
            $highRated = $allVulns | Where-Object { $_.HighRated -and -not $_.Exploited -and -not $_.ExploitationLikely } | Sort-Object CvssScore -Descending
            if ($highRated.Count -gt 0) {
                [void]$md.AppendLine("## High Rated Vulnerabilities (CVSS >= $BaseScore)")
                [void]$md.AppendLine("")
                [void]$md.AppendLine("| CVE | CVSS | Criticality | Title |")
                [void]$md.AppendLine("|-----|------|-------------|-------|")
                foreach ($cve in $highRated) {
                    [void]$md.AppendLine("| [$($cve.CVE)]($($cve.URL)) | $($cve.CvssScore) | $($cve.Criticality) | $($cve.Title) |")
                }
                [void]$md.AppendLine("")
            }
            
            [void]$md.AppendLine("## All Vulnerabilities")
            [void]$md.AppendLine("")
            [void]$md.AppendLine("| CVE | CVSS | Criticality | Exploited | Likely | Disclosed | Title |")
            [void]$md.AppendLine("|-----|------|-------------|-----------|--------|-----------|-------|")
            foreach ($cve in ($allVulns | Sort-Object @{Expression={if($_.CvssScore -eq "N/A"){0}else{[float]$_.CvssScore}};Descending=$true})) {
                $exp = if ($cve.Exploited) { "YES" } else { "-" }
                $likely = if ($cve.ExploitationLikely) { "YES" } else { "-" }
                $disc = if ($cve.PubliclyDisclosed) { "YES" } else { "-" }
                [void]$md.AppendLine("| [$($cve.CVE)]($($cve.URL)) | $($cve.CvssScore) | $($cve.Criticality) | $exp | $likely | $disc | $($cve.Title) |")
            }
            
            $md.ToString() | Out-File $filePath -Encoding UTF8
            Write-CustodianLog "Report exported: $filePath" -Level SUCCESS
        }
        
        "HTML" {
            $filePath = Join-Path $OutputPath "PatchTuesday_${dateStr}.html"
            $exploitedCount = ($allVulns | Where-Object Exploited).Count
            $likelyCount = ($allVulns | Where-Object ExploitationLikely).Count
            $highCount = ($allVulns | Where-Object HighRated).Count
            
            $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>$reportTitle</title>
    <style>
        body { font-family: 'Segoe UI', Arial, sans-serif; margin: 20px; background: #1e1e1e; color: #d4d4d4; }
        h1 { color: #569cd6; border-bottom: 2px solid #569cd6; padding-bottom: 10px; }
        h2 { color: #4ec9b0; margin-top: 30px; }
        table { border-collapse: collapse; width: 100%; margin: 15px 0; }
        th, td { border: 1px solid #3c3c3c; padding: 10px; text-align: left; }
        th { background: #2d2d2d; color: #9cdcfe; }
        tr:nth-child(even) { background: #252526; }
        tr:hover { background: #2a2d2e; }
        .critical { background: #5c2020 !important; color: #f48771; }
        .warning { background: #5c4d20 !important; color: #dcdcaa; }
        .info { background: #203c5c !important; }
        a { color: #4fc1ff; text-decoration: none; }
        a:hover { text-decoration: underline; }
        .summary-box { display: inline-block; padding: 15px 25px; margin: 10px; background: #2d2d2d; border-radius: 5px; }
        .summary-box.critical { border-left: 4px solid #f14c4c; }
        .summary-box.warning { border-left: 4px solid #cca700; }
        .summary-box.info { border-left: 4px solid #3794ff; }
        .count { font-size: 28px; font-weight: bold; }
    </style>
</head>
<body>
    <h1>$reportTitle</h1>
    <p>Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | Total Vulnerabilities: $($allVulns.Count)</p>
    
    <div>
        <div class="summary-box critical"><div class="count">$exploitedCount</div>Actively Exploited</div>
        <div class="summary-box warning"><div class="count">$likelyCount</div>Exploitation Likely</div>
        <div class="summary-box info"><div class="count">$highCount</div>High Rated</div>
    </div>
"@
            
            $exploited = $allVulns | Where-Object Exploited | Sort-Object CvssScore -Descending
            if ($exploited.Count -gt 0) {
                $html += "<h2>Actively Exploited Vulnerabilities</h2><table><tr><th>CVE</th><th>CVSS</th><th>Criticality</th><th>Title</th></tr>"
                foreach ($cve in $exploited) {
                    $html += "<tr class='critical'><td><a href='$($cve.URL)' target='_blank'>$($cve.CVE)</a></td><td>$($cve.CvssScore)</td><td>$($cve.Criticality)</td><td>$($cve.Title)</td></tr>"
                }
                $html += "</table>"
            }
            
            $likely = $allVulns | Where-Object { $_.ExploitationLikely -and -not $_.Exploited } | Sort-Object CvssScore -Descending
            if ($likely.Count -gt 0) {
                $html += "<h2>Exploitation More Likely</h2><table><tr><th>CVE</th><th>CVSS</th><th>Criticality</th><th>Title</th></tr>"
                foreach ($cve in $likely) {
                    $html += "<tr class='warning'><td><a href='$($cve.URL)' target='_blank'>$($cve.CVE)</a></td><td>$($cve.CvssScore)</td><td>$($cve.Criticality)</td><td>$($cve.Title)</td></tr>"
                }
                $html += "</table>"
            }
            
            $html += "<h2>All Vulnerabilities</h2><table><tr><th>CVE</th><th>CVSS</th><th>Criticality</th><th>Exploited</th><th>Likely</th><th>Title</th></tr>"
            foreach ($cve in ($allVulns | Sort-Object @{Expression={if($_.CvssScore -eq "N/A"){0}else{[float]$_.CvssScore}};Descending=$true})) {
                $rowClass = if ($cve.Exploited) { "class='critical'" } elseif ($cve.ExploitationLikely) { "class='warning'" } else { "" }
                $exp = if ($cve.Exploited) { "YES" } else { "-" }
                $likely = if ($cve.ExploitationLikely) { "YES" } else { "-" }
                $html += "<tr $rowClass><td><a href='$($cve.URL)' target='_blank'>$($cve.CVE)</a></td><td>$($cve.CvssScore)</td><td>$($cve.Criticality)</td><td>$exp</td><td>$likely</td><td>$($cve.Title)</td></tr>"
            }
            $html += "</table></body></html>"
            
            $html | Out-File $filePath -Encoding UTF8
            Write-CustodianLog "Report exported: $filePath" -Level SUCCESS
            
            Start-Process $filePath
        }
    }
}

function Compare-CustodianPatchTuesday {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Month1,
        
        [string]$Month2
    )
    
    Write-CustodianLog "Comparing Patch Tuesday: $Month1 vs $Month2" -Level INFO
    Write-Host ""
    
    $data1 = Get-CustodianPatchTuesday -ReportDate $Month1 2>$null
    $data2 = Get-CustodianPatchTuesday -ReportDate $Month2 2>$null
    
    if ($null -eq $data1 -or $null -eq $data2) {
        Write-CustodianLog "Could not retrieve data for comparison" -Level ERROR
        return
    }
    
    Write-Host ""
    Write-Host "  =============================================" -ForegroundColor Cyan
    Write-Host "  PATCH TUESDAY COMPARISON" -ForegroundColor Cyan
    Write-Host "  =============================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Metric                    $($Month1.PadRight(12)) $Month2" -ForegroundColor White
    Write-Host "  ---------------------------------------------" -ForegroundColor Gray
    Write-Host "  Total CVEs                $($data1.Count.ToString().PadRight(12)) $($data2.Count)" -ForegroundColor Gray
    Write-Host "  Actively Exploited        $(($data1 | Where-Object Exploited).Count.ToString().PadRight(12)) $(($data2 | Where-Object Exploited).Count)" -ForegroundColor Red
    Write-Host "  Exploitation Likely       $(($data1 | Where-Object ExploitationLikely).Count.ToString().PadRight(12)) $(($data2 | Where-Object ExploitationLikely).Count)" -ForegroundColor Yellow
    Write-Host "  High Rated                $(($data1 | Where-Object HighRated).Count.ToString().PadRight(12)) $(($data2 | Where-Object HighRated).Count)" -ForegroundColor Cyan
    Write-Host ""
    
    return [PSCustomObject]@{
        Month1 = $Month1
        Month2 = $Month2
        Month1Data = $data1
        Month2Data = $data2
        Month1Total = $data1.Count
        Month2Total = $data2.Count
        Month1Exploited = ($data1 | Where-Object Exploited).Count
        Month2Exploited = ($data2 | Where-Object Exploited).Count
    }
}

#endregion

#region Module Export

Export-ModuleMember -Function @(
    'Get-CustodianPatchTuesday',
    'Get-CustodianExploitedCVEs',
    'Get-CustodianPriorityPatches',
    'Export-CustodianPatchReport',
    'Compare-CustodianPatchTuesday'
)

#endregion