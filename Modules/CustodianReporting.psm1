#Requires -Version 5.1
<#
.SYNOPSIS
    Custodian-HT Reporting Module
.DESCRIPTION
    Provides report generation, data export, and IOC extraction functions
.AUTHOR
    RootGuard Cyber Defence
.VERSION
    1.3.0 - CSV reading and HTML report generation with verbose output
#>

#region Helper Functions

function Write-CustodianLog {
    param(
        [string]$Message,
        [ValidateSet("INFO","SUCCESS","WARN","ERROR")][string]$Level = "INFO"
    )
    $colors = @{ INFO = "Cyan"; SUCCESS = "Green"; WARN = "Yellow"; ERROR = "Red" }
    $prefix = @{ INFO = "[*]"; SUCCESS = "[+]"; WARN = "[!]"; ERROR = "[-]" }
    Write-Host "$($prefix[$Level]) $Message" -ForegroundColor $colors[$Level]
}

function Export-CustodianData {
    <#
    .SYNOPSIS
        Export data to CSV or JSON with null handling
    .PARAMETER Data
        Data to export
    .PARAMETER OutputPath
        Output directory
    .PARAMETER FileName
        Output filename
    .PARAMETER Format
        Output format: CSV or JSON (default: CSV)
    .PARAMETER Append
        Append to existing file (CSV only)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowNull()][AllowEmptyCollection()]$Data,
        [Parameter(Mandatory)][string]$OutputPath,
        [Parameter(Mandatory)][string]$FileName,
        [ValidateSet("CSV","JSON")][string]$Format = "CSV",
        [switch]$Append
    )
    
    # Handle null or empty data
    if ($null -eq $Data -or @($Data).Count -eq 0) {
        Write-CustodianLog "No data to export for $FileName" -Level "WARN"
        return $null
    }
    
    # Ensure output directory exists
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }
    
    try {
        $filePath = Join-Path $OutputPath $FileName
        
        switch ($Format.ToUpper()) {
            "JSON" {
                $Data | ConvertTo-Json -Depth 10 | Out-File -FilePath $filePath -Encoding UTF8 -Force
            }
            default {
                # CSV
                if ($Append -and (Test-Path $filePath)) {
                    @($Data) | Export-Csv -Path $filePath -NoTypeInformation -Append
                } else {
                    @($Data) | Export-Csv -Path $filePath -NoTypeInformation -Force
                }
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

#region HTML Report Generation

function New-CustodianTriageReport {
    <#
    .SYNOPSIS
        Generate comprehensive HTML triage report from collected CSV data
    .DESCRIPTION
        Reads all CSV files from triage folder and generates interactive HTML report
        with tabbed interface, searchable tables, and summary statistics
    .PARAMETER InputPath
        Path to the triage folder containing CSV files
    .PARAMETER CaseName
        Case identifier for the report
    .PARAMETER Analyst
        Analyst name (default: current user)
    .EXAMPLE
        New-CustodianTriageReport -InputPath "C:\Triage\Case001" -CaseName "IR-2026-001"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$InputPath,
        [Parameter(Mandatory)][string]$CaseName,
        [string]$Analyst = $env:USERNAME
    )
    
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  GENERATING HTML TRIAGE REPORT" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    
    # Validate input path
    if (-not (Test-Path $InputPath)) {
        Write-Host "[-] ERROR: Input path not found: $InputPath" -ForegroundColor Red
        return $null
    }
    
    Write-Host "[*] Input folder: $InputPath" -ForegroundColor Cyan
    
    # Find all CSV files
    $csvFiles = @(Get-ChildItem -Path $InputPath -Filter "*.csv" -File -ErrorAction SilentlyContinue)
    
    Write-Host "[*] Found $($csvFiles.Count) CSV files" -ForegroundColor Cyan
    
    if ($csvFiles.Count -eq 0) {
        Write-Host "[-] ERROR: No CSV files found in $InputPath" -ForegroundColor Red
        Write-Host "    Make sure collection completed successfully" -ForegroundColor Yellow
        return $null
    }
    
    # List found files
    Write-Host ""
    Write-Host "CSV Files Found:" -ForegroundColor Yellow
    foreach ($f in $csvFiles) {
        $size = [math]::Round($f.Length / 1KB, 1)
        Write-Host "    - $($f.Name) ($size KB)" -ForegroundColor Gray
    }
    Write-Host ""
    
    # Load data from each CSV
    $dataSections = @()
    
    foreach ($csv in $csvFiles) {
        Write-Host "[*] Loading: $($csv.Name)..." -ForegroundColor Cyan -NoNewline
        
        try {
            # Read CSV content
            $rawData = @(Import-Csv -Path $csv.FullName -ErrorAction Stop)
            
            if ($rawData.Count -gt 0) {
                # Get column names from first row
                $columns = @($rawData[0].PSObject.Properties.Name)
                
                # Create section object
                $section = [PSCustomObject]@{
                    Name = ($csv.BaseName -replace '_', ' ' -replace '-', ' ')
                    FileName = $csv.Name
                    Data = $rawData
                    Count = $rawData.Count
                    Columns = $columns
                }
                
                $dataSections += $section
                Write-Host " $($rawData.Count) records" -ForegroundColor Green
            } else {
                Write-Host " empty file" -ForegroundColor Yellow
            }
        } catch {
            Write-Host " FAILED: $_" -ForegroundColor Red
        }
    }
    
    Write-Host ""
    
    if ($dataSections.Count -eq 0) {
        Write-Host "[-] ERROR: No valid data loaded from CSV files" -ForegroundColor Red
        return $null
    }
    
    Write-Host "[+] Loaded $($dataSections.Count) data sections" -ForegroundColor Green
    
    # Calculate statistics
    $totalRecords = ($dataSections | ForEach-Object { $_.Count } | Measure-Object -Sum).Sum
    
    # Find specific categories for stats
    $netCount = ($dataSections | Where-Object { $_.Name -match 'Network|Connection' } | ForEach-Object { $_.Count } | Measure-Object -Sum).Sum
    $procCount = ($dataSections | Where-Object { $_.Name -match 'Process' } | ForEach-Object { $_.Count } | Measure-Object -Sum).Sum
    $svcCount = ($dataSections | Where-Object { $_.Name -match 'Service' } | ForEach-Object { $_.Count } | Measure-Object -Sum).Sum
    $taskCount = ($dataSections | Where-Object { $_.Name -match 'Task|Scheduled' } | ForEach-Object { $_.Count } | Measure-Object -Sum).Sum
    $autoCount = ($dataSections | Where-Object { $_.Name -match 'Autorun|Startup|Run' } | ForEach-Object { $_.Count } | Measure-Object -Sum).Sum
    
    if (-not $netCount) { $netCount = 0 }
    if (-not $procCount) { $procCount = 0 }
    if (-not $svcCount) { $svcCount = 0 }
    if (-not $taskCount) { $taskCount = 0 }
    if (-not $autoCount) { $autoCount = 0 }
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $computerName = $env:COMPUTERNAME
    $reportFile = Join-Path $InputPath "TriageReport_$CaseName.html"
    
    Write-Host "[*] Building HTML report..." -ForegroundColor Cyan
    
    # Build HTML content
    $htmlBuilder = [System.Text.StringBuilder]::new()
    
    # HTML Header
    [void]$htmlBuilder.AppendLine(@"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Custodian-HT Triage Report - $CaseName</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: 'Segoe UI', Tahoma, sans-serif; background: #f0f2f5; color: #333; line-height: 1.6; }
        .container { max-width: 1800px; margin: 0 auto; padding: 20px; }
        
        header { background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); color: white; padding: 30px; margin-bottom: 25px; border-radius: 12px; box-shadow: 0 4px 15px rgba(0,0,0,0.2); }
        header h1 { font-size: 2.2em; margin-bottom: 8px; }
        header .subtitle { opacity: 0.85; font-size: 1.1em; }
        
        .meta-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin-top: 25px; }
        .meta-item { background: rgba(255,255,255,0.1); padding: 15px 20px; border-radius: 8px; }
        .meta-item .label { font-size: 0.8em; opacity: 0.7; text-transform: uppercase; letter-spacing: 0.5px; }
        .meta-item .value { font-size: 1.15em; font-weight: 600; margin-top: 5px; }
        
        .stats-grid { display: grid; grid-template-columns: repeat(6, 1fr); gap: 15px; margin-bottom: 25px; }
        .stat-card { background: white; padding: 25px 20px; border-radius: 12px; text-align: center; box-shadow: 0 2px 8px rgba(0,0,0,0.06); border-left: 4px solid #1a73e8; transition: transform 0.2s, box-shadow 0.2s; }
        .stat-card:hover { transform: translateY(-3px); box-shadow: 0 4px 15px rgba(0,0,0,0.1); }
        .stat-card .number { font-size: 2.5em; font-weight: 700; color: #1a73e8; }
        .stat-card .label { color: #666; font-size: 0.9em; margin-top: 8px; }
        
        .tabs { display: flex; flex-wrap: wrap; gap: 8px; background: white; padding: 15px; border-radius: 12px; margin-bottom: 20px; box-shadow: 0 2px 8px rgba(0,0,0,0.06); }
        .tab-btn { padding: 12px 20px; border: none; background: #e9ecef; border-radius: 8px; cursor: pointer; font-size: 0.9em; transition: all 0.2s; display: flex; align-items: center; gap: 10px; }
        .tab-btn:hover { background: #dee2e6; }
        .tab-btn.active { background: #1a73e8; color: white; }
        .tab-btn .badge { background: rgba(0,0,0,0.15); padding: 3px 10px; border-radius: 12px; font-size: 0.85em; font-weight: 600; }
        .tab-btn.active .badge { background: rgba(255,255,255,0.25); }
        
        .panel { display: none; background: white; border-radius: 12px; padding: 25px; box-shadow: 0 2px 8px rgba(0,0,0,0.06); }
        .panel.active { display: block; }
        .panel h2 { color: #1a1a2e; margin-bottom: 20px; padding-bottom: 15px; border-bottom: 2px solid #e9ecef; display: flex; justify-content: space-between; align-items: center; }
        .panel h2 .info { font-size: 0.55em; font-weight: 400; color: #666; background: #f0f2f5; padding: 6px 15px; border-radius: 20px; }
        
        .search-box { margin-bottom: 20px; }
        .search-box input { width: 100%; max-width: 450px; padding: 14px 18px; border: 2px solid #e9ecef; border-radius: 10px; font-size: 1em; transition: border-color 0.2s, box-shadow 0.2s; }
        .search-box input:focus { outline: none; border-color: #1a73e8; box-shadow: 0 0 0 3px rgba(26,115,232,0.1); }
        
        .table-container { overflow-x: auto; border: 1px solid #e9ecef; border-radius: 10px; max-height: 650px; overflow-y: auto; }
        table { width: 100%; border-collapse: collapse; font-size: 0.88em; }
        th { background: #f8f9fa; padding: 14px 16px; text-align: left; font-weight: 600; color: #1a1a2e; position: sticky; top: 0; z-index: 10; border-bottom: 2px solid #e9ecef; }
        td { padding: 12px 16px; border-bottom: 1px solid #f0f2f5; max-width: 350px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        tr:hover td { background: #f8f9fa; }
        td:hover { white-space: normal; word-break: break-word; }
        
        footer { text-align: center; padding: 30px; color: #888; font-size: 0.85em; margin-top: 30px; border-top: 1px solid #e9ecef; }
        
        @media (max-width: 1200px) { .meta-grid { grid-template-columns: repeat(2, 1fr); } .stats-grid { grid-template-columns: repeat(3, 1fr); } }
        @media (max-width: 768px) { .stats-grid { grid-template-columns: repeat(2, 1fr); } .tabs { gap: 5px; } .tab-btn { padding: 10px 15px; font-size: 0.85em; } }
        @media print { .tabs, .search-box { display: none; } .panel { display: block !important; page-break-inside: avoid; } }
    </style>
</head>
<body>
<div class="container">
    <header>
        <h1>Custodian-HT Triage Report</h1>
        <div class="subtitle">Threat Hunting and Digital Forensics Toolkit</div>
        <div class="meta-grid">
            <div class="meta-item"><div class="label">Case Name</div><div class="value">$CaseName</div></div>
            <div class="meta-item"><div class="label">Target System</div><div class="value">$computerName</div></div>
            <div class="meta-item"><div class="label">Analyst</div><div class="value">$Analyst</div></div>
            <div class="meta-item"><div class="label">Generated</div><div class="value">$timestamp</div></div>
        </div>
    </header>
    
    <div class="stats-grid">
        <div class="stat-card"><div class="number">$($dataSections.Count)</div><div class="label">Data Categories</div></div>
        <div class="stat-card"><div class="number">$totalRecords</div><div class="label">Total Records</div></div>
        <div class="stat-card"><div class="number">$netCount</div><div class="label">Network Connections</div></div>
        <div class="stat-card"><div class="number">$procCount</div><div class="label">Processes</div></div>
        <div class="stat-card"><div class="number">$svcCount</div><div class="label">Services</div></div>
        <div class="stat-card"><div class="number">$autoCount</div><div class="label">Autoruns</div></div>
    </div>
    
    <div class="tabs">
"@)

    # Generate tab buttons
    for ($i = 0; $i -lt $dataSections.Count; $i++) {
        $section = $dataSections[$i]
        $activeClass = if ($i -eq 0) { "active" } else { "" }
        [void]$htmlBuilder.AppendLine("        <button class=`"tab-btn $activeClass`" onclick=`"showPanel($i)`">$($section.Name)<span class=`"badge`">$($section.Count)</span></button>")
    }
    
    [void]$htmlBuilder.AppendLine("    </div>")
    
    # Generate data panels
    for ($i = 0; $i -lt $dataSections.Count; $i++) {
        $section = $dataSections[$i]
        $activeClass = if ($i -eq 0) { "active" } else { "" }
        
        [void]$htmlBuilder.AppendLine(@"
    <div class="panel $activeClass" id="panel$i">
        <h2>$($section.Name) <span class="info">$($section.Count) records from $($section.FileName)</span></h2>
        <div class="search-box">
            <input type="text" id="search$i" placeholder="Search in $($section.Name)..." onkeyup="filterTable($i)">
        </div>
        <div class="table-container">
            <table id="table$i">
                <thead><tr>
"@)
        
        # Add column headers
        foreach ($col in $section.Columns) {
            [void]$htmlBuilder.AppendLine("                    <th>$col</th>")
        }
        
        [void]$htmlBuilder.AppendLine("                </tr></thead>")
        [void]$htmlBuilder.AppendLine("                <tbody>")
        
        # Add data rows (max 2500 for performance)
        $rowLimit = 2500
        $rowNum = 0
        
        foreach ($row in $section.Data) {
            if ($rowNum -ge $rowLimit) {
                $remaining = $section.Count - $rowLimit
                [void]$htmlBuilder.AppendLine("                <tr><td colspan=`"$($section.Columns.Count)`" style=`"text-align:center;color:#888;font-style:italic;`">... $remaining additional rows not shown (limit: $rowLimit)</td></tr>")
                break
            }
            
            [void]$htmlBuilder.Append("                <tr>")
            
            foreach ($col in $section.Columns) {
                $val = $row.$col
                if ($null -eq $val) { $val = "" }
                
                # HTML encode
                $val = [string]$val
                $val = $val.Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;").Replace('"', "&quot;")
                
                # Truncate long values
                $displayVal = if ($val.Length -gt 150) { $val.Substring(0, 150) + "..." } else { $val }
                
                [void]$htmlBuilder.Append("<td title=`"$val`">$displayVal</td>")
            }
            
            [void]$htmlBuilder.AppendLine("</tr>")
            $rowNum++
        }
        
        [void]$htmlBuilder.AppendLine(@"
                </tbody>
            </table>
        </div>
    </div>
"@)
    }
    
    # Add footer and JavaScript
    [void]$htmlBuilder.AppendLine(@"
    <footer>
        <strong>Custodian-HT</strong> | Ridgeline Cyber Defence<br>
        Report: $reportFile
    </footer>
</div>

<script>
function showPanel(idx) {
    document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    document.getElementById('panel' + idx).classList.add('active');
    document.querySelectorAll('.tab-btn')[idx].classList.add('active');
}

function filterTable(idx) {
    var input = document.getElementById('search' + idx);
    var filter = input.value.toLowerCase();
    var table = document.getElementById('table' + idx);
    var rows = table.getElementsByTagName('tbody')[0].getElementsByTagName('tr');
    
    for (var i = 0; i < rows.length; i++) {
        var cells = rows[i].getElementsByTagName('td');
        var match = false;
        for (var j = 0; j < cells.length; j++) {
            if (cells[j].textContent.toLowerCase().indexOf(filter) > -1) {
                match = true;
                break;
            }
        }
        rows[i].style.display = match ? '' : 'none';
    }
}

document.addEventListener('keydown', function(e) {
    var btns = document.querySelectorAll('.tab-btn');
    var idx = Array.from(btns).findIndex(b => b.classList.contains('active'));
    if (e.key === 'ArrowRight' && idx < btns.length - 1) showPanel(idx + 1);
    if (e.key === 'ArrowLeft' && idx > 0) showPanel(idx - 1);
});
</script>
</body>
</html>
"@)

    # Write HTML file
    try {
        $htmlBuilder.ToString() | Out-File -FilePath $reportFile -Encoding UTF8 -Force
        
        Write-Host ""
        Write-Host "[+] HTML REPORT GENERATED SUCCESSFULLY!" -ForegroundColor Green
        Write-Host "    File: $reportFile" -ForegroundColor Gray
        Write-Host "    Sections: $($dataSections.Count)" -ForegroundColor Gray
        Write-Host "    Total Records: $totalRecords" -ForegroundColor Gray
        Write-Host ""
        
        # Open in browser
        try {
            Start-Process $reportFile -ErrorAction Stop
            Write-Host "[+] Report opened in default browser" -ForegroundColor Green
        } catch {
            Write-Host "[!] Could not auto-open. Please open manually:" -ForegroundColor Yellow
            Write-Host "    $reportFile" -ForegroundColor Cyan
        }
        
        return $reportFile
        
    } catch {
        Write-Host "[-] ERROR writing report: $_" -ForegroundColor Red
        return $null
    }
}

#endregion

#region IOC Extraction

function Export-CustodianIOCs {
    <#
    .SYNOPSIS
        Extract IOCs from collected data
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$InputPath,
        [ValidateSet("CSV","JSON")][string]$Format = "CSV",
        [string]$OutputPath
    )
    
    if (-not (Test-Path $InputPath)) {
        Write-CustodianLog "Input path not found" -Level "ERROR"
        return $null
    }
    
    if (-not $OutputPath) { $OutputPath = $InputPath }
    
    $iocs = @()
    $csvFiles = Get-ChildItem -Path $InputPath -Filter "*.csv" -ErrorAction SilentlyContinue
    
    foreach ($file in $csvFiles) {
        try {
            $data = @(Import-Csv $file.FullName -ErrorAction Stop)
            
            foreach ($row in $data) {
                # Extract IPs
                $ip = $row.RemoteAddress
                if (-not $ip) { $ip = $row.RemoteIP }
                if ($ip -and $ip -notmatch '^(127\.|0\.0\.0\.0|::1|::|\*|^$)') {
                    $iocs += [PSCustomObject]@{ Type = "IP"; Value = $ip; Context = "Network"; Source = $file.Name }
                }
                
                # Extract hashes
                $hash = $row.SHA256
                if (-not $hash) { $hash = $row.Hash }
                if (-not $hash) { $hash = $row.MD5 }
                if ($hash -and $hash.Length -ge 32) {
                    $ctx = if ($row.ProcessName) { $row.ProcessName } elseif ($row.Name) { $row.Name } else { "Unknown" }
                    $iocs += [PSCustomObject]@{ Type = "Hash"; Value = $hash; Context = $ctx; Source = $file.Name }
                }
            }
        } catch {}
    }
    
    $iocs = $iocs | Sort-Object Type, Value -Unique
    
    if ($iocs.Count -eq 0) {
        Write-CustodianLog "No IOCs found" -Level "WARN"
        return $null
    }
    
    $outFile = Join-Path $OutputPath "IOCs_$(Get-Date -Format 'yyyyMMdd_HHmmss').$($Format.ToLower())"
    
    if ($Format -eq "CSV") {
        $iocs | Export-Csv -Path $outFile -NoTypeInformation
    } else {
        $iocs | ConvertTo-Json -Depth 3 | Out-File $outFile -Encoding UTF8
    }
    
    Write-CustodianLog "Exported $($iocs.Count) IOCs to $outFile" -Level "SUCCESS"
    return $outFile
}

function Export-CustodianTimeline {
    <#
    .SYNOPSIS
        Generate timeline from collected data
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$InputPath,
        [string]$OutputPath
    )
    
    if (-not $OutputPath) { $OutputPath = $InputPath }
    
    $timeline = @()
    $csvFiles = Get-ChildItem -Path $InputPath -Filter "*.csv" -ErrorAction SilentlyContinue
    
    foreach ($file in $csvFiles) {
        try {
            $data = @(Import-Csv $file.FullName -ErrorAction Stop)
            if ($data.Count -eq 0) { continue }
            
            $timeCols = $data[0].PSObject.Properties.Name | Where-Object { $_ -match 'time|date|created|modified|when|timestamp' }
            
            foreach ($row in $data) {
                foreach ($col in $timeCols) {
                    if ($row.$col) {
                        try {
                            $dt = [datetime]::Parse($row.$col)
                            $timeline += [PSCustomObject]@{
                                Timestamp = $dt.ToString("yyyy-MM-dd HH:mm:ss")
                                Source = $file.BaseName
                                Field = $col
                                Data = ($row | ConvertTo-Json -Compress -Depth 1)
                            }
                        } catch {}
                    }
                }
            }
        } catch {}
    }
    
    if ($timeline.Count -eq 0) {
        Write-CustodianLog "No timeline events found" -Level "WARN"
        return $null
    }
    
    $timeline = $timeline | Sort-Object Timestamp
    $outFile = Join-Path $OutputPath "Timeline_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    $timeline | Export-Csv -Path $outFile -NoTypeInformation
    
    Write-CustodianLog "Timeline: $($timeline.Count) events" -Level "SUCCESS"
    return $outFile
}

#endregion

# Export module members
Export-ModuleMember -Function @(
    'Write-CustodianLog',
    'Export-CustodianData',
    'New-CustodianTriageReport',
    'Export-CustodianIOCs',
    'Export-CustodianTimeline'
)