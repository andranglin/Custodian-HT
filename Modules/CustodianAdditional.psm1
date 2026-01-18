#Requires -Version 5.1
<#
.SYNOPSIS
    Custodian-HT Additional Forensic Modules
.DESCRIPTION
    Additional forensic collection modules including DDE analysis, IFEO, print monitors,
    netsh helpers, WDigest, WSL detection, browser extensions, and Office addins.
.AUTHOR
    RootGuard Cyber Defence
.VERSION
    1.0.0
#>

#region DDE Analysis
function Get-CustodianDDEAnalysis {
    <#
    .SYNOPSIS
        Analyze Dynamic Data Exchange (DDE) registry settings
    #>
    [CmdletBinding()]
    param(
        [string]$ComputerName = "localhost",
        [PSCredential]$Credential,
        [string]$OutputPath = (Get-CustodianPath -PathType "Collection")
    )
    
    $scriptBlock = {
        $ddeData = @()
        
        # Office DDE settings
        $officeVersions = @("16.0", "15.0", "14.0", "12.0")  # 2016, 2013, 2010, 2007
        $officeApps = @("Word", "Excel", "PowerPoint")
        
        foreach ($version in $officeVersions) {
            foreach ($app in $officeApps) {
                $path = "HKCU:\Software\Microsoft\Office\$version\$app\Options"
                if (Test-Path $path) {
                    $dde = Get-ItemProperty -Path $path -Name "DontUpdateLinks" -ErrorAction SilentlyContinue
                    $ddeData += [PSCustomObject]@{
                        Application = "$app $version"
                        Setting = "DontUpdateLinks"
                        Value = $dde.DontUpdateLinks
                        Path = $path
                        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                    }
                }
            }
        }
        
        return $ddeData
    }
    
    try {
        Write-CustodianLog "Analyzing DDE settings on $ComputerName..." -Level "INFO"
        
        if ($ComputerName -eq "localhost") {
            $data = Invoke-Command -ScriptBlock $scriptBlock
        } else {
            $data = Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock $scriptBlock
        }
        
        if ($data) {
            Export-CustodianData -Data $data -FileName "DDEAnalysis.csv" -OutputPath $OutputPath -Format CSV
            Write-CustodianLog "DDE analysis complete: $($data.Count) settings" -Level "SUCCESS"
        }
        
        return $data
        
    } catch {
        Write-CustodianLog "Failed to analyze DDE settings: $_" -Level "ERROR"
        return $null
    }
}
#endregion

#region Print Monitors
function Get-CustodianPrintMonitors {
    <#
    .SYNOPSIS
        Collect print monitor DLLs (potential persistence mechanism)
    #>
    [CmdletBinding()]
    param(
        [string]$ComputerName = "localhost",
        [PSCredential]$Credential,
        [string]$OutputPath = (Get-CustodianPath -PathType "Collection")
    )
    
    $scriptBlock = {
        $monitorPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Monitors"
        
        if (Test-Path $monitorPath) {
            Get-ChildItem $monitorPath | ForEach-Object {
                $driver = Get-ItemProperty -Path $_.PSPath -Name "Driver" -ErrorAction SilentlyContinue
                [PSCustomObject]@{
                    MonitorName = $_.PSChildName
                    Driver = $driver.Driver
                    RegistryPath = $_.PSPath
                    Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                }
            }
        }
    }
    
    try {
        Write-CustodianLog "Collecting print monitors from $ComputerName..." -Level "INFO"
        
        if ($ComputerName -eq "localhost") {
            $data = Invoke-Command -ScriptBlock $scriptBlock
        } else {
            $data = Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock $scriptBlock
        }
        
        if ($data) {
            Export-CustodianData -Data $data -FileName "PrintMonitors.csv" -OutputPath $OutputPath -Format CSV
            Write-CustodianLog "Print monitors collected: $($data.Count) monitors" -Level "SUCCESS"
        }
        
        return $data
        
    } catch {
        Write-CustodianLog "Failed to collect print monitors: $_" -Level "ERROR"
        return $null
    }
}
#endregion

#region IFEO (Image File Execution Options)
function Get-CustodianIFEO {
    <#
    .SYNOPSIS
        Collect Image File Execution Options (debugging/hijacking)
    #>
    [CmdletBinding()]
    param(
        [string]$ComputerName = "localhost",
        [PSCredential]$Credential,
        [string]$OutputPath = (Get-CustodianPath -PathType "Collection")
    )
    
    $scriptBlock = {
        $ifeoPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
        
        if (Test-Path $ifeoPath) {
            Get-ChildItem $ifeoPath | ForEach-Object {
                $debugger = Get-ItemProperty -Path $_.PSPath -Name "Debugger" -ErrorAction SilentlyContinue
                if ($debugger) {
                    [PSCustomObject]@{
                        ImageName = $_.PSChildName
                        Debugger = $debugger.Debugger
                        RegistryPath = $_.PSPath
                        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                    }
                }
            }
        }
    }
    
    try {
        Write-CustodianLog "Collecting IFEO entries from $ComputerName..." -Level "INFO"
        
        if ($ComputerName -eq "localhost") {
            $data = Invoke-Command -ScriptBlock $scriptBlock
        } else {
            $data = Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock $scriptBlock
        }
        
        if ($data) {
            Export-CustodianData -Data $data -FileName "IFEO.csv" -OutputPath $OutputPath -Format CSV
            Write-CustodianLog "IFEO entries collected: $($data.Count) entries" -Level "SUCCESS"
        } else {
            Write-CustodianLog "No IFEO debuggers configured" -Level "INFO"
        }
        
        return $data
        
    } catch {
        Write-CustodianLog "Failed to collect IFEO: $_" -Level "ERROR"
        return $null
    }
}
#endregion

#region Netsh Helpers
function Get-CustodianNetshHelpers {
    <#
    .SYNOPSIS
        Collect netsh helper DLLs (persistence mechanism)
    #>
    [CmdletBinding()]
    param(
        [string]$ComputerName = "localhost",
        [PSCredential]$Credential,
        [string]$OutputPath = (Get-CustodianPath -PathType "Collection")
    )
    
    $scriptBlock = {
        $netshPath = "HKLM:\SOFTWARE\Microsoft\NetSh"
        
        if (Test-Path $netshPath) {
            Get-ChildItem $netshPath | ForEach-Object {
                $helper = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue
                [PSCustomObject]@{
                    HelperName = $_.PSChildName
                    DLLName = $helper.'(default)'
                    RegistryPath = $_.PSPath
                    Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                }
            }
        }
    }
    
    try {
        Write-CustodianLog "Collecting netsh helpers from $ComputerName..." -Level "INFO"
        
        if ($ComputerName -eq "localhost") {
            $data = Invoke-Command -ScriptBlock $scriptBlock
        } else {
            $data = Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock $scriptBlock
        }
        
        if ($data) {
            Export-CustodianData -Data $data -FileName "NetshHelpers.csv" -OutputPath $OutputPath -Format CSV
            Write-CustodianLog "Netsh helpers collected: $($data.Count) helpers" -Level "SUCCESS"
        }
        
        return $data
        
    } catch {
        Write-CustodianLog "Failed to collect netsh helpers: $_" -Level "ERROR"
        return $null
    }
}
#endregion

#region WDigest
function Get-CustodianWDigest {
    <#
    .SYNOPSIS
        Check WDigest credential caching setting
    #>
    [CmdletBinding()]
    param(
        [string]$ComputerName = "localhost",
        [PSCredential]$Credential,
        [string]$OutputPath = (Get-CustodianPath -PathType "Collection")
    )
    
    $scriptBlock = {
        $wdigestPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
        
        if (Test-Path $wdigestPath) {
            $useLogonCredential = Get-ItemProperty -Path $wdigestPath -Name "UseLogonCredential" -ErrorAction SilentlyContinue
            
            [PSCustomObject]@{
                Setting = "UseLogonCredential"
                Value = if ($useLogonCredential) { $useLogonCredential.UseLogonCredential } else { "Not Set" }
                Interpretation = if ($useLogonCredential.UseLogonCredential -eq 1) { "ENABLED - Credentials cached in memory" } else { "Disabled or Not Set" }
                RegistryPath = $wdigestPath
                Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            }
        } else {
            [PSCustomObject]@{
                Setting = "WDigest"
                Value = "Key Not Found"
                Interpretation = "Default (likely disabled on Windows 10+)"
                RegistryPath = $wdigestPath
                Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            }
        }
    }
    
    try {
        Write-CustodianLog "Checking WDigest setting on $ComputerName..." -Level "INFO"
        
        if ($ComputerName -eq "localhost") {
            $data = Invoke-Command -ScriptBlock $scriptBlock
        } else {
            $data = Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock $scriptBlock
        }
        
        if ($data) {
            Export-CustodianData -Data $data -FileName "WDigest.csv" -OutputPath $OutputPath -Format CSV
            Write-CustodianLog "WDigest setting: $($data.Interpretation)" -Level "SUCCESS"
        }
        
        return $data
        
    } catch {
        Write-CustodianLog "Failed to check WDigest: $_" -Level "ERROR"
        return $null
    }
}
#endregion

#region WSL Detection
function Get-CustodianWSLDetection {
    <#
    .SYNOPSIS
        Detect Windows Subsystem for Linux installation
    #>
    [CmdletBinding()]
    param(
        [string]$ComputerName = "localhost",
        [PSCredential]$Credential,
        [string]$OutputPath = (Get-CustodianPath -PathType "Collection")
    )
    
    $scriptBlock = {
        $wslData = @()
        
        # Check WSL feature
        $wslFeature = Get-WindowsOptionalFeature -Online -FeatureName "Microsoft-Windows-Subsystem-Linux" -ErrorAction SilentlyContinue
        
        if ($wslFeature) {
            $wslData += [PSCustomObject]@{
                Component = "WSL Feature"
                State = $wslFeature.State
                Details = "Windows Subsystem for Linux"
                Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            }
        }
        
        # Check for installed distributions
        $distros = Get-ChildItem "HKCU:\Software\Microsoft\Windows\CurrentVersion\Lxss" -ErrorAction SilentlyContinue
        foreach ($distro in $distros) {
            $props = Get-ItemProperty -Path $distro.PSPath -ErrorAction SilentlyContinue
            $wslData += [PSCustomObject]@{
                Component = "WSL Distribution"
                State = "Installed"
                Details = $props.DistributionName
                BasePath = $props.BasePath
                Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            }
        }
        
        return $wslData
    }
    
    try {
        Write-CustodianLog "Detecting WSL on $ComputerName..." -Level "INFO"
        
        if ($ComputerName -eq "localhost") {
            $data = Invoke-Command -ScriptBlock $scriptBlock
        } else {
            $data = Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock $scriptBlock
        }
        
        if ($data) {
            Export-CustodianData -Data $data -FileName "WSLDetection.csv" -OutputPath $OutputPath -Format CSV
            Write-CustodianLog "WSL detection complete: $($data.Count) components" -Level "SUCCESS"
        } else {
            Write-CustodianLog "WSL not detected" -Level "INFO"
        }
        
        return $data
        
    } catch {
        Write-CustodianLog "Failed to detect WSL: $_" -Level "ERROR"
        return $null
    }
}
#endregion

#region Browser Extensions
function Get-CustodianBrowserExtensions {
    <#
    .SYNOPSIS
        Collect browser extensions (Chrome, Edge, Firefox)
    #>
    [CmdletBinding()]
    param(
        [string]$ComputerName = "localhost",
        [PSCredential]$Credential,
        [string]$OutputPath = (Get-CustodianPath -PathType "Collection")
    )
    
    $scriptBlock = {
        $extensions = @()
        
        # Chrome extensions
        $chromePath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Extensions"
        if (Test-Path $chromePath) {
            Get-ChildItem $chromePath -Directory | ForEach-Object {
                $extensions += [PSCustomObject]@{
                    Browser = "Chrome"
                    ExtensionID = $_.Name
                    Path = $_.FullName
                    Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                }
            }
        }
        
        # Edge extensions
        $edgePath = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Extensions"
        if (Test-Path $edgePath) {
            Get-ChildItem $edgePath -Directory | ForEach-Object {
                $extensions += [PSCustomObject]@{
                    Browser = "Edge"
                    ExtensionID = $_.Name
                    Path = $_.FullName
                    Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                }
            }
        }
        
        # Firefox extensions
        $firefoxPath = "$env:APPDATA\Mozilla\Firefox\Profiles"
        if (Test-Path $firefoxPath) {
            Get-ChildItem $firefoxPath -Directory | ForEach-Object {
                $extPath = Join-Path $_.FullName "extensions"
                if (Test-Path $extPath) {
                    Get-ChildItem $extPath -File -Filter "*.xpi" | ForEach-Object {
                        $extensions += [PSCustomObject]@{
                            Browser = "Firefox"
                            ExtensionID = $_.BaseName
                            Path = $_.FullName
                            Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                        }
                    }
                }
            }
        }
        
        return $extensions
    }
    
    try {
        Write-CustodianLog "Collecting browser extensions from $ComputerName..." -Level "INFO"
        
        if ($ComputerName -eq "localhost") {
            $data = Invoke-Command -ScriptBlock $scriptBlock
        } else {
            $data = Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock $scriptBlock
        }
        
        if ($data) {
            Export-CustodianData -Data $data -FileName "BrowserExtensions.csv" -OutputPath $OutputPath -Format CSV
            Write-CustodianLog "Browser extensions collected: $($data.Count) extensions" -Level "SUCCESS"
        }
        
        return $data
        
    } catch {
        Write-CustodianLog "Failed to collect browser extensions: $_" -Level "ERROR"
        return $null
    }
}
#endregion

#region Office Addins
function Get-CustodianOfficeAddins {
    <#
    .SYNOPSIS
        Collect Microsoft Office addins
    #>
    [CmdletBinding()]
    param(
        [string]$ComputerName = "localhost",
        [PSCredential]$Credential,
        [string]$OutputPath = (Get-CustodianPath -PathType "Collection")
    )
    
    $scriptBlock = {
        $addins = @()
        
        $officeVersions = @("16.0", "15.0", "14.0", "12.0")
        $officeApps = @("Word", "Excel", "PowerPoint", "Outlook")
        $addinTypes = @("Addins", "Resiliency\DisabledItems")
        
        foreach ($version in $officeVersions) {
            foreach ($app in $officeApps) {
                foreach ($type in $addinTypes) {
                    $path = "HKCU:\Software\Microsoft\Office\$version\$app\$type"
                    if (Test-Path $path) {
                        $items = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
                        $items.PSObject.Properties | Where-Object {$_.Name -notlike 'PS*'} | ForEach-Object {
                            $addins += [PSCustomObject]@{
                                Application = "$app $version"
                                Type = $type
                                Name = $_.Name
                                Value = $_.Value
                                Path = $path
                                Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                            }
                        }
                    }
                }
            }
        }
        
        return $addins
    }
    
    try {
        Write-CustodianLog "Collecting Office addins from $ComputerName..." -Level "INFO"
        
        if ($ComputerName -eq "localhost") {
            $data = Invoke-Command -ScriptBlock $scriptBlock
        } else {
            $data = Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock $scriptBlock
        }
        
        if ($data) {
            Export-CustodianData -Data $data -FileName "OfficeAddins.csv" -OutputPath $OutputPath -Format CSV
            Write-CustodianLog "Office addins collected: $($data.Count) addins" -Level "SUCCESS"
        }
        
        return $data
        
    } catch {
        Write-CustodianLog "Failed to collect Office addins: $_" -Level "ERROR"
        return $null
    }
}
#endregion

#region Export Module Members
Export-ModuleMember -Function `
    Get-CustodianDDEAnalysis,
    Get-CustodianPrintMonitors,
    Get-CustodianIFEO,
    Get-CustodianNetshHelpers,
    Get-CustodianWDigest,
    Get-CustodianWSLDetection,
    Get-CustodianBrowserExtensions,
    Get-CustodianOfficeAddins
#endregion