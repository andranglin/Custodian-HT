#Requires -RunAsAdministrator

Write-Host "=== Custodian-HT Target Configuration ===" -ForegroundColor Cyan
Write-Host ""

# 1. Enable PowerShell Remoting
#    - Starts WinRM service
#    - Sets startup type to Automatic
#    - Creates a listener on 5985
#    - Enables Windows Firewall exception
Write-Host "[1/3] Enabling PowerShell Remoting..." -ForegroundColor Yellow
try {
    Enable-PSRemoting -Force -ErrorAction Stop
    Write-Host "[+] PS Remoting enabled." -ForegroundColor Green
} catch {
    Write-Host "[-] Failed to enable PS Remoting: $_" -ForegroundColor Red
    Write-Host "    (This might happen if the network connection type is set to 'Public'. Change it to 'Private' or 'Domain'.)" -ForegroundColor Gray
}

# 2. Configure LocalAccountTokenFilterPolicy
#    Crucial for connecting with local admin accounts (non-domain)
#    Without this, you will get "Access is Denied" even with correct credentials.
Write-Host "[2/3] Configuring Local Admin Access (Registry)..." -ForegroundColor Yellow
$regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$regName = "LocalAccountTokenFilterPolicy"

try {
    if (-not (Test-Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
    }
    
    New-ItemProperty -Path $regPath -Name $regName -Value 1 -PropertyType DWord -Force | Out-Null
    Write-Host "[+] LocalAccountTokenFilterPolicy set to 1." -ForegroundColor Green
} catch {
    Write-Host "[-] Failed to set registry key: $_" -ForegroundColor Red
}

# 3. Restart WinRM Service to apply changes
Write-Host "[3/3] Restarting WinRM Service..." -ForegroundColor Yellow
Restart-Service WinRM -Force
Write-Host "[+] WinRM Service restarted." -ForegroundColor Green

# 4. Verification
Write-Host ""
Write-Host "=== Status Verification ===" -ForegroundColor Cyan

# Check Listener
$listeners = Get-ChildItem WSMan:\Localhost\Listener
if ($listeners) {
    Write-Host "Listeners found:" -ForegroundColor Green
    $listeners | Select-Object Keys
} else {
    Write-Host "No WinRM Listeners found!" -ForegroundColor Red
}

# Check Firewall Rule (Basic check)
$fw = Get-NetFirewallRule -DisplayName "Windows Remote Management (HTTP-In)" -ErrorAction SilentlyContinue
if ($fw -and $fw.Enabled -eq 'True') {
    Write-Host "Firewall Rule (HTTP-In): Enabled" -ForegroundColor Green
} else {
    Write-Host "Firewall Rule (HTTP-In): Disabled or Not Found" -ForegroundColor Red
}

Write-Host ""
Write-Host "Target is ready. You can now connect from Custodian-HT." -ForegroundColor Cyan
Write-Host "IP Address: $(Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -notmatch 'Loopback' } | Select-Object -ExpandProperty IPAddress -First 1)" -ForegroundColor Gray