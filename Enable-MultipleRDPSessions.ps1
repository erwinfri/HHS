<#
.SYNOPSIS
    Enable Remote Desktop for Multiple Users via Group Policy

.DESCRIPTION
    This script modifies the Group Policy setting to allow multiple concurrent
    Remote Desktop sessions by disabling the connection limit or setting it to
    a higher value.

.PARAMETER ConnectionLimit
    The maximum number of concurrent RDP connections to allow.
    Use 0 to disable the limit entirely (unlimited connections).
    Default is 0 (unlimited).

.PARAMETER RestartComputer
    If specified, the computer will restart automatically after applying changes.

.EXAMPLE
    .\Enable-MultipleRDPSessions.ps1
    Enables unlimited RDP sessions without automatic restart.

.EXAMPLE
    .\Enable-MultipleRDPSessions.ps1 -ConnectionLimit 5 -RestartComputer
    Sets the limit to 5 concurrent sessions and restarts the computer.

.NOTES
    - Requires Administrator privileges
    - Modifies Local Group Policy
    - Changes take effect after restart or gpupdate /force
    - Registry Path: HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [ValidateRange(0, 999999)]
    [int]$ConnectionLimit = 0,
    
    [Parameter(Mandatory=$false)]
    [switch]$RestartComputer
)

# Check if running as Administrator
function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Main script execution
try {
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "Enable Multiple RDP Sessions Script" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""

    # Verify Administrator privileges
    if (-not (Test-Administrator)) {
        Write-Host "ERROR: This script requires Administrator privileges!" -ForegroundColor Red
        Write-Host "Please run PowerShell as Administrator and try again." -ForegroundColor Yellow
        exit 1
    }

    Write-Host "[✓] Running with Administrator privileges" -ForegroundColor Green
    Write-Host ""

    # Define registry path for Terminal Services policies
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
    
    # Create registry path if it doesn't exist
    if (-not (Test-Path $regPath)) {
        Write-Host "[*] Creating registry path: $regPath" -ForegroundColor Yellow
        New-Item -Path $regPath -Force | Out-Null
        Write-Host "[✓] Registry path created successfully" -ForegroundColor Green
    } else {
        Write-Host "[✓] Registry path exists: $regPath" -ForegroundColor Green
    }
    Write-Host ""

    # Backup current settings
    Write-Host "[*] Backing up current settings..." -ForegroundColor Yellow
    $backupFile = "$env:TEMP\RDP_Settings_Backup_$(Get-Date -Format 'yyyyMMdd_HHmmss').reg"
    
    try {
        reg export "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" $backupFile /y | Out-Null
        Write-Host "[✓] Backup saved to: $backupFile" -ForegroundColor Green
    } catch {
        Write-Host "[!] Warning: Could not create backup file" -ForegroundColor Yellow
    }
    Write-Host ""

    # Configure the connection limit
    Write-Host "[*] Configuring RDP connection limit..." -ForegroundColor Yellow
    
    if ($ConnectionLimit -eq 0) {
        # Disable the limit (unlimited connections)
        Write-Host "    Setting: Unlimited concurrent connections" -ForegroundColor Cyan
        Set-ItemProperty -Path $regPath -Name "MaxInstanceCount" -Value 0 -Type DWord -Force
        Set-ItemProperty -Path $regPath -Name "fSingleSessionPerUser" -Value 0 -Type DWord -Force
    } else {
        # Set specific limit
        Write-Host "    Setting: Maximum $ConnectionLimit concurrent connections" -ForegroundColor Cyan
        Set-ItemProperty -Path $regPath -Name "MaxInstanceCount" -Value $ConnectionLimit -Type DWord -Force
        Set-ItemProperty -Path $regPath -Name "fSingleSessionPerUser" -Value 0 -Type DWord -Force
    }
    
    Write-Host "[✓] Connection limit configured successfully" -ForegroundColor Green
    Write-Host ""

    # Enable Remote Desktop if not already enabled
    Write-Host "[*] Ensuring Remote Desktop is enabled..." -ForegroundColor Yellow
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0 -Force
    Write-Host "[✓] Remote Desktop enabled" -ForegroundColor Green
    Write-Host ""

    # Configure Windows Firewall rules
    Write-Host "[*] Configuring Windows Firewall rules..." -ForegroundColor Yellow
    try {
        Enable-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction Stop
        Write-Host "[✓] Firewall rules enabled for Remote Desktop" -ForegroundColor Green
    } catch {
        Write-Host "[!] Warning: Could not configure firewall rules automatically" -ForegroundColor Yellow
        Write-Host "    You may need to enable Remote Desktop firewall rules manually" -ForegroundColor Yellow
    }
    Write-Host ""

    # Update Group Policy
    Write-Host "[*] Updating Group Policy..." -ForegroundColor Yellow
    try {
        gpupdate /force | Out-Null
        Write-Host "[✓] Group Policy updated successfully" -ForegroundColor Green
    } catch {
        Write-Host "[!] Warning: Could not update Group Policy automatically" -ForegroundColor Yellow
        Write-Host "    Run 'gpupdate /force' manually after restart" -ForegroundColor Yellow
    }
    Write-Host ""

    # Display current configuration
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "Current Configuration:" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    
    $maxInstances = Get-ItemProperty -Path $regPath -Name "MaxInstanceCount" -ErrorAction SilentlyContinue
    $singleSession = Get-ItemProperty -Path $regPath -Name "fSingleSessionPerUser" -ErrorAction SilentlyContinue
    
    if ($maxInstances.MaxInstanceCount -eq 0) {
        Write-Host "Connection Limit: Unlimited" -ForegroundColor Green
    } else {
        Write-Host "Connection Limit: $($maxInstances.MaxInstanceCount)" -ForegroundColor Green
    }
    
    Write-Host "Single Session Per User: $($singleSession.fSingleSessionPerUser -eq 1)" -ForegroundColor Green
    Write-Host "Backup Location: $backupFile" -ForegroundColor Green
    Write-Host ""

    # Restart prompt
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "Next Steps:" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "Changes have been applied successfully!" -ForegroundColor Green
    Write-Host ""
    
    if ($RestartComputer) {
        Write-Host "[!] Computer will restart in 10 seconds..." -ForegroundColor Yellow
        Write-Host "Press Ctrl+C to cancel" -ForegroundColor Yellow
        Start-Sleep -Seconds 10
        Restart-Computer -Force
    } else {
        Write-Host "A system restart is required for changes to take full effect." -ForegroundColor Yellow
        Write-Host ""
        $response = Read-Host "Would you like to restart now? (Y/N)"
        if ($response -eq 'Y' -or $response -eq 'y') {
            Write-Host "[*] Restarting computer..." -ForegroundColor Yellow
            Restart-Computer -Force
        } else {
            Write-Host "[!] Please restart your computer manually to apply changes." -ForegroundColor Yellow
        }
    }

} catch {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Red
    Write-Host "ERROR OCCURRED" -ForegroundColor Red
    Write-Host "========================================" -ForegroundColor Red
    Write-Host "Error Message: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Error Line: $($_.InvocationInfo.ScriptLineNumber)" -ForegroundColor Red
    Write-Host ""
    Write-Host "Please check the error and try again." -ForegroundColor Yellow
    exit 1
}

# Made with Bob
