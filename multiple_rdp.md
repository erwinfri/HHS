Created PowerShell script [`Enable-MultipleRDPSessions.ps1`](Enable-MultipleRDPSessions.ps1:1) that automates enabling Remote Desktop for multiple users via Group Policy.

**Key Features:**
- Modifies registry settings to allow multiple concurrent RDP sessions
- Configurable connection limit (default: unlimited)
- Automatic administrator privilege check
- Backs up current settings before making changes
- Enables Remote Desktop and configures firewall rules
- Updates Group Policy automatically
- Optional automatic restart with `-RestartComputer` parameter

**Usage Examples:**
```powershell
# Enable unlimited RDP sessions (interactive restart prompt)
.\Enable-MultipleRDPSessions.ps1

# Set limit to 5 sessions and auto-restart
.\Enable-MultipleRDPSessions.ps1 -ConnectionLimit 5 -RestartComputer

# Set limit to 10 sessions without auto-restart
.\Enable-MultipleRDPSessions.ps1 -ConnectionLimit 10
```

**What it does:**
1. Verifies administrator privileges
2. Creates/modifies registry path: `HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services`
3. Sets `MaxInstanceCount` (0 = unlimited, or specified number)
4. Sets `fSingleSessionPerUser` to 0 (allows multiple sessions per user)
5. Enables Remote Desktop service
6. Configures Windows Firewall rules
7. Updates Group Policy with `gpupdate /force`
8. Prompts for system restart

The script must be run as Administrator and requires a system restart to take full effect.