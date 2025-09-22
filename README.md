# ADKAVEH - Active Directory Penetration Testing Toolkit
A comprehensive PowerShell-based toolkit for Active Directory security assessment, enumeration, and penetration testing.

 ### Overview
 ADKAVEH is an interactive PowerShell tool designed for security 
 professionals to perform comprehensive Active Directory security assessments. 
 It provides both enumeration capabilities and controlled attack simulations 
 to identify vulnerabilities in AD environments.

###  Supported Attacks & Techniques
     ADKAVEH provides comprehensive support for various 
     Active Directory attack techniques, focusing on both 
     enumeration and exploitation phases:

   # Enumeration & Discovery Attacks

 # 1. Kerberoasting Attack

    - Purpose: Identify service accounts vulnerable to offline password cracking
    - Technique: Enumerates user accounts with Service Principal Names (SPNs)
    - Output: Lists all SPN-enabled accounts with their service principal names
    - Use Case: Service account compromise and privilege escalation

# 2. AS-REP Roasting Attack

    - Purpose: Discover accounts vulnerable to pre-authentication bypass
    - Technique: Identifies accounts with "Do Not Require Pre-Authentication" setting (UserAccountControl flag 4194304)
    - Output: Lists accounts vulnerable to AS-REP hash extraction
    - Use Case: Offline password cracking of user accounts

# 3. Inactive Account Discovery

    - Purpose: Find abandoned or forgotten user accounts
    - Technique: Searches for accounts inactive for more than 90 days
    - Output: Lists inactive accounts with last logon dates
    - Use Case: Account takeover and persistence establishment

# 4. KRBTGT Account Analysis

    - Purpose: Detect potential Golden Ticket attacks
    - Technique: Checks KRBTGT account password last set time
    - Output: KRBTGT account information and password change history
    - Use Case: Golden Ticket attack detection and forensic analysis

### Active Exploitation Attacks

# 5. Password Spraying Attack

    - Purpose: Test single passwords across multiple user accounts
    - Technique: Attempts authentication with one password against user list
   # Features:
        - 5-second delay between attempts to avoid lockouts
        - File share connection testing for credential validation
        - Real-time success/failure reporting
        - Use Case: Initial access and low-privilege account compromise

# 6. Windows Defender Disable

    - Purpose: Evade endpoint protection detection
    - Technique: Disables Windows Defender real-time monitoring
   # Features:
        - High-privilege requirement validation
        - User confirmation before execution
        - Error handling and status reporting
        - Use Case: Defense evasion and persistence maintenance
        
### Security Features & Protections
  # Safety Mechanisms

    - Warning System: Clear warnings before high-risk operations
    - User Confirmation: Manual approval required for dangerous actions
    - Rate Limiting: Built-in delays to prevent account lockouts
    - Error Handling: Comprehensive error reporting and recovery

# Authentication Security

    - Secure Credential Storage: Uses PSCredential objects for safe credential handling
    - Module Validation: Verifies required PowerShell modules before execution
    - Domain Authentication: Supports proper domain credential authentication

 ### **Features**
   # Enumeration & Discovery
 
    - Kerberoasting Scan: Identify user accounts with Service Principal Names (SPNs)
    - AS-REP Roasting Scan: Discover accounts with "Do Not Require Pre-Authentication" setting
    - Inactive Account Discovery: Find accounts inactive for more than 90 days
    - KRBTGT Account Analysis: Check KRBTGT password last set time for Golden Ticket detection
  # Attack Simulations

    - Password Spraying: Controlled password spraying with configurable delays
    - Defender Disable: Windows Defender real-time monitoring disable (High-risk operation)


  #  Installation & Requirements
  # Prerequisites
    
    - Windows: PowerShell 5.1+ with RSAT-AD-PowerShell module
    - Linux: PowerShell 7+ with appropriate network connectivity to domain controllers
    - Appropriate permissions for AD queries
    - Legal authorization to test the target environment

  # Windows Installation
  # Ensure RSAT is installed (Windows 10/11)
    Get-WindowsCapability -Name RSAT* -Online | Add-WindowsCapability -Online
  # Clone or download the script
    git clone https://github.com/TryHackBox/ADKAVEH.git

  # Linux Installation (Ubuntu/Debian/Kali)
    Method 1: Official Microsoft Repository (Recommended)
    # Update system
        sudo apt update && sudo apt upgrade -y

  # Install prerequisites
        sudo apt install -y wget apt-transport-https software-properties-common

  # Install PowerShell 7
     # For Ubuntu:
         wget -q https://packages.microsoft.com/config/ubuntu/$(lsb_release -rs)/packages-microsoft-prod.deb
         sudo dpkg -i packages-microsoft-prod.deb
         rm packages-microsoft-prod.deb

      # For Debian/Kali:
         wget -q https://packages.microsoft.com/config/debian/$(lsb_release -rs)/packages-microsoft-prod.deb
         sudo dpkg -i packages-microsoft-prod.deb
         rm packages-microsoft-prod.deb

  # Install PowerShell
        sudo apt update
        sudo apt install -y powershell

  # Verify installation
         pwsh --version

      Method 2: Snap Package
         # Install snapd if not available
           sudo apt update
           sudo apt install -y snapd

  # Install PowerShell via snap
           sudo snap install powershell --classic

  # Start PowerShell
            pwsh
        Method 3: Direct Download
           # Download latest PowerShell release
           wget https://github.com/PowerShell/PowerShell/releases/download/v7.4.0/powershell-7.4.0-linux-x64.tar.gz
  
           # Extract and install
              tar -xzf powershell-7.4.0-linux-x64.tar.gz
              sudo mv powershell /usr/local/bin/

   ### Usage
   # Basic Execution
       # Run the interactive menu (Windows)
         .\ADKAVEH.ps1

       # Run on Linux
          pwsh -File ADKAVEH.ps1

# Interactive Menu Options
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
    
   ### Linux-Specific Considerations
   
   When running on Linux, ensure:

    - Network connectivity to domain controllers
    - Proper DNS resolution for the target domain
    - Appropriate firewall rules for AD communication
    - Valid domain credentials with necessary permissions

  
# Output Examples
  Kerberoasting Results
  
      SamAccountName SPNs
      -------------- ----
      svc_sql        MSSQLSvc/sql01.contoso.local:1433
      svc_web        HTTP/webapp.contoso.com

   KRBTGT Analysis

        Name    DistinguishedName                  PasswordLastSet
         ----    -----------------                  ---------------
        krbtgt  CN=krbtgt,CN=Users,DC=contoso,DC=local 9/15/2024 2:30:45 PM
        
### Important Warnings
 # Legal & Ethical Considerations

    - Only use on systems you own or have explicit written permission to test
    - This tool is for authorized security assessments only
    - Unauthorized use may violate laws and regulations
 # Operational Risks

    - Password spraying can cause account lockouts
    - Defender disable is extremely noisy and will trigger alerts
    - All operations should be performed during approved testing windows
    - Linux execution may have different behavioral characteristics than Windows


### Use Cases

# Red Team Operations

    - Internal penetration testing
    - AD security posture assessment
    - Privilege escalation path discovery
    - Cross-platform security testing
# Blue Team Defense

    - Identifying misconfigured accounts
    - Discovering inactive user accounts
    - Detecting potential Golden Ticket indicators
    - Security tool validation across platforms

# Security Auditing

    - Compliance checking (NIST, CIS, etc.)
    - Configuration validation
    - Security hardening assessment
    - Multi-platform environment testing

   
### Technical Details

# Dependencies

    - Windows: ActiveDirectory PowerShell module (RSAT)
    - Linux: PowerShell 7+ with network connectivity to AD
    - .NET Framework 4.5+ (Windows) / .NET Core (Linux)
    - Appropriate network connectivity to domain controllers

# Authentication

    - Supports domain credentials input
    - Uses PSCredential objects for secure authentication
    - Validates module availability before execution
    - Works with both Windows and Linux PowerShell environments

# Cross-Platform Compatibility

    - Windows: Native support with full AD module capabilities
    - Linux: Requires network connectivity to AD, some features may have limitations
    - Tested on Ubuntu, Debian, Kali Linux, and Windows 10/11

### Operational Considerations
 # Attack Characteristics

    - Kerberoasting: Medium noise level, typically goes undetected
    - AS-REP Roasting: Low noise level, difficult to detect
    - Password Spraying: High noise level, may trigger alerts
    - Defender Disable: Extreme noise level, will trigger immediate alerts

# Best Practices

    - Always test during approved maintenance windows
    - Use dedicated test accounts when possible
    - Monitor environment for unintended consequences
    - Document all activities for reporting purposes

# This comprehensive attack capability set makes ADKAVEH an essential tool for security professionals conducting authorized Active Directory security assessments.

# License

This project is licensed under the MIT License.


### Support

  # Author: Kaveh 
  # Twitter: @kavehxnet https://twitter.com/kavehxnet
  # Twitter : @OffensivePwn https://twitter.com/OffensivePwn

    
# Note: All attacks should only be performed in authorized environments with proper written permission. Unauthorized testing may violate laws and organizational policies. 

### Disclaimer

This tool is provided for educational and authorized security testing purposes only. 
The developers are not responsible for any misuse or damage caused by this tool. 
Always obtain proper authorization before conducting any security assessments.

Linux Note: While ADKAVEH works on Linux, some Active Directory features 
may behave differently compared to Windows. Always validate results in your specific environment.

# Remember: With great power comes great responsibility. Use ADKAVEH ethically and legally across all platforms! 
