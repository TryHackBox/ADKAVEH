### ADKAVEH – Active Directory Enumeration & Attack Framework

# Overview
ADKAVEH is a PowerShell-based Script for Active Directory enumeration and authorized penetration testing.
It is designed for security professionals, Red Teams, and Blue Teams who need to identify and test 
common Active Directory attack paths in a controlled and legal environment.

⚠️ Important: This toolkit is intended for educational use and authorized security assessments only.
Running it in environments without explicit written permission may be illegal and result in severe consequences.


# Features
### Enumeration
[+] Domain, users, groups, and computers.

[+] Kerberos-related data (SPNs, AS-REP accounts, KRBTGT status).

[+] GPOs and security policies.

### Attack Simulation (with explicit confirmation)
[+] Kerberoasting.

[+] AS-REP roasting.

[+] Password spraying (with rate-limiting and delays).

[+] Optional Defender tamper tests (requires --ConfirmUnsafe).

### Operational Support
[+] Credential input via Get-Credential.

[+] Configurable rate-limiting & delays.

### Installation

Requirements:

[+] PowerShell 5.1+ (Windows) or PowerShell 7+ (Linux/macOS).

[+] Domain-joined system or appropriate network access.

[+] Sufficient privileges for enumeration/attacks being tested.

# Clone the repository:
```bash
  git clone https://github.com/TryHackBox/ADKAVEH

  cd ADKAVEH
```

# Usage 
### Basic Enumeration
``` .\ADKAVEH.ps1 -EnumDomain ```

### Password Spraying (safe with delay)
``` .\ADKAVEH.ps1 -PasswordSpray -UserList users.txt -Password Winter2025! -Delay 5 ```

### High-Risk Operations (require explicit confirmation)
``` .\ADKAVEH.ps1 -DisableDefender -ConfirmUnsafe ```

# Collects information but does not perform attacks.

# Safety & Legal Disclaimer
[+] Use only in environments where you have explicit written permission.

[+] Some modules can disable security tools or trigger account lockouts.

[+] Default configuration includes rate-limiting and delays to reduce risk.

[+] The authors take no responsibility for misuse or damage caused by this script.

### Roadmap
[+] Improve cross-platform testing (Linux/macOS via pwsh).

[+] Add randomized jitter for spraying delays.

[+] Harden logging and credential handling.

### Support
  # Author: Kaveh 
    Twitter: @kavehxnet https://twitter.com/kavehxnet
    
    Twitter: @OffensivePwn https://twitter.com/OffensivePwn
    
    Star the repo.
    
    Watch for updates.
    
    Report issues or suggest features.
# License
This project is licensed under the MIT License.
