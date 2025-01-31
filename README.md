# ADKAVEH
This PowerShell script is designed for various attacks and security 
assessments in an Active Directory (AD) environment. To execute this 
script, certain prerequisites and configurations are required. Below, a 
complete explanation of the requirements, capabilities, and advantages 
of this tool is provided.

 ### Prerequisites for Running the Script

1. **Windows Operating System:**

This script is designed for Windows environments and requires PowerShell.

2. **PowerShell Modules:**

The script utilizes the ActiveDirectory and GroupPolicy
modules. These modules are typically pre-installed on Windows Server 
systems. However, if they are not installed, you can install them using 
the following command:
                       Install-WindowsFeature -Name RSAT-AD-PowerShell

After installation, import the modules using the following command:
                       Import-Module ActiveDirectory
                       Import-Module GroupPolicy

3. **Administrative Access:**
   - To execute this script, you need Domain Admin privileges or equivalent 
permissions, as many of the script's functions access sensitive AD 
information.

4. **Temporarily Disabling Windows Defender:**
  - Some functions of this script may be blocked by Windows Defender. Therefore,
    the script temporarily disables Windows Defender. If Windows Defender 
    is already disabled, this step is not necessary.

5. **Domain Information:**
   - To run the script, you need the domain name (DomainName), username 
     (Username), and password (Password). These details are used to connect 
      to the domain and execute commands.

   ### Script Capabilities
   This script includes various functions for assessing and attacking Active Directory. Below are the main capabilities        explained:

 **Temporarily Disabling Windows Defender:**
   To prevent the script from being blocked by Windows Defender, this function temporarily disables Defender.

**Kerberoasting Check:**
   - This function identifies user accounts with Service Principal Names (SPNs) that could be exploited in Kerberoasting attacks.
 
**ACL Misuse Check:**
This function examines Access Control Lists (ACLs) to detect unauthorized access or potential ACL misuse.

**Password Spraying Attack:**
This function simulates a Password Spraying attack. It uses a test password to attempt logins on user accounts.

**Golden Ticket Detection:**
This function reviews security event logs to detect signs of Golden Ticket attacks.

**Discovery of Inactive Accounts:**
This function identifies user accounts that have been inactive for more than 90 days.

**GPO Misuse Check:**
This function reviews Group Policy Objects (GPOs) to detect unauthorized access or potential GPO misuse.

**AdminSDHolder Misuse Check:**
This function examines AdminSDHolder to detect unauthorized access or potential misuse.

**AS-REP Roasting Check:**
This function identifies user accounts that do not require Kerberos 
Pre-Authentication and could be exploited in AS-REP Roasting attacks.

**Unconstrained Delegation Misuse Check:**
This function identifies computers with Unconstrained Delegation enabled.

**Constrained Delegation Misuse Check:**
This function identifies user accounts with Constrained Delegation enabled.

### Tool Advantages

**1.Comprehensiveness:**
This script covers a wide range of common attacks and vulnerabilities in Active Directory.

**2.Ease of Use:**
Using simple PowerShell commands, users can easily execute the script and view the results.

**3.No Need for External Tools:**
The script utilizes built-in PowerShell tools and standard Windows modules, eliminating the need for installing external tools.

**4.Customizability:**
Users can enable or disable specific functions or modify script parameters to align with their requirements.

**5.Security:**
By temporarily disabling Windows Defender, the script can run without restrictions, but Defender is re-enabled after execution.

### How to Execute the Script

1. Save the script in a file with a `.ps1` extension, for example, `AD-Attack-Script.ps1`.

2. Open PowerShell with administrative privileges (Run as Administrator).

3. Enter the following command to execute the script:

   .\ADKaveh.ps1 -Domain example.com -Username admin -Password (Read-Host -AsSecureString)
   
4. If you need help, use the following command:

    .\ADKaveh.ps1 -Help

   
### Security Warning

This script is designed for security testing and educational purposes only.

By using this script, you can identify and address potential vulnerabilities in your Active Directory.


