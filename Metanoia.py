import tkinter as tk
from tkinter import messagebox, ttk
import subprocess
import ctypes
import sys

# Command descriptions and corresponding registry commands
commands = [
    {
        "description": "Ensure 'Accounts: Administrator account status' is set to 'Disabled' (CIS Control 2.3.1.1)",
        "command": 'reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v EnableLUA /t REG_DWORD /d 0 /f'
    },
    {
        "description": "Ensure 'Accounts: Guest account status' is set to 'Disabled' (CIS Control 2.3.1.2)",
        "command": 'reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa" /v LimitBlankPasswordUse /t REG_DWORD /d 1 /f'
    },
    {
        "description": "Ensure 'Accounts: Limit local account use of blank passwords to console logon only' is set to 'Enabled' (CIS Control 2.3.1.3)",
        "command": 'reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa" /v LimitBlankPasswordUse /t REG_DWORD /d 2 /f'
    },
    {
        "description": "Ensure 'Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings' is set to 'Enabled' (CIS Control 2.3.2.1)",
        "command": 'auditpol /set /SubCategory:"MPSSVC rule-level Policy Change" /success:enable /failure:enable'
    },
    {
        "description": "Ensure 'Audit: Shut down system immediately if unable to log security audits' is set to 'Enabled' (CIS Control 2.3.2.2)",
        "command": 'reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v CrashOnAuditFail /t REG_DWORD /d 1 /f'
    },
    {
        "description": "Ensure 'DCOM: Machine Access Restrictions in Security Descriptor Definition Language (SDDL) syntax' is set to 'Medium Level' (CIS Control 2.3.3.1)",
        "command": 'reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Ole" /v MachineAccessRestriction /t REG_SZ /d "S:(ML;;NW;;;LW)" /f'
    },
    {
        "description": "Ensure 'DCOM: Machine Launch Restrictions in Security Descriptor Definition Language (SDDL) syntax' is set to 'Medium Level' (CIS Control 2.3.3.2)",
        "command": 'reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Ole" /v MachineLaunchRestriction /t REG_SZ /d "S:(ML;;NW;;;ME)" /f'
    },
    {
        "description": "Ensure 'Devices: Allowed to format and eject removable media' is set to 'Administrators and Interactive Users' (CIS Control 2.3.4.1)",
        "command": 'reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\StorageDevicePolicies" /v WriteProtect /t REG_DWORD /d 0 /f'
    },
    {
        "description": "Ensure 'Devices: Prevent users from installing printer drivers' is set to 'Enabled' (CIS Control 2.3.4.2)",
        "command": 'reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers" /v RestrictDriverInstallationToAdministrators /t REG_DWORD /d 1 /f'
    },
    {
        "description": "Ensure 'Domain controller: Allow server operators to schedule tasks' is set to 'Disabled' (CIS Control 2.3.5.1)",
        "command": 'reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Schedule" /v Start /t REG_DWORD /d 4 /f'
    },
    {
        "description": "Ensure 'Domain controller: LDAP server signing requirements' is set to 'Require signing' (CIS Control 2.3.6.1)",
        "command": 'reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters" /v LDAPServerIntegrity /t REG_DWORD /d 2 /f'
    },
    {
        "description": "Ensure 'Domain controller: Refuse machine account password changes' is set to 'Enabled' (CIS Control 2.3.6.2)",
        "command": 'reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters" /v RefusePasswordChange /t REG_DWORD /d 1 /f'
    },
    {
        "description": "Ensure 'Domain member: Digitally encrypt or sign secure channel data (always)' is set to 'Enabled' (CIS Control 2.3.7.1)",
        "command": 'reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters" /v RequireSignOrSeal /t REG_DWORD /d 1 /f'
    },
    {
        "description": "Ensure 'Domain member: Digitally encrypt secure channel data (when possible)' is set to 'Enabled' (CIS Control 2.3.7.2)",
        "command": 'reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters" /v SealSecureChannel /t REG_DWORD /d 1 /f'
    },
    {
        "description": "Ensure 'Domain member: Digitally sign secure channel data (when possible)' is set to 'Enabled' (CIS Control 2.3.7.3)",
        "command": 'reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters" /v SignSecureChannel /t REG_DWORD /d 1 /f'
    },
    {
        "description": "Ensure 'Domain member: Disable machine account password changes' is set to 'Disabled' (CIS Control 2.3.7.4)",
        "command": 'reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters" /v DisablePasswordChange /t REG_DWORD /d 0 /f'
    },
    {
        "description": "Ensure 'Domain member: Maximum machine account password age' is set to '30 or fewer days, but not 0' (CIS Control 2.3.7.5)",
        "command": 'reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters" /v MaximumPasswordAge /t REG_DWORD /d 30 /f'
    },
    {
        "description": "Ensure 'Domain member: Require strong (Windows 2000 or later) session key' is set to 'Enabled' (CIS Control 2.3.7.6)",
        "command": 'reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters" /v RequireStrongKey /t REG_DWORD /d 1 /f'
    },
    {
        "description": "Ensure 'Interactive logon: Machine inactivity limit' is set to '900 or fewer seconds, but not 0' (CIS Control 2.3.8.1)",
        "command": 'reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v InactivityTimeoutSecs /t REG_DWORD /d 900 /f'
    },
    {
        "description": "Ensure 'Interactive logon: Message text for users attempting to log on' is set to 'Display text' (CIS Control 2.3.8.2)",
        "command": 'reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v LegalNoticeText /t REG_SZ /d "You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only." /f'
    },
    {
        "description": "Ensure 'Interactive logon: Message title for users attempting to log on' is set to 'Display text' (CIS Control 2.3.8.3)",
        "command": 'reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v LegalNoticeCaption /t REG_SZ /d "Warning" /f'
    },
    {
        "description": "Ensure 'Interactive logon: Number of previous logons to cache (in case domain controller is not available)' is set to '4 or fewer logons' (CIS Control 2.3.8.4)",
        "command": 'reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v CachedLogonsCount /t REG_SZ /d 4 /f'
    },
    {
        "description": "Ensure 'Interactive logon: Prompt user to change password before expiration' is set to 'between 5 and 14 days' (CIS Control 2.3.8.5)",
        "command": 'reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v PasswordExpiryWarning /t REG_DWORD /d 10 /f'
    },
    {
        "description": "Ensure 'Interactive logon: Require Domain Controller authentication to unlock workstation' is set to 'Enabled' (CIS Control 2.3.8.6)",
        "command": 'reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v RequireCtrlAltDel /t REG_DWORD /d 1 /f'
    },
    {
        "description": "Ensure 'Interactive logon: Require smart card' is set to 'Required' (CIS Control 2.3.8.7)",
        "command": 'reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v scforceoption /t REG_DWORD /d 1 /f'
    },
    {
        "description": "Ensure 'Microsoft network client: Digitally sign communications (if server agrees)' is set to 'Enabled' (CIS Control 2.3.9.1)",
        "command": 'reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters" /v RequireSecuritySignature /t REG_DWORD /d 1 /f'
    },
    {
        "description": "Ensure 'Microsoft network client: Send unencrypted password to third-party SMB servers' is set to 'Disabled' (CIS Control 2.3.9.2)",
        "command": 'reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters" /v EnablePlainTextPassword /t REG_DWORD /d 0 /f'
    },
    {
        "description": "Ensure 'Microsoft network server: Amount of idle time required before suspending session' is set to '15 or fewer minutes, but not 0' (CIS Control 2.3.10.1)",
        "command": 'reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters" /v autodisconnect /t REG_DWORD /d 15 /f'
    },
    {
        "description": "Ensure 'Microsoft network server: Digitally sign communications (always)' is set to 'Enabled' (CIS Control 2.3.10.2)",
        "command": 'reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters" /v RequireSecuritySignature /t REG_DWORD /d 1 /f'
    },
    {
        "description": "Ensure 'Microsoft network server: Disconnect clients when logon hours expire' is set to 'Enabled' (Automated)",
        "command": 'reg add "HKLM\\System\\CurrentControlSet\\Services\\LanmanServer\\Parameters" /v EnableForcedLogoff /t REG_DWORD /d 1 /f'
    },
    {
        "description": "Ensure 'Microsoft network server: Server SPN target name validation level' is set to 'Accept if provided by client' or higher (Automated)",
        "command": 'reg add "HKLM\\System\\CurrentControlSet\\Services\\LanmanServer\\Parameters" /v SmbServerNameHardeningLevel /t REG_DWORD /d 1 /f'
    },
    {
        "description": "Ensure 'Network access: Allow anonymous SID/Name translation' is set to 'Disabled' (Automated)",
        "command": 'reg add "HKLM\\System\\CurrentControlSet\\Control\\LSA" /v TurnOffAnonymousBlock /t REG_DWORD /d 1 /f'
    },
    {
        "description": "Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts' is set to 'Enabled' (Automated)",
        "command": 'reg add "HKLM\\System\\CurrentControlSet\\Control\\LSA" /v RestrictAnonymousSAM /t REG_DWORD /d 1 /f'
    },
    {
        "description": "Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts and shares' is set to 'Enabled' (Automated)",
        "command": 'reg add "HKLM\\System\\CurrentControlSet\\Control\\LSA" /v RestrictAnonymous /t REG_DWORD /d 3 /f'
    },
    {
        "description": "Ensure 'Network access: Do not allow storage of passwords and credentials for network authentication' is set to 'Enabled' (Automated)",
        "command": 'reg add "HKLM\\System\\CurrentControlSet\\Control\\LSA" /v DisableDomainCreds /t REG_DWORD /d 1 /f'
    },
    {
        "description": "Ensure 'Network access: Let Everyone permissions apply to anonymous users' is set to 'Disabled' (Automated)",
        "command": 'reg add "HKLM\\System\\CurrentControlSet\\Services\\LanmanServer\\Parameters" /v EveryoneIncludesAnonymous /t REG_DWORD /d 0 /f'
    },
    {
        "description": "Ensure 'Network access: Named Pipes that can be accessed anonymously' is set to 'None' (Automated)",
        "command": 'reg add "HKLM\\System\\CurrentControlSet\\Services\\LanmanServer\\Parameters" /v NullSessionPipes /t REG_MULTI_SZ /d "" /f'
    },
    {
        "description": "Ensure 'Network access: Remotely accessible registry paths' is configured (Automated)",
        "command": 'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurePipeServers\\Winreg\\AllowedPaths" /v Machine /t REG_MULTI_SZ /d "System\\CurrentControlSet\\Control\\ProductOptions,System\\CurrentControlSet\\Control\\Server Applications,Software\\Microsoft\\Windows NT\\CurrentVersion" /f'
    },
    {
        "description": "Ensure 'Network access: Remotely accessible registry paths and sub-paths' is configured (Automated)",
        "command": 'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurePipeServers\\Winreg\\AllowedExactPaths" /v Machine /t REG_MULTI_SZ /d "System\\CurrentControlSet\\Control\\ProductOptions,System\\CurrentControlSet\\Control\\Server Applications,Software\\Microsoft\\Windows NT\\CurrentVersion,System\\CurrentControlSet\\Control\\Print\\Printers,System\\CurrentControlSet\\Services\\Eventlog,Software\\Microsoft\\OLAP Server,Software\\Microsoft\\Windows NT\\CurrentVersion\\Print,Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows,System\\CurrentControlSet\\Control\\ContentIndex,System\\CurrentControlSet\\Control\\Terminal Server,System\\CurrentControlSet\\Control\\Terminal Server\\UserConfig,System\\CurrentControlSet\\Control\\Terminal Server\\DefaultUserConfiguration,Software\\Microsoft\\Windows NT\\CurrentVersion\\Perflib,System\\CurrentControlSet\\Services\\SysmonLog" /f'
    },
    {
        "description": "Ensure 'Network access: Restrict anonymous access to Named Pipes and Shares' is set to 'Enabled' (CIS Control 2.3.10.9)",
        "command": 'reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters" /v RestrictNullSessAccess /t REG_DWORD /d 1 /f'
    },
    {
        "description": "Ensure 'Network access: Restrict clients allowed to make remote calls to SAM' is set to 'Administrators: Remote Access: Allow' (CIS Control 2.3.10.10)",
        "command": 'reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\LSA" /v RestrictRemoteSam /t REG_MULTI_SZ /d Administrators /f'
    },
    {
        "description": "Ensure 'Network access: Shares that can be accessed anonymously' is set to 'None' (CIS Control 2.3.10.11)",
        "command": 'reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters" /v NullSessionShares /t REG_MULTI_SZ /d "" /f'
    },
    {
        "description": "Ensure 'Network access: Sharing and security model for local accounts' is set to 'Classic - local users authenticate as themselves' (CIS Control 2.3.10.12)",
        "command": 'reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa" /v ForceGuest /t REG_DWORD /d 0 /f'
    },
    {
        "description": "Ensure 'Network security: Allow Local System to use computer identity for NTLM' is set to 'Enabled' (CIS Control 2.3.11.1)",
        "command": 'reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa" /v UseMachineId /t REG_DWORD /d 1 /f'
    },
    {
        "description": "Ensure 'Network security: Allow LocalSystem NULL session fallback' is set to 'Disabled' (CIS Control 2.3.11.2)",
        "command": 'reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa" /v RestrictNullSessAccess /t REG_DWORD /d 1 /f'
    },
    {
        "description": "Ensure 'Network Security: Allow PKU2U authentication requests to this computer to use online identities' is set to 'Disabled' (CIS Control 2.3.11.3)",
        "command": 'reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\pku2u" /v AllowOnlineID /t REG_DWORD /d 0 /f'
    },
    {
        "description": "Ensure 'Network security: Do not store LAN Manager hash value on next password change' is set to 'Enabled' (CIS Control 2.3.11.4)",
        "command": 'reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa" /v NoLMHash /t REG_DWORD /d 1 /f'
    },
    {
        "description": "Ensure 'Network security: Force logoff when logon hours expire' is set to 'Enabled' (CIS Control 2.3.11.5)",
        "command": 'reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" /v ForceLogoffWhenHourExpire /t REG_DWORD /d 1 /f'
    },
    {
        "description": "Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM' (CIS Control 2.3.11.6)",
        "command": 'reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa" /v LmCompatibilityLevel /t REG_DWORD /d 5 /f'
    },
    {
        "description": "Ensure 'Network security: LDAP client signing requirements' is set to 'Negotiate signing' (CIS Control 2.3.11.7)",
        "command": 'reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\LDAP" /v LDAPServerIntegrity /t REG_DWORD /d 2 /f'
    },
    {
        "description": "Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) clients' is set to 'Require NTLMv2 session security, Require 128-bit encryption' (CIS Control 2.3.11.8)",
        "command": 'reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0" /v NtlmMinClientSec /t REG_DWORD /d 537395200 /f'
    },
    {
        "description": "Ensure 'Network security: Restrict NTLM: Add remote server exceptions for NTLM authentication' is set to 'Authenticated server' (CIS Control 2.3.11.10)",
        "command": 'reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0" /v RestrictReceivingNTLMTraffic /t REG_MULTI_SZ /d "ServerName1,ServerName2" /f'
    },
    {
        "description": "Ensure 'Network security: Restrict NTLM: Audit Incoming NTLM Traffic' is set to 'Enabled' (CIS Control 2.3.11.11)",
        "command": 'reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0" /v AuditReceivingNTLMTraffic /t REG_DWORD /d 1 /f'
    },
    {
        "description": "Ensure 'Network security: Restrict NTLM: Audit NTLM authentication in this domain' is set to 'Enabled' (CIS Control 2.3.11.12)",
        "command": 'reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0" /v AuditNTLMInDomain /t REG_DWORD /d 1 /f'
    },
    {
        "description": "Ensure 'Network security: Restrict NTLM: Incoming NTLM traffic' is set to 'Deny all accounts' (CIS Control 2.3.11.13)",
        "command": 'reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0" /v RestrictSendingNTLMTraffic /t REG_DWORD /d 2 /f'
    },
    {
        "description": "Ensure 'Recovery console: Allow automatic administrative logon' is set to 'Disabled' (CIS Control 2.3.12.1)",
        "command": 'reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Setup\\RecoveryConsole" /v SecurityLevel /t REG_DWORD /d 1 /f'
    },
    {
        "description": "Ensure 'Recovery console: Allow floppy copy and access to all drives and all folders' is set to 'Disabled' (CIS Control 2.3.12.2)",
        "command": 'reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Setup\\RecoveryConsole" /v SetCommand /t REG_DWORD /d 1 /f'
    },
    {
        "description": "Ensure 'Shutdown: Allow system to be shut down without having to log on' is set to 'Disabled' (CIS Control 2.3.13.1)",
        "command": 'reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v ShutdownWithoutLogon /t REG_DWORD /d 0 /f'
    },
    {
        "description": "Ensure 'System cryptography: Force strong key protection for user keys stored on the computer' is set to 'Enabled' (CIS Control 2.3.14.1)",
        "command": 'reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography" /v ForceKeyProtection /t REG_DWORD /d 1 /f'
    },
    {
        "description": "Ensure 'System cryptography: Use FIPS-compliant algorithms for encryption, hashing, and signing' is set to 'Enabled' (CIS Control 2.3.14.2)",
        "command": 'reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\FIPSAlgorithmPolicy" /v Enabled /t REG_DWORD /d 1 /f'
    },
    {
        "description": "Ensure 'User Account Control: Admin Approval Mode for the built-in Administrator account' is set to 'Enabled' (CIS Control 2.3.15.1)",
        "command": 'reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v FilterAdministratorToken /t REG_DWORD /d 1 /f'
    },
    {
        "description": "Ensure 'User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode' is set to 'Prompt for consent on the secure desktop' (CIS Control 2.3.15.2)",
        "command": 'reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 2 /f'
    },
    {
        "description": "Ensure 'User Account Control: Behavior of the elevation prompt for standard users' is set to 'Automatically deny elevation requests' (CIS Control 2.3.15.3)",
        "command": 'reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v ConsentPromptBehaviorUser /t REG_DWORD /d 0 /f'
    },
    {
        "description": "Ensure 'User Account Control: Detect application installations and prompt for elevation' is set to 'Enabled' (CIS Control 2.3.15.4)",
        "command": 'reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v EnableInstallerDetection /t REG_DWORD /d 1 /f'
    },
    {
        "description": "Ensure 'User Account Control: Only elevate UIAccess applications that are installed in secure locations' is set to 'Enabled' (CIS Control 2.3.15.5)",
        "command": 'reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v EnableSecureUIAPaths /t REG_DWORD /d 1 /f'
    },
    {
        "description": "Ensure 'User Account Control: Run all administrators in Admin Approval Mode' is set to 'Enabled' (CIS Control 2.3.15.6)",
        "command": 'reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v EnableLUA /t REG_DWORD /d 1 /f'
    },
    {
        "description": "Ensure 'User Account Control: Switch to the secure desktop when prompting for elevation' is set to 'Enabled' (CIS Control 2.3.15.7)",
        "command": 'reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v PromptOnSecureDesktop /t REG_DWORD /d 1 /f'
    },
    {
        "description": "Ensure 'User Account Control: Virtualize file and registry write failures to per-user locations' is set to 'Enabled' (CIS Control 2.3.15.8)",
        "command": 'reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v EnableVirtualization /t REG_DWORD /d 1 /f'
    },
    {
        "description": "Ensure 'User Rights Assignment: Access Credential Manager as a trusted caller' is set to 'No One' (CIS Control 2.3.16.1)",
        "command": 'secedit /configure /cfg "%systemroot%\\security\\templates\\setup.inf" /db sec.sdb /areas USER_RIGHTS /quiet'
    },
    {
        "description": "Ensure 'User Rights Assignment: Access this computer from the network' is set to 'Administrators, ASP.NET Machine Account, Domain Admins, IIS_IUSRS, Guests, Remote Desktop Users, SQLServerMSSQLUsers, Users' (CIS Control 2.3.16.2)",
        "command": 'secedit /configure /cfg "%systemroot%\\security\\templates\\setup.inf" /db sec.sdb /areas USER_RIGHTS /quiet'
    },
    {
        "description": "Ensure 'User Rights Assignment: Act as part of the operating system' is set to 'No One' (CIS Control 2.3.16.3)",
        "command": 'secedit /configure /cfg "%systemroot%\\security\\templates\\setup.inf" /db sec.sdb /areas USER_RIGHTS /quiet'
    },
    {
        "description": "Ensure 'User Rights Assignment: Add workstations to domain' is set to 'Administrators, Domain Admins' (CIS Control 2.3.16.4)",
        "command": 'secedit /configure /cfg "%systemroot%\\security\\templates\\setup.inf" /db sec.sdb /areas USER_RIGHTS /quiet'
    },
    {
        "description": "Ensure 'User Rights Assignment: Adjust memory quotas for a process' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE' (CIS Control 2.3.16.5)",
        "command": 'secedit /configure /cfg "%systemroot%\\security\\templates\\setup.inf" /db sec.sdb /areas USER_RIGHTS /quiet'
    },
    {
        "description": "Ensure 'User Rights Assignment: Allow log on locally' is set to 'Administrators, Authenticated Users' (CIS Control 2.3.16.6)",
        "command": 'secedit /configure /cfg "%systemroot%\\security\\templates\\setup.inf" /db sec.sdb /areas USER_RIGHTS /quiet'
    },
    {
        "description": "Ensure 'User Rights Assignment: Allow log on through Remote Desktop Services' is set to 'Administrators, Remote Desktop Users' (CIS Control 2.3.16.7)",
        "command": 'secedit /configure /cfg "%systemroot%\\security\\templates\\setup.inf" /db sec.sdb /areas USER_RIGHTS /quiet'
    },
    {
        "description": "Ensure 'User Rights Assignment: Back up files and directories' is set to 'Administrators, Backup Operators' (CIS Control 2.3.16.8)",
        "command": 'secedit /configure /cfg "%systemroot%\\security\\templates\\setup.inf" /db sec.sdb /areas USER_RIGHTS /quiet'
    },
    {
        "description": "Ensure 'User Rights Assignment: Change the system time' is set to 'Administrators, LOCAL SERVICE' (CIS Control 2.3.16.9)",
        "command": 'secedit /configure /cfg "%systemroot%\\security\\templates\\setup.inf" /db sec.sdb /areas USER_RIGHTS /quiet'
    },
    {
        "description": "Ensure 'User Rights Assignment: Create a pagefile' is set to 'Administrators' (CIS Control 2.3.16.10)",
        "command": 'secedit /configure /cfg "%systemroot%\\security\\templates\\setup.inf" /db sec.sdb /areas USER_RIGHTS /quiet'
    },
    {
        "description": "Ensure 'User Rights Assignment: Create a token object' is set to 'No One' (CIS Control 2.3.16.11)",
        "command": 'secedit /configure /cfg "%systemroot%\\security\\templates\\setup.inf" /db sec.sdb /areas USER_RIGHTS /quiet'
    },
    {
        "description": "Ensure 'User Rights Assignment: Create global objects' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE' (CIS Control 2.3.16.12)",
        "command": 'secedit /configure /cfg "%systemroot%\\security\\templates\\setup.inf" /db sec.sdb /areas USER_RIGHTS /quiet'
    },
    {
        "description": "Ensure 'User Rights Assignment: Create permanent shared objects' is set to 'No One' (CIS Control 2.3.16.13)",
        "command": 'secedit /configure /cfg "%systemroot%\\security\\templates\\setup.inf" /db sec.sdb /areas USER_RIGHTS /quiet'
    },
    {
        "description": "Ensure 'User Rights Assignment: Create symbolic links' is set to 'Administrators' (CIS Control 2.3.16.14)",
        "command": 'secedit /configure /cfg "%systemroot%\\security\\templates\\setup.inf" /db sec.sdb /areas USER_RIGHTS /quiet'
    },
    {
        "description": "Ensure 'User Rights Assignment: Debug programs' is set to 'Administrators' (CIS Control 2.3.16.15)",
        "command": 'secedit /configure /cfg "%systemroot%\\security\\templates\\setup.inf" /db sec.sdb /areas USER_RIGHTS /quiet'
    },
    {
        "description": "Ensure 'User Rights Assignment: Deny access to this computer from the network' is set to 'Guests, LOCAL SERVICE, NETWORK SERVICE' (CIS Control 2.3.16.16)",
        "command": 'secedit /configure /cfg "%systemroot%\\security\\templates\\setup.inf" /db sec.sdb /areas USER_RIGHTS /quiet'
    },
    {
        "description": "Ensure 'User Rights Assignment: Deny log on as a batch job' to include 'Guests' (CIS Control 2.3.16.17)",
        "command": 'secedit /configure /cfg "%systemroot%\\security\\templates\\setup.inf" /db sec.sdb /areas USER_RIGHTS /quiet'
    },
    {
        "description": "Ensure 'User Rights Assignment: Deny log on as a service' to include 'Guests' (CIS Control 2.3.16.18)",
        "command": 'secedit /configure /cfg "%systemroot%\\security\\templates\\setup.inf" /db sec.sdb /areas USER_RIGHTS /quiet'
    },
    {
        "description": "Ensure 'User Rights Assignment: Deny log on locally' is set to 'Guests, Remote Desktop Users' (CIS Control 2.3.16.19)",
        "command": 'secedit /configure /cfg "%systemroot%\\security\\templates\\setup.inf" /db sec.sdb /areas USER_RIGHTS /quiet'
    },
    {
        "description": "Ensure 'User Rights Assignment: Deny log on through Remote Desktop Services' is set to 'Guests, Remote Desktop Users' (CIS Control 2.3.16.20)",
        "command": 'secedit /configure /cfg "%systemroot%\\security\\templates\\setup.inf" /db sec.sdb /areas USER_RIGHTS /quiet'
    },
    {
        "description": "Ensure 'User Rights Assignment: Enable computer and user accounts to be trusted for delegation' is set to 'No One' (CIS Control 2.3.16.21)",
        "command": 'secedit /configure /cfg "%systemroot%\\security\\templates\\setup.inf" /db sec.sdb /areas USER_RIGHTS /quiet'
    },
    {
        "description": "Ensure 'User Rights Assignment: Force shutdown from a remote system' to include 'Administrators' (CIS Control 2.3.16.22)",
        "command": 'secedit /configure /cfg "%systemroot%\\security\\templates\\setup.inf" /db sec.sdb /areas USER_RIGHTS /quiet'
    },
    {
        "description": "Ensure 'User Rights Assignment: Generate security audits' is set to 'LOCAL SERVICE, NETWORK SERVICE, SERVICE, Administrators' (CIS Control 2.3.16.23)",
        "command": 'secedit /configure /cfg "%systemroot%\\security\\templates\\setup.inf" /db sec.sdb /areas USER_RIGHTS /quiet'
    },
    {
        "description": "Ensure 'User Rights Assignment: Impersonate a client after authentication' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE' (CIS Control 2.3.16.24)",
        "command": 'secedit /configure /cfg "%systemroot%\\security\\templates\\setup.inf" /db sec.sdb /areas USER_RIGHTS /quiet'
    },
    {
        "description": "Ensure 'User Rights Assignment: Increase scheduling priority' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE' (CIS Control 2.3.16.25)",
        "command": 'secedit /configure /cfg "%systemroot%\\security\\templates\\setup.inf" /db sec.sdb /areas USER_RIGHTS /quiet'
    },
    {
        "description": "Ensure 'User Rights Assignment: Load and unload device drivers' is set to 'Administrators' (CIS Control 2.3.16.26)",
        "command": 'secedit /configure /cfg "%systemroot%\\security\\templates\\setup.inf" /db sec.sdb /areas USER_RIGHTS /quiet'
    },
    {
        "description": "Ensure 'User Rights Assignment: Lock pages in memory' is set to 'No One' (CIS Control 2.3.16.27)",
        "command": 'secedit /configure /cfg "%systemroot%\\security\\templates\\setup.inf" /db sec.sdb /areas USER_RIGHTS /quiet'
    },
    {
        "description": "Ensure 'User Rights Assignment: Manage auditing and security log' is set to 'Administrators, NETWORK SERVICE' (CIS Control 2.3.16.28)",
        "command": 'secedit /configure /cfg "%systemroot%\\security\\templates\\setup.inf" /db sec.sdb /areas USER_RIGHTS /quiet'
    },
    {
        "description": "Ensure 'User Rights Assignment: Modify an object label' is set to 'No One' (CIS Control 2.3.16.29)",
        "command": 'secedit /configure /cfg "%systemroot%\\security\\templates\\setup.inf" /db sec.sdb /areas USER_RIGHTS /quiet'
    },
    {
        "description": "Ensure 'User Rights Assignment: Modify firmware environment values' is set to 'Administrators' (CIS Control 2.3.16.30)",
        "command": 'secedit /configure /cfg "%systemroot%\\security\\templates\\setup.inf" /db sec.sdb /areas USER_RIGHTS /quiet'
    },
    {
        "description": "Ensure 'User Rights Assignment: Perform volume maintenance tasks' is set to 'Administrators' (CIS Control 2.3.16.31)",
        "command": 'secedit /configure /cfg "%systemroot%\\security\\templates\\setup.inf" /db sec.sdb /areas USER_RIGHTS /quiet'
    },
    {
        "description": "Ensure 'User Rights Assignment: Profile single process' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE' (CIS Control 2.3.16.32)",
        "command": 'secedit /configure /cfg "%systemroot%\\security\\templates\\setup.inf" /db sec.sdb /areas USER_RIGHTS /quiet'
    },
    {
        "description": "Ensure 'User Rights Assignment: Profile system performance' is set to 'Administrators, NT SERVICE\\WdiServiceHost' (CIS Control 2.3.16.33)",
        "command": 'secedit /configure /cfg "%systemroot%\\security\\templates\\setup.inf" /db sec.sdb /areas USER_RIGHTS /quiet'
    },
    {
        "description": "Ensure 'User Rights Assignment: Remove computer from docking station' is set to 'Administrators, Users' (CIS Control 2.3.16.34)",
        "command": 'secedit /configure /cfg "%systemroot%\\security\\templates\\setup.inf" /db sec.sdb /areas USER_RIGHTS /quiet'
    },
    {
        "description": "Ensure 'User Rights Assignment: Replace a process level token' is set to 'LOCAL SERVICE, NETWORK SERVICE' (CIS Control 2.3.16.35)",
        "command": 'secedit /configure /cfg "%systemroot%\\security\\templates\\setup.inf" /db sec.sdb /areas USER_RIGHTS /quiet'
    },
    {
        "description": "Ensure 'User Rights Assignment: Restore files and directories' is set to 'Administrators, Backup Operators' (CIS Control 2.3.16.36)",
        "command": 'secedit /configure /cfg "%systemroot%\\security\\templates\\setup.inf" /db sec.sdb /areas USER_RIGHTS /quiet'
    },
    {
        "description": "Ensure 'User Rights Assignment: Shut down the system' is set to 'Administrators, Users' (CIS Control 2.3.16.37)",
        "command": 'secedit /configure /cfg "%systemroot%\\security\\templates\\setup.inf" /db sec.sdb /areas USER_RIGHTS /quiet'
    },
    {
        "description": "Ensure 'User Rights Assignment: Synchronize directory service data' is set to 'No One' (CIS Control 2.3.16.38)",
        "command": 'secedit /configure /cfg "%systemroot%\\security\\templates\\setup.inf" /db sec.sdb /areas USER_RIGHTS /quiet'
    },
    {
        "description": "Ensure 'User Rights Assignment: Take ownership of files or other objects' is set to 'Administrators' (CIS Control 2.3.16.39)",
        "command": 'secedit /configure /cfg "%systemroot%\\security\\templates\\setup.inf" /db sec.sdb /areas USER_RIGHTS /quiet'
    }
]

# Check if running as admin on Windows
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False

# Function to run selected commands
def run_selected_commands():
    selected_commands = []
    for cmd_info in commands_displayed:
        if command_vars[cmd_info["description"]].get() == 1:
            selected_commands.append(cmd_info["command"])
    
    # Execute selected commands (you can define your logic here)
    for cmd in selected_commands:
        print(f"Running command: {cmd}")
        # Execute your command logic here

    messagebox.showinfo("Commands Executed", "Selected commands have been executed.")

# Function to display commands on the GUI for the current page
def show_commands(page_num):
    global commands_displayed
    page_start = page_num * 10
    page_end = page_start + 10
    commands_displayed = commands[page_start:page_end]

    # Clear previous checkboxes
    for widget in commands_frame.winfo_children():
        widget.destroy()

    # Display commands for the current page
    for i, cmd_info in enumerate(commands_displayed, start=1):
        var = tk.IntVar(value=1)  # Default to enabled (1), change to 0 to disable by default
        command_vars[cmd_info["description"]] = var
        chk = tk.Checkbutton(commands_frame, text=cmd_info["description"], variable=var)
        chk.grid(row=i, column=0, sticky='w', padx=10, pady=5)

# Function to handle page navigation
def next_page():
    global current_page
    if current_page < max_pages - 1:
        current_page += 1
        show_commands(current_page)

def prev_page():
    global current_page
    if current_page > 0:
        current_page -= 1
        show_commands(current_page)

# Main tkinter window
root = tk.Tk()
root.title("Commands GUI")

# Check admin status
if not is_admin():
    messagebox.showwarning("Admin Privileges Required", "This script requires admin privileges to run properly.")

# Create a frame for commands
commands_frame = ttk.Frame(root)
commands_frame.pack(padx=10, pady=10)

# Initialize variables to store command checkboxes and pagination
command_vars = {}
commands_displayed = []  # List to hold commands displayed on current page
current_page = 0

# Calculate total pages
total_commands = len(commands)
max_pages = (total_commands - 1) // 10 + 1  # Calculate total pages

# Display initial commands
show_commands(current_page)

# Navigation buttons
prev_button = tk.Button(root, text="Previous Page", command=prev_page)
prev_button.pack(side=tk.LEFT, padx=10, pady=10)

next_button = tk.Button(root, text="Next Page", command=next_page)
next_button.pack(side=tk.RIGHT, padx=10, pady=10)

# Run button to execute selected commands
run_button = tk.Button(root, text="Run Selected Commands", command=run_selected_commands)
run_button.pack(pady=10)

# Run the tkinter main loop
root.mainloop()