import tkinter as tk
from tkinter import messagebox, simpledialog
import subprocess
import ctypes
import os
import sys

def is_admin():
    """
    Check if the script is running with administrative privileges.
    """
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

if not is_admin():
    messagebox.showerror("Error", "You need to have Administrator rights to run this program.")
    exit()

# Prompt user for new Administrator username
root = tk.Tk()
root.withdraw()  # Hide the main window
new_admin_username = simpledialog.askstring("New Administrator Username", "Enter the new Administrator username:")

# Prompt user to set Legal Notice Text

def set_legal_notice_text():
    legal_notice_text = input("Enter the message text for users attempting to log on: ").strip()
    
    # Check if the input is not empty
    if not legal_notice_text:
        print("Legal notice text cannot be empty.")
        return
    
    # Define the registry key path and value name "Configure 'Interactive logon: Message text for users attempting to log on' (CIS Control 2.3.7.5)"
    key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    value_name = "LegalNoticeText"
    
    # Construct the command to set the registry value
    command = f'reg add "HKLM\\{key_path}" /v {value_name} /t REG_SZ /d "{legal_notice_text}" /f'
    
    # Execute the command
    os.system(command)
    
    print(f"LegalNoticeText set to: {legal_notice_text}")

if __name__ == "__main__":
    # Check if the script is running with administrator privileges
    if not ctypes.windll.shell32.IsUserAnAdmin():
        print("Please run the script as an administrator.")
        sys.exit(1)
    
    set_legal_notice_text()

#Set Legal notice Title "2.3.7.6 (L1) Configure 'Interactive logon: Message title for users attempting to log on'"
def set_message_title():
    message_title = input("Enter the message title for users attempting to log on: ").strip()
    
    # Check if the input is not empty
    if not message_title:
        print("Message title cannot be empty.")
        return
    
    # Define the registry key path and value name
    key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    value_name = "LegalNoticeCaption"
    
    # Construct the command to set the registry value
    command = f'reg add "HKLM\\{key_path}" /v {value_name} /t REG_SZ /d "{message_title}" /f'
    
    # Execute the command
    os.system(command)
    
    print(f"Message title set to: {message_title}")

if __name__ == "__main__":
    # Check if the script is running with administrator privileges
    if not ctypes.windll.shell32.IsUserAnAdmin():
        print("Please run the script as an administrator.")
        sys.exit(1)
    
    set_message_title()

# Define the registry commands
commands = [
    {
        "description": "Enforce password history (CIS Control 1.1.1)",
        "command": 'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters" /v MaximumPasswordAge /t REG_DWORD /d 24 /f'
    },
    {
        "description": "Minimum password length (CIS Control 1.1.2)",
        "command": 'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters" /v MinimumPasswordLength /t REG_DWORD /d 14 /f'
    },
    {
        "description": "Minimum password age is set to 1 or more day(s) (CIS Control 1.1.3)",
        "command": 'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters" /v MinimumPasswordAge /t REG_DWORD /d 1 /f'
    },
    {
        "description": "Ensure Minimum password length' is set to '14 or more character(s) (CIS Control 1.1.4)",
        "command": 'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters" /v MinimumPasswordLength /t REG_DWORD /d 14 /f'
    },
    {
        "description": "Ensure Password must meet complexity requirements is set to 'Enabled' (CIS Control 1.1.5)",
        "command": 'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters" /v PasswordComplexity /t REG_DWORD /d 1 /f'
    },
    {
        "description": "Ensure 'Relax minimum password length limits' is set to 'Enabled' (CIS Control 1.1.6)",
        "command": 'reg add "HKLM\\System\\CurrentControlSet\\Control\\SAM" /v RelaxMinimumPasswordLengthLimits /t REG_DWORD /d 1 /f'
    },
    {
        "description": "Ensure 'Store passwords using reversible encryption' is set to 'Disabled' (CIS Control 1.1.7)",
        "command": 'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters" /v ClearTextPassword /t REG_DWORD /d 0 /f'
    },
    {
        "description": "Ensure 'Account lockout duration' is set to '15 or more minute(s)'  (CIS Control 1.2.1)",
        "command": 'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters" /v LockoutDuration /t REG_DWORD /d 15 /f'
    },
    {
        "description": "Account lockout threshold (CIS Control 1.2.2)",
        "command": 'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters" /v LockoutBadCount /t REG_DWORD /d 5 /f'
    },
    {
        "description": "Ensure 'Allow Administrator account lockout' is set to 'Enabled' (CIS Control 1.2.3)",
        "command": 'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v AllowAdministratorAccountLockout /t REG_DWORD /d 1 /f'
    },
    {
        "description": "Ensure 'Reset account lockout counter after' is set to '15 or more minute(s) (CIS Control 1.2.4)",
        "command": 'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v ResetAccountLockoutCounterAfter /t REG_DWORD /d 15 /f'
    },
    {
        "description": "Ensure 'Access Credential Manager as a trusted caller' is set to 'No One' (CIS Control 2.2.1)",
        "command": 'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa" /v SCENoOne /t REG_SZ /d "" /f'
    },
    {
        "description": "Ensure 'Adjust memory quotas for a process' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE' (CIS Control 2.2.4)",
        "command": 'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management" /v AdjustProcessAccessToken /t REG_MULTI_SZ /d "Administrators\0LOCAL SERVICE\0NETWORK SERVICE" /f'
    },
    {
        "description": "Ensure 'Act as part of the operating system' is set to 'No One' (CIS Control 2.2.2)",
        "command": 'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa" /v restrictanonymous /t REG_DWORD /d 1 /f'
    },
    {
        "description": "Ensure 'Access this computer from the network' is set to 'Administrators, Remote Desktop Users' (CIS Control 2.2.2)",
        "command": 'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa" /v restrictanonymous /t REG_DWORD /d 1 /f'
    },
    {
        "description": "Ensure 'Adjust memory quotas for a process' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE' (CIS Control 2.2.4)",
        "command": 'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management" /v AdjustProcessAccessToken /t REG_MULTI_SZ /d "Administrators\0LOCAL SERVICE\0NETWORK SERVICE" /f'
    },
    {
        "description": "Ensure 'Allow log on locally' is set to 'Administrators, Users' (CIS Control 2.2.5)",
        "command": 'reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\System" /v AllowLogonLocally /t REG_MULTI_SZ /d "Administrators\\0Users" /f'
    },
    {
        "description": "Ensure 'Allow log on through Remote Desktop Services' is set to 'Administrators, Remote Desktop Users' (CIS Control 2.2.6)",
        "command": 'reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services" /v AllowLogonThroughTerminalServices /t REG_MULTI_SZ /d "Administrators\\0Remote Desktop Users" /f'
    },
    {
        "description": "Ensure 'Back up files and directories' is set to 'Administrators' (CIS Control 2.2.7)",
        "command": 'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters" /v SMBBackupOperators /t REG_MULTI_SZ /d "Administrators" /f'
    },
    {
        "description": "Ensure 'Change the system time' is set to 'Administrators, LOCAL SERVICE' (CIS Control 2.2.8)",
        "command": 'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v FullPrivilegeAuditing /t REG_DWORD /d 0 /f'
    },
    {
        "description": "Ensure 'Change the time zone' is set to 'Administrators, LOCAL SERVICE, Users' (CIS Control 2.2.9)",
        "command": 'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v TimeZoneInformation /t REG_MULTI_SZ /d "Administrators\0LOCAL SERVICE\0Users" /f'
    },
    {
        "description": "Ensure 'Create a pagefile' is set to 'Administrators' (CIS Control 2.2.10)",
        "command": 'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management" /v PagingFiles /t REG_MULTI_SZ /d "C:\\pagefile.sys 0 0" /f'
    },
    {
        "description": "Ensure 'Create a token object' is set to 'No One' (CIS Control 2.2.11)",
        "command": 'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Services\\WinRM" /v TokenObject /t REG_DWORD /d 0 /f'
    },
    {
        "description": "Ensure 'Create global objects' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE' (CIS Control 2.2.12)",
        "command": 'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v CreateGlobalObjects /t REG_MULTI_SZ /d "Administrators\0LOCAL SERVICE\0NETWORK SERVICE\0SERVICE" /f'
    },
    {
        "description": "Ensure 'Create permanent shared objects' is set to 'No One' (CIS Control 2.2.13)",
        "command": 'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager" /v ProtectionMode /t REG_DWORD /d 1 /f'
    },
    {
        "description": "Ensure 'Create symbolic links' is set to 'Administrators' (CIS Control 2.2.14)",
        "command": 'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v EnableLinkedConnections /t REG_DWORD /d 1 /f'
    },
    {
        "description": "Ensure 'Debug programs' is set to 'Administrators' (CIS Control 2.2.15)",
        "command": 'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v Debugger /t REG_MULTI_SZ /d "Administrators" /f'
    },
    {
        "description": "Ensure 'Deny access to this computer from the network' is set to 'Guests, Local account' (CIS Control 2.2.16)",
        "command": 'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f'
    },
    {
        "description": "Ensure 'Deny log on as a batch job' to include 'Guests' (CIS Control 2.2.17)",
        "command": 'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa" /v EveryoneIncludesAnonymous /t REG_DWORD /d 0 /f'
    },
    {
        "description": "Ensure 'Deny log on as a service' to include 'Guests' (CIS Control 2.2.18)",
        "command": 'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa" /v NoLMHash /t REG_DWORD /d 1 /f'
    },
    {
        "description": "Ensure 'Deny log on locally' to include 'Guests' (CIS Control 2.2.19)",
        "command": 'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa" /v limitblankpassworduse /t REG_DWORD /d 1 /f'
    },
    {
        "description": "Ensure 'Deny log on through Remote Desktop Services' to include 'Guests, Local account' (CIS Control 2.2.20)",
        "command": 'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v FilterAdministratorToken /t REG_DWORD /d 1 /f'
    },
    {
        "description": "Ensure 'Enable admin approval mode for the built-in Administrator account' is set to 'Enabled' (CIS Control 2.2.21)",
        "command": 'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v EnableLUA /t REG_DWORD /d 1 /f'
    },
    {
        "description": "Ensure 'Force shutdown from a remote system' is set to 'Administrators' (CIS Control 2.2.22)",
        "command": 'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters" /v NullSessionPipes /t REG_MULTI_SZ /d "RPCSS\0COMNAP\0Srvsvc" /f'
    },
    {
        "description": "Ensure 'Impersonate a client after authentication' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE' (CIS Control 2.2.23)",
        "command": 'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v SeTcbPrivilege /t REG_DWORD /d 0 /f'
    },
    {
        "description": "Ensure 'Increase a process working set' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE' (CIS Control 2.2.24)",
        "command": 'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management" /v PageFileExecution /t REG_DWORD /d 1 /f'
    },
    {
        "description": "Ensure 'Increase scheduling priority' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE' (CIS Control 2.2.25)",
        "command": 'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management" /v DisablePagingExecutive /t REG_DWORD /d 1 /f'
    },
    {
        "description": "Ensure 'Load and unload device drivers' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE' (CIS Control 2.2.26)",
        "command": 'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v EnableInstallerDetection /t REG_DWORD /d 1 /f'
    },
    {
        "description": "Ensure 'Lock pages in memory' is set to 'Administrators' (CIS Control 2.2.27)",
        "command": 'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters" /v RestrictNullSessAccess /t REG_MULTI_SZ /d "0" /f'
    },
    {
        "description": "Ensure 'Log on as a batch job' includes 'Administrators, Users' (CIS Control 2.2.28)",
        "command": 'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v HideLegacyLogonScripts /t REG_DWORD /d 1 /f'
    },
    {
        "description": "Ensure 'Log on as a service' includes 'Administrators, Users' (CIS Control 2.2.29)",
        "command": 'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v HideLogoffScripts /t REG_DWORD /d 1 /f'
    },
    {
        "description": "Ensure 'Log on locally' includes 'Administrators, Users' (CIS Control 2.2.30)",
        "command": 'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v RunStartupScriptSync /t REG_DWORD /d 1 /f'
    },
    {
        "description": "Ensure 'Manage auditing and security log' includes 'Administrators, Audit administrators, Backup operators, Users' (CIS Control 2.2.31)",
        "command": 'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v HideStartupScripts /t REG_DWORD /d 1 /f'
    },
    {
        "description": "Ensure 'Modify firmware environment values' is set to 'Administrators' (CIS Control 2.2.32)",
        "command": 'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v HideStartupScripts /t REG_DWORD /d 1 /f'
    },
    {
        "description": "Ensure 'Perform volume maintenance tasks' is set to 'Administrators' (CIS Control 2.2.33)",
        "command": 'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v HideStartupScripts /t REG_DWORD /d 1 /f'
    },
    {
        "description": "Ensure 'Profile single process' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE' (CIS Control 2.2.34)",
        "command": 'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v RunLogonScriptSync /t REG_DWORD /d 1 /f'
    },
    {
        "description": "Ensure 'Profile system performance' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE' (CIS Control 2.2.35)",
        "command": 'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v HideStartupScripts /t REG_DWORD /d 1 /f'
    },
    {
        "description": "Ensure 'Replace a process level token' is set to 'Administrators' (CIS Control 2.2.36)",
        "command": 'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v RunStartupScriptSync /t REG_DWORD /d 1 /f'
    },
    {
        "description": "Ensure 'Restore files and directories' is set to 'Administrators' (CIS Control 2.2.37)",
        "command": 'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v RunStartupScriptSync /t REG_DWORD /d 1 /f'
    },
    {
        "description": "Ensure 'Shut down the system' is set to 'Administrators, Users' (CIS Control 2.2.38)",
        "command": 'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v HideStartupScripts /t REG_DWORD /d 1 /f'
    },
    {
        "description": "Ensure 'Take ownership of files or other objects' is set to 'Administrators' (CIS Control 2.2.39)",
        "command": 'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v HideStartupScripts /t REG_DWORD /d 1 /f'
    },
    {
    "description": "Ensure 'Accounts: Block Microsoft accounts' is set to 'Users can't add or log on with Microsoft accounts' (CIS Control 2.3.1.1)",
    "command": 'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v NoConnectedUser /t REG_DWORD /d 3 /f'
    },
    {
    "description": "Ensure 'Accounts: Guest account status' is set to 'Disabled' (CIS Control 2.3.1.2)",
    "command": 'net user Guest /active:no'
    },
    {
    "description": "Ensure 'Accounts: Limit local account use of blank passwords to console logon only' is set to 'Enabled' (CIS Control 2.3.1.3)",
    "command": 'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa" /v LimitBlankPasswordUse /t REG_DWORD /d 1 /f'
    },
    #{
    #"description": "Configure 'Accounts: Rename administrator account' (CIS Control 2.3.1.4)",
    #"command": 'schtasks /Create /SC ONSTART /TN RenameAdmin /TR "net user administrator new_admin_name"'
    #},
    {
    "description": "Configure 'Accounts: Rename guest account' (CIS Control 2.3.1.5)",
    "command": 'schtasks /Create /SC ONSTART /TN RenameGuest /TR "net user guest Disabled"'
    },
    {
    "description": "Ensure 'Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings' is set to 'Enabled' (CIS Control 2.3.2.1)",
    "command": 'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa" /v ScenoApplyLegacyAuditPolicy /t REG_DWORD /d 0 /f'
    },
    {
    "description": "Ensure 'Audit: Shut down system immediately if unable to log security audits' is set to 'Disabled' (CIS Control 2.3.2.2)",
    "command": 'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa" /v CrashOnAuditFail /t REG_DWORD /d 0 /f'
    },
    {
    "description": "Ensure 'Devices: Prevent users from installing printer drivers' is set to 'Enabled' (CIS Control 2.3.4.1)",
    "command": 'reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers" /v PreventNetworkPrintersInstall /t REG_DWORD /d 1 /f'
    },
    {
    "description": "Ensure 'Interactive logon: Do not require CTRL+ALT+DEL' is set to 'Disabled' (CIS Control 2.3.7.1)",
    "command": 'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v DisableCAD /t REG_DWORD /d 0 /f'
    },
    {
    "description": "Ensure 'Interactive logon: Don't display last signed-in' is set to 'Enabled' (CIS Control 2.3.7.2)",
    "command": 'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v DontDisplayLastUserName /t REG_DWORD /d 1 /f'
    },
    {
    "description": "Ensure 'Interactive logon: Machine inactivity limit' is set to '900 or fewer second(s), but not 0' (CIS Control 2.3.7.4)",
    "command": 'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v InactivityTimeoutSecs /t REG_DWORD /d 900 /f'
    },
    {
    "description": "Ensure 'Interactive logon: Prompt user to change password before expiration' is set to 'between 5 and 14 days' (Automated)",
    "command": 'powershell -Command "& {Set-ItemProperty -Path \'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\' -Name \'PasswordExpiryWarning\' -Value 14}"'
    },
    {
    "description": "Ensure 'Interactive logon: Smart card removal behavior' is set to 'Lock Workstation' or higher (Automated)",
    "command": 'reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\SmartCardCredentialProvider" /v ForceLockOnSmartCardRemoval /t REG_DWORD /d 1 /f'
    },
    {
    "description": "Ensure 'Microsoft network client: Digitally sign communications (always)' is set to 'Enabled' (Automated)",
    "command": 'reg add "HKLM\\System\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters" /v RequireSecuritySignature /t REG_DWORD /d 1 /f'
    },
    {
    "description": "Ensure 'Microsoft network client: Digitally sign communications (if server agrees)' is set to 'Enabled' (Automated)",
    "command": 'reg add "HKLM\\System\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters" /v EnableSecuritySignature /t REG_DWORD /d 1 /f'
    },
    {
    "description": "Ensure 'Microsoft network client: Send unencrypted password to third-party SMB servers' is set to 'Disabled' (Automated)",
    "command": 'reg add "HKLM\\System\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters" /v EnablePlainTextPassword /t REG_DWORD /d 0 /f'
    },
    {
    "description": "Ensure 'Microsoft network server: Amount of idle time required before suspending session' is set to '15 or fewer minute(s)' (Automated)",
    "command": 'reg add "HKLM\\System\\CurrentControlSet\\Services\\LanmanServer\\Parameters" /v AutoDisconnect /t REG_DWORD /d 15 /f'
    },
    {
    "description": "Ensure 'Microsoft network server: Digitally sign communications (always)' is set to 'Enabled' (Automated)",
    "command": 'reg add "HKLM\\System\\CurrentControlSet\\Services\\LanmanServer\\Parameters" /v RequireSecuritySignature /t REG_DWORD /d 1 /f'
    },
    {
    "description": "Ensure 'Microsoft network server: Digitally sign communications (if client agrees)' is set to 'Enabled' (Automated)",
    "command": 'reg add "HKLM\\System\\CurrentControlSet\\Services\\LanmanServer\\Parameters" /v EnableSecuritySignature /t REG_DWORD /d 1 /f'
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
    "command": "reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters\" /v RestrictNullSessAccess /t REG_DWORD /d 1 /f"
    },
    {
    "description": "Ensure 'Network access: Restrict clients allowed to make remote calls to SAM' is set to 'Administrators: Remote Access: Allow' (CIS Control 2.3.10.10)",
    "command": "reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\LSA\" /v RestrictRemoteSam /t REG_MULTI_SZ /d Administrators /f"
    },
    {
    "description": "Ensure 'Network access: Shares that can be accessed anonymously' is set to 'None' (CIS Control 2.3.10.11)",
    "command": "reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters\" /v NullSessionShares /t REG_MULTI_SZ /d \"\" /f"
    },
    {
    "description": "Ensure 'Network access: Sharing and security model for local accounts' is set to 'Classic - local users authenticate as themselves' (CIS Control 2.3.10.12)",
    "command": "reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\" /v ForceGuest /t REG_DWORD /d 0 /f"
    },
    {
    "description": "Ensure 'Network security: Allow Local System to use computer identity for NTLM' is set to 'Enabled' (CIS Control 2.3.11.1)",
    "command": "reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\" /v UseMachineId /t REG_DWORD /d 1 /f"
    },
    {
    "description": "Ensure 'Network security: Allow LocalSystem NULL session fallback' is set to 'Disabled' (CIS Control 2.3.11.2)",
    "command": "reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\" /v RestrictNullSessAccess /t REG_DWORD /d 1 /f"
    },
    {
    "description": "Ensure 'Network Security: Allow PKU2U authentication requests to this computer to use online identities' is set to 'Disabled' (CIS Control 2.3.11.3)",
    "command": "reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\" /v UseMachineId /t REG_DWORD /d 0 /f"
    },
    {
    "description": "Ensure 'Network security: Configure encryption types allowed for Kerberos' is set to 'AES128_HMAC_SHA1, AES256_HMAC_SHA1, Future encryption types' (CIS Control 2.3.11.4)",
    "command": "reg add \"HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Kerberos\\Parameters\" /v SupportedEncryptionTypes /t REG_DWORD /d 2147483647 /f"
    },
    {
    "description": "Ensure 'Network security: Do not store LAN Manager hash value on next password change' is set to 'Enabled' (CIS Control 2.3.11.5)",
    "command": "reg add \"HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa\" /v NoLMHash /t REG_DWORD /d 1 /f"
    },
    {
    "description": "Ensure 'Network security: Force logoff when logon hours expire' is set to 'Enabled' (CIS Control 2.3.11.6)",
    "command": "reg add \"HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa\" /v ForceLogoffWhenHourExpire /t REG_DWORD /d 1 /f"
    },
    {
    "description": "Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM' (CIS Control 2.3.11.7)",
    "command": "reg add \"HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa\" /v LmCompatibilityLevel /t REG_DWORD /d 5 /f"
    },
    {
    "description": "Ensure 'Network security: LDAP client signing requirements' is set to 'Negotiate signing' or higher (CIS Control 2.3.11.8)",
    "command": "reg add \"HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\LDAP\" /v LDAPClientIntegrity /t REG_DWORD /d 1 /f"
    },
    {
    "description": "Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) clients' is set to 'Require NTLMv2 session security, Require 128-bit encryption' (CIS Control 2.3.11.9)",
    "command": "reg add \"HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\MSV1_0\" /v NTLMMinClientSec /t REG_DWORD /d 537395200 /f"
    },
    {
    "description": "Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) servers' is set to 'Require NTLMv2 session security, Require 128-bit encryption' (CIS Control 2.3.11.10)",
    "command": "reg add \"HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\MSV1_0\" /v NTLMMinServerSec /t REG_DWORD /d 537395200 /f"
    },
    {
    "description": "Ensure 'Network security: Restrict NTLM: Audit Incoming NTLM Traffic' is set to 'Enable auditing for all accounts' (CIS Control 2.3.11.11)",
    "command": "auditpol /set /subcategory:\"Audit Incoming NTLM Traffic\" /success:enable /failure:enable"
    },
    {
    "description": "Ensure 'Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers' is set to 'Audit all' or higher (CIS Control 2.3.11.12)",
    "command": "auditpol /set /subcategory:\"Audit Outgoing NTLM Traffic\" /success:enable /failure:enable"
    },
    {
    "description": "Ensure 'System cryptography: Force strong key protection for user keys stored on the computer' is set to 'User is prompted when the key is first used' or higher (CIS Control 2.3.14.1)",
    "command": "reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Cryptography\" /v ForceKeyProtection /t REG_DWORD /d 1 /f"
    },
    {
    "description": "Ensure 'System objects: Require case insensitivity for non-Windows subsystems' is set to 'Enabled' (CIS Control 2.3.15.1)",
    "command": "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Kernel\" /v ObCaseInsensitive /t REG_DWORD /d 1 /f"
    },
    {
    "description": "Ensure 'System objects: Strengthen default permissions of internal system objects (e.g. Symbolic Links)' is set to 'Enabled' (CIS Control 2.3.15.2)",
    "command": "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\" /v ProtectionMode /t REG_DWORD /d 1 /f"
    },
    {
    "description": "Ensure 'User Account Control: Admin Approval Mode for the Built-in Administrator account' is set to 'Enabled' (CIS Control 2.3.17.1)",
    "command": "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" /v FilterAdministratorToken /t REG_DWORD /d 1 /f"
    },
    {
    "description": "Ensure 'User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode' is set to 'Prompt for consent on the secure desktop' or higher (CIS Control 2.3.17.2)",
    "command": "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 2 /f"
    },
    {
    "description": "Ensure 'User Account Control: Behavior of the elevation prompt for standard users' is set to 'Automatically deny elevation requests' (CIS Control 2.3.17.3)",
    "command": "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" /v ConsentPromptBehaviorUser /t REG_DWORD /d 0 /f"
    },
    {
    "description": "Ensure 'User Account Control: Detect application installations and prompt for elevation' is set to 'Enabled' (CIS Control 2.3.17.4)",
    "command": "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" /v EnableInstallerDetection /t REG_DWORD /d 1 /f"
    },
    {
    "description": "Ensure 'User Account Control: Only elevate UIAccess applications that are installed in secure locations' is set to 'Enabled' (CIS Control 2.3.17.5)",
    "command": "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" /v EnableSecureUIAPaths /t REG_DWORD /d 1 /f"
    },
    {
    "description": "Ensure 'User Account Control: Run all administrators in Admin Approval Mode' is set to 'Enabled' (CIS Control 2.3.17.6)",
    "command": "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" /v EnableLUA /t REG_DWORD /d 1 /f"
    },
    {
    "description": "Ensure 'User Account Control: Switch to the secure desktop when prompting for elevation' is set to 'Enabled' (CIS Control 2.3.17.7)",
    "command": "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" /v PromptOnSecureDesktop /t REG_DWORD /d 1 /f"
    },
    {
    "description": "Ensure 'User Account Control: Virtualize file and registry write failures to per-user locations' is set to 'Enabled' (CIS Control 2.3.17.8)",
    "command": "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" /v EnableVirtualization /t REG_DWORD /d 1 /f"
    }
]

def run_selected_commands():
    """
    Run the selected commands based on the checked checkboxes.
    """
    for var, cmd in zip(check_vars, commands):
        if var.get():
            try:
                subprocess.run(cmd["command"], shell=True, check=True)
                print(f"Successfully executed: {cmd['description']}")
            except subprocess.CalledProcessError as e:
                print(f"Failed to execute: {cmd['description']}\nError: {e}")

    messagebox.showinfo("Info", "Selected commands executed successfully.")

def update_checkboxes():
    """
    Update the visibility of checkboxes based on the current page.
    """
    for cb in checkboxes:
        cb.pack_forget()

    start_idx = current_page * items_per_page
    end_idx = start_idx + items_per_page
    for i in range(start_idx, end_idx):
        if i < len(commands):
            checkboxes[i].pack(anchor='w')

    update_navigation_buttons()

def prev_page():
    """
    Navigate to the previous page of checkboxes.
    """
    global current_page
    if current_page > 0:
        current_page -= 1
        update_checkboxes()

def next_page():
    """
    Navigate to the next page of checkboxes.
    """
    global current_page
    if (current_page + 1) * items_per_page < len(commands):
        current_page += 1
        update_checkboxes()

def update_navigation_buttons():
    """
    Update the state of the navigation buttons based on the current page.
    """
    if current_page == 0:
        prev_button.config(state=tk.DISABLED)
    else:
        prev_button.config(state=tk.NORMAL)

    if (current_page + 1) * items_per_page >= len(commands):
        next_button.config(state=tk.DISABLED)
    else:
        next_button.config(state=tk.NORMAL)

# Create the main window
root = tk.Tk()
root.title("CIS Benchmark Level 1")

# Create a list to hold the state variables for the checkboxes
check_vars = []
checkboxes = []

# Create a checkbox for each command
for cmd in commands:
    var = tk.BooleanVar(value=True)  # Set default value to True (checked)
    check_vars.append(var)
    cb = tk.Checkbutton(root, text=cmd["description"], variable=var)
    checkboxes.append(cb)

# Pagination setup
current_page = 0
items_per_page = 10

# Function to run selected commands
def run_selected_commands():
    for var, cmd in zip(check_vars, commands):
        if var.get():
            try:
                subprocess.run(cmd["command"], shell=True, check=True)
                print(f"Successfully executed: {cmd['description']}")
            except subprocess.CalledProcessError as e:
                print(f"Failed to execute: {cmd['description']}\nError: {e}")

    messagebox.showinfo("Info", "Selected commands executed successfully.")

# Function to update checkboxes based on current page
def update_checkboxes():
    for cb in checkboxes:
        cb.pack_forget()

    start_idx = current_page * items_per_page
    end_idx = start_idx + items_per_page
    for i in range(start_idx, end_idx):
        if i < len(checkboxes):
            checkboxes[i].pack(anchor='w')

    update_navigation_buttons()

# Function to navigate to previous page
def prev_page():
    global current_page
    if current_page > 0:
        current_page -= 1
        update_checkboxes()

# Function to navigate to next page
def next_page():
    global current_page
    if (current_page + 1) * items_per_page < len(checkboxes):
        current_page += 1
        update_checkboxes()

# Function to update navigation buttons state
def update_navigation_buttons():
    if current_page == 0:
        prev_button.config(state=tk.DISABLED)
    else:
        prev_button.config(state=tk.NORMAL)

    if (current_page + 1) * items_per_page >= len(checkboxes):
        next_button.config(state=tk.DISABLED)
    else:
        next_button.config(state=tk.NORMAL)

# Buttons for navigation
prev_button = tk.Button(root, text="Previous", command=prev_page)
prev_button.pack(side=tk.LEFT, padx=10, pady=10)

next_button = tk.Button(root, text="Next", command=next_page)
next_button.pack(side=tk.RIGHT, padx=10, pady=10)

# Run button
run_button = tk.Button(root, text="Run Selected Commands", command=run_selected_commands)
run_button.pack(side=tk.BOTTOM, pady=20)

# Initial checkbox display
update_checkboxes()

# Start the tkinter main loop
root.mainloop()


