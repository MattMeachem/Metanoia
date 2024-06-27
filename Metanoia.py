import tkinter as tk
from tkinter import messagebox, simpledialog
import subprocess
import ctypes

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
        "description": "Ensure 'Create global objects' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE' (CIS Control 2.
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


