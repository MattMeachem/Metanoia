import tkinter as tk
from tkinter import messagebox
import subprocess
import os
import ctypes

# Ensure script is run as an administrator
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

if not is_admin():
    messagebox.showerror("Error", "You need to have Administrator rights to run this program.")
    exit()

# Define the registry and system commands
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
        "description": "Enable 'Do not display last user name' (CIS Control 2.2.1)",
        "command": 'reg add "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v DontDisplayLastUserName /t REG_DWORD /d 1 /f'
    },
    {
        "description": "Disable 'Do not require CTRL+ALT+DEL' (CIS Control 2.2.2)",
        "command": 'reg add "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v DisableCAD /t REG_DWORD /d 0 /f'
    },
    {
        "description": "Set 'Audit Logon Events' to 'Success and Failure' (CIS Control 2.3.1)",
        "command": 'auditpol /set /subcategory:"Logon" /success:enable /failure:enable'
    },
    {
        "description": "Disable Guest account (CIS Control 3.2)",
        "command": 'net user guest /active:no'
    },
    {
        "description": "Enable Windows Defender (CIS Control 5.1)",
        "command": 'reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 0 /f'
    }
]

def run_selected_commands():
    for var, cmd in zip(check_vars, commands):
        if var.get():
            try:
                subprocess.run(cmd["command"], shell=True, check=True)
                print(f"Successfully executed: {cmd['description']}")
            except subprocess.CalledProcessError as e:
                print(f"Failed to execute: {cmd['description']}\nError: {e}")

    messagebox.showinfo("Info", "Selected commands executed successfully.")

def update_checkboxes():
    for cb in checkboxes:
        cb.pack_forget()
    
    start_idx = current_page * items_per_page
    end_idx = start_idx + items_per_page
    for i in range(start_idx, end_idx):
        if i < len(commands):
            checkboxes[i].pack(anchor='w')

    update_navigation_buttons()

def prev_page():
    global current_page
    if current_page > 0:
        current_page -= 1
        update_checkboxes()

def next_page():
    global current_page
    if (current_page + 1) * items_per_page < len(commands):
        current_page += 1
        update_checkboxes()

def update_navigation_buttons():
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

# Pagination variables
items_per_page = 10
current_page = 0

# Navigation buttons
prev_button = tk.Button(root, text="Previous", command=prev_page)
next_button = tk.Button(root, text="Next", command=next_page)

# Place navigation buttons
prev_button.pack(side=tk.LEFT)
next_button.pack(side=tk.RIGHT)

# Create a button to run the selected commands
run_button = tk.Button(root, text="Run Selected", command=run_selected_commands)
run_button.pack(side=tk.BOTTOM)

# Display the initial set of checkboxes
update_checkboxes()

# Start the GUI event loop
root.mainloop()
