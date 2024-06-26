Add-Type -AssemblyName System.Windows.Forms

function Test-Admin {
    $currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Admin)) {
    [System.Windows.Forms.MessageBox]::Show("You need to have Administrator rights to run this program.", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    exit
}

# Define the registry and system commands
$commands = @(
    @{
        description = "Enforce password history (CIS Control 1.1.1)"
        command = 'reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v MaximumPasswordAge /t REG_DWORD /d 24 /f'
    },
    @{
        description = "Minimum password length (CIS Control 1.1.2)"
        command = 'reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v MinimumPasswordLength /t REG_DWORD /d 14 /f'
    },
    @{
        description = "Minimum password age is set to 1 or more day(s) (CIS Control 1.1.3)"
        command = 'reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v MinimumPasswordAge /t REG_DWORD /d 1 /f'
    },
    @{
        description = "Ensure Minimum password length' is set to '14 or more character(s) (CIS Control 1.1.4)"
        command = 'reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v MinimumPasswordLength /t REG_DWORD /d 14 /f'
    },
    @{
        description = "Ensure Password must meet complexity requirements is set to 'Enabled' (CIS Control 1.1.5)"
        command = 'reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v PasswordComplexity /t REG_DWORD /d 1 /f'
    },
    @{
        description = "Ensure 'Relax minimum password length limits' is set to 'Enabled' (CIS Control 1.1.6)"
        command = 'reg add "HKLM\System\CurrentControlSet\Control\SAM" /v RelaxMinimumPasswordLengthLimits /t REG_DWORD /d 1 /f'
    },
    @{
        description = "Ensure 'Store passwords using reversible encryption' is set to 'Disabled' (CIS Control 1.1.7)"
        command = 'reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v ClearTextPassword /t REG_DWORD /d 0 /f'
    },
    @{
        description = "Ensure 'Account lockout duration' is set to '15 or more minute(s)' (CIS Control 1.2.1)"
        command = 'reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v LockoutDuration /t REG_DWORD /d 15 /f'
    },
    @{
        description = "Account lockout threshold (CIS Control 1.2.2)"
        command = 'reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v LockoutBadCount /t REG_DWORD /d 5 /f'
    },
    @{
        description = "Enable 'Do not display last user name' (CIS Control 2.2.1)"
        command = 'reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v DontDisplayLastUserName /t REG_DWORD /d 1 /f'
    },
    @{
        description = "Disable 'Do not require CTRL+ALT+DEL' (CIS Control 2.2.2)"
        command = 'reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v DisableCAD /t REG_DWORD /d 0 /f'
    },
    @{
        description = "Set 'Audit Logon Events' to 'Success and Failure' (CIS Control 2.3.1)"
        command = 'auditpol /set /subcategory:"Logon" /success:enable /failure:enable'
    },
    @{
        description = "Disable Guest account (CIS Control 3.2)"
        command = 'net user guest /active:no'
    },
    @{
        description = "Enable Windows Defender (CIS Control 5.1)"
        command = 'reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 0 /f'
    }
)

# Create the main form
$form = New-Object Windows.Forms.Form
$form.Text = "CIS Benchmark Level 1"
$form.Width = 800
$form.Height = 600

# Create a panel to hold the checkboxes
$panel = New-Object Windows.Forms.Panel
$panel.Dock = [System.Windows.Forms.DockStyle]::Fill
$form.Controls.Add($panel)

# Create checkboxes for each command
$checkboxes = @()
foreach ($cmd in $commands) {
    $checkbox = New-Object Windows.Forms.CheckBox
    $checkbox.Text = $cmd.description
    $checkbox.AutoSize = $true
    $checkbox.Checked = $true
    $panel.Controls.Add($checkbox)
    $checkboxes += $checkbox
}

# Create a button to run the selected commands
$runButton = New-Object Windows.Forms.Button
$runButton.Text = "Run Selected"
$runButton.Dock = [System.Windows.Forms.DockStyle]::Bottom
$form.Controls.Add($runButton)

# Define the event handler for the run button
$runButton.Add_Click({
    foreach ($i in 0..($checkboxes.Length - 1)) {
        if ($checkboxes[$i].Checked) {
            try {
                Invoke-Expression $commands[$i].command
                [System.Windows.Forms.MessageBox]::Show("Successfully executed: " + $commands[$i].description, "Success", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
            } catch {
                [System.Windows.Forms.MessageBox]::Show("Failed to execute: " + $commands[$i].description + "`nError: $_", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
            }
        }
    }
})

# Show the form
[void]$form.ShowDialog()
