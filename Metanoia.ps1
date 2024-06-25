# Ensure script is run as an administrator
If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "You need to have Administrator rights to run this script."
    Break
}

# Function to set a registry value

function Set-RegistryValue {
    param (
        [string]$KeyPath,
        [string]$Name,
        [string]$Value,
        [string]$PropertyType = "String"
    )

    try {
        New-Item -Path $KeyPath -Force -ErrorAction Stop
        Set-ItemProperty -Path $KeyPath -Name $Name -Value $Value -PropertyType $PropertyType -Force -ErrorAction Stop
        Write-Output "Set registry key: $KeyPath\$Name to $Value"
    } catch {
        Write-Output "Failed to set registry key: $KeyPath\$Name"
    }
}

# Enforce password history (CIS Control 1.1.1)
Set-RegistryValue -KeyPath "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "MaximumPasswordAge" -Value "24"

# Minimum password length (CIS Control 1.1.2)
Set-RegistryValue -KeyPath "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "MinimumPasswordLength" -Value "14"

# Minimum password age is set to 1 or more day(s) (CIS Control 1.1.3)
Set-RegistryValue -KeyPath "HKLM\SYSTEM\CurrentControlSet\Policies\WindowsSettings\SecuritySettings\AccountPolicies\PasswordPolicy" -Name "Minimumpasswordage" -Value "1"

# Ensure Minimum password length' is set to '14 or more character(s) (CIS Control 1.1.4)
Set-RegistryValue -KeyPath "HKLM\SYSTEM\CurrentControlSet\Policies\WindowsSettings\SecuritySettings\AccountPolicies\PasswordPolicy" -Name "Minimumpasswordlength" -Value "14"

# Ensure Password must meet complexity requirements is set to 'Enabled' (CIS Control 1.1.5)
Set-RegistryValue -KeyPath "HKLM\SYSTEM\CurrentControlSet\Policies\WindowsSettings\SecuritySettings\AccountPolicies\PasswordPolicy" -Name "Passwordmustmeetcomplexityrequirements " -Value "Enabled"

# Account lockout threshold (CIS Control 1.2.1)
Set-RegistryValue -KeyPath "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "LockoutBadCount" -Value "5"

# Set 'Audit Logon Events' to 'Success and Failure' (CIS Control 2.3.1)
auditpol /set /subcategory:"Logon" /success:enable /failure:enable

# Disable Guest account (CIS Control 3.2)
net user guest /active:no

# Enable 'Do not display last user name' (CIS Control 2.2.1)
Set-RegistryValue -KeyPath "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DontDisplayLastUserName" -Value "1" -PropertyType "DWord"

# Enable 'Do not require CTRL+ALT+DEL' (CIS Control 2.2.2)
Set-RegistryValue -KeyPath "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableCAD" -Value "0" -PropertyType "DWord"

# Enable Windows Defender (CIS Control 5.1)
Set-RegistryValue -KeyPath "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value "0" -PropertyType "DWord"

Write-Output "CIS Benchmark Level 1 settings applied successfully."
