Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# -----------------------------
# Script-scoped variables
# -----------------------------
$script:inputFile = $null
$script:outputFile = $null

# -----------------------------
# Create main form
# -----------------------------
$form = New-Object System.Windows.Forms.Form
$form.Text = "Metanoia"
$form.Size = New-Object System.Drawing.Size(500, 320)
$form.StartPosition = "CenterScreen"

# Conversion mode dropdown
$modeLabel = New-Object System.Windows.Forms.Label
$modeLabel.Text = "Conversion Mode:"
$modeLabel.Location = New-Object System.Drawing.Point(20,20)
$modeLabel.AutoSize = $true
$form.Controls.Add($modeLabel)

$modeCombo = New-Object System.Windows.Forms.ComboBox
$modeCombo.Items.AddRange(@("to-ndjson","to-json"))
$modeCombo.SelectedIndex = 0
$modeCombo.Location = New-Object System.Drawing.Point(150,18)
$modeCombo.Width = 150
$form.Controls.Add($modeCombo)

# Input file label
$inputLabel = New-Object System.Windows.Forms.Label
$inputLabel.Text = "Drop input file here or use the button"
$inputLabel.Location = New-Object System.Drawing.Point(20,60)
$inputLabel.Width = 440
$inputLabel.Height = 40
$inputLabel.BorderStyle = 'Fixed3D'
$inputLabel.TextAlign = 'MiddleCenter'
$inputLabel.AllowDrop = $true
$form.Controls.Add($inputLabel)

# Drag-and-drop input
$inputLabel.Add_DragEnter({
    if ($_.Data.GetDataPresent([Windows.Forms.DataFormats]::FileDrop)) {
        $_.Effect = [System.Windows.Forms.DragDropEffects]::Copy
    }
})

$inputLabel.Add_DragDrop({
    $files = $_.Data.GetData([Windows.Forms.DataFormats]::FileDrop)
    if ($files.Length -ge 1) {
        $script:inputFile = $files[0]
        $inputLabel.Text = $script:inputFile

        # Suggest output file if not set
        if (-not $script:outputFile) {
            $base = [System.IO.Path]::GetFileNameWithoutExtension($script:inputFile)
            $ext = if ($modeCombo.SelectedItem -eq "to-ndjson") { ".ndjson" } else { ".json" }
            $script:outputFile = [System.IO.Path]::Combine([System.IO.Path]::GetDirectoryName($script:inputFile), "$base$ext")
            $outputLabel.Text = $script:outputFile
        }
    }
})

# Input file button
$inputButton = New-Object System.Windows.Forms.Button
$inputButton.Text = "Select Input File"
$inputButton.Location = New-Object System.Drawing.Point(20,110)
$inputButton.Width = 150
$form.Controls.Add($inputButton)

$inputButton.Add_Click({
    $ofd = New-Object System.Windows.Forms.OpenFileDialog
    $ofd.Filter = "JSON or NDJSON|*.json;*.ndjson|All files|*.*"
    if ($ofd.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        $script:inputFile = $ofd.FileName
        $inputLabel.Text = $script:inputFile

        # Suggest output file if not set
        if (-not $script:outputFile) {
            $base = [System.IO.Path]::GetFileNameWithoutExtension($script:inputFile)
            $ext = if ($modeCombo.SelectedItem -eq "to-ndjson") { ".ndjson" } else { ".json" }
            $script:outputFile = [System.IO.Path]::Combine([System.IO.Path]::GetDirectoryName($script:inputFile), "$base$ext")
            $outputLabel.Text = $script:outputFile
        }
    }
})

# Output file label
$outputLabel = New-Object System.Windows.Forms.Label
$outputLabel.Text = "No file selected"
$outputLabel.Location = New-Object System.Drawing.Point(20,160)
$outputLabel.Width = 440
$outputLabel.Height = 25
$form.Controls.Add($outputLabel)

# Output file button
$outputButton = New-Object System.Windows.Forms.Button
$outputButton.Text = "Select Output File"
$outputButton.Location = New-Object System.Drawing.Point(20,190)
$outputButton.Width = 150
$form.Controls.Add($outputButton)

$outputButton.Add_Click({
    $sfd = New-Object System.Windows.Forms.SaveFileDialog
    $sfd.Filter = "JSON|*.json|NDJSON|*.ndjson|All files|*.*"
    $sfd.FileName = if ($script:outputFile) { $script:outputFile } elseif ($script:inputFile) {
        $base = [System.IO.Path]::GetFileNameWithoutExtension($script:inputFile)
        $ext = if ($modeCombo.SelectedItem -eq "to-ndjson") { ".ndjson" } else { ".json" }
        "$base$ext"
    } else { "output.json" }

    if ($sfd.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        $script:outputFile = $sfd.FileName
        $outputLabel.Text = $script:outputFile
    }
})

# Convert button
$convertButton = New-Object System.Windows.Forms.Button
$convertButton.Text = "Convert"
$convertButton.Location = New-Object System.Drawing.Point(200,230)
$convertButton.Width = 100
$form.Controls.Add($convertButton)

$convertButton.Add_Click({
    try {
        if (-not $script:inputFile -or -not $script:outputFile) {
            [System.Windows.Forms.MessageBox]::Show("Please select input and output files","Metanoia","OK","Warning")
            return
        }

        if ($modeCombo.SelectedItem -eq "to-ndjson") {
            $data = Get-Content $script:inputFile -Raw | ConvertFrom-Json
            Remove-Item $script:outputFile -ErrorAction SilentlyContinue
            if ($data -is [System.Collections.IEnumerable]) {
                $data | ForEach-Object {
                    $_ | ConvertTo-Json -Compress | Out-File -Append -Encoding UTF8 $script:outputFile
                }
            } else {
                $data | ConvertTo-Json -Compress | Out-File -Encoding UTF8 $script:outputFile
            }
        } else {
            $lines = Get-Content $script:inputFile
            $data = $lines | ForEach-Object { $_ | ConvertFrom-Json }
            $data | ConvertTo-Json -Depth 100 | Set-Content $script:outputFile -Encoding UTF8
        }

        [System.Windows.Forms.MessageBox]::Show("Conversion completed!`nOutput: $script:outputFile","Metanoia","OK","Information")
    } catch {
        [System.Windows.Forms.MessageBox]::Show("Error: $($_.Exception.Message)","Metanoia","OK","Error")
    }
})

# Form shown
$form.Topmost = $true
$form.Add_Shown({$form.Activate()})
[void] $form.ShowDialog()
