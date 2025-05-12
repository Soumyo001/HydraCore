# script must run as admin
$nssmUrl = "https://nssm.cc/release/nssm-2.24.zip"  # URL to download NSSM
$nssmFolder = "C:\nssm"
$scriptUrl = "http://example.com/your-script.ps1"  # Replace with the URL of your PowerShell script
$scriptPath = "C:\path\to\your\script.ps1"  # Local path to save the downloaded PowerShell script
$batchFilePath = "C:\path\to\RunScript.bat"  # Path to the batch file that runs the script
$serviceName = "MyPowerShellService"


Write-Host "Downloading NSSM..."
$downloadPath = "$nssmFolder\nssm.zip"
Invoke-WebRequest -Uri $nssmUrl -OutFile $downloadPath


Write-Host "Extracting NSSM..."
Expand-Archive -Path $downloadPath -DestinationPath $nssmFolder


Write-Host "Downloading PowerShell script..."
Invoke-WebRequest -Uri $scriptUrl -OutFile $scriptPath


Write-Host "Creating batch file..."
$batchContent = "@echo off`npowershell.exe -ExecutionPolicy Bypass -File $scriptPath"
Set-Content -Path $batchFilePath -Value $batchContent


Write-Host "Creating the service using NSSM..."
Start-Process -FilePath "$nssmFolder\nssm-2.24\win64\nssm.exe" -ArgumentList "install", $serviceName, $batchFilePath


Write-Host "Configuring the service to run under SYSTEM privileges..."
sc.exe config $serviceName obj=LocalSystem


Write-Host "Setting the service to start automatically..."
sc.exe config $serviceName start=auto


Write-Host "Starting the service..."
Start-Service -Name $serviceName

Write-Host "Service '$serviceName' has been created and started successfully!"
