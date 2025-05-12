# script must run as admin
$nssmUrl = "https://nssm.cc/release/nssm-2.24.zip"  # URL to download NSSM
$nssmFolder = "C:\nssm" # modify this path based on needs
$scriptPath = "C:\path\to\your\script.ps1"  # path to save the downloaded PowerShell script
$serviceName = "MyService"
$exePath = "powershell.exe"
$arguments = "-ep bypass -noP -File $scriptPath"

$downloadPath = "$nssmFolder\nssm.zip"
Invoke-WebRequest -Uri $nssmUrl -OutFile $downloadPath

Expand-Archive -Path $downloadPath -DestinationPath $nssmFolder

Start-Process -FilePath "$nssmFolder\nssm-2.24\win64\nssm.exe" -ArgumentList "install", $serviceName, $exePath, $arguments

sc.exe config $serviceName obj=LocalSystem
sc.exe config $serviceName start=auto

Get-Service -Name $serviceName
Start-Service -Name $serviceName

Write-Host "Service '$serviceName' has been created and started successfully!"
