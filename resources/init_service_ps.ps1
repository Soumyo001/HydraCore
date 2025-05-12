# script must run as admin
$nssmUrl = "https://nssm.cc/release/nssm-2.24.zip"  # URL to download NSSM
$nssmFolder = "C:\nssm" # modify this path based on needs
$nssmexe = "$nssmFolder\nssm-2.24\win64\nssm.exe" # for 64-bit systems
$scriptPath = "C:\path\to\your\script.ps1"  # path to save the downloaded PowerShell script
$serviceName = "MyService"
$exePath = "powershell.exe"
$arguments = "-ep bypass -noP -File $scriptPath"

$downloadPath = "$nssmFolder\nssm.zip"

if(-not(Test-Path -Path $downloadPath)){
    Invoke-WebRequest -Uri $nssmUrl -OutFile $downloadPath
}
if(-not(Test-Path -Path "$nssmFolder\nssm-2.24" -PathType Container)){
    Expand-Archive -Path $downloadPath -DestinationPath $nssmFolder
}

if(Get-Service $ServiceName -ErrorAction SilentlyContinue){
    & $nssmexe stop $serviceName
    & $nssmexe remove $serviceName confirm
}

# Start-Process -FilePath "$nssmFolder\nssm-2.24\win64\nssm.exe" -ArgumentList "install", $serviceName, $exePath, $arguments
# sc.exe config $serviceName obj=LocalSystem
# sc.exe config $serviceName start=auto
# Get-Service -Name $serviceName
# Start-Service -Name $serviceName

& $nssmexe install $serviceName $exePath $arguments

& $nssmexe set $serviceName Start SERVICE_AUTO_START
& $nssmexe set $serviceName ObjectName "LocalSystem"
& $nssmexe set $serviceName AppExit Default Exit
& $nssmexe set $serviceName AppExit 0 Exit 

& $nssmexe start $serviceName

Write-Host "Service '$serviceName' has been created and started successfully!"
