# script must run as admin
$nssmUrl = "https://nssm.cc/release/nssm-2.24.zip"  # URL to download NSSM
$nssmFolder = "C:\nssm" # modify this path based on needs
$nssmexe = "$nssmFolder\nssm-2.24\win64\nssm.exe" # for 64-bit systems
$scriptPath = "C:\path\to\your\root_script.ps1"  # path to save the downloaded PowerShell script
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
# key to making the service run only once
& $nssmexe set $serviceName AppExit Default Exit # set NSSM default exit behaviour (Exit - Defaults to Exit and Restart - Defaults to Restart)
& $nssmexe set $serviceName AppExit 0 Exit # default behaviour based on exit codes (0 Exit - Defaults to Exit for exit code 0)
# Set restart delay in milliseconds (e.g., 5000 ms = 5 seconds)
# & $nssmexe set $serviceName AppRestartDelay 5000
# & $nssmexe set $serviceName AppPriority REALTIME_PRIORITY_CLASS

# Set up stdout/stderr logging
# & $nssmexe set $serviceName AppStdout "C:\Scripts\$ServiceName-output.log"
# & $nssmexe set $serviceName AppStderr "C:\Scripts\$ServiceName-error.log"

& $nssmexe start $serviceName

Write-Host "Service '$serviceName' has been created and started successfully!"

# Set service SDDL to allow ONLY SYSTEM access
$SDDL = "O:SYD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)"
sc.exe sdset $serviceName $SDDL

# Remove inheritance and lock permissions except current user and SYSTEM
# icacls $nssmexe /inheritance:r /grant:r "SYSTEM:F" /grant:r "$env:USERNAME:F"
# icacls $scriptPath /inheritance:r /grant:r "SYSTEM:F" /grant:r "$env:USERNAME:F"

# Take ownership (if needed)
takeown /F "$nssmexe" /A /R /D Y 2>&1 | Out-Null
takeown /F "$scriptPath" /A /R /D Y 2>&1 | Out-Null
icacls "$nssmexe" /setowner "NT AUTHORITY\SYSTEM" /T /Q 2>&1 | Out-Null
icacls "$scriptPath" /setowner "NT AUTHORITY\SYSTEM" /T /Q 2>&1 | Out-Null

# Remove inheritance and grant SYSTEM full control
icacls "$nssmexe" /inheritance:r /grant:r "SYSTEM:F" /T /Q 2>&1 | Out-Null
icacls "$scriptPath" /inheritance:r /grant:r "SYSTEM:F" /T /Q 2>&1 | Out-Null

# Remove all other users/groups (optional safety measure)
icacls "$nssmexe" /remove "Administrators" "Users" "Authenticated Users" "Everyone" /T /Q 2>&1 | Out-Null
icacls "$scriptPath" /remove "Administrators" "Users" "Authenticated Users" "Everyone" /T /Q 2>&1 | Out-Null

# Prevent modification even by SYSTEM (optional)
attrib +r +s +h $nssmexe
attrib +r +s +h $scriptPath
