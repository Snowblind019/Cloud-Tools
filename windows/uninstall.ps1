<#
Removes AWS Kit for the current Windows user. The installer copies this to
%LOCALAPPDATA%\AWSKit, and Settings > Apps > AWS Kit runs it from there.
Your settings in %APPDATA%\awskit and your AWS profiles in ~\.aws are kept.
#>
param([switch]$Quiet)

$ErrorActionPreference = 'Continue'
$Root = Join-Path $env:LOCALAPPDATA 'AWSKit'
$Bin = Join-Path $Root 'bin'
$ProgId = 'AWSKit.ImageRedact'

Write-Host 'Removing AWS Kit' -ForegroundColor Cyan
Write-Host '   Close AWS Kit first if it is open.'

$programs = [Environment]::GetFolderPath('Programs')
$menu = Join-Path $programs 'AWS Kit'
if (Test-Path $menu) { Remove-Item $menu -Recurse -Force }
foreach ($link in (Join-Path $programs 'Image Redact.lnk'),
                  (Join-Path ([Environment]::GetFolderPath('Desktop')) 'AWS Kit.lnk'),
                  (Join-Path ([Environment]::GetFolderPath('Desktop')) 'Image Redact.lnk')) {
    if (Test-Path $link) { Remove-Item $link -Force }
}

# The Lab Sweep daily check, if it was turned on.
& schtasks.exe /Delete /F /TN 'AWS Kit Lab Sweep' 2>$null | Out-Null

Remove-Item -Path "HKCU:\Software\Classes\$ProgId" -Recurse -Force -ErrorAction SilentlyContinue
foreach ($ext in '.png', '.jpg', '.jpeg', '.bmp', '.webp') {
    Remove-ItemProperty -Path "HKCU:\Software\Classes\$ext\OpenWithProgids" -Name $ProgId -ErrorAction SilentlyContinue
}
foreach ($key in 'AWSKit', 'AWSKit-ImageRedact') {
    Remove-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\$key" -Recurse -Force -ErrorAction SilentlyContinue
}

$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if ($userPath) {
    $kept = ($userPath -split ';') | Where-Object { $_ -and $_ -ne $Bin }
    [Environment]::SetEnvironmentVariable('Path', ($kept -join ';'), 'User')
}

# The private Python, if the installer had to add one.
$setup = Join-Path $Root 'python-setup.exe'
if (Test-Path $setup) {
    Write-Host '   Removing the Python that was installed for AWS Kit'
    Start-Process -FilePath $setup -ArgumentList '/uninstall', '/quiet' -Wait
}

# This script lives inside the folder it's deleting, so the delete runs just after it exits.
if (Test-Path $Root) {
    Start-Process -FilePath 'cmd.exe' -WindowStyle Hidden -ArgumentList "/c timeout /t 2 /nobreak >nul & rmdir /s /q `"$Root`""
}

Write-Host ''
Write-Host 'AWS Kit is removed.' -ForegroundColor Green
Write-Host "   Your settings are still in $(Join-Path $env:APPDATA 'awskit'). Delete that folder too if you want them gone."
Write-Host '   If you added the awskit line to your PowerShell profile, remove it with: notepad $PROFILE'
if (-not $Quiet) { Read-Host 'Press Enter to close' | Out-Null }
