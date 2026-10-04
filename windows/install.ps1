<#
Installs AWS Kit, with all eight tools and the same windows as on Linux, for the current
Windows user. No admin rights needed.

Double-click install-windows.cmd in the Cloud-Tools folder, or run:
  powershell -NoProfile -ExecutionPolicy Bypass -File windows\install.ps1

Everything goes in %LOCALAPPDATA%\AWSKit. Running it again updates it.

What it sets up there:
  python\   Python 3.14, just for AWS Kit (skipped if you already have 3.14)
  gtk\      GTK 4 for Windows, from the gvsbuild project
  venv\     PyGObject, pycairo, boto3 and Pillow
  app\      the AWS Kit code
  bin\      awskit, pii-redact and awsp commands, added to your PATH

Options:
  -Desktop        also put an AWS Kit shortcut on the desktop
  -NoPath         don't add the commands to your PATH
  -Quiet          don't ask anything
  -GtkZip PATH    use a GTK zip you already downloaded instead of downloading it
#>
param([switch]$Desktop, [switch]$NoPath, [switch]$Quiet, [string]$GtkZip = '')

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'  # Invoke-WebRequest is very slow with the progress bar
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

$Repo = Split-Path -Parent $PSScriptRoot
$Root = Join-Path $env:LOCALAPPDATA 'AWSKit'
$App = Join-Path $Root 'app'
$Venv = Join-Path $Root 'venv'
$Bin = Join-Path $Root 'bin'
$PyDir = Join-Path $Root 'python'
$Gtk = Join-Path $Root 'gtk'
# The GTK bundle's PyGObject and pycairo are built for this Python, so they have to match.
$PyMinor = '3.14'
$PyFallback = '3.14.8'
$GtkVersion = '2026.8.0'
$GtkUrl = "https://github.com/wingtk/gvsbuild/releases/download/$GtkVersion/GTK4_Gvsbuild_${GtkVersion}_x64.zip"
$ProgId = 'AWSKit.ImageRedact'
$UninstallKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\AWSKit'
$MenuDir = Join-Path ([Environment]::GetFolderPath('Programs')) 'AWS Kit'
$Tools = @('awskit', 'pii-redact', 'image-redact', 'lab-sweep', 'exposure-audit', 'cloudtrail',
           'plan-check', 'policy-check', 'profiles')

function Step($text) { Write-Host ''; Write-Host "== $text" -ForegroundColor Cyan }
function Note($text) { Write-Host "   $text" }
function Fail($text) {
    Write-Host ''
    Write-Host $text -ForegroundColor Red
    exit 1
}
function Ask($question, $default) {
    if ($Quiet) { return $default }
    $hint = if ($default) { '[Y/n]' } else { '[y/N]' }
    $answer = Read-Host "$question $hint"
    if ([string]::IsNullOrWhiteSpace($answer)) { return $default }
    return $answer.Trim().ToLower().StartsWith('y')
}
# Windows PowerShell 5.1 turns anything a program writes to stderr into an error when the
# output is captured, and $ErrorActionPreference = 'Stop' makes that fatal. GTK and pip print
# warnings there, so captured runs go through this with errors relaxed for that call only.
function Invoke-Quietly([scriptblock]$Block) {
    $saved = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try { & $Block } finally { $ErrorActionPreference = $saved }
}
function Download($url, $out) {
    try {
        Invoke-WebRequest -Uri $url -OutFile $out -UseBasicParsing -ErrorAction Stop
    } catch {
        if (Test-Path $out) { Remove-Item $out -Force }
        throw
    }
}

if ($env:PROCESSOR_ARCHITECTURE -ne 'AMD64' -and $env:PROCESSOR_ARCHITEW6432 -ne 'AMD64') {
    if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') {
        Note 'This is an ARM PC. The GTK bundle is built for x64, which ARM Windows runs through emulation.'
    }
}
foreach ($t in $Tools) {
    if (-not (Test-Path (Join-Path $Repo $t))) {
        Fail "Couldn't find the $t folder. Run this from inside the Cloud-Tools folder."
    }
}
$version = '0'
$match = Select-String -Path (Join-Path $Repo 'awskit\common.py') -Pattern '^VERSION = "([^"]+)"' | Select-Object -First 1
if ($match) { $version = $match.Matches[0].Groups[1].Value }

Write-Host "Installing AWS Kit $version for $env:USERNAME" -ForegroundColor Green
Note "Into $Root. No admin rights needed."
Note 'The first install downloads about 330 MB and takes a few minutes.'
New-Item -ItemType Directory -Force -Path $Root | Out-Null

# ------------------------------------------------------------------- tidy up 1.3
# AWS Kit 1.3 installed only Image Redact, with Python 3.12. Its pieces get replaced.
$old = Join-Path ([Environment]::GetFolderPath('Programs')) 'Image Redact.lnk'
if (Test-Path $old) { Remove-Item $old -Force }
Remove-Item -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\AWSKit-ImageRedact' -Recurse -Force -ErrorAction SilentlyContinue
foreach ($f in 'image-redact.pyw', 'pii-redact.py', 'bin\awskit-image.cmd') {
    $p = Join-Path $Root $f
    if (Test-Path $p) { Remove-Item $p -Force }
}

# ------------------------------------------------------------------- Python 3.14
Step "Finding Python $PyMinor"

function Test-Python($exe, $pre) {
    $ErrorActionPreference = 'Continue'
    try {
        $out = & $exe @pre -c "import sys, venv; print(sys.executable); print('%d.%d' % sys.version_info[:2])" 2>$null
        if ($LASTEXITCODE -ne 0 -or $null -eq $out) { return $null }
        $lines = @($out)
        if ($lines.Count -lt 2 -or $lines[1].Trim() -ne $PyMinor) { return $null }
        return $lines[0].Trim()
    } catch {
        return $null
    }
}

$candidates = New-Object System.Collections.ArrayList
[void]$candidates.Add(@{ Exe = (Join-Path $PyDir 'python.exe'); Pre = @() })
if (Get-Command py -ErrorAction SilentlyContinue) { [void]$candidates.Add(@{ Exe = 'py'; Pre = @("-$PyMinor") }) }
foreach ($n in 'python', 'python3') {
    $c = Get-Command $n -ErrorAction SilentlyContinue
    if ($c -and $c.Source -notlike '*\WindowsApps\*') { [void]$candidates.Add(@{ Exe = $c.Source; Pre = @() }) }
}
$userPy = Join-Path $env:LOCALAPPDATA ("Programs\Python\Python" + $PyMinor.Replace('.', '') + "\python.exe")
[void]$candidates.Add(@{ Exe = $userPy; Pre = @() })

$Python = $null
foreach ($c in $candidates) {
    if ($c.Exe -like '*\*' -and -not (Test-Path $c.Exe)) { continue }
    $found = Test-Python $c.Exe $c.Pre
    if ($found) { $Python = $found; break }
}

if ($Python) {
    Note "Using $Python"
} else {
    # A Python left by AWS Kit 1.3 is the wrong version. Remove it first.
    $oldSetup = Join-Path $Root 'python-setup.exe'
    if (Test-Path $oldSetup) {
        Note 'Removing the Python 3.12 that AWS Kit 1.3 installed'
        Start-Process -FilePath $oldSetup -ArgumentList '/uninstall', '/quiet' -Wait
        Remove-Item $oldSetup -Force -ErrorAction SilentlyContinue
    }
    if (Test-Path $PyDir) { Remove-Item $PyDir -Recurse -Force -ErrorAction SilentlyContinue }

    $pyVersion = $PyFallback
    try {
        $listing = (Invoke-WebRequest -Uri 'https://www.python.org/ftp/python/' -UseBasicParsing -ErrorAction Stop).Content
        $found = [regex]::Matches($listing, 'href="(3\.14\.\d+)/"') | ForEach-Object { [version]$_.Groups[1].Value } |
                 Sort-Object -Descending | Select-Object -First 1
        if ($found -and $found -gt [version]$PyFallback) { $pyVersion = $found.ToString() }
    } catch { }
    $arch = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { 'arm64' } else { 'amd64' }
    $setup = Join-Path $Root 'python-setup.exe'
    Note "No Python $PyMinor found, so installing Python $pyVersion just for AWS Kit."
    Note "It goes in $PyDir, for your user only."
    $downloaded = $false
    foreach ($v in @($pyVersion, $PyFallback) | Select-Object -Unique) {
        try {
            Download "https://www.python.org/ftp/python/$v/python-$v-$arch.exe" $setup
            $downloaded = $true
            break
        } catch { }
    }
    if (-not $downloaded) {
        Fail ("Couldn't download Python from python.org.`n`n" +
              "Install Python $PyMinor yourself from python.org (untick 'Use admin privileges'), " +
              "then run this again.")
    }
    $proc = Start-Process -FilePath $setup -Wait -PassThru -ArgumentList @(
        '/quiet', 'InstallAllUsers=0', 'PrependPath=0', 'Include_launcher=0', 'Include_test=0',
        'Include_doc=0', 'Include_tcltk=1', 'Include_pip=1', 'Shortcuts=0', 'AssociateFiles=0',
        "TargetDir=`"$PyDir`"")
    if ($proc.ExitCode -ne 0) { Fail "The Python installer stopped with exit code $($proc.ExitCode)." }
    $Python = Test-Python (Join-Path $PyDir 'python.exe') @()
    if (-not $Python) { Fail "Python installed, but it doesn't run. Try running this again." }
    Note "Installed $Python"
}

# ------------------------------------------------------------------- GTK 4
Step "Setting up GTK 4 for Windows ($GtkVersion)"
$marker = Join-Path $Gtk 'AWSKIT-GTK-VERSION'
$haveGtk = (Test-Path $marker) -and ((Get-Content $marker -Raw).Trim() -eq $GtkVersion) -and
           (Test-Path (Join-Path $Gtk 'bin\gtk-4-1.dll'))
if ($haveGtk) {
    Note 'Already set up'
} else {
    $zip = $GtkZip
    $removeZip = $false
    if (-not $zip) {
        $zip = Join-Path $env:TEMP "GTK4_Gvsbuild_${GtkVersion}_x64.zip"
        if (-not (Test-Path $zip) -or (Get-Item $zip).Length -lt 200MB) {
            Note 'Downloading about 300 MB from github.com/wingtk/gvsbuild'
            try {
                Download $GtkUrl $zip
            } catch {
                Fail ("Couldn't download GTK from $GtkUrl`n$($_.Exception.Message)`n`n" +
                      "Download that file another way, then run:`n" +
                      "  powershell -ExecutionPolicy Bypass -File windows\install.ps1 -GtkZip C:\path\to\the.zip")
            }
        }
        $removeZip = $true
    }
    if (-not (Test-Path $zip)) { Fail "Couldn't find $zip" }
    Note 'Unpacking the parts AWS Kit needs (about 180 MB)'
    if (Test-Path $Gtk) { Remove-Item $Gtk -Recurse -Force }
    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $keep = @('bin/', 'etc/', 'lib/girepository-1.0/', 'lib/gdk-pixbuf-2.0/', 'share/glib-2.0/schemas/',
              'share/icons/', 'share/gtk-4.0/', 'share/fontconfig/', 'wheels/')
    $skip = @('.pdb', '.lib', '.h', '.a')
    $archive = [IO.Compression.ZipFile]::OpenRead($zip)
    try {
        foreach ($entry in $archive.Entries) {
            $name = $entry.FullName.Replace('\', '/')
            if ($name.EndsWith('/')) { continue }
            if (-not ($keep | Where-Object { $name.StartsWith($_) })) { continue }
            if ($skip | Where-Object { $name.EndsWith($_) }) { continue }
            $dest = Join-Path $Gtk ($name.Replace('/', '\'))
            New-Item -ItemType Directory -Force -Path (Split-Path -Parent $dest) | Out-Null
            [IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $dest, $true)
        }
    } finally {
        $archive.Dispose()
    }
    if (-not (Test-Path (Join-Path $Gtk 'bin\gtk-4-1.dll'))) { Fail "The GTK zip didn't have what AWS Kit needs." }
    Set-Content -Path $marker -Value $GtkVersion -Encoding ASCII
    if ($removeZip) { Remove-Item $zip -Force -ErrorAction SilentlyContinue }
    Note "Into $Gtk"
}

# ------------------------------------------------------------------- packages
Step 'Setting up packages (PyGObject, pycairo, boto3, Pillow)'
$VenvPy = Join-Path $Venv 'Scripts\python.exe'
$VenvPyw = Join-Path $Venv 'Scripts\pythonw.exe'
$healthy = $false
if (Test-Path $VenvPy) {
    $v = Invoke-Quietly { & $VenvPy -c "import sys; print('%d.%d' % sys.version_info[:2])" 2>$null }
    $healthy = ($LASTEXITCODE -eq 0 -and "$v".Trim() -eq $PyMinor)
}
if (-not $healthy) {
    if (Test-Path $Venv) { Remove-Item $Venv -Recurse -Force }
    & $Python -m venv $Venv
    if ($LASTEXITCODE -ne 0) { Fail "Couldn't create the Python environment in $Venv." }
}
& $VenvPy -m pip install --disable-pip-version-check --no-input --quiet --upgrade pip
# These two have to be the GTK bundle's builds, made against its cairo. The ones on PyPI
# carry their own cairo, which crashes when GTK hands them a drawing surface.
& $VenvPy -m pip install --disable-pip-version-check --no-input --quiet --force-reinstall --no-deps --no-index --find-links (Join-Path $Gtk 'wheels') pycairo pygobject
if ($LASTEXITCODE -ne 0) { Fail "Couldn't install PyGObject and pycairo from $Gtk\wheels." }
& $VenvPy -m pip install --disable-pip-version-check --no-input --quiet --upgrade boto3 Pillow
if ($LASTEXITCODE -ne 0) {
    Fail ("pip couldn't install boto3 and Pillow. If your network needs a proxy, set it first, " +
          "like:`n  `$env:HTTPS_PROXY = 'http://proxy.example.com:8080'`nthen run this again from " +
          "the same PowerShell window.")
}
Note 'Done'

# ------------------------------------------------------------------- app files
Step 'Copying AWS Kit'
if (Test-Path $App) { Remove-Item $App -Recurse -Force }
New-Item -ItemType Directory -Force -Path $App | Out-Null
foreach ($folder in $Tools) {
    Copy-Item -Path (Join-Path $Repo $folder) -Destination (Join-Path $App $folder) -Recurse -Force
}
Get-ChildItem $App -Recurse -Directory | Where-Object { $_.Name -in '__pycache__', 'docs', 'examples' } |
    Sort-Object FullName -Descending | Remove-Item -Recurse -Force
Get-ChildItem $App -Recurse -File | Where-Object { $_.Extension -in '.md', '.pyc' -or $_.Name -like '*Zone.Identifier' } |
    Remove-Item -Force
Copy-Item (Join-Path $PSScriptRoot 'awskit.ico') (Join-Path $Root 'awskit.ico') -Force
Copy-Item (Join-Path $PSScriptRoot 'image-redact.ico') (Join-Path $Root 'image-redact.ico') -Force
Copy-Item (Join-Path $PSScriptRoot 'uninstall.ps1') (Join-Path $Root 'uninstall.ps1') -Force

$Launcher = Join-Path $Root 'awskit.pyw'
@'
import os
import sys

here = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(here, "app"))
os.environ.setdefault("AWSKIT_GTK", os.path.join(here, "gtk"))
from awskit.cli import main  # noqa: E402

sys.exit(main(sys.argv[1:]))
'@ | Set-Content -Path $Launcher -Encoding ASCII

New-Item -ItemType Directory -Force -Path $Bin | Out-Null
$shims = @{ 'awskit.cmd' = ''; 'pii-redact.cmd' = ' redact'; 'awsp.cmd' = ' profile' }
foreach ($name in $shims.Keys) {
    "@echo off`r`n`"$VenvPy`" `"$Launcher`"$($shims[$name]) %*`r`n" |
        Set-Content -Path (Join-Path $Bin $name) -Encoding ASCII -NoNewline
}
Note "Into $App"

# ------------------------------------------------------------------- shortcuts
Step 'Adding shortcuts'
$shell = New-Object -ComObject WScript.Shell
function New-Shortcut($path, $arguments, $icon, $description) {
    $lnk = $shell.CreateShortcut($path)
    $lnk.TargetPath = $VenvPyw
    $lnk.Arguments = ("`"$Launcher`" " + $arguments).Trim()
    $lnk.WorkingDirectory = $env:USERPROFILE
    $lnk.IconLocation = "$(Join-Path $Root $icon),0"
    $lnk.Description = $description
    $lnk.Save()
}
New-Item -ItemType Directory -Force -Path $MenuDir | Out-Null
New-Shortcut (Join-Path $MenuDir 'AWS Kit.lnk') '' 'awskit.ico' 'PII Redact, Image Redact, Lab Sweep, Exposure Audit, CloudTrail, Plan Check, Policy Check and Profiles'
New-Shortcut (Join-Path $MenuDir 'PII Redact.lnk') 'redact' 'awskit.ico' 'Paste output and get it back with account IDs, keys and personal info redacted'
New-Shortcut (Join-Path $MenuDir 'Image Redact.lnk') 'image' 'image-redact.ico' 'Cover account IDs, keys and personal info in screenshots'
New-Shortcut (Join-Path $MenuDir 'AWS Profile Picker.lnk') 'profile' 'awskit.ico' 'Switch the AWS profile your terminals use'
Note 'Start menu: AWS Kit folder with AWS Kit, PII Redact, Image Redact and AWS Profile Picker'
$DesktopLink = Join-Path ([Environment]::GetFolderPath('Desktop')) 'AWS Kit.lnk'
if ($Desktop -or (Test-Path $DesktopLink) -or (Ask 'Add an AWS Kit shortcut to the desktop?' $false)) {
    New-Shortcut $DesktopLink '' 'awskit.ico' 'AWS Kit'
    Note 'Desktop: AWS Kit'
}

# Open With for images, for Image Redact. This only adds it to the list. It doesn't change
# what opens images when you double-click them.
$prog = "HKCU:\Software\Classes\$ProgId"
New-Item -Path "$prog\shell\open\command" -Force | Out-Null
New-Item -Path "$prog\DefaultIcon" -Force | Out-Null
New-Item -Path "$prog\Application" -Force | Out-Null
Set-Item -Path $prog -Value 'Image'
Set-Item -Path "$prog\DefaultIcon" -Value (Join-Path $Root 'image-redact.ico')
Set-ItemProperty -Path "$prog\shell\open" -Name 'FriendlyAppName' -Value 'Image Redact'
Set-ItemProperty -Path "$prog\Application" -Name 'ApplicationName' -Value 'Image Redact'
Set-ItemProperty -Path "$prog\Application" -Name 'ApplicationIcon' -Value (Join-Path $Root 'image-redact.ico')
Set-Item -Path "$prog\shell\open\command" -Value "`"$VenvPyw`" `"$Launcher`" image `"%1`""
foreach ($ext in '.png', '.jpg', '.jpeg', '.bmp', '.webp') {
    $key = "HKCU:\Software\Classes\$ext\OpenWithProgids"
    if (-not (Test-Path $key)) { New-Item -Path $key | Out-Null }
    New-ItemProperty -Path $key -Name $ProgId -PropertyType String -Value '' -Force | Out-Null
}
try {
    Add-Type -Namespace AWSKit -Name Shell -MemberDefinition '[System.Runtime.InteropServices.DllImport("shell32.dll")] public static extern void SHChangeNotify(int e, int f, System.IntPtr a, System.IntPtr b);'
    [AWSKit.Shell]::SHChangeNotify(0x08000000, 0, [IntPtr]::Zero, [IntPtr]::Zero)
} catch { }
Note 'Right-click an image, Open with: Image Redact'

# ------------------------------------------------------------------- PATH
if (-not $NoPath) {
    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    if ($null -eq $userPath) { $userPath = '' }
    if (($userPath -split ';') -notcontains $Bin) {
        $newPath = (($userPath.TrimEnd(';'), $Bin) | Where-Object { $_ }) -join ';'
        [Environment]::SetEnvironmentVariable('Path', $newPath, 'User')
        Note "Added $Bin to your PATH. New terminals get awskit, pii-redact and awsp."
    }
}

# ------------------------------------------------------------------- Apps & features
New-Item -Path $UninstallKey -Force | Out-Null
$sizeKb = [int]((Get-ChildItem $Root -Recurse -File -ErrorAction SilentlyContinue | Measure-Object Length -Sum).Sum / 1KB)
$props = @{
    DisplayName = 'AWS Kit'
    DisplayVersion = $version
    Publisher = 'Snowblind019'
    InstallLocation = $Root
    DisplayIcon = (Join-Path $Root 'awskit.ico')
    UninstallString = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$(Join-Path $Root 'uninstall.ps1')`""
    URLInfoAbout = 'https://github.com/Snowblind019/Cloud-Tools'
}
foreach ($k in $props.Keys) { Set-ItemProperty -Path $UninstallKey -Name $k -Value $props[$k] }
foreach ($k in 'NoModify', 'NoRepair') { New-ItemProperty -Path $UninstallKey -Name $k -PropertyType DWord -Value 1 -Force | Out-Null }
New-ItemProperty -Path $UninstallKey -Name 'EstimatedSize' -PropertyType DWord -Value $sizeKb -Force | Out-Null

# ------------------------------------------------------------------- check
Step 'Checking'
$env:AWSKIT_GTK = $Gtk
$check = Invoke-Quietly { & $VenvPy -c "import sys; sys.path.insert(0, r'$App'); import awskit, gi; gi.require_version('Gtk', '4.0'); from gi.repository import Gtk; print('GTK %d.%d.%d' % (Gtk.get_major_version(), Gtk.get_minor_version(), Gtk.get_micro_version()))" 2>&1 }
if ($LASTEXITCODE -ne 0) {
    Write-Host ($check | Out-String) -ForegroundColor Yellow
    Fail 'GTK did not load. The message above says why.'
}
$gtkLine = @($check | ForEach-Object { "$_" } | Where-Object { $_ -like 'GTK *' }) | Select-Object -Last 1
Note "$gtkLine loads"
& $VenvPy $Launcher image check
if (-not (Get-Command aws -ErrorAction SilentlyContinue)) {
    Note 'Note: SSO sign-in from the Profiles page needs the AWS CLI v2. Everything else works without it.'
}
if (-not (Get-Command terraform -ErrorAction SilentlyContinue) -and -not (Get-Command tofu -ErrorAction SilentlyContinue)) {
    Note 'Note: Plan Check can only run plans itself if terraform or tofu is on your PATH.'
}

Write-Host ''
Write-Host 'AWS Kit is installed.' -ForegroundColor Green
Note 'Open it from the Start menu, in the AWS Kit folder.'
Note 'For awsp in PowerShell, run: notepad $PROFILE  and add this line:'
Note '  awskit shell-init powershell | Out-String | Invoke-Expression'
Note 'To remove it, go to Settings, Apps, Installed apps, AWS Kit.'
if (Ask 'Open AWS Kit now?' $true) {
    Start-Process -FilePath $VenvPyw -ArgumentList "`"$Launcher`""
}
