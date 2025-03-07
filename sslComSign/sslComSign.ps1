param(
    [Parameter(Mandatory=$true)]
    [string]$appFile,

    [Parameter(Mandatory=$true)]
    [string]$user,

    [Parameter(Mandatory=$true)]
    [securestring]$password,

    [Parameter(Mandatory=$true)]
    [string]$totp,

    [Parameter(Mandatory=$false)]
    [ValidateSet("product", "sandbox")]
    [string]$mode = "product", # For Sandbox Certificate it must be "sandbox"

    [Parameter(Mandatory=$false)]
    [string]$timestampService = "http://ts.ssl.com",

    [Parameter(Mandatory=$false)]
    [string]$digestAlgorithm = "sha256"
)
$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($password)
$plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
$BSTRtotp = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($totp)
$plainTotp = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTRtotp)

# $env:GITHUB_WORKSPACE = "C:\2\_work\CustomTipalti\CustomTipalti"
$baseFolder = $env:GITHUB_WORKSPACE

Write-Host "Importing AL:Go and BCContainerHelper helper libraries..."

# Find latest AL-Go-Actions path
$helperBasePath = "..\..\_actions\microsoft\AL-Go-Actions\"
$alGoActionsPath = Get-ChildItem -Path $helperBasePath -Directory | 
    Sort-Object Name -Descending | 
    Select-Object -First 1

if ($null -eq $alGoActionsPath) {
    throw "AL-Go-Actions directory not found."
}
Write-Host "AL-Go Actions path: $($alGoActionsPath.Fullname)"

# Import the AL-Go helper script now that $baseFolder is defined
$helperScriptPath = Join-Path -Path $alGoActionsPath.FullName -ChildPath "AL-Go-Helper.ps1"
. $helperScriptPath

# Continue with your logic...

DownloadAndImportBcContainerHelper
$bcHelperFunctionsPath = Join-Path -Path $bcContainerHelperPath.FullName -ChildPath "BcContainerHelper\HelperFunctions.ps1"
. $bcHelperFunctionsPath
Get-Command Write-GroupStart -Verbose -ErrorAction SilentlyContinue
Write-Host "Signing $appFile"

Write-Host "====================== Signing $appFile process ======================"
Write-Host "===== 1. Register NavSip.dll ====="
function GetNavSipFromArtifacts
(
    [string] $NavSipDestination = "C:\Windows\System32"
    #"C:\Windows\System32\NavSip.dll"
)
{
    $artifactTempFolder = Join-Path $([System.IO.Path]::GetTempPath()) ([System.IO.Path]::GetRandomFileName())

    try {
        Download-Artifacts -artifactUrl (Get-BCArtifactUrl -type Sandbox -country core) -basePath $artifactTempFolder | Out-Null
        Write-Host "Downloaded artifacts to $artifactTempFolder"
        $navsip = Get-ChildItem -Path $artifactTempFolder -Filter "NavSip.dll" -Recurse
        Write-Host "Found navsip at $($navsip.FullName)"
        Copy-Item -Path $navsip.FullName -Destination $NavSipDestination -Force | Out-Null
        Write-Host "Copied navsip to $NavSipDestination"
    }
    finally {
        Remove-Item -Path $artifactTempFolder -Recurse -Force
    }
}

function Register-NavSip() {
    $navSipDestination = "C:\Windows\System32"
    $navSipDllPath = Join-Path $navSipDestination "NavSip.dll"
    try {
        if (-not (Test-Path $navSipDllPath)) {
            GetNavSipFromArtifacts -NavSipDestination $navSipDllPath
        }

        Write-Host "Unregistering dll $navSipDllPath"
        RegSvr32 /u /s $navSipDllPath
        Write-Host "Registering dll $navSipDllPath"
        RegSvr32 /s $navSipDllPath
        $msvcr120Path = "C:\Windows\System32\msvcr120.dll"
        Write-Host "Unregistering dll $msvcr120Path"
        RegSvr32 /u /s $msvcr120Path
        Write-Host "Registering dll $msvcr120Path"
        RegSvr32 /s $msvcr120Path
    }
    catch {
        Write-Host "Failed to copy navsip to $navSipDestination"
    }

}
Register-NavSip
# Create download folder
$downloadFolder = (Join-Path ([System.IO.Path]::GetTempPath()) ([System.IO.Path]::GetRandomFileName()))
if (-not (Test-Path $downloadFolder)) {
    New-Item -ItemType Directory -Path $downloadFolder | Out-Null
}

# Download and install eSignerCKA
$release = Invoke-RestMethod -Uri "https://api.github.com/repos/SSLcom/eSignerCKA/releases/latest" -Headers @{ "User-Agent" = "PowerShell" }
$targetAsset = $release.assets | Where-Object { $_.name -like "SSL.COM-eSigner-CKA_*.zip" } | Select-Object -First 1

$filePath = Join-Path $downloadFolder "eSigner_CKA_Setup.zip"
Invoke-WebRequest -Uri $targetAsset.browser_download_url -OutFile $filePath

# Download the file
Write-Output "Found asset: $($targetAsset.name). Downloading..."
$fileName = "eSigner_CKA_Setup.zip"
$filePath = Join-Path $DownloadFolder $fileName
Invoke-WebRequest -Uri $targetAsset.browser_download_url -OutFile $filePath
Write-Output "Download complete: $filePath"

# Expand the archive
Write-Output "Expanding archive..."
$parentFolder = Split-Path -Parent $filePath
$setupFolder = Join-Path $parentFolder "eSigner_CKA_Setup"
$tempExtractPath = Join-Path $parentFolder "temp_extract"

# Create setup folder
New-Item -Force -ItemType Directory -Path $setupFolder | Out-Null
Expand-Archive -Force -Path $filePath -DestinationPath $tempExtractPath

# Move installer
Get-ChildItem -Path $tempExtractPath -Recurse -Filter "*.exe" | 
    Select-Object -First 1 | 
    Move-Item -Destination (Join-Path $setupFolder "eSigner_CKA_Installer.exe") -Force

# Clean up extracted files
Remove-Item -Path $filePath -Force
Remove-Item -Path $tempExtractPath -Recurse -Force

# Install eSigner
$TempInstallDir = Join-Path ([System.IO.Path]::GetTempPath()) "eSignerSetup"
New-Item -ItemType Directory -Force -Path $TempInstallDir | Out-Null

# Run installer
$installerPath = Join-Path $setupFolder "eSigner_CKA_Installer.exe"
$installArgs = "/CURRENTUSER /VERYSILENT /SUPPRESSMSGBOXES /DIR=`"$TempInstallDir`""
Write-Output "Running installer: $installerPath $installArgs"
Start-Process $installerPath -ArgumentList $installArgs -Wait

# Post-install steps
if (-not (Test-Path $TempInstallDir)) {
    Write-Error "Installation failed - directory not found"
    exit 1
}

# Run additional tools
$registerKsp = Join-Path $TempInstallDir "RegisterKSP.exe"
$configExe = Join-Path $TempInstallDir "eSignerCSP.Config.exe"

if (Test-Path $registerKsp) {
    Write-Output "Running RegisterKSP.exe..."
    Start-Process $registerKsp -Wait
}

if (Test-Path $configExe) {
    Write-Output "Running eSignerCSP.Config.exe..."
    Start-Process $configExe -Wait
}

Start-Process (Join-Path $setupFolder "eSigner_CKA_Installer.exe") -ArgumentList "/CURRENTUSER /VERYSILENT /SUPPRESSMSGBOXES /DIR=`"$TempInstallDir`"" -Wait

# Configure eSigner
$masterKeyFile = Join-Path -Path $TempInstallDir -ChildPath "master.key"
$eSignerCKATool = Get-ChildItem -Path $TempInstallDir -Filter "eSignerCKATool.exe" -Recurse | Select-Object -First 1

& $eSignerCKATool.FullName config -mode $mode -user $user -pass $plainPassword -totp $plainTotp -key $masterKeyFile -r
& $eSignerCKATool.FullName load

$cert = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert | Where-Object { $_.Subject -like "*Tipalti*" -and $_.NotAfter -gt (Get-Date) } | Select-Object -First 1
if (-not $cert) { throw "No valid certificate found" }

$signTool = Get-ChildItem "C:\Program Files (x86)\Windows Kits\10\bin\*\x64\SignTool.exe" | Sort-Object { [version]$_.Directory.Parent.Name } -Descending | Select-Object -First 1

& $signTool.FullName sign /fd $digestAlgorithm /s MY /tr $timestampService /td $digestAlgorithm /sha1 $cert.Thumbprint $appFile

$signature = Get-AuthenticodeSignature $appFile
if ($signature.Status -ne 'Valid') {
    throw "Signature verification failed"
}
