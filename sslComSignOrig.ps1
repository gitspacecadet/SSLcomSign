# Param(
#     [Parameter(Mandatory = $true)]
#     [hashtable] $parameters
# )

# $appFile = $parameters["appFile"]
# if (-not $appFile) {
#     throw "No app file specified in the parameters ('appFile' key is missing)."
# }
$appFile = "C:\Users\vmadmin\Documents\Tipalti_Tipalti Finance Automation (W1)_24.1.46.0.app"
# $env:GITHUB_WORKSPACE = "C:\2\_work\CustomTipalti\CustomTipalti"
# $baseFolder = $env:GITHUB_WORKSPACE
# if (-not $baseFolder) {
#     # Define your actual local path explicitly if running locally
#     $baseFolder = "C:\2\_work\CustomTipalti\CustomTipalti"
# }

# Set the workspace explicitly for local runs
$env:GITHUB_WORKSPACE = "C:\2\_work\CustomTipalti\CustomTipalti"
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
############
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
$DownloadFolder = (Join-Path ([System.IO.Path]::GetTempPath()) ([System.IO.Path]::GetRandomFileName()))
if (-not (Test-Path $DownloadFolder)) {
    New-Item -ItemType Directory -Path $DownloadFolder | Out-Null
}

# Download the release asset
$apiUrl = "https://api.github.com/repos/SSLcom/eSignerCKA/releases/latest"
Write-Output "Fetching latest release info..."
$release = Invoke-RestMethod -Uri $apiUrl -Headers @{ "User-Agent" = "PowerShell" }
Write-Output "Latest Release: $($release.tag_name)"

# Get the asset
$targetAsset = $release.assets | Where-Object { $_.name -like "SSL.COM-eSigner-CKA_*.zip" } | Select-Object -First 1
if (-not $targetAsset) {
    Write-Error "No matching asset found"
    exit 1
}

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

# Configure eSigner
$masterKeyFile = Join-Path -Path $TempInstallDir -ChildPath "master.key"
$eSignerCKATool = Get-ChildItem -Path $TempInstallDir -Filter "eSignerCKATool.exe" -Recurse | 
    Select-Object -First 1

if (-not $eSignerCKATool) {
    Write-Error "eSignerCKATool.exe not found"
    exit 1
}

# Run configuration
# Configure the eSigner tool.
    # $masterKeyFile = Join-Path $eSignerSetupTempFolder "master.key"
    $masterKeyFile = Join-Path -Path $TempInstallDir -ChildPath "master.key"
    $mode = "product"
    $totpSecret = "qmsZAI+ojbuho5xxWz5AGAUj2Xtp9xssxXejRSLC/28="
    $password = "`$Sl@2o25!"
    $userName = "eh-ciellos"
Write-Output "Configuring eSigner..."
& $eSignerCKATool.FullName config -mode $mode `
    -user $userName `
    -pass $password `
    -totp $totpSecret `
    -key $masterKeyFile -r

# Certificate validation
Write-Output "Loading certificates..."
& $eSignerCKATool.FullName load

# Check certificates
$certs = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert | 
    Where-Object { $_.Subject -like "*Tipalti*" -and $_.NotAfter -gt (Get-Date) }

if (-not $certs) {
    Write-Error "No valid Tipalti certificates found"
    exit 1
}

# Find SignTool
$signToolPath = "C:\Program Files (x86)\Windows Kits\10\bin\*\x64\SignTool.exe"
$signTool = Get-ChildItem $signToolPath | 
    Sort-Object { [version]$_.Directory.Parent.Name } -Descending |
    Select-Object -First 1

if (-not $signTool) {
    Write-Error "SignTool not found"
    exit 1
}

# Sign the application
if (-not $appFile) {
    throw "No app file specified in the parameters ('appFile' key is missing)."
}
Write-Output "Signing file: $appFile"

& $signTool.FullName sign /debug /fd sha256 /s MY /tr "http://ts.ssl.com" /td sha256 /sha1 $certs[0].Thumbprint $appFile
# & $signToolExe.FullName sign /debug /fd sha256 /s MY /tr http://ts.ssl.com /td sha256 /sha1 $thumbprint $appFile

# Verify signature
$signature = Get-AuthenticodeSignature $appFile
Write-Output "Signature status: $($signature.Status)"

if ($signature.Status -ne 'Valid') {
    Write-Error "Signature verification failed"
    exit 1
}

$endTime = [DateTime]::Now
$duration = $endTime.Subtract($startTime)
Write-Host "Duration: $([Math]::Round($duration.TotalSeconds,2)) seconds"