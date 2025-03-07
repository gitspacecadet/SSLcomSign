function Import-BcHelperLibraries {
    Write-Host "Importing AL:Go and BCContainerHelper helper libraries..."
    $helperBasePath = "C:\3\_work\_actions\microsoft\AL-Go-Actions\"
    $bcContainerHelperBasePath = "C:\ProgramData\BcContainerHelper\"

    $alGoActionsPath = Get-ChildItem -Path $helperBasePath -Directory | 
        Sort-Object Name -Descending | 
        Select-Object -First 1
    if ($null -eq $alGoActionsPath) {
        throw "AL-Go-Actions directory not found."
    }

    $versionRegex = '^\d+\.\d+\.\d+$'
    $bcContainerHelperPath = Get-ChildItem -Path $bcContainerHelperBasePath -Directory | 
        Where-Object { $_.Name -match $versionRegex } |
        Sort-Object Name -Descending | 
        Select-Object -First 1
    if ($null -eq $bcContainerHelperPath) {
        throw "BcContainerHelper directory not found."
    }

    $helperPath = Join-Path -Path $alGoActionsPath.FullName -ChildPath "AL-Go-Helper.ps1"
    . $helperPath
    DownloadAndImportBcContainerHelper
    $bcHelperFunctionsPath = Join-Path -Path $bcContainerHelperPath.FullName -ChildPath "BcContainerHelper\HelperFunctions.ps1"
    . $bcHelperFunctionsPath
}

function Get-NavSipFromArtifacts {
    param (
        [string] $NavSipDestination = "C:\Windows\System32"
    )

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

function Register-NavSip {
    $navSipDestination = "C:\Windows\System32"
    $navSipDllPath = Join-Path $navSipDestination "NavSip.dll"
    try {
        if (-not (Test-Path $navSipDllPath)) {
            Get-NavSipFromArtifacts -NavSipDestination $navSipDllPath
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
        throw
    }
}

function Install-ESignerCKA {
    param(
        [string]$DownloadFolder = (Join-Path ([System.IO.Path]::GetTempPath()) ([System.IO.Path]::GetRandomFileName()))
    )

    if (-not (Test-Path $DownloadFolder)) {
        New-Item -ItemType Directory -Path $DownloadFolder | Out-Null
    }

    # Download the release asset
    $apiUrl = "https://api.github.com/repos/SSLcom/eSignerCKA/releases/latest"
    Write-Output "Fetching latest release info..."
    $release = Invoke-RestMethod -Uri $apiUrl -Headers @{ "User-Agent" = "PowerShell" }
    
    $targetAsset = $release.assets | Where-Object { $_.name -like "SSL.COM-eSigner-CKA_*.zip" } | Select-Object -First 1
    if (-not $targetAsset) {
        throw "No matching asset found"
    }

    $fileName = "eSigner_CKA_Setup.zip"
    $filePath = Join-Path $DownloadFolder $fileName
    Invoke-WebRequest -Uri $targetAsset.browser_download_url -OutFile $filePath

    # Expand and setup
    $parentFolder = Split-Path -Parent $filePath
    $setupFolder = Join-Path $parentFolder "eSigner_CKA_Setup"
    $tempExtractPath = Join-Path $parentFolder "temp_extract"

    New-Item -Force -ItemType Directory -Path $setupFolder | Out-Null
    Expand-Archive -Force -Path $filePath -DestinationPath $tempExtractPath

    Get-ChildItem -Path $tempExtractPath -Recurse -Filter "*.exe" | 
        Select-Object -First 1 | 
        Move-Item -Destination (Join-Path $setupFolder "eSigner_CKA_Installer.exe") -Force

    Remove-Item -Path $filePath -Force
    Remove-Item -Path $tempExtractPath -Recurse -Force

    return $setupFolder
}

function Initialize-ESigner {
    param(
        [string]$SetupFolder,
        [string]$User,
        [string]$Password,
        [string]$TotpKey
    )

    $TempInstallDir = Join-Path ([System.IO.Path]::GetTempPath()) "eSignerSetup"
    New-Item -ItemType Directory -Force -Path $TempInstallDir | Out-Null

    # Run installer
    $installerPath = Join-Path $SetupFolder "eSigner_CKA_Installer.exe"
    $installArgs = "/CURRENTUSER /VERYSILENT /SUPPRESSMSGBOXES /DIR=`"$TempInstallDir`""
    Start-Process $installerPath -ArgumentList $installArgs -Wait

    if (-not (Test-Path $TempInstallDir)) {
        throw "Installation failed - directory not found"
    }

    # Run additional tools
    $registerKsp = Join-Path $TempInstallDir "RegisterKSP.exe"
    $configExe = Join-Path $TempInstallDir "eSignerCSP.Config.exe"

    if (Test-Path $registerKsp) {
        Start-Process $registerKsp -Wait
    }

    if (Test-Path $configExe) {
        Start-Process $configExe -Wait
    }

    # Configure eSigner
    $masterKeyFile = Join-Path -Path $TempInstallDir -ChildPath "master.key"
    $eSignerCKATool = Get-ChildItem -Path $TempInstallDir -Filter "eSignerCKATool.exe" -Recurse | 
        Select-Object -First 1

    if (-not $eSignerCKATool) {
        throw "eSignerCKATool.exe not found"
    }

    & $eSignerCKATool.FullName config -mode "product" `
        -user $User `
        -pass $Password `
        -totp $TotpKey `
        -key $masterKeyFile -r

    & $eSignerCKATool.FullName load

    return $TempInstallDir
}

function Get-SigningCertificate {
    $certs = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert | 
        Where-Object { $_.Subject -like "*Tipalti*" -and $_.NotAfter -gt (Get-Date) }

    if (-not $certs) {
        throw "No valid Tipalti certificates found"
    }

    return $certs[0]
}

function Get-SignTool {
    $signToolPath = "C:\Program Files (x86)\Windows Kits\10\bin\*\x64\SignTool.exe"
    $signTool = Get-ChildItem $signToolPath | 
        Sort-Object { [version]$_.Directory.Parent.Name } -Descending |
        Select-Object -First 1

    if (-not $signTool) {
        throw "SignTool not found"
    }

    return $signTool
}

function Invoke-SignApp {
    param(
        [Parameter(Mandatory = $true)]
        [string]$AppFile,
        [string]$TimestampServer = "http://ts.ssl.com"
    )

    $cert = Get-SigningCertificate
    $signTool = Get-SignTool

    & $signTool.FullName sign /debug /fd sha256 /s MY /tr $TimestampServer /td sha256 /sha1 $cert.Thumbprint $AppFile

    $signature = Get-AuthenticodeSignature $AppFile
    if ($signature.Status -ne 'Valid') {
        throw "Signature verification failed"
    }

    Write-Output "App signed successfully: $AppFile"
}

Export-ModuleMember -Function @(
    'Import-BcHelperLibraries',
    'Register-NavSip',
    'Install-ESignerCKA',
    'Initialize-ESigner',
    'Invoke-SignApp'
)