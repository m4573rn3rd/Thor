<#
.SYNOPSIS
    Downloads and installs the Thor application's root CA certificate.
.DESCRIPTION
    This script downloads the ca_cert.pem file from a running Thor server
    and installs it into the Local Machine's Trusted Root Certification Authorities store.
    It must be run with Administrator privileges.
.PARAMETER ServerIp
    The IP address of the Thor server.
.EXAMPLE
    .\Install-ThorCA.ps1 -ServerIp "192.168.1.100"
#>
param(
    [Parameter(Mandatory=$true)]
    [string]$ServerIp
)

# --- 1. Check for Administrator Privileges ---
Write-Host "Checking for Administrator privileges..."
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run with Administrator privileges. Please open PowerShell as an Administrator and try again."
    # Pause to allow user to read the error before the window closes
    if ($Host.Name -eq "ConsoleHost") { Read-Host -Prompt "Press Enter to exit" }
    exit 1
}
Write-Host "Administrator privileges confirmed." -ForegroundColor Green

# --- 2. Define Paths and Download ---
$Url = "http://${ServerIp}:5000/ca.pem"
$TempFilePath = Join-Path $env:TEMP "Thor_CA.pem"

try {
    Write-Host "Downloading CA certificate from $Url..."
    Invoke-WebRequest -Uri $Url -OutFile $TempFilePath -UseBasicParsing
    Write-Host "Successfully downloaded certificate to $TempFilePath" -ForegroundColor Green
}
catch {
    Write-Error "Failed to download the certificate. Please ensure the Thor server is running and the IP address is correct."
    Write-Error $_.Exception.Message
    if ($Host.Name -eq "ConsoleHost") { Read-Host -Prompt "Press Enter to exit" }
    exit 1
}

# --- 3. Install the Certificate ---
try {
    Write-Host "Importing certificate to Trusted Root Certification Authorities store..."
    $cert = Import-Certificate -FilePath $TempFilePath -CertStoreLocation "Cert:\LocalMachine\Root" -ErrorAction Stop
    Write-Host "Certificate successfully installed!" -ForegroundColor Green
    Write-Host "  - Subject: $($cert.Subject)"
    Write-Host "  - Thumbprint: $($cert.Thumbprint)"
}
catch {
    Write-Error "Failed to import the certificate."
    Write-Error $_.Exception.Message
    if ($Host.Name -eq "ConsoleHost") { Read-Host -Prompt "Press Enter to exit" }
    exit 1
}
finally {
    # --- 4. Clean Up ---
    if (Test-Path $TempFilePath) {
        Write-Host "Cleaning up temporary file..."
        Remove-Item $TempFilePath
    }
}

Write-Host "Setup complete. The Thor CA is now trusted on this machine."
if ($Host.Name -eq "ConsoleHost") { Read-Host -Prompt "Press Enter to exit" }