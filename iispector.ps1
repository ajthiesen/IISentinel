<#
.SYNOPSIS
    IISpector - IIS & SSL Certificate Inventory Tool

.DESCRIPTION
    Discovers Windows servers via OU or explicit list, identifies IIS installations,
    enumerates all IIS sites and bindings (running or stopped), inspects HTTPS
    certificates, evaluates expiration and crypto risk, and exports results to CSV.

.NOTES
    Read-only. Safe for production. Designed for on-prem Active Directory.
#>

param(
    [string[]]$ServerNames,
    [string]$OU,
    [Parameter(Mandatory)]
    [pscredential]$Credential,
    [int]$ThrottleLimit = 25
)

$ErrorActionPreference = "Stop"

# =========================
# Output Configuration
# =========================
$OutputDir = "C:\IISpector"
if (-not (Test-Path $OutputDir)) {
    New-Item -Path $OutputDir -ItemType Directory -Force | Out-Null
}

$TimeStamp = Get-Date -Format "yyyyMMdd-HHmmss"
$OutputCsv = Join-Path $OutputDir "IISpector_Inventory_$TimeStamp.csv"

# =========================
# 1. Target Discovery
# =========================
$Targets = [System.Collections.Generic.List[string]]::new()

if ($ServerNames) {
    $Targets.AddRange([string[]]$ServerNames)
}

if ($OU) {
    Write-Host "[*] Discovering servers from OU: $OU" -ForegroundColor Cyan

    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        throw "ActiveDirectory module not available. RSAT required."
    }

    Import-Module ActiveDirectory

    try {
        $Discovered = Get-ADComputer `
            -SearchBase $OU `
            -SearchScope Subtree `
            -Filter { Enabled -eq $true } |
            Select-Object -ExpandProperty Name

        if ($Discovered) {
            $Targets.AddRange([string[]]$Discovered)
            Write-Host "    + Found $($Discovered.Count) servers" -ForegroundColor Green
        }
    }
    catch {
        throw "OU discovery failed: $($_.Exception.Message)"
    }
}

$FinalTargets = $Targets | Sort-Object -Unique

if ($FinalTargets.Count -eq 0) {
    throw "No servers resolved. Aborting."
}

Write-Host "[*] Total targets: $($FinalTargets.Count)" -ForegroundColor Cyan

# =========================
# 2. Remote Inspection Logic
# =========================
$RemoteScript = {

    $results = @()

    # --- IIS Detection (OS-level, not service state) ---
    try {
        $iisFeature = Get-WindowsFeature -Name Web-Server -ErrorAction Stop
        $iisInstalled = $iisFeature.Installed
    }
    catch {
        $iisInstalled = $false
    }

    if (-not $iisInstalled) {
        return [PSCustomObject]@{
            ServerName            = $env:COMPUTERNAME
            IISInstalled          = "No"
            SiteName              = $null
            SiteState             = $null
            Binding               = $null
            Protocol              = $null
            CertName              = $null
            CertExpirationDate    = $null
            CertDaysRemaining     = $null
            CertRisk              = $null
            Error                 = "IIS not installed"
        }
    }

    # --- Load IIS Configuration ---
    try {
        Import-Module WebAdministration -ErrorAction Stop
        $sites = Get-ChildItem IIS:\Sites
    }
    catch {
        return [PSCustomObject]@{
            ServerName            = $env:COMPUTERNAME
            IISInstalled          = "Yes"
            SiteName              = $null
            SiteState             = $null
            Binding               = $null
            Protocol              = $null
            CertName              = $null
            CertExpirationDate    = $null
            CertDaysRemaining     = $null
            CertRisk              = $null
            Error                 = "WebAdministration failure: $($_.Exception.Message)"
        }
    }

    foreach ($site in $sites) {
        foreach ($binding in $site.Bindings.Collection) {

            $row = [PSCustomObject]@{
                ServerName            = $env:COMPUTERNAME
                IISInstalled          = "Yes"
                SiteName              = $site.Name
                SiteState             = $site.State
                Binding               = $binding.bindingInformation
                Protocol              = $binding.protocol
                CertName              = $null
                CertExpirationDate    = $null
                CertDaysRemaining     = $null
                CertRisk              = $null
                Error                 = $null
            }

            # --- HTTPS Certificate Inspection ---
            if ($binding.protocol -eq "https" -and $binding.certificateHash) {
                try {

                    # --- Robust thumbprint conversion ---
                    if ($binding.certificateHash -is [byte[]]) {
                        $thumbprint = [BitConverter]::ToString($binding.certificateHash).Replace('-', '')
                    }
                    else {
                        $thumbprint = $binding.certificateHash.ToString().Replace(' ', '').Replace('-', '')
                    }

                    $cert = Get-ChildItem Cert:\LocalMachine\My -Recurse |
                            Where-Object { $_.Thumbprint -eq $thumbprint } |
                            Select-Object -First 1

                    if (-not $cert) {
                        $cert = Get-ChildItem Cert:\LocalMachine\WebHosting -Recurse |
                                Where-Object { $_.Thumbprint -eq $thumbprint } |
                                Select-Object -First 1
                    }

                    if ($cert) {
                        $daysLeft = ($cert.NotAfter - (Get-Date)).Days

                        # Risk Classification
                        if ($daysLeft -lt 0) { $risk = "Expired" }
                        elseif ($daysLeft -le 30) { $risk = "30" }
                        elseif ($daysLeft -le 60) { $risk = "60" }
                        elseif ($daysLeft -le 90) { $risk = "90" }
                        else { $risk = "OK" }

                        if ($cert.SignatureAlgorithm.FriendlyName -match "sha1") {
                            $risk = "Insecure"
                        }

                        if ($cert.PublicKey.Key.KeySize -lt 2048) {
                            $risk = "Insecure"
                        }

                        $row.CertName           = $cert.Subject
                        $row.CertExpirationDate = $cert.NotAfter
                        $row.CertDaysRemaining  = $daysLeft
                        $row.CertRisk           = $risk
                    }
                    else {
                        $row.Error = "Certificate not found for thumbprint $thumbprint"
                    }
                }
                catch {
                    $row.Error = "Certificate inspection error: $($_.Exception.Message)"
                }
            }

            $results += $row
        }
    }

    return $results
}

# =========================
# 3. Execute (Parallel, Safe)
# =========================
Write-Host "[*] Inspecting IIS across servers..." -ForegroundColor Cyan

$Results = Invoke-Command `
    -ComputerName $FinalTargets `
    -Credential $Credential `
    -ScriptBlock $RemoteScript `
    -ThrottleLimit $ThrottleLimit `
    -ErrorAction SilentlyContinue

# =========================
# 4. Export Results
# =========================
$CleanResults = $Results |
    Select-Object ServerName, IISInstalled, SiteName, SiteState, Binding, Protocol,
                  CertName, CertExpirationDate, CertDaysRemaining, CertRisk, Error

$CleanResults | Export-Csv -Path $OutputCsv -NoTypeInformation

Write-Host "[+] Inventory written to $OutputCsv" -ForegroundColor Green