<#
.SYNOPSIS
    IISentinel - IIS & SSL Inventory with Excel and Email Report
#>

param(
    [string[]]$ServerNames,
    [string]$OU,
    [pscredential]$Credential,
    [switch]$SendEmail,
    [string]$SmtpServer,
    [string]$From,
    [string]$To
)

$ErrorActionPreference = "Stop"

# ------------------------------------------------------------
# Output
# ------------------------------------------------------------
$OutputDir = "C:\IISentinel"
if (-not (Test-Path $OutputDir)) {
    New-Item -Path $OutputDir -ItemType Directory -Force | Out-Null
}

if (-not (Get-Module -ListAvailable -Name ImportExcel)) {
    throw "ImportExcel module required. Install-Module ImportExcel"
}

# ------------------------------------------------------------
# Run metadata
# ------------------------------------------------------------
$RunID     = [guid]::NewGuid().ToString()
$RunDate   = Get-Date
$TimeStamp = $RunDate.ToString("yyyyMMdd-HHmm")

# ------------------------------------------------------------
# 1) Discover Targets
# ------------------------------------------------------------
$Targets = [System.Collections.Generic.List[string]]::new()

if ($ServerNames) {
    $Targets.AddRange([string[]]$ServerNames)
}

if ($OU) {
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        throw "ActiveDirectory module required for OU discovery."
    }

    Import-Module ActiveDirectory

    try {
        $discovered = Get-ADComputer `
            -SearchBase $OU `
            -SearchScope Subtree `
            -Filter { Enabled -eq $true } |
            Select-Object -ExpandProperty Name

        # *** CRITICAL FIX ***
        # AddRange requires string[]
        [string[]]$discoveredStrings = $discovered
        $Targets.AddRange($discoveredStrings)
    }
    catch {
        throw "OU discovery failed: $($_.Exception.Message)"
    }
}

$Targets = $Targets | Sort-Object -Unique
if ($Targets.Count -eq 0) {
    throw "No servers found."
}

Write-Host "[*] Targets discovered: $($Targets.Count)" -ForegroundColor Cyan

# ------------------------------------------------------------
# 2) Remote Script
# ------------------------------------------------------------
$RemoteScript = {
    param($RunID)

    function Normalize-Thumbprint {
        param($t)
        if (-not $t) { return $null }
        return $t.Replace(" ", "").ToUpper()
    }

    function Get-CertDetails {
        param($thumb)

        $thumb = Normalize-Thumbprint $thumb

        $cert = Get-ChildItem Cert:\LocalMachine\My -Recurse -ErrorAction SilentlyContinue |
            Where-Object {
                (Normalize-Thumbprint $_.Thumbprint) -eq $thumb
            } |
            Select-Object -First 1

        if (-not $cert) {
            $cert = Get-ChildItem Cert:\LocalMachine\WebHosting -Recurse -ErrorAction SilentlyContinue |
                Where-Object {
                    (Normalize-Thumbprint $_.Thumbprint) -eq $thumb
                } |
                Select-Object -First 1
        }

        if (-not $cert) { return $null }

        $san = $cert.Extensions |
            Where-Object { $_.Oid.FriendlyName -eq "Subject Alternative Name" }

        $sanValue = $null
        if ($san) {
            $sanValue = ($san.Format($false) -split "`n" | ForEach-Object { $_.Trim() }) -join "; "
        }

        return [pscustomobject]@{
            CertName           = $cert.Subject
            CertExpirationDate = $cert.NotAfter
            CertDaysRemaining  = [math]::Round(($cert.NotAfter - (Get-Date)).TotalDays)
            Issuer             = $cert.Issuer
            SAN                = $sanValue
            CertRisk           = if ($cert.SignatureAlgorithm.FriendlyName -match "sha1") { "Weak (SHA1)" } else { "OK" }
        }
    }

    # IIS installed?
    $iis = Get-WindowsFeature Web-Server -ErrorAction SilentlyContinue
    if (-not $iis -or -not $iis.Installed) {
        return [pscustomobject]@{
            RunID        = $RunID
            ServerName   = $env:COMPUTERNAME
            IISInstalled = $false
            Error        = "IIS not installed"
        }
    }

    Import-Module WebAdministration -ErrorAction Stop

    $results = @()
    $sites = Get-ChildItem IIS:\Sites

    foreach ($site in $sites) {
        foreach ($binding in $site.Bindings.Collection) {

            $bindingInfo = $binding.bindingInformation
            $parts = $bindingInfo -split ":"

            $port     = $parts[1]
            $hostname = if ($parts[2]) { $parts[2] } else { "N/A" }

            $certDetails = $null
            $tlsVersion  = ""

            if ($binding.protocol -eq "https") {
                try {
                    $thumb = ($binding.certificateHash | ForEach-Object { $_.ToString("X2") }) -join ""
                    $certDetails = Get-CertDetails -thumb $thumb
                    $tlsVersion  = if ($binding.sslFlags -eq 0) { "TLS 1.0/1.1 possible" } else { "TLS 1.2+" }
                }
                catch {}
            }

            $results += [pscustomobject]@{
                RunID              = $RunID
                ServerName         = $env:COMPUTERNAME
                IISInstalled       = $true
                SiteName           = $site.Name
                SiteState          = $site.State
                Binding            = $bindingInfo
                Protocol           = $binding.protocol
                Hostname           = $hostname
                Port               = $port
                CertName           = $certDetails?.CertName
                CertExpirationDate = $certDetails?.CertExpirationDate
                CertDaysRemaining  = $certDetails?.CertDaysRemaining
                Issuer             = $certDetails?.Issuer
                SAN                = $certDetails?.SAN
                CertRisk           = $certDetails?.CertRisk
                TLSVersion         = $tlsVersion
                Error              = if ($binding.protocol -eq "https" -and -not $certDetails) { "Certificate inspection failed" } else { "" }
            }
        }
    }

    return $results
}

# ------------------------------------------------------------
# 3) Run Inventory
# ------------------------------------------------------------
$Inventory = Invoke-Command `
    -ComputerName $Targets `
    -Credential $Credential `
    -ScriptBlock $RemoteScript `
    -ArgumentList $RunID `
    -ThrottleLimit 32 `
    -ErrorAction SilentlyContinue

$Errors   = $Inventory | Where-Object { $_.Error }
$Expiring = $Inventory | Where-Object { $_.CertDaysRemaining -ne $null -and $_.CertDaysRemaining -le 90 }

# ------------------------------------------------------------
# 4) Orphan Certificates
# ------------------------------------------------------------
$OrphanCerts = Invoke-Command -ComputerName $Targets -Credential $Credential -ScriptBlock {
    Import-Module WebAdministration

    $boundThumbs = Get-ChildItem IIS:\Sites |
        ForEach-Object { $_.Bindings.Collection } |
        Where-Object { $_.certificateHash } |
        ForEach-Object {
            ($_.certificateHash | ForEach-Object { $_.ToString("X2") }) -join ""
        }

    Get-ChildItem Cert:\LocalMachine\My |
        Where-Object {
            ($_.Thumbprint.Replace(" ", "").ToUpper()) -notin $boundThumbs
        } |
        Select-Object PSComputerName, Subject, Issuer, NotAfter, Thumbprint
} -ErrorAction SilentlyContinue

# ------------------------------------------------------------
# 5) Summary
# ------------------------------------------------------------
$Summary = [pscustomobject]@{
    RunID                = $RunID
    RunDate              = $RunDate
    ServersScanned       = $Targets.Count
    IISInstalledCount    = ($Inventory | Where-Object IISInstalled | Select-Object -Expand ServerName -Unique).Count
    IISNotInstalledCount = ($Inventory | Where-Object { -not $_.IISInstalled } | Select-Object -Expand ServerName -Unique).Count
    TotalErrors          = $Errors.Count
    ExpiringCerts        = $Expiring.Count
}

# ------------------------------------------------------------
# 6) Excel Export
# ------------------------------------------------------------
$ExcelPath = Join-Path $OutputDir "IISentinel_Report_$TimeStamp.xlsx"

$pkg = @{
    Path          = $ExcelPath
    AutoSize      = $true
    BoldTopRow    = $true
    FreezeTopRow  = $true
}

$Inventory   | Export-Excel @pkg -WorksheetName "Inventory"
$Errors      | Export-Excel @pkg -WorksheetName "Errors"
$Summary     | Export-Excel @pkg -WorksheetName "Summary"
$OrphanCerts | Export-Excel @pkg -WorksheetName "OrphanCerts"

Write-Host "[+] Excel report created: $ExcelPath" -ForegroundColor Green
