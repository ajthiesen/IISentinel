<#
.SYNOPSIS
    IISentinel - IIS & SSL Inventory with Excel and Email Report

.DESCRIPTION
    Discovers servers from OU or explicit list.
    Runs in parallel to collect IIS sites, bindings, certificates.
    Generates a single Excel workbook with:
        - Inventory
        - Errors
        - Summary
        - Metadata
        - Orphaned Certificates
    Sends HTML email report with workbook attached.
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

# ----------------------------
# Output
# ----------------------------
$OutputDir = "C:\IISentinel"
if (-not (Test-Path $OutputDir)) {
    New-Item -Path $OutputDir -ItemType Directory -Force | Out-Null
}

if (-not (Get-Module -ListAvailable -Name ImportExcel)) {
    throw "ImportExcel module required. Install-Module ImportExcel"
}

# ----------------------------
# Run metadata
# ----------------------------
$RunID    = [guid]::NewGuid().ToString()
$RunDate  = Get-Date
$TimeStamp = $RunDate.ToString("yyyyMMdd-HHmm")

# ----------------------------
# 1) Discover Targets
# ----------------------------
$Targets = New-Object System.Collections.Generic.List[string]

if ($ServerNames) {
    foreach ($s in $ServerNames) { $Targets.Add($s) }
}

if ($OU) {
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        throw "ActiveDirectory module required for OU discovery."
    }

    Import-Module ActiveDirectory

    try {
        $discovered = Get-ADComputer -SearchBase $OU -SearchScope Subtree `
            -Filter { Enabled -eq $true } |
            Select-Object -ExpandProperty Name

        foreach ($d in $discovered) { $Targets.Add($d) }
    }
    catch {
        throw "OU discovery failed: $($_.Exception.Message)"
    }
}

$Targets = $Targets | Sort-Object -Unique
if ($Targets.Count -eq 0) { throw "No servers found." }

Write-Host "[*] Targets discovered: $($Targets.Count)" -ForegroundColor Cyan

# ----------------------------
# 2) Remote Script
# ----------------------------
$RemoteScript = {
param($RunID)

function Get-CertDetails {
    param($thumb)

    $cert = Get-ChildItem Cert:\LocalMachine\My,Cert:\LocalMachine\WebHosting -Recurse |
        Where-Object { $_.Thumbprint -eq $thumb } |
        Select-Object -First 1

    if (-not $cert) { return $null }

    $san = $cert.Extensions | Where-Object { $_.Oid.FriendlyName -eq "Subject Alternative Name" }
    $sanValues = if ($san) {
        ($san.Format($false) -split "`n" | ForEach-Object { $_.Trim() }) -join "; "
    }

    $days = [math]::Round(($cert.NotAfter - (Get-Date)).TotalDays)

    $risk =
        if ($days -lt 0) { "Expired" }
        elseif ($days -le 30) { "High" }
        elseif ($days -le 60) { "Medium" }
        elseif ($days -le 90) { "Low" }
        else { "OK" }

    return [pscustomobject]@{
        CertName           = $cert.Subject
        CertExpirationDate = $cert.NotAfter
        CertDaysRemaining  = $days
        Issuer             = $cert.Issuer
        SAN                = $sanValues
        CertRisk           = $risk
        Thumbprint         = $cert.Thumbprint
    }
}

$results = @()
$boundThumbprints = @()

# IIS installed?
if (-not (Get-Service W3SVC -ErrorAction SilentlyContinue)) {
    return [pscustomobject]@{
        Inventory = @([pscustomobject]@{
            RunID        = $RunID
            ServerName   = $env:COMPUTERNAME
            IISInstalled = $false
            Error        = "IIS not installed"
        })
        Orphaned = @()
    }
}

try { Import-Module WebAdministration -ErrorAction Stop }
catch {
    return [pscustomobject]@{
        Inventory = @([pscustomobject]@{
            RunID        = $RunID
            ServerName   = $env:COMPUTERNAME
            IISInstalled = $true
            Error        = "WebAdministration failed"
        })
        Orphaned = @()
    }
}

foreach ($site in Get-ChildItem IIS:\Sites) {
    foreach ($binding in $site.Bindings.Collection) {

        $protocol = $binding.protocol
        $bindingInfo = $binding.bindingInformation

        # Split host/port from binding info
        $parts = $bindingInfo -split ":"
        $hostname = if ($parts[2]) { $parts[2] } else { "N/A" }
        $port = $parts[1]

        # auto-detect HTTP vs HTTPS port
        if ($protocol -eq "https" -and $port -eq "80") { $port = "443" }

        $certDetails = $null

        if ($protocol -eq "https" -and $binding.certificateHash) {
            $thumb = ($binding.certificateHash | ForEach-Object { $_.ToString("X2") }) -join ""
            $certDetails = Get-CertDetails $thumb
            if ($certDetails) { $boundThumbprints += $certDetails.Thumbprint }
        }

        $results += [pscustomobject]@{
            RunID              = $RunID
            ServerName         = $env:COMPUTERNAME
            IISInstalled       = $true
            SiteName           = $site.Name
            SiteState          = $site.State
            Binding            = $bindingInfo
            Protocol           = $protocol
            Hostname           = $hostname
            Port               = $port
            CertName           = $certDetails?.CertName
            CertExpirationDate = $certDetails?.CertExpirationDate
            CertDaysRemaining  = $certDetails?.CertDaysRemaining
            Issuer             = $certDetails?.Issuer
            SAN                = $certDetails?.SAN
            CertRisk           = $certDetails?.CertRisk
            Error              = if ($protocol -eq "https" -and -not $certDetails) {
                                    "Certificate inspection failed"
                                 } else { "" }
        }
    }
}

# ----------------------------
# Orphaned Certificates
# ----------------------------
$orphaned = @()
foreach ($store in "My","WebHosting") {
    Get-ChildItem "Cert:\LocalMachine\$store" | ForEach-Object {
        if ($boundThumbprints -notcontains $_.Thumbprint) {
            $days = [math]::Round(($_.NotAfter - (Get-Date)).TotalDays)
            $orphaned += [pscustomobject]@{
                RunID         = $RunID
                ServerName    = $env:COMPUTERNAME
                Store         = $store
                Subject       = $_.Subject
                Issuer        = $_.Issuer
                Thumbprint    = $_.Thumbprint
                NotAfter      = $_.NotAfter
                DaysRemaining = $days
            }
        }
    }
}

return @{ Inventory = $results; Orphaned = $orphaned }
}

# ----------------------------
# 3) Invoke
# ----------------------------
$raw = Invoke-Command -ComputerName $Targets `
    -Credential $Credential `
    -ScriptBlock $RemoteScript `
    -ArgumentList $RunID `
    -ThrottleLimit 50 `
    -ErrorAction SilentlyContinue

$Inventory = @()
$Orphaned  = @()

foreach ($r in $raw) {
    $Inventory += $r.Inventory
    $Orphaned  += $r.Orphaned
}

$Errors = $Inventory | Where-Object { $_.Error }

# ----------------------------
# 4) Summary
# ----------------------------
$Summary = [pscustomobject]@{
    RunID           = $RunID
    RunDate         = $RunDate
    ServersScanned  = $Targets.Count
    IISInstalled    = ($Inventory | Where-Object IISInstalled | Select-Object ServerName -Unique).Count
    TotalErrors     = $Errors.Count
    OrphanedCerts   = $Orphaned.Count
}

# ----------------------------
# 5) Excel
# ----------------------------
$ExcelPath = Join-Path $OutputDir "IISentinel_Report_$TimeStamp.xlsx"
$pkg = @{ Path=$ExcelPath; AutoSize=$true; FreezeTopRow=$true; BoldTopRow=$true }

$Inventory | Export-Excel @pkg -WorksheetName "Inventory"
$Errors    | Export-Excel @pkg -WorksheetName "Errors"
$Summary   | Export-Excel @pkg -WorksheetName "Summary"
$Orphaned  | Export-Excel @pkg -WorksheetName "OrphanedCertificates"

# Run metadata sheet
$RunMeta = [pscustomobject]@{
    RunID = $RunID
    RunDate = $RunDate
    ServerCount = $Targets.Count
}
$RunMeta | Export-Excel @pkg -WorksheetName "RunMetadata"

Write-Host "[+] Excel report created: $ExcelPath" -ForegroundColor Green

# ----------------------------
# 6) Email
if ($SendEmail) {
    $body = @"
<html>
<body>
    <h2>IISentinel Report</h2>
    <p>Run ID: $RunID</p>
    <p>Servers scanned: $($Targets.Count)</p>
    <p>Errors: $($Errors.Count)</p>
    <p>Orphaned certs: $($Orphaned.Count)</p>
    <p>See attached report.</p>
</body>
</html>
"@

    Send-MailMessage -SmtpServer $SmtpServer -From $From -To $To `
        -Subject "IISentinel Report $TimeStamp" `
        -Body $body -BodyAsHtml `
        -Attachments $ExcelPath
}
