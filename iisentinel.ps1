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
        - RunMetadata
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
$RunID     = [guid]::NewGuid().ToString()
$RunDate   = Get-Date
$TimeStamp = $RunDate.ToString("yyyyMMdd-HHmm")

# ----------------------------
# 1) Discover Targets  ✅ FIXED
# ----------------------------
$Targets = New-Object System.Collections.Generic.List[string]

if ($ServerNames) {
    foreach ($s in $ServerNames) {
        if ($s) { $Targets.Add($s) | Out-Null }
    }
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

        foreach ($d in $discovered) {
            if ($d) { $Targets.Add($d) | Out-Null }
        }
    }
    catch {
        throw "OU discovery failed: $($_.Exception.Message)"
    }
}

$Targets = $Targets | Sort-Object -Unique
if ($Targets.Count -eq 0) {
    throw "No servers found."
}

Write-Host "[*] Targets: $($Targets.Count)" -ForegroundColor Cyan

# ----------------------------
# 2) Remote Script
# ----------------------------
$RemoteScript = {
    param($RunID)

    function Get-TlsVersionFlag {
        param($cert)
        if ($cert.SignatureAlgorithm.FriendlyName -match "sha1") {
            return "Weak (SHA1)"
        }
        return "OK"
    }

    function Get-CertDetails {
        param($thumb)

        try {
            $cert = Get-ChildItem Cert:\LocalMachine\My,Cert:\LocalMachine\WebHosting -Recurse |
                    Where-Object { $_.Thumbprint -eq $thumb } |
                    Select-Object -First 1
            if (-not $cert) { return $null }

            $san = $cert.Extensions | Where-Object { $_.Oid.FriendlyName -eq "Subject Alternative Name" }
            $sanValues = if ($san) {
                ($san.Format($false) -split "`n" | ForEach-Object { $_.Trim() }) -join "; "
            }

            [pscustomobject]@{
                CertName           = $cert.Subject
                CertExpirationDate = $cert.NotAfter
                CertDaysRemaining  = [math]::Round(($cert.NotAfter - (Get-Date)).TotalDays)
                Issuer             = $cert.Issuer
                SAN                = $sanValues
                CertRisk           = Get-TlsVersionFlag $cert
            }
        }
        catch {
            return $null
        }
    }

    $iisFeature = Get-WindowsFeature -Name Web-Server -ErrorAction SilentlyContinue
    if (-not $iisFeature -or -not $iisFeature.Installed) {
        return [pscustomobject]@{
            RunID        = $RunID
            ServerName   = $env:COMPUTERNAME
            IISInstalled = $false
            SiteName     = ""
            SiteState    = ""
            Binding      = ""
            Protocol     = ""
            Hostname     = ""
            Port         = ""
            CertName     = ""
            CertExpirationDate = ""
            CertDaysRemaining  = ""
            Issuer       = ""
            SAN          = ""
            CertRisk     = ""
            Error        = "IIS not installed"
        }
    }

    try {
        Import-Module WebAdministration -ErrorAction Stop
    }
    catch {
        return [pscustomobject]@{
            RunID        = $RunID
            ServerName   = $env:COMPUTERNAME
            IISInstalled = $true
            Error        = "WebAdministration module load failed: $($_.Exception.Message)"
        }
    }

    $results = @()

    foreach ($site in Get-ChildItem IIS:\Sites) {
        foreach ($binding in $site.Bindings.Collection) {

            $parts = $binding.bindingInformation -split ":"
            $hostname = if ($parts[2]) { $parts[2] } else { "N/A" }
            $port = $parts[1]

            $certDetails = $null
            if ($binding.protocol -eq "https") {
                try {
                    $thumb = ($binding.certificateHash | ForEach-Object { $_.ToString("X2") }) -join ""
                    $certDetails = Get-CertDetails $thumb
                } catch {}
            }

            $results += [pscustomobject]@{
                RunID        = $RunID
                ServerName   = $env:COMPUTERNAME
                IISInstalled = $true
                SiteName     = $site.Name
                SiteState    = $site.State
                Binding      = $binding.bindingInformation
                Protocol     = $binding.protocol
                Hostname     = $hostname
                Port         = $port
                CertName     = $certDetails?.CertName
                CertExpirationDate = $certDetails?.CertExpirationDate
                CertDaysRemaining  = $certDetails?.CertDaysRemaining
                Issuer       = $certDetails?.Issuer
                SAN          = $certDetails?.SAN
                CertRisk     = $certDetails?.CertRisk
                Error        = if ($binding.protocol -eq "https" -and -not $certDetails) {
                    "Certificate inspection failed or not found"
                } else { "" }
            }
        }
    }

    return $results
}

# ----------------------------
# 3) Execute
# ----------------------------
Write-Host "[*] Running inventory..." -ForegroundColor Cyan

$raw = Invoke-Command `
    -ComputerName $Targets `
    -Credential $Credential `
    -ScriptBlock $RemoteScript `
    -ArgumentList $RunID `
    -ThrottleLimit 50 `
    -ErrorAction SilentlyContinue

$Inventory = $raw | Where-Object { $_ }
$Errors    = $Inventory | Where-Object { $_.Error }
$Expiring  = $Inventory | Where-Object {
    $_.CertDaysRemaining -ne "" -and [int]$_.CertDaysRemaining -le 90
}

# ----------------------------
# 4) Summary
# ----------------------------
$Summary = [pscustomobject]@{
    RunID               = $RunID
    RunDate             = $RunDate
    ServersScanned      = $Targets.Count
    IISInstalledCount   = ($Inventory | Where-Object IISInstalled | Select-Object -Expand ServerName -Unique).Count
    IISNotInstalledCount= ($Inventory | Where-Object { -not $_.IISInstalled } | Select-Object -Expand ServerName -Unique).Count
    TotalErrors         = $Errors.Count
    TotalExpiring       = $Expiring.Count
}

# ----------------------------
# 5) Export Excel
# ----------------------------
$ExcelPath = Join-Path $OutputDir "IISentinel_Report_$TimeStamp.xlsx"

$pkg = @{
    Path = $ExcelPath
    AutoSize = $true
    BoldTopRow = $true
    FreezeTopRow = $true
}

$Inventory | Export-Excel @pkg -WorksheetName "Inventory"
$Errors    | Export-Excel @pkg -WorksheetName "Errors"
$Summary   | Export-Excel @pkg -WorksheetName "Summary"

[pscustomobject]@{
    RunID = $RunID
    RunDate = $RunDate
    ServerCount = $Targets.Count
} | Export-Excel @pkg -WorksheetName "RunMetadata"

Write-Host "[+] Excel report created: $ExcelPath" -ForegroundColor Green

# ----------------------------
# 6) Email
# ----------------------------
if ($SendEmail) {
    $body = @"
<html><body>
<h2>IISentinel Report</h2>
<p>Servers scanned: $($Summary.ServersScanned)</p>
<p>Expiring certs (≤90 days): $($Summary.TotalExpiring)</p>
<p>See attached Excel.</p>
</body></html>
"@

    $msg = New-Object System.Net.Mail.MailMessage $From, $To
    $msg.Subject = "IISentinel Report - $TimeStamp"
    $msg.Body = $body
    $msg.IsBodyHtml = $true
    $msg.Attachments.Add($ExcelPath)

    (New-Object System.Net.Mail.SmtpClient $SmtpServer).Send($msg)
    Write-Host "[+] Email sent to $To" -ForegroundColor Green
}
