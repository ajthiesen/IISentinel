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
        - OrphanCerts
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
if (-not (Test-Path $OutputDir)) { New-Item -Path $OutputDir -ItemType Directory -Force | Out-Null }

$ExcelAvailable = (Get-Module -ListAvailable -Name ImportExcel)
if (-not $ExcelAvailable) {
    throw "ImportExcel module required. Install-Module ImportExcel"
}

# ----------------------------
# Run metadata
# ----------------------------
$RunID = [guid]::NewGuid().ToString()
$RunDate = Get-Date
$TimeStamp = $RunDate.ToString("yyyyMMdd-HHmm")

# ----------------------------
# 1) Discover Targets
# ----------------------------
$Targets = [System.Collections.Generic.List[string]]::new()

if ($ServerNames) {
    $Targets.AddRange($ServerNames)
}

if ($OU) {
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        throw "ActiveDirectory module required for OU discovery."
    }

    Import-Module ActiveDirectory

    try {
        $discovered = Get-ADComputer -SearchBase $OU -SearchScope Subtree -Filter {Enabled -eq $true} |
                      Select-Object -ExpandProperty Name

        # FIX: ensure AddRange receives a string[] not an object[]
        $Targets.AddRange($discovered | ForEach-Object { [string]$_ })
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

        # Detect weak TLS based on cert signature / algorithm
        if ($cert.SignatureAlgorithm.FriendlyName -match "sha1") { return "Weak (SHA1)" }
        return "OK"
    }

    function Get-CertDetails {
        param($thumb)

        try {
            # thumb is already hex string
            $cert = Get-ChildItem -Path Cert:\LocalMachine\My -Recurse |
                    Where-Object { $_.Thumbprint -eq $thumb } |
                    Select-Object -First 1

            if (-not $cert) {
                $cert = Get-ChildItem -Path Cert:\LocalMachine\WebHosting -Recurse |
                        Where-Object { $_.Thumbprint -eq $thumb } |
                        Select-Object -First 1
            }

            if (-not $cert) { return $null }

            # SAN
            $san = $cert.Extensions | Where-Object { $_.Oid.FriendlyName -eq "Subject Alternative Name" }
            $sanValues = $null
            if ($san) {
                $sanValues = ($san.Format($false) -split "`n" | ForEach-Object { $_.Trim() }) -join "; "
            }

            return [pscustomobject]@{
                CertName           = $cert.Subject
                CertExpirationDate = $cert.NotAfter
                CertDaysRemaining  = [math]::Round(($cert.NotAfter - (Get-Date)).TotalDays)
                Issuer             = $cert.Issuer
                SAN                = $sanValues
                CertRisk           = Get-TlsVersionFlag -cert $cert
            }
        }
        catch {
            return $null
        }
    }

    $results = @()

    # Check IIS installed
    $iisInstalled = Get-WindowsFeature -Name Web-Server -ErrorAction SilentlyContinue
    if (-not $iisInstalled -or $iisInstalled.Installed -ne $true) {
        return [pscustomobject]@{
            RunID               = $RunID
            ServerName          = $env:COMPUTERNAME
            IISInstalled        = $false
            SiteName            = ""
            SiteState           = ""
            Binding             = ""
            Protocol            = ""
            Hostname            = ""
            Port                = ""
            CertName            = ""
            CertExpirationDate  = ""
            CertDaysRemaining   = ""
            Issuer              = ""
            SAN                 = ""
            CertRisk            = ""
            TLSVersion          = ""
            Error               = "IIS not installed"
        }
    }

    try {
        Import-Module WebAdministration -ErrorAction Stop
    }
    catch {
        return [pscustomobject]@{
            RunID               = $RunID
            ServerName          = $env:COMPUTERNAME
            IISInstalled        = $true
            SiteName            = ""
            SiteState           = ""
            Binding             = ""
            Protocol            = ""
            Hostname            = ""
            Port                = ""
            CertName            = ""
            CertExpirationDate  = ""
            CertDaysRemaining   = ""
            Issuer              = ""
            SAN                 = ""
            CertRisk            = ""
            TLSVersion          = ""
            Error               = "WebAdministration module load failed: $($_.Exception.Message)"
        }
    }

    $sites = Get-ChildItem IIS:\Sites

    foreach ($site in $sites) {
        foreach ($binding in $site.Bindings.Collection) {
            $protocol = $binding.protocol
            $bindingInfo = $binding.bindingInformation

            # Split host/port from binding info
            $parts = $bindingInfo -split ":"
            $hostname = $parts[2]
            $port = $parts[1]

            # If binding is "*:443:" host may be empty
            if (-not $hostname) { $hostname = "N/A" }

            $certThumb = $null
            $certDetails = $null
            $tlsVersion = "Unknown"

            if ($protocol -eq "https") {
                try {
                    $certThumb = ($binding.certificateHash | ForEach-Object { $_.ToString("X2") }) -join ""
                    $certDetails = Get-CertDetails -thumb $certThumb
                }
                catch {
                    $certDetails = $null
                }

                # TLS detection (simple heuristic)
                $tlsVersion = if ($binding.sslFlags -eq 0) { "TLS 1.0/1.1 possible" } else { "TLS 1.2+" }
            }

            $results += [pscustomobject]@{
                RunID               = $RunID
                ServerName          = $env:COMPUTERNAME
                IISInstalled        = $true
                SiteName            = $site.Name
                SiteState           = $site.State
                Binding             = $bindingInfo
                Protocol            = $protocol
                Hostname            = $hostname
                Port                = $port
                CertName            = $certDetails?.CertName
                CertExpirationDate  = $certDetails?.CertExpirationDate
                CertDaysRemaining   = $certDetails?.CertDaysRemaining
                Issuer              = $certDetails?.Issuer
                SAN                 = $certDetails?.SAN
                CertRisk            = $certDetails?.CertRisk
                TLSVersion          = $tlsVersion
                Error               = if ($protocol -eq "https" -and -not $certDetails) { "Certificate inspection failed" } else { "" }
            }
        }
    }

    return $results
}

# ----------------------------
# 3) Run Remote Calls in Parallel
# ----------------------------
Write-Host "[*] Running inventory..." -ForegroundColor Cyan

$raw = Invoke-Command -ComputerName $Targets -Credential $Credential -ScriptBlock $RemoteScript -ArgumentList $RunID -ThrottleLimit 50 -ErrorAction SilentlyContinue

$Inventory = $raw | Where-Object { $_ -ne $null }
$Errors = $Inventory | Where-Object { $_.Error -ne "" }
$Expiring = $Inventory | Where-Object { $_.CertDaysRemaining -ne "" -and [int]$_.CertDaysRemaining -le 90 }

# ----------------------------
# Orphan cert inventory
# ----------------------------
$OrphanCerts = @()

foreach ($server in $Targets) {
    $OrphanCerts += Invoke-Command -ComputerName $server -Credential $Credential -ScriptBlock {
        Get-ChildItem Cert:\LocalMachine\My -Recurse |
        Where-Object {
            # exclude certificates bound to IIS
            $thumb = $_.Thumbprint
            $bindings = Get-ChildItem IIS:\Sites | ForEach-Object { $_.Bindings.Collection } |
                        Where-Object { $_.certificateHash -ne $null } |
                        ForEach-Object {
                            ($_.certificateHash | ForEach-Object { $_.ToString("X2") }) -join ""
                        }
            $thumb -notin $bindings
        } |
        Select-Object PSComputerName, Subject, Issuer, NotAfter, Thumbprint
    } -ErrorAction SilentlyContinue
}

# ----------------------------
# 4) Summary
# ----------------------------
$Summary = [pscustomobject]@{
    RunID               = $RunID
    RunDate             = $RunDate
    ServersScanned      = $Targets.Count
    IISInstalledCount   = ($Inventory | Where-Object { $_.IISInstalled -eq $true } | Select-Object -ExpandProperty ServerName -Unique).Count
    IISNotInstalledCount= ($Inventory | Where-Object { $_.IISInstalled -eq $false } | Select-Object -ExpandProperty ServerName -Unique).Count
    TotalErrors         = $Errors.Count
    TotalExpiring       = $Expiring.Count
}

# ----------------------------
# 5) Export Excel
# ----------------------------
$ExcelPath = Join-Path $OutputDir "IISentinel_Report_$TimeStamp.xlsx"

$pkg = @{
    Path      = $ExcelPath
    AutoSize  = $true
    BoldTopRow= $true
    FreezeTopRow = $true
}

$Inventory | Export-Excel @pkg -WorksheetName "Inventory"
$Errors    | Export-Excel @pkg -WorksheetName "Errors"
$Summary   | Export-Excel @pkg -WorksheetName "Summary"

$RunMeta   = [pscustomobject]@{
    RunID = $RunID
    RunDate = $RunDate
    ServerCount = $Targets.Count
}
$RunMeta | Export-Excel @pkg -WorksheetName "RunMetadata"

$OrphanCerts | Export-Excel @pkg -WorksheetName "OrphanCerts"

Write-Host "[+] Excel report created: $ExcelPath" -ForegroundColor Green

# ----------------------------
# 6) Email Report
function Build-EmailBody {
    param($summary)

    return @"
<html>
<head>
<style>
    body { font-family: Arial; font-size: 14px; }
    table { border-collapse: collapse; width: 100%; }
    th, td { border: 1px solid #ddd; padding: 8px; }
    th { background: #f2f2f2; }
</style>
</head>
<body>
    <h2>IISentinel Report</h2>
    <table>
        <tr><th>RunID</th><td>$($summary.RunID)</td></tr>
        <tr><th>RunDate</th><td>$($summary.RunDate)</td></tr>
        <tr><th>Servers Scanned</th><td>$($summary.ServersScanned)</td></tr>
        <tr><th>IIS Installed</th><td>$($summary.IISInstalledCount)</td></tr>
        <tr><th>IIS Not Installed</th><td>$($summary.IISNotInstalledCount)</td></tr>
        <tr><th>Errors</th><td>$($summary.TotalErrors)</td></tr>
        <tr><th>Expiring Certs</th><td>$($summary.TotalExpiring)</td></tr>
    </table>
    <p>See attached Excel for full details.</p>
</body>
</html>
"@
}

function Send-Email {
    param(
        [string]$smtp,
        [string]$from,
        [string]$to,
        [string]$subject,
        [string]$body,
        [string]$attachment
    )

    $msg = New-Object System.Net.Mail.MailMessage
    $msg.From = $from
    $msg.To.Add($to)
    $msg.Subject = $subject
    $msg.IsBodyHtml = $true
    $msg.Body = $body

    if ($attachment -and (Test-Path $attachment)) {
        $att = New-Object System.Net.Mail.Attachment($attachment)
        $msg.Attachments.Add($att)
    }

    $smtpClient = New-Object System.Net.Mail.SmtpClient($smtp)
    $smtpClient.Send($msg)
}

if ($SendEmail) {
    $body = Build-EmailBody -summary $Summary
    $subject = "IISentinel Report - $TimeStamp"
    Send-Email -smtp $SmtpServer -from $From -to $To -subject $subject -body $body -attachment $ExcelPath
    Write-Host "[+] Email sent to $To" -ForegroundColor Green
}
