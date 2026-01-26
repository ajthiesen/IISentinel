<#
.SYNOPSIS
    IISentinel - Enterprise IIS & SSL Inventory Tool

.DESCRIPTION
    Discovers servers via OU or explicit list, then queries IIS + HTTPS bindings + certs.
    Produces Excel report with Summary + Inventory + Errors tabs.
    Supports email alerts.
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

# Output Configuration
$OutputDir = "C:\IISentin"
if (-not (Test-Path $OutputDir)) { New-Item -Path $OutputDir -ItemType Directory -Force | Out-Null }

$ExcelAvailable = (Get-Module -ListAvailable -Name ImportExcel)

# =========================
# 1. Target Discovery
# =========================
$TargetList = [System.Collections.Generic.List[string]]::new()

if ($ServerNames) {
    foreach ($name in $ServerNames) {
        $TargetList.Add($name) | Out-Null
    }
}

if ($OU) {
    Write-Host "[*] Discovering servers in OU: $OU" -ForegroundColor Cyan

    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        Write-Warning "ActiveDirectory module missing. RSAT required."
    }
    else {
        Import-Module ActiveDirectory

        try {
            $Discovered = Get-ADComputer -SearchBase $OU -SearchScope Subtree -Filter { Enabled -eq $true } -ErrorAction Stop |
                          Select-Object -ExpandProperty Name

            # Fix: if single result, make it an array
            if ($Discovered -isnot [System.Array]) {
                $Discovered = @($Discovered)
            }

            if (-not $Discovered) { $Discovered = @() }

            foreach ($name in $Discovered) {
                $TargetList.Add($name) | Out-Null
            }

            Write-Host "    + Found $($TargetList.Count) targets total." -ForegroundColor Green
        }
        catch {
            Write-Warning "OU discovery failed: $($_.Exception.Message)"
            Write-Warning "Make sure the OU string is correct and you have permission to read it."
        }
    }
}

$FinalTargets = $TargetList | Sort-Object -Unique
if ($FinalTargets.Count -eq 0) { throw "No servers found to target." }

# =========================
# 2. Remote Execution (Parallel)
# =========================
$RemoteScript = {
    function Get-CertSAN {
        param($Cert)
        $san = $null
        try {
            $san = $Cert.Extensions |
                Where-Object { $_.Oid.FriendlyName -eq "Subject Alternative Name" } |
                Select-Object -First 1

            if ($san) {
                $raw = $san.Format($false)
                return $raw -replace "DNS Name=", "" -replace "\r\n", ", "
            }
        }
        catch {}
        return $null
    }

    function Get-WeakTLS {
        # Check TLS version from binding's sslFlags
        # This is a best-effort check, not perfect.
        return $null
    }

    $results = @()

    # Check IIS installed
    $IISStatus = Get-Service -Name W3SVC -ErrorAction SilentlyContinue

    if (-not $IISStatus) {
        return [PSCustomObject]@{
            ServerName = $env:COMPUTERNAME
            IISInstalled = $false
            SiteName = "IIS not installed"
            SiteState = $null
            Binding = $null
            Protocol = $null
            Hostname = $null
            Port = $null
            CertName = $null
            CertIssuer = $null
            CertSAN = $null
            CertExpirationDate = $null
            CertDaysRemaining = $null
            CertRisk = $null
            TLSRisk = $null
            Error = $null
        }
    }

    try {
        Import-Module WebAdministration -ErrorAction Stop
        $sites = Get-ChildItem IIS:\Sites
    }
    catch {
        return [PSCustomObject]@{
            ServerName = $env:COMPUTERNAME
            IISInstalled = $true
            SiteName = "WebAdministration failure: $($_.Exception.Message)"
            SiteState = $null
            Binding = $null
            Protocol = $null
            Hostname = $null
            Port = $null
            CertName = $null
            CertIssuer = $null
            CertSAN = $null
            CertExpirationDate = $null
            CertDaysRemaining = $null
            CertRisk = $null
            TLSRisk = $null
            Error = $null
        }
    }

    foreach ($site in $sites) {
        foreach ($binding in $site.Bindings.Collection) {

            $protocol = $binding.protocol
            $bindInfo = $binding.bindingInformation

            # Split binding into host & port
            $parts = $bindInfo.Split(":")
            $ip = $parts[0]
            $port = $parts[1]
            $host = $parts[2]

            # Map HTTP/HTTPS port (best effort)
            $port = [int]$port
            if ($protocol -eq "http") {
                $port = if ($port -eq 80) { 80 } else { $port }
            }
            elseif ($protocol -eq "https") {
                $port = if ($port -eq 443) { 443 } else { $port }
            }

            $row = [PSCustomObject]@{
                ServerName = $env:COMPUTERNAME
                IISInstalled = $true
                SiteName = $site.Name
                SiteState = $site.State
                Binding = $bindInfo
                Protocol = $protocol
                Hostname = $host
                Port = $port
                CertName = $null
                CertIssuer = $null
                CertSAN = $null
                CertExpirationDate = $null
                CertDaysRemaining = $null
                CertRisk = $null
                TLSRisk = $null
                Error = $null
            }

            if ($protocol -eq "https" -and $binding.certificateHash) {
                try {
                    # Convert thumbprint bytes to hex
                    $thumb = ($binding.certificateHash | ForEach-Object { $_.ToString("X2") }) -join ""

                    # Search cert stores
                    $cert = Get-ChildItem Cert:\LocalMachine\My -Recurse |
                            Where-Object { $_.Thumbprint -eq $thumb } |
                            Select-Object -First 1

                    if (-not $cert) {
                        $cert = Get-ChildItem Cert:\LocalMachine\WebHosting -Recurse |
                                Where-Object { $_.Thumbprint -eq $thumb } |
                                Select-Object -First 1
                    }

                    if ($cert) {
                        $row.CertName = $cert.Subject
                        $row.CertIssuer = $cert.Issuer
                        $row.CertSAN = Get-CertSAN -Cert $cert
                        $row.CertExpirationDate = $cert.NotAfter
                        $row.CertDaysRemaining = ($cert.NotAfter - (Get-Date)).Days
                        $row.CertRisk = if ($row.CertDaysRemaining -le 30) { "High" }
                                        elseif ($row.CertDaysRemaining -le 60) { "Medium" }
                                        elseif ($row.CertDaysRemaining -le 90) { "Low" }
                                        else { "OK" }

                        # Weak TLS check (best effort)
                        # If cert is old or uses weak signature, mark.
                        $row.TLSRisk = if ($cert.SignatureAlgorithm -match "sha1") { "Weak - SHA1" } else { "OK" }
                    }
                    else {
                        $row.Error = "Certificate not found in LocalMachine stores (My/WebHosting)"
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

Write-Host "[*] Querying $($FinalTargets.Count) servers in parallel..." -ForegroundColor Cyan

$RawResults = Invoke-Command -ComputerName $FinalTargets -ScriptBlock $RemoteScript -Credential $Credential -ErrorAction SilentlyContinue -ThrottleLimit 50

# =========================
# 3. Data Processing
# =========================
$Inventory = $RawResults | Select-Object * -ExcludeProperty RunspaceId, PSComputerName, PSShowComputerName
$Errors = $Inventory | Where-Object { $_.Error -ne $null }
$Expiring = $Inventory | Where-Object { $_.CertDaysRemaining -ne $null -and [int]$_.CertDaysRemaining -le 90 }

# Summary
$Summary = [PSCustomObject]@{
    RunID = [guid]::NewGuid()
    RunDate = Get-Date
    TotalServers = $FinalTargets.Count
    TotalIIS = ($Inventory | Where-Object { $_.IISInstalled -eq $true }).Count
    TotalErrors = $Errors.Count
    Expiring30 = ($Expiring | Where-Object { $_.CertDaysRemaining -le 30 }).Count
    Expiring60 = ($Expiring | Where-Object { $_.CertDaysRemaining -le 60 -and $_.CertDaysRemaining -gt 30 }).Count
    Expiring90 = ($Expiring | Where-Object { $_.CertDaysRemaining -le 90 -and $_.CertDaysRemaining -gt 60 }).Count
}

# =========================
# 4. Reporting (Excel)
# =========================
$TimeStamp = Get-Date -Format "yyyyMMdd-HHmm"
$ExcelPath = Join-Path $OutputDir "IISentinel_Report_$TimeStamp.xlsx"

if (-not $ExcelAvailable) {
    Write-Warning "ImportExcel module not found. Install it from PSGallery: Install-Module ImportExcel"
    throw "Excel module missing."
}

$pkg = @{ Path = $ExcelPath; AutoSize = $true; FreezeTopRow = $true; BoldTopRow = $true }

$Summary | Export-Excel @pkg -WorksheetName "Summary"
$Inventory | Export-Excel @pkg -WorksheetName "Inventory"
$Errors | Export-Excel @pkg -WorksheetName "Errors"

Write-Host "[+] Report generated: $ExcelPath" -ForegroundColor Green

# =========================
# 5. Email Notification
if ($SendEmail -and $Expiring) {
    $style = "<style>table{border-collapse:collapse;width:100%} th,td{border:1px solid #ddd;padding:8px} th{background:#f2f2f2}</style>"
    $body = "<h2>IISentinel Alert</h2><h3>Expiring Certificates (Next 90 Days)</h3>$($Expiring | Select-Object ServerName,SiteName,Hostname,Port,CertDaysRemaining,CertIssuer | ConvertTo-Html -Fragment)"

    $params = @{
        From       = $From
        To         = $To
        Subject    = "IISentinel Alert: $($Expiring.Count) certs expiring"
        Body       = "<html><head>$style</head><body>$body</body></html>"
        SmtpServer = $SmtpServer
        BodyAsHtml = $true
    }
    Send-MailMessage @params
    Write-Host "[+] Email alert sent." -ForegroundColor Green
}
