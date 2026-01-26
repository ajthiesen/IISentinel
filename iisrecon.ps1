<#
.SYNOPSIS
    IISpector v3.0 - IIS & SSL Inventory with Summary + Errors + Single Workbook

.DESCRIPTION
    Parallel execution inventory of IIS sites, bindings, and SSL expiry.
    Generates a single Excel workbook with:
      - Inventory
      - ExpiringCerts
      - Errors
      - Summary

    Run metadata is stored separately in JSON.
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
$OutputDir = "C:\IISpector"
if (-not (Test-Path $OutputDir)) { New-Item -Path $OutputDir -ItemType Directory -Force | Out-Null }

$ExcelAvailable = (Get-Module -ListAvailable -Name ImportExcel)

# =========================
# 1. Target Discovery
# =========================
$TargetList = [System.Collections.Generic.List[string]]::new()

if ($ServerNames) { $TargetList.AddRange([string[]]$ServerNames) }

if ($OU) {
    Write-Host "[*] Discovering servers in OU: $OU" -ForegroundColor Cyan
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        Write-Warning "ActiveDirectory module missing. RSAT required."
    }
    else {
        Import-Module ActiveDirectory
        try {
            $Discovered = Get-ADComputer -SearchBase $OU -SearchScope Subtree -Filter { Enabled -eq $true } -ErrorAction Stop | Select-Object -ExpandProperty Name
            if ($Discovered) {
                $TargetList.AddRange([string[]]$Discovered)
                Write-Host "    + Found $($Discovered.Count) objects." -ForegroundColor Green
            }
        }
        catch {
            Write-Warning "OU Discovery Error: $($_.Exception.Message)"
        }
    }
}

$FinalTargets = $TargetList | Sort-Object -Unique
if ($FinalTargets.Count -eq 0) { throw "No servers found to target." }

# =========================
# 2. Remote Execution (Parallel)
# =========================
$RemoteScript = {
    $results = @()

    # Check IIS installed
    $IISInstalled = (Get-WindowsFeature -Name Web-Server -ErrorAction SilentlyContinue).Installed

    if (-not $IISInstalled) {
        return [PSCustomObject]@{
            ServerName   = $env:COMPUTERNAME
            IISInstalled = $false
            SiteName     = $null
            SiteState    = $null
            Binding      = $null
            Protocol     = $null
            CertName     = $null
            CertExpirationDate = $null
            CertDaysRemaining  = $null
            CertRisk     = $null
            Error        = "IIS not installed"
        }
    }

    try {
        Import-Module WebAdministration -ErrorAction Stop
        $sites = Get-ChildItem IIS:\Sites
    }
    catch {
        return [PSCustomObject]@{
            ServerName   = $env:COMPUTERNAME
            IISInstalled = $true
            SiteName     = $null
            SiteState    = $null
            Binding      = $null
            Protocol     = $null
            CertName     = $null
            CertExpirationDate = $null
            CertDaysRemaining  = $null
            CertRisk     = $null
            Error        = "WebAdministration failure: $($_.Exception.Message)"
        }
    }

    foreach ($site in $sites) {
        foreach ($binding in $site.Bindings.Collection) {
            $row = [PSCustomObject]@{
                ServerName   = $env:COMPUTERNAME
                IISInstalled = $true
                SiteName     = $site.Name
                SiteState    = $site.State
                Binding      = $binding.bindingInformation
                Protocol     = $binding.protocol
                CertName     = $null
                CertExpirationDate = $null
                CertDaysRemaining  = $null
                CertRisk     = $null
                Error        = $null
            }

            # SSL Logic
            if ($binding.protocol -eq "https" -and $binding.certificateHash) {
                try {
                    $thumb = ($binding.certificateHash | ForEach-Object { $_.ToString("X2") }) -join ""
                    $cert = Get-ChildItem Cert:\LocalMachine\My -Recurse | Where-Object { $_.Thumbprint -eq $thumb } | Select-Object -First 1
                    if (-not $cert) {
                        $cert = Get-ChildItem Cert:\LocalMachine\WebHosting -Recurse | Where-Object { $_.Thumbprint -eq $thumb } | Select-Object -First 1
                    }

                    if ($cert) {
                        $row.CertName = $cert.Subject
                        $row.CertExpirationDate = $cert.NotAfter
                        $row.CertDaysRemaining = ($cert.NotAfter - (Get-Date)).Days

                        # Risk flags
                        if ($row.CertDaysRemaining -le 30) { $row.CertRisk = "30-day expiry" }
                        elseif ($row.CertDaysRemaining -le 60) { $row.CertRisk = "60-day expiry" }
                        elseif ($row.CertDaysRemaining -le 90) { $row.CertRisk = "90-day expiry" }
                        else { $row.CertRisk = "OK" }
                    }
                    else {
                        $row.Error = "Certificate not found in LocalMachine stores"
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
$Inventory = $RawResults | Select-Object * -ExcludeProperty RunspaceId, PSComputerName, PSShowComputerName
$Errors    = $Inventory | Where-Object { $_.Error -ne $null }
$Expiring  = $Inventory | Where-Object { $_.CertDaysRemaining -ne $null -and [int]$_.CertDaysRemaining -le 90 }

# Summary
$Summary = [PSCustomObject]@{
    RunDate              = (Get-Date)
    ServersScanned       = $FinalTargets.Count
    IISInstalledCount    = ($Inventory | Where-Object { $_.IISInstalled -eq $true } | Select-Object -Unique ServerName).Count
    IISNotInstalledCount = ($Inventory | Where-Object { $_.IISInstalled -eq $false } | Select-Object -Unique ServerName).Count
    ErrorsCount          = $Errors.Count
    ExpiringCount        = $Expiring.Count
}

# =========================
# 4. Reporting (Single Workbook)
$TimeStamp = Get-Date -Format "yyyyMMdd-HHmm"
$ExcelPath = Join-Path $OutputDir "IISpector_Report_$TimeStamp.xlsx"

$pkg = @{
    Path        = $ExcelPath
    AutoSize    = $true
    FreezeTopRow= $true
    BoldTopRow  = $true
}

if ($ExcelAvailable) {
    $Inventory | Export-Excel @pkg -WorksheetName "Inventory"
    $Errors    | Export-Excel @pkg -WorksheetName "Errors"
    $Expiring  | Export-Excel @pkg -WorksheetName "ExpiringCerts"
    $Summary   | Export-Excel @pkg -WorksheetName "Summary"

    Write-Host "[+] Report generated: $ExcelPath" -ForegroundColor Green
}
else {
    Write-Warning "ImportExcel module not found. Excel export requires ImportExcel."
}

# =========================
# 5. Run Metadata (Separate)
$MetaPath = Join-Path $OutputDir "IISpector_RunMetadata_$TimeStamp.json"
$Summary | ConvertTo-Json | Out-File -FilePath $MetaPath

Write-Host "[+] Run metadata saved: $MetaPath" -ForegroundColor Green

# =========================
# 6. Email Notification
if ($SendEmail -and $Expiring) {
    $style = "<style>table{border-collapse:collapse;width:100%} th,td{border:1px solid #ddd;padding:8px} th{background:#f2f2f2}</style>"
    $body  = "<h2>IISpector Alert</h2><h3>Expiring Certificates (Next 90 Days)</h3>$($Expiring | Select-Object ServerName,SiteName,CertDaysRemaining | ConvertTo-Html -Fragment)"
    
    $params = @{
        From       = $From
        To         = $To
        Subject    = "IIS Cert Alert: $($Expiring.Count) certificates expiring"
        Body       = "<html><head>$style</head><body>$body</body></html>"
        SmtpServer = $SmtpServer
        BodyAsHtml = $true
    }
    Send-MailMessage @params
    Write-Host "[+] Email alert sent." -ForegroundColor Green
}
