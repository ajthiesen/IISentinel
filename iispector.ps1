<#
.SYNOPSIS
    IISpector v3.3 - IIS & SSL Inventory with SAN, Issuer, Binding Parsing, TLS Weakness, and Summary

.DESCRIPTION
    Parallel execution inventory of IIS sites, bindings, SSL expiry, and risk detection.
    Produces single Excel workbook with Inventory, Errors, Expiring, and Summary sheets.
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

# Output directory
$OutputDir = "C:\IISpector"
if (-not (Test-Path $OutputDir)) { New-Item -Path $OutputDir -ItemType Directory -Force | Out-Null }

# ImportExcel required
if (-not (Get-Module -ListAvailable -Name ImportExcel)) {
    throw "ImportExcel module is required. Install it: Install-Module -Name ImportExcel"
}
Import-Module ImportExcel -ErrorAction Stop

$RunID = [guid]::NewGuid().ToString()

# =========================
# 1. Target Discovery
# =========================
$TargetList = [System.Collections.Generic.List[string]]::new()

if ($ServerNames) {
    $TargetList.AddRange([string[]]$ServerNames)
}

if ($OU) {
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        Write-Warning "ActiveDirectory module missing. RSAT required."
    }
    else {
        Import-Module ActiveDirectory
        try {
            $Discovered = Get-ADComputer -SearchBase $OU -SearchScope Subtree -Filter { Enabled -eq $true } -ErrorAction Stop | Select-Object -ExpandProperty Name
            if ($Discovered) { $TargetList.AddRange([string[]]$Discovered) }
        }
        catch { Write-Warning "OU Discovery Error: $($_.Exception.Message)" }
    }
}

$FinalTargets = $TargetList | Sort-Object -Unique
if ($FinalTargets.Count -eq 0) { throw "No servers found to target." }

# =========================
# 2. Remote Execution (Parallel)
# =========================
$RemoteScript = {
    param($RunID)

    function Get-TlsWeakness {
        # Detect if TLS1.0 or TLS1.1 is enabled in SCHANNEL
        $weak = $false

        $protocols = @("TLS 1.0","TLS 1.1")
        foreach ($p in $protocols) {
            $key = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$p\Server"
            if (Test-Path $key) {
                $enabled = (Get-ItemProperty -Path $key -Name "Enabled" -ErrorAction SilentlyContinue).Enabled
                $disabled = (Get-ItemProperty -Path $key -Name "DisabledByDefault" -ErrorAction SilentlyContinue).DisabledByDefault

                if ($enabled -eq 1 -or $disabled -eq 0) {
                    $weak = $true
                    break
                }
            }
        }
        return $weak
    }

    function Get-CertSAN {
        param($cert)
        $sanOid = "2.5.29.17"
        $ext = $cert.Extensions | Where-Object { $_.Oid.Value -eq $sanOid }
        if (-not $ext) { return $null }

        $raw = $ext.Format($false)
        # Format returns "DNS Name=foo, DNS Name=bar" typically
        return ($raw -replace "DNS Name=", "") -replace "\s*,\s*", ","
    }

    function Parse-Binding {
        param($bindingInfo)
        # Format: ip:port:hostname
        $parts = $bindingInfo.Split(":")
        return @{
            BindingIP   = $parts[0]
            BindingPort = $parts[1]
            BindingHost = $parts[2]
        }
    }

    $results = @()

    # Detect IIS installed
    $IISInstalled = (Get-WindowsFeature -Name Web-Server -ErrorAction SilentlyContinue).Installed

    if (-not $IISInstalled) {
        return [PSCustomObject]@{
            RunID = $RunID
            ServerName   = $env:COMPUTERNAME
            IISInstalled = $false
            SiteName     = $null
            SiteState    = $null
            Binding      = $null
            Protocol     = $null
            BindingIP    = $null
            BindingPort  = $null
            BindingHost  = $null
            CertName     = $null
            CertIssuer   = $null
            CertSAN      = $null
            CertExpirationDate = $null
            CertDaysRemaining  = $null
            CertRisk     = $null
            TLSWeakness = $null
            Error        = "IIS not installed"
        }
    }

    $tlsWeak = Get-TlsWeakness

    try {
        Import-Module WebAdministration -ErrorAction Stop
        $sites = Get-ChildItem IIS:\Sites
    }
    catch {
        return [PSCustomObject]@{
            RunID = $RunID
            ServerName   = $env:COMPUTERNAME
            IISInstalled = $true
            SiteName     = $null
            SiteState    = $null
            Binding      = $null
            Protocol     = $null
            BindingIP    = $null
            BindingPort  = $null
            BindingHost  = $null
            CertName     = $null
            CertIssuer   = $null
            CertSAN      = $null
            CertExpirationDate = $null
            CertDaysRemaining  = $null
            CertRisk     = $null
            TLSWeakness = $tlsWeak
            Error        = "WebAdministration failure: $($_.Exception.Message)"
        }
    }

    foreach ($site in $sites) {
        foreach ($binding in $site.Bindings.Collection) {

            $parsed = Parse-Binding -bindingInfo $binding.bindingInformation

            $row = [PSCustomObject]@{
                RunID = $RunID
                ServerName   = $env:COMPUTERNAME
                IISInstalled = $true
                SiteName     = $site.Name
                SiteState    = $site.State
                Binding      = $binding.bindingInformation
                Protocol     = $binding.protocol
                BindingIP    = $parsed.BindingIP
                BindingPort  = $parsed.BindingPort
                BindingHost  = $parsed.BindingHost
                CertName     = $null
                CertIssuer   = $null
                CertSAN      = $null
                CertExpirationDate = $null
                CertDaysRemaining  = $null
                CertRisk     = $null
                TLSWeakness = $tlsWeak
                Error        = $null
            }

            if ($binding.protocol -eq "https" -and $binding.certificateHash) {
                try {
                    $thumb = $null
                    if ($binding.certificateHash -is [byte[]]) {
                        $thumb = ($binding.certificateHash | ForEach-Object { "{0:X2}" -f $_ }) -join ""
                    }
                    elseif ($binding.certificateHash -is [string]) {
                        $thumb = $binding.certificateHash -replace '\s',''
                    }
                    else {
                        $thumb = $binding.certificateHash.ToString()
                    }

                    $cert = Get-ChildItem Cert:\LocalMachine\My -Recurse -ErrorAction SilentlyContinue |
                            Where-Object { $_.Thumbprint -eq $thumb } | Select-Object -First 1

                    if (-not $cert) {
                        $cert = Get-ChildItem Cert:\LocalMachine\WebHosting -Recurse -ErrorAction SilentlyContinue |
                                Where-Object { $_.Thumbprint -eq $thumb } | Select-Object -First 1
                    }

                    if ($cert) {
                        $row.CertName = $cert.Subject
                        $row.CertIssuer = $cert.Issuer
                        $row.CertSAN = Get-CertSAN -cert $cert
                        $row.CertExpirationDate = $cert.NotAfter
                        $row.CertDaysRemaining = ($cert.NotAfter - (Get-Date)).Days

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

$RawResults = Invoke-Command -ComputerName $FinalTargets -ScriptBlock $RemoteScript -ArgumentList $RunID -Credential $Credential -ErrorAction SilentlyContinue -ThrottleLimit 50

# =========================
# 3. Data Processing
$Inventory = $RawResults | Select-Object * -ExcludeProperty RunspaceId, PSComputerName, PSShowComputerName
$Errors    = $Inventory | Where-Object { $_.Error -ne $null }
$Expiring  = $Inventory | Where-Object { $_.CertDaysRemaining -ne $null -and [int]$_.CertDaysRemaining -le 90 }

$Summary = [PSCustomObject]@{
    RunID                = $RunID
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

$Inventory | Export-Excel @pkg -WorksheetName "Inventory"
$Errors    | Export-Excel @pkg -WorksheetName "Errors"
$Expiring  | Export-Excel @pkg -WorksheetName "ExpiringCerts"
$Summary   | Export-Excel @pkg -WorksheetName "Summary"

Write-Host "[+] Report generated: $ExcelPath" -ForegroundColor Green
