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
# 1) Discover Targets  (❗ FIXED HERE ❗)
# ----------------------------
$TargetList = New-Object System.Collections.Generic.List[string]

if ($ServerNames) {
    foreach ($s in $ServerNames) {
        if ($s) { $TargetList.Add($s) | Out-Null }
    }
}

if ($OU) {
    Write-Host "[*] Discovering servers in OU: $OU" -ForegroundColor Cyan

    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        throw "ActiveDirectory module required."
    }

    Import-Module ActiveDirectory

    try {
        $Discovered = Get-ADComputer `
            -SearchBase $OU `
            -SearchScope Subtree `
            -Filter { Enabled -eq $true } |
            Select-Object -ExpandProperty Name

        if (-not $Discovered) { $Discovered = @() }

        foreach ($name in $Discovered) {
            if ($name -and $name -is [string]) {
                $TargetList.Add($name) | Out-Null
            }
        }
    }
    catch {
        throw "OU discovery failed: $($_.Exception.Message)"
    }
}

$Targets = $TargetList | Sort-Object -Unique
if ($Targets.Count -eq 0) { throw "No servers found." }

Write-Host "[*] Targets discovered: $($Targets.Count)" -ForegroundColor Green

# ----------------------------
# 2) Remote Script
# ----------------------------
$RemoteScript = {
    param($RunID)

    function Get-CertDetails {
        param($thumb)

        try {
            $cert = Get-ChildItem Cert:\LocalMachine\My,Cert:\LocalMachine\WebHosting -Recurse |
                    Where-Object { $_.Thumbprint -eq $thumb } |
                    Select-Object -First 1
            if (-not $cert) { return $null }

            $san = $cert.Extensions | Where-Object { $_.Oid.FriendlyName -eq "Subject Alternative Name" }
            $sanText = if ($san) { ($san.Format($false) -split "`n").Trim() -join "; " }

            [pscustomobject]@{
                CertName           = $cert.Subject
                CertExpirationDate = $cert.NotAfter
                CertDaysRemaining  = [math]::Round(($cert.NotAfter - (Get-Date)).TotalDays)
                Issuer             = $cert.Issuer
                SAN                = $sanText
                CertRisk           = if ($cert.SignatureAlgorithm.FriendlyName -match "sha1") { "Weak (SHA1)" } else { "OK" }
            }
        }
        catch { $null }
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

    try { Import-Module WebAdministration -ErrorAction Stop }
    catch {
        return [pscustomobject]@{
            RunID        = $RunID
            ServerName   = $env:COMPUTERNAME
            IISInstalled = $true
            Error        = "WebAdministration load failure"
        }
    }

    $results = @()
    foreach ($site in Get-ChildItem IIS:\Sites) {
        foreach ($binding in $site.Bindings.Collection) {

            $parts = $binding.bindingInformation -split ":"
            $host  = if ($parts[2]) { $parts[2] } else { "N/A" }
            $port  = $parts[1]

            $cert = $null
            if ($binding.protocol -eq "https") {
                try {
                    $thumb = ($binding.certificateHash | ForEach-Object { $_.ToString("X2") }) -join ""
                    $cert = Get-CertDetails $thumb
                } catch {}
            }

            $results += [pscustomobject]@{
                RunID               = $RunID
                ServerName          = $env:COMPUTERNAME
                IISInstalled        = $true
                SiteName            = $site.Name
                SiteState           = $site.State
                Binding             = $binding.bindingInformation
                Protocol            = $binding.protocol
                Hostname            = $host
                Port                = $port
                CertName            = $cert?.CertName
                CertExpirationDate  = $cert?.CertExpirationDate
                CertDaysRemaining   = $cert?.CertDaysRemaining
                Issuer              = $cert?.Issuer
                SAN                 = $cert?.SAN
                CertRisk            = $cert?.CertRisk
                Error               = if ($binding.protocol -eq "https" -and -not $cert) { "Cert lookup failed" } else { "" }
            }
        }
    }
    $results
}

# ----------------------------
# 3) Run
# ----------------------------
Write-Host "[*] Running inventory..." -ForegroundColor Cyan

$Inventory = Invoke-Command `
    -ComputerName $Targets `
    -Credential $Credential `
    -ScriptBlock $RemoteScript `
    -ArgumentList $RunID `
    -ThrottleLimit 50 `
    -ErrorAction SilentlyContinue

$Errors   = $Inventory | Where-Object { $_.Error }
$Expiring = $Inventory | Where-Object { $_.CertDaysRemaining -and $_.CertDaysRemaining -le 90 }

# ----------------------------
# 4) Summary
# ----------------------------
$Summary = [pscustomobject]@{
    RunID         = $RunID
    RunDate       = $RunDate
    ServersScanned= $Targets.Count
    Errors        = $Errors.Count
    ExpiringCerts= $Expiring.Count
}

# ----------------------------
# 5) Excel
# ----------------------------
$ExcelPath = Join-Path $OutputDir "IISentinel_Report_$TimeStamp.xlsx"

$Inventory | Export-Excel $ExcelPath -WorksheetName Inventory -AutoSize -BoldTopRow
$Errors    | Export-Excel $ExcelPath -WorksheetName Errors    -AutoSize
$Summary   | Export-Excel $ExcelPath -WorksheetName Summary   -AutoSize

Write-Host "[+] Excel created: $ExcelPath" -ForegroundColor Green
