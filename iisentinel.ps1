<#
.SYNOPSIS
    IISentinel - IIS & SSL Inventory with Excel and Email Report
    
.DESCRIPTION
    Scans servers for IIS Bindings and SSL Certificates.
    Features: Connectivity checks, Key Size detection, Conditional Formatting.
#>

[CmdletBinding()]
param(
    [Parameter(ValueFromPipeline = $true)]
    [string[]]$ServerNames,

    [string]$OU,

    [pscredential]$Credential,

    [string]$OutputPath = "C:\IISentinel",

    [int]$WarningDays = 60,

    [switch]$SendEmail,
    [string]$SmtpServer = "smtp.yourdomain.com",
    [string]$From = "IISentinel@yourdomain.com",
    [string[]]$To,
    [string]$EmailSubject = "IIS SSL Inventory Report"
)

$ErrorActionPreference = "Stop"

# ------------------------------------------------------------
# 1) Setup & Validation
# ------------------------------------------------------------
if (-not (Test-Path $OutputPath)) {
    try {
        New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
    }
    catch {
        Throw "Could not create output directory: $OutputPath. Run as Admin or change path."
    }
}

if (-not (Get-Module -ListAvailable -Name ImportExcel)) {
    Throw "ImportExcel module required. Run: Install-Module ImportExcel -Scope CurrentUser"
}

$RunDate   = Get-Date
$TimeStamp = $RunDate.ToString("yyyyMMdd-HHmm")
$ExcelPath = Join-Path $OutputPath "IISentinel_Report_$TimeStamp.xlsx"

# ------------------------------------------------------------
# 2) Target Discovery
# ------------------------------------------------------------
Write-Host "[*] Discovering targets..." -ForegroundColor Cyan
$Targets = [System.Collections.Generic.List[string]]::new()

if ($ServerNames) { $Targets.AddRange($ServerNames) }

if ($OU) {
    if (Get-Module -ListAvailable -Name ActiveDirectory) {
        try {
            $adComputers = Get-ADComputer -SearchBase $OU -SearchScope Subtree -Filter { Enabled -eq $true } | 
                           Select-Object -ExpandProperty Name
            if ($adComputers) { [string[]]$adArray = $adComputers; $Targets.AddRange($adArray) }
        }
        catch { Write-Warning "AD Discovery failed: $($_.Exception.Message)" }
    }
    else { Write-Warning "ActiveDirectory module not found." }
}

$Targets = $Targets | Sort-Object -Unique
if ($Targets.Count -eq 0) { Throw "No targets found." }

# ------------------------------------------------------------
# 3) Connectivity Check (Ping First)
# ------------------------------------------------------------
Write-Host "[*] Verifying connectivity for $($Targets.Count) servers..." -ForegroundColor Cyan
$OnlineServers = [System.Collections.Generic.List[string]]::new()
$OfflineServers = [System.Collections.Generic.List[pscustomobject]]::new()

foreach ($Server in $Targets) {
    if (Test-Connection -ComputerName $Server -Count 1 -Quiet) {
        $OnlineServers.Add($Server)
    }
    else {
        $OfflineServers.Add([pscustomobject]@{ ServerName = $Server; Error = "Ping Failed" })
    }
}

# ------------------------------------------------------------
# 4) Remote Script Block
# ------------------------------------------------------------
$RemoteScript = {
    param($WarningDays)
    $ErrorActionPreference = "SilentlyContinue"
    Import-Module WebAdministration

    function Normalize-Thumbprint ($t) {
        if ([string]::IsNullOrWhiteSpace($t)) { return $null }
        return $t.Replace(" ", "").Replace(":", "").ToUpper()
    }

    $localCerts = @(Get-ChildItem Cert:\LocalMachine\My, Cert:\LocalMachine\WebHosting -ErrorAction SilentlyContinue)
    $certMap = @{}
    foreach ($c in $localCerts) { 
        $tp = Normalize-Thumbprint $c.Thumbprint
        $certMap[$tp] = $c 
    }

    $results = @()
    $boundThumbprints = [System.Collections.Generic.HashSet[string]]::new()

    $sites = Get-ChildItem IIS:\Sites
    foreach ($site in $sites) {
        foreach ($binding in $site.Bindings.Collection) {
            $certDetails = $null; $sslRisk = @(); $sslFlags = "N/A"
            
            if ($binding.protocol -eq "https") {
                $bindThumb = Normalize-Thumbprint (($binding.certificateHash | ForEach-Object { $_.ToString("X2") }) -join "")
                if ($bindThumb) {
                    $null = $boundThumbprints.Add($bindThumb)
                    if ($certMap.ContainsKey($bindThumb)) {
                        $cert = $certMap[$bindThumb]
                        $keySize = if ($cert.PublicKey.Key.KeySize) { $cert.PublicKey.Key.KeySize } else { "N/A" }
                        
                        if ($cert.SignatureAlgorithm.FriendlyName -match "sha1") { $sslRisk += "SHA1" }
                        if ($keySize -ne "N/A" -and $keySize -lt 2048) { $sslRisk += "WeakKey($keySize)" }

                        $certDetails = [pscustomobject]@{
                            Subject  = $cert.Subject
                            DaysLeft = [math]::Round(($cert.NotAfter - (Get-Date)).TotalDays)
                            KeySize  = $keySize
                        }
                    }
                }
            }

            $bParts = $binding.bindingInformation -split ":"
            $results += [pscustomobject]@{
                Type = "Inventory"
                Data = [pscustomobject]@{
                    ServerName = $env:COMPUTERNAME
                    SiteName   = $site.Name
                    Port       = $bParts[1]
                    Hostname   = if ($bParts[2]) { $bParts[2] } else { "*" }
                    CertName   = if ($certDetails) { $certDetails.Subject } else { "N/A" }
                    DaysLeft   = if ($certDetails) { $certDetails.DaysLeft } else { $null }
                    KeySize    = if ($certDetails) { $certDetails.KeySize } else { $null }
                    Risk       = ($sslRisk -join ", ")
                    Error      = if ($binding.protocol -eq "https" -and -not $certDetails) { "Cert Missing" } else { "" }
                }
            }
        }
    }

    foreach ($key in $certMap.Keys) {
        if (-not $boundThumbprints.Contains($key)) {
            $c = $certMap[$key]
            $results += [pscustomobject]@{ 
                Type = "Orphan"
                Data = [pscustomobject]@{ 
                    ServerName = $env:COMPUTERNAME
                    Subject    = $c.Subject
                    DaysLeft   = [math]::Round(($c.NotAfter - (Get-Date)).TotalDays)
                    Thumbprint = $key 
                } 
            }
        }
    }
    return $results
}

# ------------------------------------------------------------
# 5) Run Inventory
# ------------------------------------------------------------
Write-Host "[*] Scanning $($OnlineServers.Count) servers via WinRM..." -ForegroundColor Cyan
$RawResults = Invoke-Command `
    -ComputerName $OnlineServers `
    -Credential $Credential `
    -ScriptBlock $RemoteScript `
    -ArgumentList $WarningDays `
    -ThrottleLimit 40 `
    -ErrorAction SilentlyContinue `
    -ErrorVariable WinRMErrors

$Inventory = ($RawResults | Where-Object { $_.Type -eq "Inventory" }).Data
$Orphans   = ($RawResults | Where-Object { $_.Type -eq "Orphan" }).Data

if ($WinRMErrors) {
    foreach ($err in $WinRMErrors) {
        $OfflineServers.Add([pscustomobject]@{ 
            ServerName = $err.TargetObject
            Error      = "WinRM Blocked/Timed Out"
        })
    }
}

$SuccessCount = ($Inventory.ServerName | Select-Object -Unique | Measure-Object).Count
Write-Host "[+] Scan complete. Success: $SuccessCount, Failed: $($OfflineServers.Count)" -ForegroundColor Green

# ------------------------------------------------------------
# 6) Excel Export
# ------------------------------------------------------------
try {
    $ExcelPackage = Open-ExcelPackage -Path $ExcelPath -Create
    
    if ($Inventory) {
        $Inventory | Export-Excel -ExcelPackage $ExcelPackage -WorksheetName "Inventory" -AutoSize -BoldTopRow
        $sheet = $ExcelPackage.Workbook.Worksheets["Inventory"]
        # Column F is 'DaysLeft' in this object structure
        Add-ConditionalFormatting -Worksheet $sheet -Address "F:F" -RuleType LessThan -ConditionValue 30 -ForegroundColor White -BackgroundColor Red
        Add-ConditionalFormatting -Worksheet $sheet -Address "F:F" -RuleType LessThan -ConditionValue $WarningDays -ForegroundColor Black -BackgroundColor Yellow
    }

    if ($Orphans) {
        $Orphans | Export-Excel -ExcelPackage $ExcelPackage -WorksheetName "Orphan_Certs" -AutoSize -BoldTopRow
    }

    if ($OfflineServers.Count -gt 0) {
        $OfflineServers | Export-Excel -ExcelPackage $ExcelPackage -WorksheetName "Errors_Offline" -AutoSize -BoldTopRow
    }

    Close-ExcelPackage -ExcelPackage $ExcelPackage
    Write-Host "[+] Report saved to: $ExcelPath" -ForegroundColor Green
}
catch {
    Write-Error "Excel Export Failed: $($_.Exception.Message)"
}

# ------------------------------------------------------------
# 7) Email Summary
# ------------------------------------------------------------
if ($SendEmail -and $To) {
    $Soon = ($Inventory | Where-Object { $_.DaysLeft -lt $WarningDays -and $_.DaysLeft -ne $null }).Count
    $EmailBody = @"
    <h2>IIS SSL Inventory Summary</h2>
    <p><b>Date:</b> $RunDate</p>
    <p><b>Servers Scanned:</b> $SuccessCount</p>
    <p><b>Expiring Certs (< $WarningDays days):</b> <span style='color:red;'>$Soon</span></p>
    <p><b>Failed Connections:</b> $($OfflineServers.Count)</p>
    <br>
    <p>Full report attached: $ExcelPath</p>
"@
    Send-MailMessage -To $To -From $From -Subject "$EmailSubject - $TimeStamp" -Body $EmailBody -BodyAsHtml -SmtpServer $SmtpServer -Attachments $ExcelPath
    Write-Host "[+] Email summary sent." -ForegroundColor Green
}