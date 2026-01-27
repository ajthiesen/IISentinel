<#
.SYNOPSIS
    IISentinel - IIS & SSL Inventory with Excel and Email Report.
    Compatible with Windows PowerShell 5.1 and PowerShell 7+.

.DESCRIPTION
    Scans servers for IIS Bindings and SSL Certificates.
    Features: Ping-checks, Key Size detection, Conditional Excel Formatting, and SNI detection.
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
    New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
}

if (-not (Get-Module -ListAvailable -Name ImportExcel)) {
    Throw "ImportExcel module required. Run: Install-Module ImportExcel -Scope CurrentUser"
}

$RunDate   = Get-Date
$TimeStamp = $RunDate.ToString("yyyyMMdd-HHmm")

# ------------------------------------------------------------
# 2) Target Discovery
# ------------------------------------------------------------
$Targets = [System.Collections.Generic.List[string]]::new()
if ($ServerNames) { $Targets.AddRange($ServerNames) }

if ($OU) {
    if (Get-Module -ListAvailable -Name ActiveDirectory) {
        try {
            $adComputers = Get-ADComputer -SearchBase $OU -SearchScope Subtree -Filter { Enabled -eq $true } | Select-Object -ExpandProperty Name
            if ($adComputers) { [string[]]$adStringArray = $adComputers; $Targets.AddRange($adStringArray) }
        } catch { Write-Warning "AD Discovery failed: $($_.Exception.Message)" }
    } else { Write-Warning "ActiveDirectory module not found." }
}

$Targets = $Targets | Sort-Object -Unique
if ($Targets.Count -eq 0) { Throw "No targets found." }

# ------------------------------------------------------------
# 3) Connectivity Check (Ping First)
# ------------------------------------------------------------
Write-Host "[*] Verifying connectivity for $($Targets.Count) servers..." -ForegroundColor Cyan
$OnlineServers = [System.Collections.Generic.List[string]]::new()
$OfflineServers = @()

foreach ($Server in $Targets) {
    if (Test-Connection -ComputerName $Server -Count 1 -Quiet) {
        $OnlineServers.Add($Server)
    } else {
        $OfflineServers += [pscustomobject]@{ ServerName = $Server; Error = "Server Unreachable (Ping Failed)" }
    }
}

# ------------------------------------------------------------
# 4) Remote Execution Block
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
    foreach ($c in $localCerts) { $certMap[Normalize-Thumbprint $c.Thumbprint] = $c }

    $results = @()
    $boundThumbprints = [System.Collections.Generic.HashSet[string]]::new()

    if (-not (Get-Module -ListAvailable WebAdministration)) {
        return [pscustomobject]@{ Type="Error"; Data=[pscustomobject]@{ ServerName=$env:COMPUTERNAME; Error="WebAdministration module missing" } }
    }

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
                        $keySize = $cert.PublicKey.Key.KeySize
                        
                        if ($cert.SignatureAlgorithm.FriendlyName -match "sha1") { $sslRisk += "Weak Algo (SHA1)" }
                        if ($keySize -lt 2048) { $sslRisk += "Weak Key ($keySize-bit)" }

                        $certDetails = [pscustomobject]@{
                            Subject = $cert.Subject; Issuer = $cert.Issuer; NotAfter = $cert.NotAfter
                            DaysLeft = [math]::Round(($cert.NotAfter - (Get-Date)).TotalDays); KeySize = $keySize
                        }
                    }
                }
                switch ($binding.sslFlags) { 0 {$sslFlags="No SNI"} 1 {$sslFlags="SNI"} 2 {$sslFlags="CCS"} 3 {$sslFlags="SNI+CCS"} }
            }

            $results += [pscustomobject]@{
                Type = "Inventory"
                Data = [pscustomobject]@{
                    ServerName = $env:COMPUTERNAME; SiteName = $site.Name; Protocol = $binding.protocol
                    Hostname = $binding.bindingInformation.Split(':')[-1]; Port = $binding.bindingInformation.Split(':')[-2]
                    SSLFlags = $sslFlags; CertName = $certDetails.Subject; DaysLeft = $certDetails.DaysLeft
                    KeySize = $certDetails.KeySize; Risk = ($sslRisk -join ", "); Error = if ($binding.protocol -eq "https" -and -not $certDetails) { "Cert Missing" }
                }
            }
        }
    }

    foreach ($key in $certMap.Keys) {
        if (-not $boundThumbprints.Contains($key)) {
            $c = $certMap[$key]
            $results += [pscustomobject]@{ Type="Orphan"; Data=[pscustomobject]@{ ServerName=$env:COMPUTERNAME; Subject=$c.Subject; DaysLeft=[math]::Round(($c.NotAfter - (Get-Date)).TotalDays); Thumbprint=$key } }
        }
    }
    return $results
}

# ------------------------------------------------------------
# 5) Run & Process
# ------------------------------------------------------------
Write-Host "[*] Scanning $($OnlineServers.Count) online servers..." -ForegroundColor Cyan
$RawResults = Invoke-Command -ComputerName $OnlineServers -Credential $Credential -ScriptBlock $RemoteScript -ArgumentList $WarningDays -ThrottleLimit 20

$Inventory = ($RawResults | Where-Object { $_.Type -eq "Inventory" }).Data
$Orphans   = ($RawResults | Where-Object { $_.Type -eq "Orphan" }).Data

# ------------------------------------------------------------
# 6) Excel Export with Conditional Formatting
# ------------------------------------------------------------
$ExcelPath = Join-Path $OutputPath "IISentinel_Report_$TimeStamp.xlsx"
$pkg = Export-Excel -Path $ExcelPath -InputObject $Inventory -WorksheetName "All_Bindings" -AutoSize -BoldTopRow -FreezeTopRow -PassThru

# Apply Red formatting for items expiring soon (< 30 days)
Add-ConditionalFormatting -Worksheet $pkg.All_Bindings -Address "H:H" -RuleType LessThan -ConditionValue 30 -ForegroundColor White -BackgroundColor Red
# Apply Yellow formatting for items expiring within the WarningDays window
Add-ConditionalFormatting -Worksheet $pkg.All_Bindings -Address "H:H" -RuleType LessThan -ConditionValue $WarningDays -ForegroundColor Black -BackgroundColor Yellow

if ($Orphans) { $Orphans | Export-Excel -ExcelPackage $pkg -WorksheetName "Orphan_Certs" }
if ($OfflineServers) { $OfflineServers | Export-Excel -ExcelPackage $pkg -WorksheetName "Offline_Servers" }

Close-ExcelPackage $pkg
Write-Host "[+] Report created: $ExcelPath" -ForegroundColor Green

# ------------------------------------------------------------
# 7) Email Summary
# ------------------------------------------------------------
if ($SendEmail -and $To) {
    $ExpCount = ($Inventory | Where-Object { $_.DaysLeft -lt $WarningDays -and $_.DaysLeft -ne $null }).Count
    $Body = "<h2>IIS SSL Summary</h2><p>Servers Scanned: $($OnlineServers.Count)</p><p>Expiring Certs (< $WarningDays days): <b style='color:red'>$ExpCount</b></p>"
    Send-MailMessage -To $To -From $From -Subject "$EmailSubject - $TimeStamp" -Body $Body -BodyAsHtml -SmtpServer $SmtpServer -Attachments $ExcelPath
    Write-Host "[+] Email sent to $To" -ForegroundColor Green
}