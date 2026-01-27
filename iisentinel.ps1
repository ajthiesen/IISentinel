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

# ------------------------------------------------------------
# 2) Target Discovery
# ------------------------------------------------------------
Write-Host "[*] Discovering targets..." -ForegroundColor Cyan
$Targets = [System.Collections.Generic.List[string]]::new()

if ($ServerNames) {
    $Targets.AddRange($ServerNames)
}

if ($OU) {
    if (Get-Module -ListAvailable -Name ActiveDirectory) {
        try {
            $adComputers = Get-ADComputer -SearchBase $OU -SearchScope Subtree -Filter { Enabled -eq $true } | 
                           Select-Object -ExpandProperty Name
            if ($adComputers) {
                [string[]]$adStringArray = $adComputers
                $Targets.AddRange($adStringArray)
            }
        }
        catch {
            Write-Warning "AD Discovery failed: $($_.Exception.Message)"
        }
    }
    else {
        Write-Warning "ActiveDirectory module not found. Skipping OU discovery."
    }
}

$Targets = $Targets | Sort-Object -Unique
if ($Targets.Count -eq 0) {
    Throw "No targets found. Please provide -ServerNames or a valid -OU."
}

# ------------------------------------------------------------
# 3) Connectivity Check (Ping First)
# ------------------------------------------------------------
Write-Host "[*] Verifying connectivity for $($Targets.Count) servers..." -ForegroundColor Cyan
$OnlineServers = [System.Collections.Generic.List[string]]::new()
$OfflineServers = @()

foreach ($Server in $Targets) {
    if (Test-Connection -ComputerName $Server -Count 1 -Quiet) {
        $OnlineServers.Add($Server)
    }
    else {
        $OfflineServers += [pscustomobject]@{ 
            ServerName = $Server 
            Error      = "Server Unreachable (Ping Failed)" 
        }
    }
}

if ($OnlineServers.Count -eq 0) {
    Write-Warning "No servers responded to ping. Exiting."
    return
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

    if (-not (Get-Module -ListAvailable WebAdministration)) {
        return [pscustomobject]@{ 
            Type = "Error" 
            Data = [pscustomobject]@{ ServerName=$env:COMPUTERNAME; Error="WebAdministration module missing" } 
        }
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
                        
                        # KeySize detection
                        $keySize = if ($cert.PublicKey.Key -is [System.Security.Cryptography.RSACryptoServiceProvider] -or $cert.PublicKey.Key -is [System.Security.Cryptography.RSACng]) { $cert.PublicKey.Key.KeySize } else { "N/A" }
                        
                        if ($cert.SignatureAlgorithm.FriendlyName -match "sha1") { $sslRisk += "Weak Algo (SHA1)" }
                        if ($keySize -ne "N/A" -and $keySize -lt 2048) { $sslRisk += "Weak Key ($keySize-bit)" }

                        $certDetails = [pscustomobject]@{
                            Subject    = $cert.Subject
                            Issuer     = $cert.Issuer
                            NotAfter   = $cert.NotAfter
                            DaysLeft   = [math]::Round(($cert.NotAfter - (Get-Date)).TotalDays)
                            KeySize    = $keySize
                        }
                    }
                }
                switch ($binding.sslFlags) { 
                    0 {$sslFlags="No SNI"} 
                    1 {$sslFlags="SNI"} 
                    2 {$sslFlags="CCS"} 
                    3 {$sslFlags="SNI+CCS"} 
                }
            }

            $bParts = $binding.bindingInformation -split ":"
            $results += [pscustomobject]@{
                Type = "Inventory"
                Data = [pscustomobject]@{
                    ServerName = $env:COMPUTERNAME
                    SiteName   = $site.Name
                    Protocol   = $binding.protocol
                    Hostname   = if ($bParts[2]) { $bParts[2] } else { "*" }
                    Port       = $bParts[1]
                    SSLFlags   = $sslFlags
                    CertName   = if ($certDetails) { $certDetails.Subject } else { $null }
                    DaysLeft   = if ($certDetails) { $certDetails.DaysLeft } else { $null }
                    KeySize    = if ($certDetails) { $certDetails.KeySize } else { $null }
                    Risk       = ($sslRisk -join ", ")
                    Error      = if ($binding.protocol -eq "https" -and -not $certDetails) { "Cert Missing in Store" } else { $null }
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
Write-Host "[*] Scanning $($OnlineServers.Count) online servers via WinRM..." -ForegroundColor Cyan

$RawResults = Invoke-Command `
    -ComputerName $OnlineServers `
    -Credential $Credential `
    -ScriptBlock $RemoteScript `
    -ArgumentList $WarningDays `
    -ThrottleLimit 32 `
    -ErrorAction SilentlyContinue `
    -ErrorVariable WinRMErrors

# Process successful results
$Inventory = ($RawResults | Where-Object { $_.Type -eq "Inventory" }).Data
$Orphans   = ($RawResults | Where-Object { $_.Type -eq "Orphan" }).Data

# Process WinRM Failures (like ATLT-SCERSQL)
if ($WinRMErrors) {
    foreach ($err in $WinRMErrors) {
        $OfflineServers += [pscustomobject]@{ 
            ServerName = $err.TargetObject
            Error      = "WinRM Failed: $($err.Exception.Message.Split(".")[0])" # Shortens the long WinRM error
        }
    }
}

Write-Host "[+] Scan complete. Success: $($Inventory.ServerName | Select -Unique).Count, Failed: $($OfflineServers.Count)" -ForegroundColor Green

# ------------------------------------------------------------
# 6) Excel Export with Conditional Formatting
# ------------------------------------------------------------
$ExcelPath = Join-Path $OutputPath "IISentinel_Report_$TimeStamp.xlsx"

# Use 'Open-ExcelPackage' to manage multiple sheets more reliably
$ExcelPackage = Open-ExcelPackage -Path $ExcelPath

# 1. Export Inventory
$Inventory | Export-Excel -ExcelPackage $ExcelPackage -WorksheetName "All_Bindings" -AutoSize -BoldTopRow -FreezeTopRow

# 2. Export Orphans (if any)
if ($Orphans) { 
    $Orphans | Export-Excel -ExcelPackage $ExcelPackage -WorksheetName "Orphan_Certs" -AutoSize -BoldTopRow 
}

# 3. Export Offline Servers (if any)
if ($OfflineServers.Count -gt 0) { 
    $OfflineServers | Export-Excel -ExcelPackage $ExcelPackage -WorksheetName "Offline_Servers" -AutoSize -BoldTopRow 
}

# 4. Apply Conditional Formatting to the Inventory Sheet
$InvSheet = $ExcelPackage.Workbook.Worksheets["All_Bindings"]
if ($InvSheet) {
    # H:H is usually the 'DaysLeft' column. 
    # Note: If you changed the property order, double check the column letter!
    Add-ConditionalFormatting -Worksheet $InvSheet -Address "H:H" -RuleType LessThan -ConditionValue 30 -ForegroundColor White -BackgroundColor Red
    Add-ConditionalFormatting -Worksheet $InvSheet -Address "H:H" -RuleType LessThan -ConditionValue $WarningDays -ForegroundColor Black -BackgroundColor Yellow
}

# 5. Save and Close
Close-ExcelPackage -ExcelPackage $ExcelPackage
Write-Host "[+] Report created: $ExcelPath" -ForegroundColor Green

# ------------------------------------------------------------
# 7) Email Summary
# ------------------------------------------------------------
if ($SendEmail -and $To) {
    $ExpiringSoon = ($Inventory | Where-Object { $_.DaysLeft -lt $WarningDays -and $_.DaysLeft -ne $null }).Count
    
    $EmailBody = @"
    <h2>IIS SSL Inventory Summary</h2>
    <p><b>Servers Scanned:</b> $($OnlineServers.Count)</p>
    <p><b>Expiring Certificates (< $WarningDays days):</b> <span style='color:red;'>$ExpiringSoon</span></p>
    <p><b>Orphaned Certificates Found:</b> $($Orphans.Count)</p>
    <br>
    <p>Full details are available in the attached Excel report.</p>
"@

    $MailProps = @{
        To         = $To
        From       = $From
        Subject    = "$EmailSubject - $TimeStamp"
        Body       = $EmailBody
        BodyAsHtml = $true
        SmtpServer = $SmtpServer
        Attachments = $ExcelPath
    }

    try {
        Send-MailMessage @MailProps
        Write-Host "[+] Email summary sent to $To" -ForegroundColor Green
    }
    catch {
        Write-Warning "Failed to send email: $($_.Exception.Message)"
    }
}

Write-Host "IISentinel Scan Complete." -ForegroundColor Cyan