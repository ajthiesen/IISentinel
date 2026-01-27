<#
.SYNOPSIS
    IISentinel - IIS & SSL Inventory with Excel and Email Report.
    Compatible with Windows PowerShell 5.1 and PowerShell 7+.

.DESCRIPTION
    Scans servers for IIS Bindings and SSL Certificates.
    Identifies expiring certificates, weak algorithms, and orphaned certificates.
    Generates an Excel report and optionally emails a summary.

.EXAMPLE
    .\IISentinel.ps1 -ServerNames "WEB01", "WEB02" -SendEmail -To "admin@domain.com"
#>

[CmdletBinding()]
param(
    [Parameter(ValueFromPipeline = $true)]
    [string[]]$ServerNames,

    [string]$OU,

    [pscredential]$Credential,

    [string]$OutputPath = "C:\IISentinel",

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
        Write-Verbose "Querying AD OU: $OU"
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

Write-Host "[+] Targets identified: $($Targets.Count)" -ForegroundColor Green

# ------------------------------------------------------------
# 3) Remote Execution Block
# ------------------------------------------------------------
$RemoteScript = {
    $ErrorActionPreference = "SilentlyContinue"
    Import-Module WebAdministration

    # --- Helper Functions ---
    function Normalize-Thumbprint ($t) {
        if ([string]::IsNullOrWhiteSpace($t)) { return $null }
        return $t.Replace(" ", "").Replace(":", "").ToUpper()
    }

    # --- IIS Check ---
    $iisFeature = Get-WindowsFeature Web-Server
    if (-not $iisFeature.Installed) {
        return [pscustomobject]@{
            Type = "Error"
            Data = [pscustomobject]@{
                ServerName = $env:COMPUTERNAME
                Error      = "IIS not installed"
            }
        }
    }

    # --- Collect All Local Certs (My + WebHosting) ---
    # We load these once into a Hashset for fast lookup later
    $localCerts = @(
        Get-ChildItem Cert:\LocalMachine\My -Recurse
        Get-ChildItem Cert:\LocalMachine\WebHosting -Recurse
    )
    
    # Dictionary for fast lookup: Key=Thumbprint, Value=CertObject
    $certMap = @{}
    foreach ($c in $localCerts) {
        $tp = Normalize-Thumbprint $c.Thumbprint
        if (-not $certMap.ContainsKey($tp)) {
            $certMap[$tp] = $c
        }
    }

    $results = @()
    $boundThumbprints = [System.Collections.Generic.HashSet[string]]::new()

    # --- Scan Sites & Bindings ---
    $sites = Get-ChildItem IIS:\Sites
    foreach ($site in $sites) {
        foreach ($binding in $site.Bindings.Collection) {
            
            $bindingInfo = $binding.bindingInformation
            $parts = $bindingInfo -split ":"
            $port = $parts[1]
            $hostname = if ($parts[2]) { $parts[2] } else { "(Empty)" }
            
            # Default values
            $certDetails = $null
            $sslRisk     = $null
            $sslFlags    = "N/A"

            # HTTPS Logic
            if ($binding.protocol -eq "https") {
                # Get clean thumbprint from binding
                $rawHash = $binding.certificateHash
                if ($rawHash) {
                    $bindThumb = ($rawHash | ForEach-Object { $_.ToString("X2") }) -join ""
                    $bindThumb = Normalize-Thumbprint $bindThumb
                    
                    # Track for Orphan check
                    $null = $boundThumbprints.Add($bindThumb)

                    # Lookup in our pre-loaded map
                    if ($certMap.ContainsKey($bindThumb)) {
                        $cert = $certMap[$bindThumb]
                        
                        # Parse SAN
                        $sanExt = $cert.Extensions | Where-Object { $_.Oid.FriendlyName -eq "Subject Alternative Name" }
                        $sanValue = if ($sanExt) { ($sanExt.Format($false) -split "`n" | ForEach-Object { $_.Trim() }) -join "; " } else { $null }

                        # Risk Logic
                        $algo = $cert.SignatureAlgorithm.FriendlyName
                        $sslRisk = if ($algo -match "sha1" -or $algo -match "md5") { "Weak ($algo)" } else { "OK" }

                        $certDetails = [pscustomobject]@{
                            Subject    = $cert.Subject
                            Issuer     = $cert.Issuer
                            NotAfter   = $cert.NotAfter
                            DaysLeft   = [math]::Round(($cert.NotAfter - (Get-Date)).TotalDays)
                            SAN        = $sanValue
                            Thumbprint = $bindThumb
                        }
                    }
                }

                # Decode SSL Flags (Sum of values)
                # 0=Default, 1=SNI, 2=CCS, 3=SNI+CCS
                $f = $binding.sslFlags
                switch ($f) {
                    0 { $sslFlags = "No SNI" }
                    1 { $sslFlags = "SNI Enabled" }
                    2 { $sslFlags = "Central Cert Store" }
                    3 { $sslFlags = "SNI + CCS" }
                    default { $sslFlags = "Flags: $f" }
                }
            }

            # Add Binding Result
            $results += [pscustomobject]@{
                Type = "Inventory"
                Data = [pscustomobject]@{
                    ServerName   = $env:COMPUTERNAME
                    SiteName     = $site.Name
                    State        = $site.State
                    Protocol     = $binding.protocol
                    Hostname     = $hostname
                    Port         = $port
                    SSLFlags     = $sslFlags
                    CertName     = if ($certDetails) { $certDetails.Subject } else { $null }
                    DaysLeft     = if ($certDetails) { $certDetails.DaysLeft } else { $null }
                    Expiration   = if ($certDetails) { $certDetails.NotAfter } else { $null }
                    Issuer       = if ($certDetails) { $certDetails.Issuer } else { $null }
                    Risk         = $sslRisk
                    Error        = if ($binding.protocol -eq "https" -and -not $certDetails) { "Cert Missing/Unreadable" } else { $null }
                }
            }
        }
    }

    # --- Scan for Orphans ---
    # Orphans = Certs in 'My' store that are NOT in $boundThumbprints
    foreach ($key in $certMap.Keys) {
        if (-not $boundThumbprints.Contains($key)) {
            $c = $certMap[$key]
            
            # Filter: Ignore root CAs or expired junk usually found? 
            # For now, just report everything not bound.
            $results += [pscustomobject]@{
                Type = "Orphan"
                Data = [pscustomobject]@{
                    ServerName = $env:COMPUTERNAME
                    Subject    = $c.Subject
                    Issuer     = $c.Issuer
                    Expiration = $c.NotAfter
                    DaysLeft   = [math]::Round(($c.NotAfter - (Get-Date)).TotalDays)
                    Thumbprint = $key
                }
            }
        }
    }

    return $results
}

# ------------------------------------------------------------
# 4) Processing
# ------------------------------------------------------------
Write-Host "[*] Scanning servers (Timeout: 2 mins per batch)..." -ForegroundColor Cyan

$RawResults = Invoke-Command `
    -ComputerName $Targets `
    -Credential $Credential `
    -ScriptBlock $RemoteScript `
    -ThrottleLimit 20 `
    -ErrorAction SilentlyContinue `
    -ErrorVariable ConnErrors

# Separate Data Streams
$Inventory   = ($RawResults | Where-Object { $_.Type -eq "Inventory" }).Data
$Orphans     = ($RawResults | Where-Object { $_.Type -eq "Orphan" }).Data
$ScriptErrors = ($RawResults | Where-Object { $_.Type -eq "Error" }).Data

# Process Connection Errors (RPC/WinRM failures)
if ($ConnErrors) {
    $ConnErrorList = $ConnErrors | Select-Object @{N='ServerName';E={$_.TargetObject}}, @{N='Error';E={$_.Exception.Message}}
}

# Logic Checks
$ExpiringCerts = $Inventory | Where-Object { $_.DaysLeft -ne $null -and $_.DaysLeft -le 60 }
$BindingErrors = $Inventory | Where-Object { $_.Error -ne $null }

# ------------------------------------------------------------
# 5) Summary Object
# ------------------------------------------------------------
$Summary = [pscustomobject]@{
    ScanDate        = $RunDate
    TargetsTargeted = $Targets.Count
    ServersReached  = ($Inventory.ServerName | Select-Object -Unique).Count
    TotalSites      = $Inventory.Count
    ExpiringCount   = $ExpiringCerts.Count
    OrphanCount     = $Orphans.Count
    FailedServers   = $ConnErrorList.Count
}

Write-Host "------------------------------------------------"
Write-Host " Scan Complete " 
Write-Host " Expiring Certs (60d): $($Summary.ExpiringCount)" -ForegroundColor Yellow
Write-Host " Orphan Certs:         $($Summary.OrphanCount)"
Write-Host " Failed Connections:   $($Summary.FailedServers)" -ForegroundColor Red
Write-Host "------------------------------------------------"

# ------------------------------------------------------------
# 6) Export Report
# ------------------------------------------------------------
$ExcelPath = Join-Path $OutputPath "IISentinel_Report_$TimeStamp.xlsx"
$ExcelPkg  = @{ Path = $ExcelPath; AutoSize = $true; BoldTopRow = $true; FreezeTopRow = $true }

# Create Sheets (Order matters)
if ($Summary)       { $Summary       | Export-Excel @ExcelPkg -WorksheetName "Summary" }
if ($ExpiringCerts) { $ExpiringCerts | Export-Excel @ExcelPkg -WorksheetName "Expiring_ActionReq" -TabColor Red }
if ($Inventory)     { $Inventory     | Export-Excel @ExcelPkg -WorksheetName "All_Bindings" }
if ($Orphans)       { $Orphans       | Export-Excel @ExcelPkg -WorksheetName "Orphan_Certs" }
if ($ScriptErrors)  { $ScriptErrors  | Export-Excel @ExcelPkg -WorksheetName "IIS_Missing" }
if ($ConnErrorList) { $ConnErrorList | Export-Excel @ExcelPkg -WorksheetName "Connection_Errors" }

Write-Host "[+] Report saved: $ExcelPath" -ForegroundColor Green

# ------------------------------------------------------------
# 7) Email Notification
# ------------------------------------------------------------
if ($SendEmail) {
    if (-not $To) { Write-Warning "SendEmail switch used but -To address is missing."; break }

    Write-Host "[*] Sending email report..." -ForegroundColor Cyan

    $Body = @"
    <h2>IIS & SSL Inventory Report</h2>
    <p><b>Date:</b> $($RunDate)</p>
    <p><b>Output:</b> $ExcelPath</p>
    
    <table border="1" style="border-collapse:collapse; cellpadding:5;">
        <tr><td style="background-color:#eee"><b>Servers Scanned</b></td><td>$($Summary.ServersReached) / $($Summary.TargetsTargeted)</td></tr>
        <tr><td style="background-color:#eee"><b>Expiring Certs (<60d)</b></td><td><span style="color:red"><b>$($Summary.ExpiringCount)</b></span></td></tr>
        <tr><td style="background-color:#eee"><b>Orphan Certs</b></td><td>$($Summary.OrphanCount)</td></tr>
        <tr><td style="background-color:#eee"><b>Connection Errors</b></td><td>$($Summary.FailedServers)</td></tr>
    </table>
    <br>
    <p><i>See attached Excel file for full details.</i></p>
"@

    $MsgParams = @{
        To          = $To
        From        = $From
        Subject     = "$EmailSubject - $TimeStamp"
        Body        = $Body
        BodyAsHtml  = $true
        SmtpServer  = $SmtpServer
        Attachments = $ExcelPath
    }

    try {
        Send-MailMessage @MsgParams
        Write-Host "[+] Email sent successfully." -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to send email: $($_.Exception.Message)"
    }
}