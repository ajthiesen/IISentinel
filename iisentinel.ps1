<#
.SYNOPSIS
    IISentinel Pro - Enterprise Edition (Final Stable Build)
    
.DESCRIPTION
    Inventory IIS Bindings & SSL Certificates across an OU.
    Features: Ping-checks, WinRM error handling, Auto-Sorting, and Conditional Formatting.
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
# 1) Pre-Flight & Setup
# ------------------------------------------------------------
if (-not (Test-Path $OutputPath)) { New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null }
if (-not (Get-Module -ListAvailable -Name ImportExcel)) { Throw "ImportExcel module required. Run: Install-Module ImportExcel" }

$RunDate   = Get-Date
$TimeStamp = $RunDate.ToString("yyyyMMdd-HHmm")
$ExcelPath = Join-Path $OutputPath "IISentinel_Report_$TimeStamp.xlsx"

# ------------------------------------------------------------
# 2) Discovery & Connectivity
# ------------------------------------------------------------
Write-Host "[*] Discovering targets..." -ForegroundColor Cyan
$Targets = [System.Collections.Generic.List[string]]::new()
if ($ServerNames) { $Targets.AddRange($ServerNames) }
if ($OU) {
    try {
        $adComputers = Get-ADComputer -SearchBase $OU -SearchScope Subtree -Filter { Enabled -eq $true } | Select-Object -ExpandProperty Name
        if ($adComputers) { [string[]]$adArray = $adComputers; $Targets.AddRange($adArray) }
    } catch { Write-Warning "AD Search failed. Check OU path." }
}
$Targets = $Targets | Sort-Object -Unique

Write-Host "[*] Verifying connectivity for $($Targets.Count) servers..." -ForegroundColor Cyan
$OnlineServers = [System.Collections.Generic.List[string]]::new()
$OfflineServers = [System.Collections.Generic.List[pscustomobject]]::new()

foreach ($Server in $Targets) {
    if (Test-Connection -ComputerName $Server -Count 1 -Quiet) { $OnlineServers.Add($Server) }
    else { $OfflineServers.Add([pscustomobject]@{ ServerName = $Server; Error = "Ping Failed" }) }
}

# ------------------------------------------------------------
# 3) Remote Inventory Logic
# ------------------------------------------------------------
$RemoteScript = {
    param($WarningDays)
    $ErrorActionPreference = "SilentlyContinue"
    Import-Module WebAdministration
    function Norm-Thumb ($t) { if($t){$t.Replace(" ","").Replace(":","").ToUpper()} }
    
    $certMap = @{}
    # Scan both My and WebHosting stores
    Get-ChildItem Cert:\LocalMachine\My, Cert:\LocalMachine\WebHosting | ForEach-Object { $certMap[(Norm-Thumb $_.Thumbprint)] = $_ }

    $results = @(); $boundHashes = [System.Collections.Generic.HashSet[string]]::new()
    $sites = Get-ChildItem IIS:\Sites
    foreach ($site in $sites) {
        foreach ($bind in $site.Bindings.Collection) {
            $certData = $null; $risk = @()
            if ($bind.protocol -eq "https") {
                $hash = Norm-Thumb (($bind.certificateHash | ForEach-Object { $_.ToString("X2") }) -join "")
                if ($hash) {
                    $null = $boundHashes.Add($hash)
                    if ($certMap.ContainsKey($hash)) {
                        $c = $certMap[$hash]
                        $ks = if ($c.PublicKey.Key.KeySize) { $c.PublicKey.Key.KeySize } else { "N/A" }
                        if ($c.SignatureAlgorithm.FriendlyName -match "sha1") { $risk += "SHA1" }
                        if ($ks -ne "N/A" -and $ks -lt 2048) { $risk += "WeakKey($ks)" }
                        
                        $certData = [pscustomobject]@{ 
                            Subject  = $c.Subject
                            DaysLeft = [math]::Round(($c.NotAfter - (Get-Date)).TotalDays)
                            KeySize  = $ks 
                        }
                    }
                }
            }
            $parts = $bind.bindingInformation -split ":"
            $results += [pscustomobject]@{ 
                Type="Inv"; Data=[pscustomobject]@{
                    ServerName  = $env:COMPUTERNAME
                    SiteName    = $site.Name
                    Port        = $parts[1]
                    Hostname    = if($parts[2]){$parts[2]}else{"*"}
                    CertSubject = if($certData){$certData.Subject}else{"N/A"}
                    DaysLeft    = if($certData){$certData.DaysLeft}else{$null}
                    KeySize     = if($certData){$certData.KeySize}else{$null}
                    Risk        = ($risk -join ", ")
                    Error       = if($bind.protocol -eq "https" -and !$certData){"Cert Missing"}else{""}
                }
            }
        }
    }
    # Check for Orphaned certs (in store but not in IIS)
    foreach ($key in $certMap.Keys) {
        if (-not $boundHashes.Contains($key)) {
            $c = $certMap[$key]
            $results += [pscustomobject]@{ 
                Type="Orphan"; Data=[pscustomobject]@{ 
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

Write-Host "[*] Scanning $($OnlineServers.Count) servers via WinRM..." -ForegroundColor Cyan
$RawResults = Invoke-Command -ComputerName $OnlineServers -Credential $Credential -ScriptBlock $RemoteScript -ArgumentList $WarningDays -ThrottleLimit 25 -ErrorAction SilentlyContinue -ErrorVariable WinRMErrors

$Inventory = ($RawResults | Where-Object { $_.Type -eq "Inv" }).Data
$Orphans   = ($RawResults | Where-Object { $_.Type -eq "Orphan" }).Data

if ($WinRMErrors) {
    foreach ($e in $WinRMErrors) { $OfflineServers.Add([pscustomobject]@{ ServerName=$e.TargetObject; Error="WinRM Blocked/Timeout" }) }
}

$SuccessCount = ($Inventory.ServerName | Select -Unique | Measure-Object).Count
Write-Host "[+] Scan complete. Success: $SuccessCount, Failed: $($OfflineServers.Count)" -ForegroundColor Green

# ------------------------------------------------------------
# 4) Professional Excel Export & Auto-Sort
# ------------------------------------------------------------
try {
    if (Test-Path $ExcelPath) { Remove-Item $ExcelPath -Force -ErrorAction SilentlyContinue }

    Write-Host "[*] Creating Excel Sheets..." -ForegroundColor Cyan
    
    # 1. Main Inventory - Sorted by DaysLeft (Ascending)
    if ($Inventory) {
        $Inventory | Sort-Object DaysLeft | Select-Object ServerName, SiteName, Port, Hostname, CertSubject, DaysLeft, KeySize, Risk, Error | 
            Export-Excel -Path $ExcelPath -WorksheetName "Inventory" `
            -TableStyle Medium2 -AutoSize -BoldTopRow -FreezeTopRow
    }

    # 2. Orphans
    if ($Orphans) {
        $Orphans | Sort-Object DaysLeft | Export-Excel -Path $ExcelPath -WorksheetName "Orphaned_Certs" -TableStyle Medium9 -AutoSize
    }

    # 3. Connection Errors
    if ($OfflineServers.Count -gt 0) {
        $OfflineServers | Export-Excel -Path $ExcelPath -WorksheetName "Connection_Errors" -TableStyle Medium1 -AutoSize
    }

    # 4. Final Pass: Apply Conditional Formatting
    Write-Host "[*] Applying final formatting..." -ForegroundColor Cyan
    $finalPkg = Open-ExcelPackage -Path $ExcelPath
    $invSheet = $finalPkg.Workbook.Worksheets["Inventory"]
    
    if ($null -ne $invSheet) {
        # Column F (6th column) is DaysLeft.
        # Format Red if < 30 days, Yellow if < WarningDays.
        Add-ConditionalFormatting -Worksheet $invSheet -Address "F:F" -RuleType LessThan -ConditionValue 30 -ForegroundColor White -BackgroundColor Red
        Add-ConditionalFormatting -Worksheet $invSheet -Address "F:F" -RuleType LessThan -ConditionValue $WarningDays -ForegroundColor Black -BackgroundColor Yellow
    }
    
    Close-ExcelPackage -ExcelPackage $finalPkg
    Write-Host "[+] Success! Report saved: $ExcelPath" -ForegroundColor Green
}
catch {
    Write-Error "Excel Export Failed: $($_.Exception.Message)"
}

# ------------------------------------------------------------
# 5) Email Summary
# ------------------------------------------------------------
if ($SendEmail -and $To) {
    $Soon = ($Inventory | Where-Object { $_.DaysLeft -lt $WarningDays -and $_.DaysLeft -ne $null }).Count
    $EmailBody = @"
    <h2>IIS SSL Inventory Summary</h2>
    <p><b>Servers Successfully Scanned:</b> $SuccessCount</p>
    <p><b>Certs Expiring soon (< $WarningDays days):</b> <span style='color:red;'>$Soon</span></p>
    <p><b>Connectivity Failures:</b> $($OfflineServers.Count)</p>
    <br>
    <p>Please see the attached Excel report for full details. It is sorted by 'DaysLeft' for your convenience.</p>
"@
    Send-MailMessage -To $To -From $From -Subject "$EmailSubject - $TimeStamp" -Body $EmailBody -BodyAsHtml -SmtpServer $SmtpServer -Attachments $ExcelPath
    Write-Host "[+] Email notification sent." -ForegroundColor Green
}

Write-Host "[!] Task Finished." -ForegroundColor Cyan