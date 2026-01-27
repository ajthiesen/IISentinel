<#
.SYNOPSIS
    IISentinel Pro - Enterprise Audit Edition v2.2
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
    [string]$EmailSubject = "IIS SSL Audit Report"
)

$ErrorActionPreference = "Stop"

# 1) Setup
if (-not (Test-Path $OutputPath)) { New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null }
if (-not (Get-Module -ListAvailable -Name ImportExcel)) { Throw "ImportExcel module required." }

$RunDate   = Get-Date
$TimeStamp = $RunDate.ToString("yyyyMMdd-HHmm")
$ExcelPath = Join-Path $OutputPath "IISentinel_Audit_$TimeStamp.xlsx"

# 2) Target Discovery
Write-Host "[*] Discovering targets..." -ForegroundColor Cyan
$Targets = [System.Collections.Generic.List[string]]::new()
if ($ServerNames) { $Targets.AddRange($ServerNames) }
if ($OU) {
    try {
        $adComputers = Get-ADComputer -SearchBase $OU -SearchScope Subtree -Filter { Enabled -eq $true } | Select-Object -ExpandProperty Name
        if ($adComputers) { [string[]]$adArray = $adComputers; $Targets.AddRange($adArray) }
    } catch { Write-Warning "AD Search failed." }
}
$Targets = $Targets | Sort-Object -Unique

Write-Host "[*] Verifying connectivity for $($Targets.Count) servers..." -ForegroundColor Cyan
$OnlineServers = [System.Collections.Generic.List[string]]::new()
$OfflineServers = [System.Collections.Generic.List[pscustomobject]]::new()
foreach ($Server in $Targets) {
    if (Test-Connection -ComputerName $Server -Count 1 -Quiet) { $OnlineServers.Add($Server) }
    else { $OfflineServers.Add([pscustomobject]@{ ServerName = $Server; Status = "Offline"; Error = "Ping Failed" }) }
}

# 3) Remote Audit Logic
$RemoteScript = {
    param($WarningDays)
    $ErrorActionPreference = "SilentlyContinue"
    Import-Module WebAdministration
    function Norm-Thumb ($t) { if($t){$t.Replace(" ","").Replace(":","").ToUpper()} }
    
    $certMap = @{}
    Get-ChildItem Cert:\LocalMachine\My, Cert:\LocalMachine\WebHosting | ForEach-Object { $certMap[(Norm-Thumb $_.Thumbprint)] = $_ }
    
    $results = @()
    $sites = Get-ChildItem IIS:\Sites
    foreach ($site in $sites) {
        foreach ($bind in $site.Bindings.Collection) {
            $certData = $null; $risk = @(); $grade = "A"; $guidance = "No action required."
            
            if ($bind.protocol -eq "https") {
                $hash = Norm-Thumb (($bind.certificateHash | ForEach-Object { $_.ToString("X2") }) -join "")
                if ($hash -and $certMap.ContainsKey($hash)) {
                    $c = $certMap[$hash]
                    $ks = if ($c.PublicKey.Key.KeySize) { $c.PublicKey.Key.KeySize } else { 0 }
                    $days = [math]::Round(($c.NotAfter-(Get-Date)).TotalDays)
                    
                    # Audit Logic
                    if ($days -lt 0) { $grade = "F"; $guidance = "EXPIRED: Replace certificate immediately." }
                    elseif ($days -lt 30) { $grade = "B"; $guidance = "EXPIRING SOON: Renew within 30 days." }
                    
                    if ($c.SignatureAlgorithm.FriendlyName -match "sha1") { 
                        $grade = "C"; $risk += "SHA1"
                        $guidance = "WEAK CRYPTO: Re-issue using SHA256." 
                    }
                    if ($ks -gt 0 -and $ks -lt 2048) { 
                        $grade = "C"; $risk += "WeakKey($ks)"
                        $guidance = "WEAK KEY: Re-issue with 2048-bit minimum." 
                    }
                    
                    $certData = [pscustomobject]@{ Subject=$c.Subject; DaysLeft=$days; KeySize=$ks }
                } else {
                    $grade = "F"; $guidance = "CRITICAL: HTTPS Binding exists but Certificate is MISSING."
                }
            }
            
            $parts = $bind.bindingInformation -split ":"
            $results += [pscustomobject]@{ Type="Inv"; Data=[pscustomobject]@{ 
                ServerName=$env:COMPUTERNAME; SiteName=$site.Name; Port=$parts[1]; 
                CertSubject=if($certData){$certData.Subject}else{"N/A"}; 
                DaysLeft=if($certData){$certData.DaysLeft}else{$null}; 
                Grade=$grade; Risk=($risk -join ", "); Guidance=$guidance 
            } }
        }
    }
    return $results
}

Write-Host "[*] Auditing $($OnlineServers.Count) servers via WinRM..." -ForegroundColor Cyan
$RawResults = Invoke-Command -ComputerName $OnlineServers -Credential $Credential -ScriptBlock $RemoteScript -ArgumentList $WarningDays -ThrottleLimit 20 -ErrorAction SilentlyContinue -ErrorVariable WinRMErrors
$Inventory = ($RawResults | Where-Object { $_.Type -eq "Inv" }).Data
if ($WinRMErrors) { foreach ($e in $WinRMErrors) { $OfflineServers.Add([pscustomobject]@{ ServerName=$e.TargetObject; Status="WinRM Error"; Error="Connection Blocked" }) } }

# 4) Data Preparation
$ServerSummary = $Inventory | Group-Object ServerName | Select-Object @{Name="Server Name";Expression={$_.Name}}, @{Name="Cert Count";Expression={$_.Count}}, @{Name="Avg Grade";Expression={ ($_.Group.Grade | Sort-Object | Select-Object -First 1) }} | Sort-Object "Avg Grade"
$VersionHistory = @(
    [pscustomobject]@{ Version="2.2"; Date="2026-01-27"; Change="Added Security Grades & Remediation Guidance" }
    [pscustomobject]@{ Version="2.1"; Date="2026-01-27"; Change="Fixed Style Helper Bug & Added Summaries" }
)

# 5) Branded Excel Export
try {
    if (Test-Path $ExcelPath) { Remove-Item $ExcelPath -Force -ErrorAction SilentlyContinue }
    Write-Host "[*] Building Audit Report..." -ForegroundColor Cyan

    # A) Disclaimer
    $Disclaimer = @(
        [pscustomobject]@{ "IISentinel Security Audit" = "Prepared For: NCH HCS Server Team" }
        [pscustomobject]@{ "IISentinel Security Audit" = "Generated By: $env:USERNAME" }
        [pscustomobject]@{ "IISentinel Security Audit" = "Grade Key: A=Healthy, B=Warning, C=Weak Crypto, F=Critical/Expired" }
    )
    $Disclaimer | Export-Excel -Path $ExcelPath -WorksheetName "Disclaimer" -Title "AUDIT OVERVIEW" -TitleBold -TitleSize 14

    # B) Server Summary
    $ServerSummary | Export-Excel -Path $ExcelPath -WorksheetName "Server_Summary" -TableStyle Medium4 -AutoSize

    # C) Full Inventory (Auto-Sorted by Grade)
    if ($Inventory) {
        $Inventory | Sort-Object Grade -Descending | Select-Object ServerName, SiteName, Port, CertSubject, DaysLeft, Grade, Risk, Guidance | 
            Export-Excel -Path $ExcelPath -WorksheetName "Inventory" -TableStyle Medium2 -AutoSize -BoldTopRow -FreezeTopRow
    }

    # D) Failures & History
    if ($OfflineServers.Count -gt 0) { $OfflineServers | Export-Excel -Path $ExcelPath -WorksheetName "Connectivity_Errors" -TableStyle Medium1 -AutoSize }
    $VersionHistory | Export-Excel -Path $ExcelPath -WorksheetName "Version_History" -TableStyle Medium9 -AutoSize

    # E) Final Pass: Conditional Formatting
    $pkg = Open-ExcelPackage -Path $ExcelPath
    $invSheet = $pkg.Workbook.Worksheets["Inventory"]
    if ($null -ne $invSheet) {
        # Column F = DaysLeft, Column G = Grade
        Add-ConditionalFormatting -Worksheet $invSheet -Address "G:G" -RuleType Equal -ConditionValue "A" -ForegroundColor White -BackgroundColor Green
        Add-ConditionalFormatting -Worksheet $invSheet -Address "G:G" -RuleType Equal -ConditionValue "C" -ForegroundColor Black -BackgroundColor Yellow
        Add-ConditionalFormatting -Worksheet $invSheet -Address "G:G" -RuleType Equal -ConditionValue "F" -ForegroundColor White -BackgroundColor Red
    }
    Close-ExcelPackage -ExcelPackage $pkg
    Write-Host "[+] Audit Report saved: $ExcelPath" -ForegroundColor Green
}
catch { Write-Error "Export Failed: $($_.Exception.Message)" }

# 6) Email Notification
if ($SendEmail -and $To) {
    $Critical = ($Inventory | Where-Object { $_.Grade -eq "F" }).Count
    $EmailBody = "<h2>SSL Audit Summary</h2><p>Critical Issues (Grade F): <span style='color:red;'>$Critical</span></p><p>Total Sites Audited: $($Inventory.Count)</p><br><p>Audit report attached.</p>"
    Send-MailMessage -To $To -From $From -Subject "$EmailSubject - $TimeStamp" -Body $EmailBody -BodyAsHtml -SmtpServer $SmtpServer -Attachments $ExcelPath
}
Write-Host "[!] Audit Finished." -ForegroundColor Cyan