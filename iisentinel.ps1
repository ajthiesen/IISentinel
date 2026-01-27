<#
.SYNOPSIS
    IISentinel Pro - Enterprise Audit Edition v2.3.1 (SAN Expansion - Fix)
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
$ExcelPath = Join-Path $OutputPath "IISentinel_Audit_SAN_$TimeStamp.xlsx"

# 2) Discovery & Connectivity
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

# 3) Remote Audit Logic (Fixed Version)
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
                    
                    # --- SAN Extraction Logic ---
                    $sanList = ""
                    $sanExtension = $c.Extensions | Where-Object { $_.Oid.FriendlyName -match "Subject Alternative Name" }
                    if ($sanExtension) {
                        $sanList = ($sanExtension.Format($false) -split "," | ForEach-Object { $_.Trim().Replace("DNS Name=", "") }) -join ", "
                    }
                    
                    $ks = if ($c.PublicKey.Key.KeySize) { $c.PublicKey.Key.KeySize } else { 0 }
                    $days = [math]::Round(($c.NotAfter-(Get-Date)).TotalDays)
                    
                    # Audit Logic
                    if ($days -lt 0) { $grade = "F"; $guidance = "EXPIRED: Replace certificate immediately." }
                    elseif ($days -lt 30) { 
                        if ($grade -ne "F") { $grade = "B" }
                        $guidance = "EXPIRING SOON: Renew within 30 days." 
                    }
                    
                    if ($c.SignatureAlgorithm.FriendlyName -match "sha1") { 
                        $grade = "C"; $risk += "SHA1"; $guidance = "WEAK CRYPTO: Re-issue using SHA256." 
                    }
                    if ($ks -gt 0 -and $ks -lt 2048) { 
                        $grade = "C"; $risk += "WeakKey($ks)"; $guidance = "WEAK KEY: Re-issue with 2048-bit minimum." 
                    }
                    
                    # Missing SAN Check (The Fixed Line)
                    if (-not $sanList) { 
                        $risk += "Missing-SAN"
                        if ($grade -ne "F") { $grade = "C" }
                        $guidance = "MODERN COMPLIANCE: Cert missing SAN field. Re-issue." 
                    }
                    
                    $certData = [pscustomobject]@{ Subject=$c.Subject; SAN=$sanList; DaysLeft=$days; KeySize=$ks }
                } else {
                    $grade = "F"; $guidance = "CRITICAL: HTTPS Binding exists but Certificate is MISSING from Store."
                }
            }
            
            $parts = $bind.bindingInformation -split ":"
            $results += [pscustomobject]@{ Type="Inv"; Data=[pscustomobject]@{ 
                ServerName  = $env:COMPUTERNAME; 
                SiteName    = $site.Name; 
                Port        = $parts[1]; 
                CertSubject = if($certData){$certData.Subject}else{"N/A"}; 
                SAN         = if($certData){$certData.SAN}else{"N/A"};
                DaysLeft    = if($certData){$certData.DaysLeft}else{$null}; 
                Grade       = $grade; 
                Risk        = ($risk -join ", "); 
                Guidance    = $guidance 
            } }
        }
    }
    return $results
}

Write-Host "[*] Auditing $($OnlineServers.Count) servers via WinRM (SAN Scan)..." -ForegroundColor Cyan
$RawResults = Invoke-Command -ComputerName $OnlineServers -Credential $Credential -ScriptBlock $RemoteScript -ArgumentList $WarningDays -ThrottleLimit 20 -ErrorAction SilentlyContinue -ErrorVariable WinRMErrors
$Inventory = ($RawResults | Where-Object { $_.Type -eq "Inv" }).Data

# 4) Data Preparation
$ServerSummary = $Inventory | Group-Object ServerName | Select-Object @{Name="Server Name";Expression={$_.Name}}, @{Name="Cert Count";Expression={$_.Count}}, @{Name="Lowest Grade";Expression={ ($_.Group.Grade | Sort-Object | Select-Object -First 1) }} | Sort-Object "Lowest Grade"
$VersionHistory = @(
    [pscustomobject]@{ Version="2.3.1"; Date="2026-01-27"; Change="Fixed PowerShell Ternary Syntax Bug" }
    [pscustomobject]@{ Version="2.3"; Date="2026-01-27"; Change="Added SAN Expansion" }
)

# 5) Branded Excel Export
try {
    if (Test-Path $ExcelPath) { Remove-Item $ExcelPath -Force -ErrorAction SilentlyContinue }
    Write-Host "[*] Building SAN-Enabled Report..." -ForegroundColor Cyan

    $Disclaimer = @(
        [pscustomobject]@{ "IISentinel Security Audit" = "Prepared For: NCH HCS Server Team" }
        [pscustomobject]@{ "IISentinel Security Audit" = "Grade Key: A=Healthy, B=Warning, C=Weak Crypto, F=Critical/Expired" }
    )
    $Disclaimer | Export-Excel -Path $ExcelPath -WorksheetName "Disclaimer" -Title "AUDIT OVERVIEW" -TitleBold -TitleSize 14

    $ServerSummary | Export-Excel -Path $ExcelPath -WorksheetName "Server_Summary" -TableStyle Medium4 -AutoSize

    if ($Inventory) {
        $Inventory | Sort-Object Grade -Descending | Select-Object ServerName, SiteName, Port, CertSubject, SAN, DaysLeft, Grade, Risk, Guidance | 
            Export-Excel -Path $ExcelPath -WorksheetName "Inventory" -TableStyle Medium2 -AutoSize -BoldTopRow -FreezeTopRow
    }

    if ($OfflineServers.Count -gt 0) { $OfflineServers | Export-Excel -Path $ExcelPath -WorksheetName "Connectivity_Errors" -TableStyle Medium1 -AutoSize }
    $VersionHistory | Export-Excel -Path $ExcelPath -WorksheetName "Version_History" -TableStyle Medium9 -AutoSize

    $pkg = Open-ExcelPackage -Path $ExcelPath
    $invSheet = $pkg.Workbook.Worksheets["Inventory"]
    if ($null -ne $invSheet) {
        Add-ConditionalFormatting -Worksheet $invSheet -Address "G:G" -RuleType Equal -ConditionValue "A" -ForegroundColor White -BackgroundColor Green
        Add-ConditionalFormatting -Worksheet $invSheet -Address "G:G" -RuleType Equal -ConditionValue "B" -ForegroundColor Black -BackgroundColor Yellow
        Add-ConditionalFormatting -Worksheet $invSheet -Address "G:G" -RuleType Equal -ConditionValue "C" -ForegroundColor Black -BackgroundColor Orange
        Add-ConditionalFormatting -Worksheet $invSheet -Address "G:G" -RuleType Equal -ConditionValue "F" -ForegroundColor White -BackgroundColor Red
    }
    Close-ExcelPackage -ExcelPackage $pkg
    Write-Host "[+] Audit Report saved: $ExcelPath" -ForegroundColor Green
}
catch { Write-Error "Export Failed: $($_.Exception.Message)" }

# 6) Email
if ($SendEmail -and $To) {
    Send-MailMessage -To $To -From $From -Subject "$EmailSubject - $TimeStamp" -Body "SSL Audit attached." -SmtpServer $SmtpServer -Attachments $ExcelPath
}
Write-Host "[!] Audit Finished Successfully." -ForegroundColor Cyan