<#
.SYNOPSIS
    IISentinel Pro - Enterprise Edition v2.1
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

# 1) Setup
if (-not (Test-Path $OutputPath)) { New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null }
if (-not (Get-Module -ListAvailable -Name ImportExcel)) { Throw "ImportExcel module required." }

$RunDate   = Get-Date
$TimeStamp = $RunDate.ToString("yyyyMMdd-HHmm")
$ExcelPath = Join-Path $OutputPath "IISentinel_Report_$TimeStamp.xlsx"

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

# 3) Remote Scan
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
            $certData = $null; $risk = @()
            if ($bind.protocol -eq "https") {
                $hash = Norm-Thumb (($bind.certificateHash | ForEach-Object { $_.ToString("X2") }) -join "")
                if ($hash -and $certMap.ContainsKey($hash)) {
                    $c = $certMap[$hash]
                    $ks = if ($c.PublicKey.Key.KeySize) { $c.PublicKey.Key.KeySize } else { "N/A" }
                    if ($c.SignatureAlgorithm.FriendlyName -match "sha1") { $risk += "SHA1" }
                    if ($ks -ne "N/A" -and $ks -lt 2048) { $risk += "WeakKey" }
                    $certData = [pscustomobject]@{ Subject=$c.Subject; DaysLeft=[math]::Round(($c.NotAfter-(Get-Date)).TotalDays); KeySize=$ks }
                }
            }
            $parts = $bind.bindingInformation -split ":"
            $results += [pscustomobject]@{ Type="Inv"; Data=[pscustomobject]@{ ServerName=$env:COMPUTERNAME; SiteName=$site.Name; Port=$parts[1]; Hostname=if($parts[2]){$parts[2]}else{"*"}; CertSubject=if($certData){$certData.Subject}else{"N/A"}; DaysLeft=if($certData){$certData.DaysLeft}else{$null}; KeySize=if($certData){$certData.KeySize}else{$null}; Risk=($risk -join ", "); Error=if($bind.protocol -eq "https" -and !$certData){"Cert Missing"}else{""} } }
        }
    }
    return $results
}

Write-Host "[*] Scanning $($OnlineServers.Count) servers via WinRM..." -ForegroundColor Cyan
$RawResults = Invoke-Command -ComputerName $OnlineServers -Credential $Credential -ScriptBlock $RemoteScript -ArgumentList $WarningDays -ThrottleLimit 20 -ErrorAction SilentlyContinue -ErrorVariable WinRMErrors
$Inventory = ($RawResults | Where-Object { $_.Type -eq "Inv" }).Data
if ($WinRMErrors) { foreach ($e in $WinRMErrors) { $OfflineServers.Add([pscustomobject]@{ ServerName=$e.TargetObject; Status="WinRM Error"; Error="Connection Blocked" }) } }

# 4) Data Preparation
$ServerSummary = $Inventory | Group-Object ServerName | Select-Object @{Name="Server Name";Expression={$_.Name}}, @{Name="Total Certificates";Expression={$_.Count}} | Sort-Object "Total Certificates" -Descending
$VersionHistory = @(
    [pscustomobject]@{ Version="2.1"; Date="2026-01-27"; Change="Added Server Summary & Fixed Style Helper Bug" }
    [pscustomobject]@{ Version="2.0"; Date="2026-01-26"; Change="Added Branded Disclaimer & Linear Export Logic" }
    [pscustomobject]@{ Version="1.0"; Date="2026-01-20"; Change="Initial Inventory Script" }
)

# 5) Branded Excel Export
try {
    if (Test-Path $ExcelPath) { Remove-Item $ExcelPath -Force -ErrorAction SilentlyContinue }
    Write-Host "[*] Building Branded Report..." -ForegroundColor Cyan

    # A) Disclaimer
    $Disclaimer = @(
        [pscustomobject]@{ "IISentinel Security Report" = "Prepared For: NCH HCS Server Team" }
        [pscustomobject]@{ "IISentinel Security Report" = "Generated By: $env:USERNAME" }
        [pscustomobject]@{ "IISentinel Security Report" = "Date: $(Get-Date)" }
        [pscustomobject]@{ "IISentinel Security Report" = "" }
        [pscustomobject]@{ "IISentinel Security Report" = "CONFIDENTIAL: Do not distribute outside of IT Operations." }
    )
    $Disclaimer | Export-Excel -Path $ExcelPath -WorksheetName "Disclaimer" -Title "REPORT OVERVIEW" -TitleBold -TitleSize 14

    # B) Server Summary
    $ServerSummary | Export-Excel -Path $ExcelPath -WorksheetName "Server_Summary" -TableStyle Medium4 -AutoSize

    # C) Full Inventory
    if ($Inventory) {
        $Inventory | Sort-Object DaysLeft | Select-Object ServerName, SiteName, Port, Hostname, CertSubject, DaysLeft, KeySize, Risk, Error | 
            Export-Excel -Path $ExcelPath -WorksheetName "Inventory" -TableStyle Medium2 -AutoSize -BoldTopRow -FreezeTopRow
    }

    # D) Failures & History
    if ($OfflineServers.Count -gt 0) { $OfflineServers | Export-Excel -Path $ExcelPath -WorksheetName "Connectivity_Errors" -TableStyle Medium1 -AutoSize }
    $VersionHistory | Export-Excel -Path $ExcelPath -WorksheetName "Version_History" -TableStyle Medium9 -AutoSize

    # E) Final Formatting
    $pkg = Open-ExcelPackage -Path $ExcelPath
    $invSheet = $pkg.Workbook.Worksheets["Inventory"]
    if ($null -ne $invSheet) {
        Add-ConditionalFormatting -Worksheet $invSheet -Address "F:F" -RuleType LessThan -ConditionValue 30 -ForegroundColor White -BackgroundColor Red
        Add-ConditionalFormatting -Worksheet $invSheet -Address "F:F" -RuleType LessThan -ConditionValue $WarningDays -ForegroundColor Black -BackgroundColor Yellow
    }
    Close-ExcelPackage -ExcelPackage $pkg
    Write-Host "[+] Success! Report saved: $ExcelPath" -ForegroundColor Green
}
catch { Write-Error "Excel Export Failed: $($_.Exception.Message)" }

# 6) Email Notification
if ($SendEmail -and $To) {
    $Soon = ($Inventory | Where-Object { $_.DaysLeft -lt $WarningDays -and $_.DaysLeft -ne $null }).Count
    $EmailBody = "<h2>IIS SSL Inventory Summary</h2><p>Servers reached: $SuccessCount</p><p>Expiring (< $WarningDays days): <span style='color:red;'>$Soon</span></p><br><p>Full branded report attached.</p>"
    Send-MailMessage -To $To -From $From -Subject "$EmailSubject - $TimeStamp" -Body $EmailBody -BodyAsHtml -SmtpServer $SmtpServer -Attachments $ExcelPath
}
Write-Host "[!] Task Finished." -ForegroundColor Cyan