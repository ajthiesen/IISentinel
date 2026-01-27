<#
.SYNOPSIS
    IISentinel Pro - Executive Edition v2.5
    Features: Dashboard, SAN Expansion, Grade Auditing, and Chain Validation.
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
    [string]$EmailSubject = "Executive IIS SSL Audit"
)

$ErrorActionPreference = "Stop"

# 1) Setup
if (-not (Test-Path $OutputPath)) { New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null }
if (-not (Get-Module -ListAvailable -Name ImportExcel)) { Throw "ImportExcel module required." }

$RunDate   = Get-Date
$TimeStamp = $RunDate.ToString("yyyyMMdd-HHmm")
$ExcelPath = Join-Path $OutputPath "IISentinel_Executive_Audit_$TimeStamp.xlsx"

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

# 3) Remote Audit Logic (With Chain Validation & SAN)
$RemoteScript = {
    param($WarningDays)
    $ErrorActionPreference = "SilentlyContinue"
    Import-Module WebAdministration
    function Norm-Thumb ($t) { if($t){$t.Replace(" ","").Replace(":","").ToUpper()} }
    
    $certMap = @{}
    Get-ChildItem Cert:\LocalMachine -Recurse | Where-Object { $_.Thumbprint } | ForEach-Object {
        if (-not $certMap.ContainsKey($_.Thumbprint)) { $certMap[$_.Thumbprint] = $_ }
    }
    
    $results = @()
    $sites = Get-ChildItem IIS:\Sites
    foreach ($site in $sites) {
        foreach ($bind in $site.Bindings.Collection) {
            if ($bind.protocol -ne "https") { continue }
            $certData = $null; $risk = @(); $grade = "A"; $guidance = "Healthy."
            
            $hash = Norm-Thumb (($bind.certificateHash | ForEach-Object { $_.ToString("X2") }) -join "")
            if ([string]::IsNullOrEmpty($hash)) {
                $sniPath = "IIS:\SslBindings\*!$($bind.bindingInformation.Split(':')[1])"
                $hash = (Get-Item $sniPath).Thumbprint | ForEach-Object { Norm-Thumb $_ }
            }

            if ($hash -and $certMap.ContainsKey($hash)) {
                $c = $certMap[$hash]
                $days = [math]::Round(($c.NotAfter-(Get-Date)).TotalDays)
                
                # Chain Validation
                $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
                $chainValid = $chain.Build($c)
                if (-not $chainValid) { $grade = "C"; $risk += "UntrustedChain"; $guidance = "Warning: Chain is untrusted or incomplete." }

                # Standard Audit
                if ($days -lt 0) { $grade = "F"; $guidance = "EXPIRED: Replace immediately." }
                elseif ($days -lt 30) { if($grade -ne "F"){$grade="B"}; $guidance = "Renew within 30 days." }
                if ($c.SignatureAlgorithm.FriendlyName -match "sha1") { $grade = "C"; $risk += "SHA1" }
                
                $certData = [pscustomobject]@{ Subject=$c.Subject; DaysLeft=$days }
            } else {
                $grade = "F"; $guidance = "CRITICAL: Binding Hash not found in Stores."
            }
            
            $parts = $bind.bindingInformation -split ":"
            $results += [pscustomobject]@{ Type="Inv"; Data=[pscustomobject]@{ 
                ServerName=$env:COMPUTERNAME; SiteName=$site.Name; Port=$parts[1]; 
                CertSubject=if($certData){$certData.Subject}else{"N/A"}; DaysLeft=if($certData){$certData.DaysLeft}else{$null}; 
                Grade=$grade; Risk=($risk -join ", "); Guidance=$guidance 
            } }
        }
    }
    return $results
}

Write-Host "[*] Auditing $($OnlineServers.Count) servers via WinRM..." -ForegroundColor Cyan
$RawResults = Invoke-Command -ComputerName $OnlineServers -Credential $Credential -ScriptBlock $RemoteScript -ArgumentList $WarningDays -ThrottleLimit 20 -ErrorAction SilentlyContinue
$Inventory = ($RawResults | Where-Object { $_.Type -eq "Inv" }).Data

# ------------------------------------------------------------
# 4) Dashboard Generation Logic
# ------------------------------------------------------------
$TotalSites = $Inventory.Count
$Grades = $Inventory | Group-Object Grade
$SummaryStats = foreach ($g in $Grades) {
    [pscustomobject]@{ Grade = $g.Name; Count = $g.Count; Percentage = "{0:P0}" -f ($g.Count / $TotalSites) }
}
$HealthScore = "{0:P0}" -f (($Inventory | Where-Object { $_.Grade -match "A|B" }).Count / $TotalSites)

$TopRiskServers = $Inventory | Where-Object { $_.Grade -eq "F" } | Group-Object ServerName | 
                  Select-Object @{Name="Server";Expression={$_.Name}}, @{Name="CriticalIssues";Expression={$_.Count}} | 
                  Sort-Object CriticalIssues -Descending | Select -First 5

# ------------------------------------------------------------
# 5) Branded Excel Export
# ------------------------------------------------------------
try {
    if (Test-Path $ExcelPath) { Remove-Item $ExcelPath -Force -ErrorAction SilentlyContinue }
    Write-Host "[*] Building Executive Dashboard..." -ForegroundColor Cyan

    # A) Dashboard Sheet
    $DashboardInfo = @(
        [pscustomobject]@{ "Metric" = "Fleet Health Score"; "Value" = $HealthScore }
        [pscustomobject]@{ "Metric" = "Total HTTPS Sites Audited"; "Value" = $TotalSites }
        [pscustomobject]@{ "Metric" = "Critical Failures (Grade F)"; "Value" = ($Inventory | Where-Object {$_.Grade -eq "F"}).Count }
    )
    $DashboardInfo | Export-Excel -Path $ExcelPath -WorksheetName "Dashboard" -Title "FLEET SECURITY POSTURE" -TitleBold -TitleSize 16
    $SummaryStats  | Export-Excel -Path $ExcelPath -WorksheetName "Dashboard" -StartRow 7 -TableName "GradeSummary"
    $TopRiskServers | Export-Excel -Path $ExcelPath -WorksheetName "Dashboard" -StartRow 7 -StartColumn 6 -TableName "TopRisks"

    # B) Data Sheets
    $Inventory | Sort-Object Grade -Descending | Export-Excel -Path $ExcelPath -WorksheetName "Inventory" -TableStyle Medium2 -AutoSize -BoldTopRow
    if ($OfflineServers) { $OfflineServers | Export-Excel -Path $ExcelPath -WorksheetName "Connectivity_Errors" -TableStyle Medium1 -AutoSize }

    # C) Formatting
    $pkg = Open-ExcelPackage -Path $ExcelPath
    $invSheet = $pkg.Workbook.Worksheets["Inventory"]
    if ($null -ne $invSheet) {
        # Column F is Grade
        Add-ConditionalFormatting -Worksheet $invSheet -Address "F:F" -RuleType Equal -ConditionValue "A" -ForegroundColor White -BackgroundColor Green
        Add-ConditionalFormatting -Worksheet $invSheet -Address "F:F" -RuleType Equal -ConditionValue "F" -ForegroundColor White -BackgroundColor Red
    }
    Close-ExcelPackage -ExcelPackage $pkg
    Write-Host "[+] Executive Audit saved: $ExcelPath" -ForegroundColor Green
}
catch { Write-Error "Export Failed: $($_.Exception.Message)" }