<#
.SYNOPSIS
    IISentinel Pro - Executive Edition v2.6.1
    Fixes: Dashboard Worksheet Not Found / Empty Inventory Errors
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
$ExcelPath = Join-Path $OutputPath "IISentinel_Audit_$TimeStamp.xlsx"

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

if ($OnlineServers.Count -eq 0) { Write-Error "No servers are online to scan. Exiting."; return }

# 3) Remote Audit Logic
$RemoteScript = {
    param($WarningDays)
    $ErrorActionPreference = "SilentlyContinue"
    Import-Module WebAdministration -ErrorAction SilentlyContinue
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
                
                $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
                $chainValid = $chain.Build($c)
                if (-not $chainValid) { $grade = "C"; $risk += "UntrustedChain"; $guidance = "Chain untrusted or incomplete." }

                if ($days -lt 0) { $grade = "F"; $guidance = "EXPIRED: Replace immediately." }
                elseif ($days -lt 30) { if($grade -ne "F"){$grade="B"}; $guidance = "Renew within 30 days." }
                
                $sanList = ""
                $sanExt = $c.Extensions | Where-Object { $_.Oid.FriendlyName -match "Subject Alternative Name" }
                if ($sanExt) { $sanList = ($sanExt.Format($false) -split "," | ForEach-Object { $_.Trim().Replace("DNS Name=", "") }) -join ", " }

                $certData = [pscustomobject]@{ Subject=$c.Subject; SAN=$sanList; DaysLeft=$days }
            } else { $grade = "F"; $guidance = "CRITICAL: Hash not found." }
            
            $results += [pscustomobject]@{ Type="Inv"; Data=[pscustomobject]@{ 
                ServerName=$env:COMPUTERNAME; SiteName=$site.Name; Port=($bind.bindingInformation -split ":")[1]; 
                CertSubject=if($certData){$certData.Subject}else{"N/A"}; SAN=if($certData){$certData.SAN}else{"N/A"};
                DaysLeft=if($certData){$certData.DaysLeft}else{$null}; Grade=$grade; Risk=($risk -join ", "); Guidance=$guidance 
            } }
        }
    }
    return $results
}

Write-Host "[*] Auditing $($OnlineServers.Count) servers via WinRM..." -ForegroundColor Cyan
$RawResults = Invoke-Command -ComputerName $OnlineServers -Credential $Credential -ScriptBlock $RemoteScript -ArgumentList $WarningDays -ThrottleLimit 20 -ErrorAction SilentlyContinue
$Inventory = ($RawResults | Where-Object { $_.Type -eq "Inv" }).Data

if (-not $Inventory) {
    Write-Warning "Scan completed but no IIS HTTPS bindings were found on the target servers."
    # We still export the connectivity errors if they exist
    if ($OfflineServers) { $OfflineServers | Export-Excel -Path $ExcelPath -WorksheetName "Connectivity_Errors" -AutoSize }
    return
}

# 4) Dashboard Prep
$TotalSites = $Inventory.Count
$SummaryStats = $Inventory | Group-Object Grade | Select-Object @{N="Grade";E={$_.Name}}, @{N="Count";E={$_.Count}}, @{N="Percentage";E={"{0:P0}" -f ($_.Count / $TotalSites)}}
$HealthScore = "{0:P0}" -f (($Inventory | Where-Object { $_.Grade -match "A|B" }).Count / $TotalSites)
$TopRiskServers = $Inventory | Where-Object { $_.Grade -eq "F" } | Group-Object ServerName | Select-Object @{N="Server";E={$_.Name}}, @{N="CriticalIssues";E={$_.Count}} | Sort CriticalIssues -Des | Select -First 5
$ServerSummary = $Inventory | Group-Object ServerName | Select-Object @{N="Server Name";E={$_.Name}}, @{N="Cert Count";E={$_.Count}}, @{N="Lowest Grade";E={($_.Group.Grade | Sort | Select -First 1)}} | Sort "Lowest Grade"

# 5) Consolidated Export
try {
    Write-Host "[*] Building Executive Dashboard & Drilled-down Sheets..." -ForegroundColor Cyan
    
    # Start with the Inventory to establish the file
    $Pkg = $Inventory | Sort Grade -Des | Select ServerName, SiteName, Port, CertSubject, SAN, DaysLeft, Grade, Risk, Guidance | 
           Export-Excel -Path $ExcelPath -WorksheetName "Inventory" -TableStyle Medium2 -AutoSize -BoldTopRow -PassThru

    # Add the Dashboard
    $DashboardInfo = @(
        [pscustomobject]@{ "Security Metric" = "Fleet Health Score"; "Status" = $HealthScore }
        [pscustomobject]@{ "Security Metric" = "Total HTTPS Sites Audited"; "Status" = $TotalSites }
        [pscustomobject]@{ "Security Metric" = "Critical Failures (Grade F)"; "Status" = ($Inventory | Where-Object {$_.Grade -eq "F"}).Count }
    )
    $DashboardInfo | Export-Excel -ExcelPackage $Pkg -WorksheetName "Dashboard" -Title "FLEET SECURITY POSTURE" -TitleBold -TitleSize 16
    $SummaryStats  | Export-Excel -ExcelPackage $Pkg -WorksheetName "Dashboard" -StartRow 7 -TableName "GradeSummary"
    if ($TopRiskServers) { $TopRiskServers | Export-Excel -ExcelPackage $Pkg -WorksheetName "Dashboard" -StartRow 7 -StartColumn 6 -TableName "TopRisks" }

    # Add Server Summary
    $ServerSummary | Export-Excel -ExcelPackage $Pkg -WorksheetName "Server_Summary" -TableStyle Medium4 -AutoSize

    # Add Failures
    if ($OfflineServers) { $OfflineServers | Export-Excel -ExcelPackage $Pkg -WorksheetName "Connectivity_Errors" -TableStyle Medium1 -AutoSize }

    # Formatting and Active Sheet
    $invSheet = $Pkg.Workbook.Worksheets["Inventory"]
    $Pkg.Workbook.Worksheets.MoveToStart("Dashboard")
    
    if ($invSheet) {
        # Column G is Grade in the Inventory sheet
        Add-ConditionalFormatting -Worksheet $invSheet -Address "G:G" -RuleType Equal -ConditionValue "A" -ForegroundColor White -BackgroundColor Green
        Add-ConditionalFormatting -Worksheet $invSheet -Address "G:G" -RuleType Equal -ConditionValue "F" -ForegroundColor White -BackgroundColor Red
    }
    
    Close-ExcelPackage -ExcelPackage $Pkg
    Write-Host "[+] Audit Complete! File saved to $ExcelPath" -ForegroundColor Green
}
catch { Write-Error "Export Failed: $($_.Exception.Message)" }