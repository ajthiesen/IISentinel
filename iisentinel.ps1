<#
.SYNOPSIS
    IISentinel Pro v4.5.3 - Full Integrity Build
    LOCKED CORE: v4.1 remains the engine.
    FIX: Fully restored styling loop and populated DaysLeft.
#>

[CmdletBinding()]
param(
    [Parameter(ValueFromPipeline = $true)]
    [string[]]$ServerNames,
    [string]$OU,
    [pscredential]$Credential,
    [string]$OutputPath = "C:\IISentinel",
    [int]$WarningDays = 60,
    [string]$ClientName = "Internal Audit"
)

$ErrorActionPreference = "Stop"

# 1) Setup
if (-not (Test-Path $OutputPath)) { New-Item $OutputPath -ItemType Directory -Force | Out-Null }
$RunDate = Get-Date
$TimeStamp = $RunDate.ToString("yyyyMMdd-HHmm")
$ExcelPath = Join-Path $OutputPath "IISentinel_Audit_$TimeStamp.xlsx"

# 2) Discovery & Connection Tracking (Locked Logic)
Write-Host "[*] Discovering targets..." -ForegroundColor Cyan
$Targets = [System.Collections.Generic.List[string]]::new()
if ($ServerNames) { $Targets.AddRange($ServerNames) }
if ($OU) {
    try {
        $adComputers = Get-ADComputer -SearchBase $OU -SearchScope Subtree -Filter { Enabled -eq $true } | Select-Object -ExpandProperty Name
        if ($adComputers) { [string[]]$adArray = $adComputers; $Targets.AddRange($adArray) }
    } catch { Write-Error "AD Search failed."; return }
}
$UniqueTargets = $Targets | Sort-Object -Unique

Write-Host "[*] Verifying connectivity for $($UniqueTargets.Count) servers..." -ForegroundColor Cyan
$OnlineServers = @(); $OfflineServers = @()
foreach ($Server in $UniqueTargets) {
    if (Test-Connection -ComputerName $Server -Count 1 -Quiet) { $OnlineServers += $Server } 
    else { $OfflineServers += [pscustomobject]@{ ServerName = $Server; Status = "Offline/Ping Failed"; Latency = "N/A" } }
}
if (-not $OnlineServers) { Write-Error "No servers responded to ping."; return }

# 3) Remote Audit Logic (LOCKED v4.1)
$RemoteScript = {
    param($WarningDays)
    if (-not (Get-Module -Name WebAdministration)) { Import-Module WebAdministration -ErrorAction SilentlyContinue }
    if (-not (Test-Path IIS:\Sites)) { return $null }

    $tls10 = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -Name Enabled -ErrorAction SilentlyContinue
    $tls11 = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" -Name Enabled -ErrorAction SilentlyContinue
    $weakTLS = ($tls10.Enabled -eq 1 -or $tls11.Enabled -eq 1)
    $certMap = @{}
    Get-ChildItem Cert:\LocalMachine -Recurse | Where-Object {$_.Thumbprint} | ForEach-Object { if(!$certMap.ContainsKey($_.Thumbprint)){$certMap[$_.Thumbprint]=$_} }
    
    $results = @()
    foreach ($site in (Get-ChildItem IIS:\Sites)) {
        $hasHttps = $false; $hasHttp = $false
        $redirect = (Get-WebConfigurationProperty -pspath "IIS:\Sites\$($site.Name)" -filter "system.webServer/httpRedirect" -name "enabled").Value
        foreach ($bind in $site.Bindings.Collection) {
            $port = ($bind.bindingInformation -split ":")[1]
            $grade = "A"; $risk = @(); $certData = $null
            if ($bind.protocol -eq "https") {
                $hasHttps = $true
                if ($port -ne "443") { $grade = "B"; $risk += "NonStandardPort" }
                if ($weakTLS) { $grade = "C"; $risk += "WeakTLS" }
                $hash = if ($bind.certificateHash) { [System.BitConverter]::ToString($bind.certificateHash).Replace("-","").ToUpper() } else { "" }
                if ($hash -and $certMap.ContainsKey($hash)) {
                    $c = $certMap[$hash]; $days = [math]::Round(($c.NotAfter-(Get-Date)).TotalDays)
                    $sanList = ($c.Extensions | Where-Object { $_.Oid.FriendlyName -match "Subject Alternative Name" }).Format($false)
                    if ($days -lt 0) { $grade = "F" } elseif ($days -lt 30) { $grade = "B" }
                    $certData = [pscustomobject]@{ Sub=$c.Subject; SAN=$sanList; Days=$days }
                } else { $grade = "F" }
            } elseif ($bind.protocol -eq "http") { $hasHttp = $true }
            $results += [pscustomobject]@{ 
                ServerName=$env:COMPUTERNAME; SiteName=$site.Name; Protocol=$bind.protocol; Port=$port;
                CertSubject=if($certData){$certData.Sub}else{"N/A"}; SAN=if($certData){$certData.SAN}else{"N/A"};
                DaysLeft=if($certData){$certData.Days}else{$null}; Grade=$grade; Risk=($risk -join ",")
            }
        }
        if ($hasHttp -and $hasHttps -and -not $redirect) {
            $results += [pscustomobject]@{ ServerName=$env:COMPUTERNAME; SiteName=$site.Name; Protocol="GAP"; Port="80"; CertSubject="N/A"; SAN="N/A"; DaysLeft=$null; Grade="C"; Risk="MissingRedirect" }
        }
    }
    return $results
}

Write-Host "[*] Auditing $($OnlineServers.Count) servers via WinRM..." -ForegroundColor Cyan
# FIXED: DaysLeft Mapping
$Inventory = Invoke-Command -ComputerName $OnlineServers -Credential $Credential -ScriptBlock $RemoteScript -ArgumentList $WarningDays -ThrottleLimit 20 -ErrorAction SilentlyContinue | 
             Where-Object { $_.ServerName } | 
             Select-Object ServerName, SiteName, Protocol, Port, CertSubject, SAN, 
                           @{N="DaysLeft"; E={if($_.DaysLeft -ne $null){$_.DaysLeft}else{"N/A"}}}, 
                           Grade, Risk

# 4) Post-Processing
$AuditedServers = $Inventory.ServerName | Sort-Object -Unique
$WinRMFailures = $OnlineServers | Where-Object { $_ -notin $AuditedServers } | ForEach-Object { [pscustomobject]@{ ServerName=$_; Status="WinRM Denied"; Latency="Online" } }
$FullFailLog = $OfflineServers + $WinRMFailures

$RemediationList = @()
foreach ($issue in ($Inventory | Where-Object { $_.Grade -ne "A" })) {
    $fix = switch -regex ($issue.Risk) {
        "MissingRedirect" { "Set-WebConfigurationProperty -pspath 'IIS:\Sites\$($issue.SiteName)' -filter 'system.webServer/httpRedirect' -name 'enabled' -value 'True'" }
        "WeakTLS" { "New-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -Name 'Enabled' -Value 0 -PropertyType DWord -Force" }
        default { if($issue.Grade -eq "F" -and $issue.CertSubject -eq "N/A") { "Bind valid SSL certificate to port $($issue.Port)" } }
    }
    if ($fix) { $RemediationList += [pscustomobject]@{ Server=$issue.ServerName; Site=$issue.SiteName; Issue=$issue.Risk; PowerShell_Fix=$fix } }
}
$GradeCounts = $Inventory | Group-Object Grade | Select-Object @{N="Grade";E={$_.Name}}, Count | Sort-Object Grade

# 5) Stable Export & Visualization
try {
    Write-Host "[*] Saving Master Report..." -ForegroundColor Cyan
    
    $Inventory | Sort-Object Grade -Descending | Export-Excel -Path $ExcelPath -WorksheetName "Inventory" -TableStyle Medium2 -AutoSize -BoldTopRow
    
    $DashData = @(
        [pscustomobject]@{ Client = $ClientName; Date = $RunDate.ToShortDateString() }
        [pscustomobject]@{ Metric = "Fleet Health Score"; Value = ("{0:P0}" -f (($Inventory | Where-Object {$_.Grade -match "A|B"}).Count / $Inventory.Count)) }
        [pscustomobject]@{ Metric = "Total Bindings Audited"; Value = $Inventory.Count }
        [pscustomobject]@{ Metric = "Security Fixes Identified"; Value = $RemediationList.Count }
    )
    $DashData | Export-Excel -Path $ExcelPath -WorksheetName "Dashboard" -Title "$ClientName Security Summary" -AutoSize
    
    $GradeCounts | Export-Excel -Path $ExcelPath -WorksheetName "Dashboard" -StartRow 10 -TableName "ChartData"
    if ($RemediationList) { $RemediationList | Export-Excel -Path $ExcelPath -WorksheetName "Remediation_Plan" -TableStyle Medium9 -AutoSize }
    if ($FullFailLog) { $FullFailLog | Export-Excel -Path $ExcelPath -WorksheetName "Connectivity_Issues" -TableStyle Medium1 -AutoSize }

    # --- FULL STYLING & CHARTING LOOP ---
    $Pkg = Open-ExcelPackage -Path $ExcelPath
    $dashSheet = $Pkg.Workbook.Worksheets["Dashboard"]
    $invSheet = $Pkg.Workbook.Worksheets["Inventory"]

    # Dashboard Chart
    $chart = $dashSheet.Drawings.AddChart("HealthChart", [OfficeOpenXml.Drawing.Chart.eChartType]::Pie)
    $chart.SetPosition(2, 0, 5, 0); $chart.SetSize(400, 300); $chart.Title.Text = "Security Grade Distribution"
    $series = $chart.Series.Add($dashSheet.Cells["B11:B$(10 + $GradeCounts.Count)"], $dashSheet.Cells["A11:A$(10 + $GradeCounts.Count)"])
    $chart.DataLabel.ShowPercent = $true

    # Inventory Coloring (LOCKED)
    if ($invSheet.Dimension) {
        for ($i = 2; $i -le $invSheet.Dimension.Rows; $i++) {
            # Column 7: DaysLeft | Column 8: Grade
            $dayCell = $invSheet.Cells[$i, 7]
            $gradeCell = $invSheet.Cells[$i, 8]
            
            # Grade Colors
            $gradeCell.Style.Fill.PatternType = [OfficeOpenXml.Style.ExcelFillStyle]::Solid
            if ($gradeCell.Value -eq "A") { $gradeCell.Style.Fill.BackgroundColor.SetColor([System.Drawing.Color]::Green); $gradeCell.Style.Font.Color.SetColor([System.Drawing.Color]::White) }
            elseif ($gradeCell.Value -eq "C") { $gradeCell.Style.Fill.BackgroundColor.SetColor([System.Drawing.Color]::Orange) }
            elseif ($gradeCell.Value -eq "F") { $gradeCell.Style.Fill.BackgroundColor.SetColor([System.Drawing.Color]::Red); $gradeCell.Style.Font.Color.SetColor([System.Drawing.Color]::White) }
            
            # Expiry Warning (Yellow if < 30 days)
            if ($dayCell.Value -ne "N/A" -and [int]$dayCell.Value -lt 30 -and [int]$dayCell.Value -ge 0) {
                $dayCell.Style.Fill.PatternType = [OfficeOpenXml.Style.ExcelFillStyle]::Solid
                $dayCell.Style.Fill.BackgroundColor.SetColor([System.Drawing.Color]::Yellow)
            }
        }
    }

    $dashSheet.View.ShowGridLines = $false
    $Pkg.Workbook.Worksheets.MoveToStart("Dashboard")
    Close-ExcelPackage -ExcelPackage $Pkg
    
    Write-Host "[+] Success! Full Report saved: $ExcelPath" -ForegroundColor Green
    explorer.exe /select,$ExcelPath
} catch {
    Write-Error "Export failed: $($_.Exception.Message)"
}