<#
.SYNOPSIS
    IISentinel Pro v4.8 - The Universal Hash Fix
    LOCKED CORE: v4.1 Remote Audit Engine + v4.5.5 Reporting.
    FIX: Universal Hash Cleaner handles both String and Byte[] hash types.
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

# 2) Discovery & Connection Tracking
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
    if (Test-Connection -ComputerName $Server -Count 1 -Quiet) { 
        $OnlineServers += $Server 
    } else { 
        $OfflineServers += [pscustomobject]@{ ServerName = $Server; Status = "Offline"; Latency = "N/A" } 
    }
}

# 3) Remote Audit Logic (UNIVERSAL HASH CLEANER)
$RemoteScript = {
    param($WarningDays)
    if (-not (Get-Module -Name WebAdministration)) { Import-Module WebAdministration -ErrorAction SilentlyContinue }
    if (-not (Test-Path IIS:\Sites)) { return $null }

    $tls10 = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -Name Enabled -ErrorAction SilentlyContinue
    $tls11 = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" -Name Enabled -ErrorAction SilentlyContinue
    $weakTLS = ($tls10.Enabled -eq 1 -or $tls11.Enabled -eq 1)
    
    # Load ALL certificate stores
    $allCerts = Get-ChildItem Cert:\LocalMachine\My, Cert:\LocalMachine\WebHosting -ErrorAction SilentlyContinue
    
    $results = @()
    foreach ($site in (Get-ChildItem IIS:\Sites)) {
        $hasHttps = $false; $hasHttp = $false
        $redirect = (Get-WebConfigurationProperty -pspath "IIS:\Sites\$($site.Name)" -filter "system.webServer/httpRedirect" -name "enabled").Value
        
        foreach ($bind in $site.Bindings.Collection) {
            $port = ($bind.bindingInformation -split ":")[1]
            $hostName = ($bind.bindingInformation -split ":")[2]
            $grade = "A"; $risk = @(); $daysStr = "N/A"; $sub = "N/A"; $san = "N/A"; $tp = "N/A"
            
            if ($bind.protocol -eq "https") {
                $hasHttps = $true
                if ($port -ne "443") { $grade = "B"; $risk += "NonStandardPort" }
                if ($weakTLS) { $grade = "C"; $risk += "WeakTLS" }
                
                # --- UNIVERSAL HASH CLEANER ---
                $rawHash = $bind.certificateHash
                $cleanHash = ""
                
                if ($rawHash) {
                    if ($rawHash -is [byte[]]) {
                        # Convert Byte Array to Hex String
                        $cleanHash = [System.BitConverter]::ToString($rawHash).Replace("-","")
                    } elseif ($rawHash -is [string]) {
                        # Already a string, just clean it
                        $cleanHash = $rawHash.Replace(" ","").Replace(":","").ToUpper()
                    }
                }
                # ------------------------------

                $foundCert = $null
                # Method 1: Exact Hash Match
                if ($cleanHash) {
                    $foundCert = $allCerts | Where-Object { $_.Thumbprint -eq $cleanHash } | Select-Object -First 1
                }
                
                # Method 2: Fuzzy Fallback (Hostname)
                if (-not $foundCert -and $hostName) {
                    $foundCert = $allCerts | Where-Object { $_.Subject -match $hostName -or $_.DnsNameList -contains $hostName } | Select-Object -First 1
                    if ($foundCert) { $risk += "FuzzyMatchUsed" }
                }

                if ($foundCert) {
                    $diff = [math]::Round(($foundCert.NotAfter-(Get-Date)).TotalDays)
                    $daysStr = [string]$diff
                    $sub = $foundCert.Subject
                    $tp = $foundCert.Thumbprint
                    $san = ($foundCert.Extensions | Where-Object { $_.Oid.FriendlyName -match "Subject Alternative Name" }).Format($false)
                    if ($diff -lt 0) { $grade = "F" } elseif ($diff -lt 30) { $grade = "B" }
                } else {
                    $flags = $bind.GetAttributeValue("sslFlags")
                    if ($flags -eq 2 -or $flags -eq 3) {
                         $grade = "A"; $risk += "CCS:Managed"; $daysStr = "CCS"; $sub = "Centralized Store"
                    } else {
                         $grade = "F"; $risk += "CertNotFound"
                    }
                }

            } elseif ($bind.protocol -eq "http") { $hasHttp = $true }

            $results += [pscustomobject]@{ 
                ServerName=$env:COMPUTERNAME; SiteName=$site.Name; Protocol=$bind.protocol; Port=$port;
                CertSubject=$sub; Thumbprint=$tp; SAN=$san; DaysLeft=$daysStr; Grade=$grade; Risk=($risk -join ",")
            }
        }
        if ($hasHttp -and $hasHttps -and -not $redirect) {
            $results += [pscustomobject]@{ ServerName=$env:COMPUTERNAME; SiteName=$site.Name; Protocol="GAP"; Port="80"; CertSubject="N/A"; Thumbprint="N/A"; SAN="N/A"; DaysLeft="N/A"; Grade="C"; Risk="MissingRedirect" }
        }
    }
    return $results
}

Write-Host "[*] Auditing $($OnlineServers.Count) servers via WinRM..." -ForegroundColor Cyan
$InventoryRaw = Invoke-Command -ComputerName $OnlineServers -Credential $Credential -ScriptBlock $RemoteScript -ArgumentList $WarningDays -ThrottleLimit 20 -ErrorAction SilentlyContinue 

# 4) Post-Processing (Standard v4.5.5 Logic)
$Inventory = $InventoryRaw | Where-Object { $_.ServerName } | Select-Object ServerName, SiteName, Protocol, Port, CertSubject, Thumbprint, SAN, DaysLeft, Grade, Risk
$GradeCounts = $Inventory | Group-Object Grade | Select-Object @{N="Grade";E={$_.Name}}, Count | Sort-Object Grade

$AuditedServers = $Inventory.ServerName | Sort-Object -Unique
$WinRMFailures = $OnlineServers | Where-Object { $_ -notin $AuditedServers } | ForEach-Object { [pscustomobject]@{ ServerName=$_; Status="WinRM Denied/No IIS"; Latency="Online" } }
$FullFailLog = $OfflineServers + $WinRMFailures

$RemediationList = @()
foreach ($issue in ($Inventory | Where-Object { $_.Grade -ne "A" })) {
    $fix = switch -regex ($issue.Risk) {
        "MissingRedirect" { "Set-WebConfigurationProperty -pspath 'IIS:\Sites\$($issue.SiteName)' -filter 'system.webServer/httpRedirect' -name 'enabled' -value 'True'" }
        "WeakTLS" { "New-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -Name 'Enabled' -Value 0 -PropertyType DWord -Force" }
        "CertNotFound" { "Cert missing from Local/WebHosting Store. Re-import." }
        default { if($issue.Grade -eq "F") { "Bind valid SSL certificate to port $($issue.Port)" } }
    }
    if ($fix) { $RemediationList += [pscustomobject]@{ Server=$issue.ServerName; Site=$issue.SiteName; Issue=$issue.Risk; PowerShell_Fix=$fix } }
}

# 5) Stable Export (Locked v4.5.5 Logic)
try {
    Write-Host "[*] Saving Universal Hash Audit..." -ForegroundColor Cyan
    $Inventory | Sort-Object Grade -Descending | Export-Excel -Path $ExcelPath -WorksheetName "Inventory" -TableStyle Medium2 -AutoSize -BoldTopRow
    
    $DashData = @(
        [pscustomobject]@{ Client = $ClientName; Date = $RunDate.ToShortDateString() }
        [pscustomobject]@{ Metric = "Fleet Health Score"; Value = ("{0:P0}" -f (($Inventory | Where-Object {$_.Grade -match "A|B"}).Count / $Inventory.Count)) }
        [pscustomobject]@{ Metric = "Total Bindings Audited"; Value = $Inventory.Count }
        [pscustomobject]@{ Metric = "Critical Issues Found"; Value = $RemediationList.Count }
    )
    $DashData | Export-Excel -Path $ExcelPath -WorksheetName "Dashboard" -Title "$ClientName Security Summary" -AutoSize
    $GradeCounts | Export-Excel -Path $ExcelPath -WorksheetName "Dashboard" -StartRow 10 -TableName "ChartData"
    if ($RemediationList) { $RemediationList | Export-Excel -Path $ExcelPath -WorksheetName "Remediation_Plan" -TableStyle Medium9 -AutoSize }
    if ($FullFailLog) { $FullFailLog | Export-Excel -Path $ExcelPath -WorksheetName "Connectivity_Issues" -TableStyle Medium1 -AutoSize }

    $Pkg = Open-ExcelPackage -Path $ExcelPath
    $dashSheet = $Pkg.Workbook.Worksheets["Dashboard"]; $invSheet = $Pkg.Workbook.Worksheets["Inventory"]
    
    $chart = $dashSheet.Drawings.AddChart("HealthChart", [OfficeOpenXml.Drawing.Chart.eChartType]::Pie)
    $chart.SetPosition(2, 0, 5, 0); $chart.SetSize(400, 300); $chart.Title.Text = "Security Grade Distribution"
    $series = $chart.Series.Add($dashSheet.Cells["B11:B$(10 + $GradeCounts.Count)"], $dashSheet.Cells["A11:A$(10 + $GradeCounts.Count)"])
    $chart.DataLabel.ShowPercent = $true

    if ($invSheet.Dimension) {
        for ($i = 2; $i -le $invSheet.Dimension.Rows; $i++) {
            $dayCell = $invSheet.Cells[$i, 8]; $gradeCell = $invSheet.Cells[$i, 9]
            $gradeCell.Style.Fill.PatternType = [OfficeOpenXml.Style.ExcelFillStyle]::Solid
            if ($gradeCell.Value -eq "A") { $gradeCell.Style.Fill.BackgroundColor.SetColor([System.Drawing.Color]::Green); $gradeCell.Style.Font.Color.SetColor([System.Drawing.Color]::White) }
            elseif ($gradeCell.Value -eq "C") { $gradeCell.Style.Fill.BackgroundColor.SetColor([System.Drawing.Color]::Orange) }
            elseif ($gradeCell.Value -eq "F") { $gradeCell.Style.Fill.BackgroundColor.SetColor([System.Drawing.Color]::Red); $gradeCell.Style.Font.Color.SetColor([System.Drawing.Color]::White) }
            
            if ($dayCell.Value -ne "N/A" -and $dayCell.Value -ne "CCS" -and $dayCell.Value -match '^-?\d+$' -and [int]$dayCell.Value -lt 30) {
                $dayCell.Style.Fill.PatternType = [OfficeOpenXml.Style.ExcelFillStyle]::Solid
                $dayCell.Style.Fill.BackgroundColor.SetColor([System.Drawing.Color]::Yellow)
            }
        }
    }
    $dashSheet.View.ShowGridLines = $false; $Pkg.Workbook.Worksheets.MoveToStart("Dashboard")
    Close-ExcelPackage -ExcelPackage $Pkg
    Write-Host "[+] Success! 'Universal Hash' logic applied." -ForegroundColor Green
    explorer.exe /select,$ExcelPath
} catch {
    Write-Error "Export failed: $($_.Exception.Message)"
}