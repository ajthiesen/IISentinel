<#
.SYNOPSIS
    IISentinel Pro v4.5.7 - Forensic Certificate Hunt
    LOCKED CORE: v4.1 remains the engine.
    FIX: Specifically targets WebHosting store and uses bit-conversion hardening.
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
    if (Test-Connection -ComputerName $Server -Count 1 -Quiet) { $OnlineServers += $Server } 
    else { $OfflineServers += [pscustomobject]@{ ServerName = $Server; Status = "Offline" } }
}

# 3) Remote Audit Logic (FORENSIC SEARCH)
$RemoteScript = {
    param($WarningDays)
    if (-not (Get-Module -Name WebAdministration)) { Import-Module WebAdministration -ErrorAction SilentlyContinue }
    if (-not (Test-Path IIS:\Sites)) { return $null }

    # SCHANNEL Security Check
    $tls10 = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -Name Enabled -ErrorAction SilentlyContinue
    $tls11 = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" -Name Enabled -ErrorAction SilentlyContinue
    $weakTLS = ($tls10.Enabled -eq 1 -or $tls11.Enabled -eq 1)
    
    # AGGRESSIVE CERT PRE-LOAD: Pull from My and WebHosting specifically
    $allCerts = Get-ChildItem Cert:\LocalMachine\My, Cert:\LocalMachine\WebHosting -ErrorAction SilentlyContinue
    
    $results = @()
    foreach ($site in (Get-ChildItem IIS:\Sites)) {
        $redirect = (Get-WebConfigurationProperty -pspath "IIS:\Sites\$($site.Name)" -filter "system.webServer/httpRedirect" -name "enabled").Value
        
        foreach ($bind in $site.Bindings.Collection) {
            $port = ($bind.bindingInformation -split ":")[1]
            $grade = "A"; $risk = @(); $daysStr = "N/A"; $sub = "N/A"; $san = "N/A"; $tp = "N/A"
            
            if ($bind.protocol -eq "https") {
                if ($port -ne "443") { $grade = "B"; $risk += "NonStandardPort" }
                if ($weakTLS) { $grade = "C"; $risk += "WeakTLS" }
                
                # Convert the raw byte array to a clean Thumbprint string
                $rawHash = $bind.certificateHash
                if ($rawHash) {
                    $lookupHash = [System.BitConverter]::ToString($rawHash).Replace("-","")
                    $c = $allCerts | Where-Object { $_.Thumbprint -eq $lookupHash } | Select-Object -First 1
                    
                    if ($c) {
                        $diff = [math]::Round(($c.NotAfter-(Get-Date)).TotalDays)
                        $daysStr = [string]$diff
                        $sub = $c.Subject
                        $tp = $c.Thumbprint
                        $san = ($c.Extensions | Where-Object { $_.Oid.FriendlyName -match "Subject Alternative Name" }).Format($false)
                        if ($diff -lt 0) { $grade = "F" } elseif ($diff -lt 30) { $grade = "B" }
                    } else { 
                        $grade = "F"; $risk += "CertStoreMismatch" 
                    }
                } else { $grade = "F"; $risk += "MissingBindingHash" }
            }

            $results += [pscustomobject]@{ 
                ServerName=$env:COMPUTERNAME; SiteName=$site.Name; Protocol=$bind.protocol; Port=$port;
                CertSubject=$sub; Thumbprint=$tp; SAN=$san; DaysLeft=$daysStr; Grade=$grade; Risk=($risk -join ",")
            }
        }
        # GAP Check
        if ($site.Bindings.Collection.protocol -contains "http" -and $site.Bindings.Collection.protocol -contains "https" -and -not $redirect) {
            $results += [pscustomobject]@{ ServerName=$env:COMPUTERNAME; SiteName=$site.Name; Protocol="GAP"; Port="80"; CertSubject="N/A"; Thumbprint="N/A"; SAN="N/A"; DaysLeft="N/A"; Grade="C"; Risk="MissingRedirect" }
        }
    }
    return $results
}

Write-Host "[*] Auditing servers via WinRM..." -ForegroundColor Cyan
$InventoryRaw = Invoke-Command -ComputerName $OnlineServers -Credential $Credential -ScriptBlock $RemoteScript -ArgumentList $WarningDays -ThrottleLimit 20 -ErrorAction SilentlyContinue 

# 4) Post-Processing
$Inventory = $InventoryRaw | Where-Object { $_.ServerName } | Select-Object ServerName, SiteName, Protocol, Port, CertSubject, Thumbprint, SAN, DaysLeft, Grade, Risk
$GradeCounts = $Inventory | Group-Object Grade | Select-Object @{N="Grade";E={$_.Name}}, Count | Sort-Object Grade

# 5) Export (Keeping v4.5.5 Stability)
try {
    Write-Host "[*] Saving Forensic Audit Report..." -ForegroundColor Cyan
    $Inventory | Sort-Object Grade -Descending | Export-Excel -Path $ExcelPath -WorksheetName "Inventory" -TableStyle Medium2 -AutoSize -BoldTopRow
    
    $DashData = @(
        [pscustomobject]@{ Client = $ClientName; Date = $RunDate.ToShortDateString() }
        [pscustomobject]@{ Metric = "Fleet Health Score"; Value = ("{0:P0}" -f (($Inventory | Where-Object {$_.Grade -match "A|B"}).Count / $Inventory.Count)) }
        [pscustomobject]@{ Metric = "Total Bindings"; Value = $Inventory.Count }
    )
    $DashData | Export-Excel -Path $ExcelPath -WorksheetName "Dashboard" -Title "$ClientName Summary" -AutoSize
    $GradeCounts | Export-Excel -Path $ExcelPath -WorksheetName "Dashboard" -StartRow 10 -TableName "ChartData"

    $Pkg = Open-ExcelPackage -Path $ExcelPath
    $dashSheet = $Pkg.Workbook.Worksheets["Dashboard"]; $invSheet = $Pkg.Workbook.Worksheets["Inventory"]
    
    # Chart
    $chart = $dashSheet.Drawings.AddChart("HealthChart", [OfficeOpenXml.Drawing.Chart.eChartType]::Pie)
    $chart.SetPosition(2, 0, 5, 0); $chart.SetSize(400, 300); $chart.Title.Text = "Grade Distribution"
    $series = $chart.Series.Add($dashSheet.Cells["B11:B$(10 + $GradeCounts.Count)"], $dashSheet.Cells["A11:A$(10 + $GradeCounts.Count)"])

    # Color Loop
    if ($invSheet.Dimension) {
        for ($i = 2; $i -le $invSheet.Dimension.Rows; $i++) {
            $gradeCell = $invSheet.Cells[$i, 9]
            $gradeCell.Style.Fill.PatternType = [OfficeOpenXml.Style.ExcelFillStyle]::Solid
            if ($gradeCell.Value -eq "A") { $gradeCell.Style.Fill.BackgroundColor.SetColor([System.Drawing.Color]::Green) }
            elseif ($gradeCell.Value -eq "C") { $gradeCell.Style.Fill.BackgroundColor.SetColor([System.Drawing.Color]::Orange) }
            elseif ($gradeCell.Value -eq "F") { $gradeCell.Style.Fill.BackgroundColor.SetColor([System.Drawing.Color]::Red) }
        }
    }
    
    Close-ExcelPackage -ExcelPackage $Pkg
    Write-Host "[+] Success! Check the 'Risk' column if N/A persists." -ForegroundColor Green
} catch {
    Write-Error "Export failed: $($_.Exception.Message)"
}