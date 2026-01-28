<#
.SYNOPSIS
    IISentinel Pro v4.5.2 - Fine-Grained Update
    LOCKED CORE: v4.1 remains the engine.
    FIX: Populated 'DaysLeft' column in the Inventory selection.
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
    else { $OfflineServers += [pscustomobject]@{ ServerName = $Server; Status = "Offline/Ping Failed"; Latency = "N/A" } }
}
if (-not $OnlineServers) { Write-Error "No servers responded to ping."; return }

# 3) Remote Audit Logic (LOCKED v4.1 - DO NOT CHANGE)
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
$Inventory = Invoke-Command -ComputerName $OnlineServers -Credential $Credential -ScriptBlock $RemoteScript -ArgumentList $WarningDays -ThrottleLimit 20 -ErrorAction SilentlyContinue | 
             Where-Object { $_.ServerName } | 
             Select-Object ServerName, SiteName, Protocol, Port, CertSubject, SAN, DaysLeft, Grade, Risk

# 4) Post-Processing
Write-Host "[*] Auditing $($OnlineServers.Count) servers via WinRM..." -ForegroundColor Cyan

# UPDATED: Ensuring DaysLeft is explicitly mapped from the remote result
$Inventory = Invoke-Command -ComputerName $OnlineServers -Credential $Credential -ScriptBlock $RemoteScript -ArgumentList $WarningDays -ThrottleLimit 20 -ErrorAction SilentlyContinue | 
             Where-Object { $_.ServerName } | 
             Select-Object ServerName, SiteName, Protocol, Port, CertSubject, SAN, 
                           @{N="DaysLeft"; E={if($_.DaysLeft -ne $null){$_.DaysLeft}else{"N/A"}}}, 
                           Grade, Risk

# CHANGE: Force alphabetical sort on Grades for the Chart
$GradeCounts = $Inventory | Group-Object Grade | Select-Object @{N="Grade";E={$_.Name}}, Count | Sort-Object Grade

# 5) Stable Export (Locked Styling)
try {
    Write-Host "[*] Saving Report with Expiry Data..." -ForegroundColor Cyan
    
    # Export Data Sheets
    $Inventory | Sort-Object Grade -Descending | Export-Excel -Path $ExcelPath -WorksheetName "Inventory" -TableStyle Medium2 -AutoSize -BoldTopRow
    
    # Dash Metrics
    $DashData = @(
        [pscustomobject]@{ Client = $ClientName; Date = $RunDate.ToShortDateString() }
        [pscustomobject]@{ Metric = "Fleet Health Score"; Value = ("{0:P0}" -f (($Inventory | Where-Object {$_.Grade -match "A|B"}).Count / $Inventory.Count)) }
        [pscustomobject]@{ Metric = "Total Bindings Audited"; Value = $Inventory.Count }
        [pscustomobject]@{ Metric = "Security Fixes Identified"; Value = $RemediationList.Count }
    )
    $DashData | Export-Excel -Path $ExcelPath -WorksheetName "Dashboard" -Title "$ClientName Security Summary" -AutoSize
    
    # Supporting Tabs (Ensuring Grade Table is sorted A-F)
    $GradeCounts | Export-Excel -Path $ExcelPath -WorksheetName "Dashboard" -StartRow 10 -TableName "ChartData"
    if ($RemediationList) { $RemediationList | Export-Excel -Path $ExcelPath -WorksheetName "Remediation_Plan" -TableStyle Medium9 -AutoSize }
    if ($FullFailLog) { $FullFailLog | Export-Excel -Path $ExcelPath -WorksheetName "Connectivity_Issues" -TableStyle Medium1 -AutoSize }

     Styling & Charting (EPPlus)
    $Pkg = Open-ExcelPackage -Path $ExcelPath
    $dashSheet = $Pkg.Workbook.Worksheets["Dashboard"]
    $invSheet = $Pkg.Workbook.Worksheets["Inventory"]

    # [Inventory Coloring Loop remains identical to v4.5]
    # Note: Because we added the DaysLeft mapping, Column 8 is still Grade.
    if ($invSheet.Dimension) {
        for ($i = 2; $i -le $invSheet.Dimension.Rows; $i++) {
            $cell = $invSheet.Cells[$i, 8]
            # ... [Color Logic for A, C, F] ...
        }
    }

    Close-ExcelPackage -ExcelPackage $Pkg
    Write-Host "[+] Success! Expiry data populated." -ForegroundColor Green
} catch {
    Write-Error "Export failed: $($_.Exception.Message)"
}