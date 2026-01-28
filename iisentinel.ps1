<#
.SYNOPSIS
    IISentinel Pro v3.5 - High-Stability Build
    Fix: Uses a CSV buffer to ensure data is "cold" before Excel styling.
#>

[CmdletBinding()]
param(
    [Parameter(ValueFromPipeline = $true)]
    [string[]]$ServerNames,
    [string]$OU,
    [pscredential]$Credential,
    [string]$OutputPath = "C:\IISentinel",
    [int]$WarningDays = 60
)

$ErrorActionPreference = "Stop"

# 1) Setup
if (-not (Test-Path $OutputPath)) { New-Item $OutputPath -ItemType Directory -Force | Out-Null }
$RunDate = Get-Date
$TimeStamp = $RunDate.ToString("yyyyMMdd-HHmm")
$ExcelPath = Join-Path $OutputPath "IISentinel_Audit_$TimeStamp.xlsx"
$TempCsv   = Join-Path $OutputPath "IISentinel_Temp.csv"

# 2) Discovery
Write-Host "[*] Discovering targets..." -ForegroundColor Cyan
$Targets = [System.Collections.Generic.List[string]]::new()
if ($ServerNames) { $Targets.AddRange($ServerNames) }
if ($OU) {
    try {
        $Targets.AddRange((Get-ADComputer -SearchBase $OU -Filter {Enabled -eq $true}).Name)
    } catch { Write-Warning "AD Search failed." }
}
$OnlineServers = $Targets | Sort-Object -Unique | Where-Object { Test-Connection $_ -Count 1 -Quiet }

# 3) Remote Audit Logic
$RemoteScript = {
    param($WarningDays)
    Import-Module WebAdministration -ErrorAction SilentlyContinue
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

                $hash = ""
                if ($bind.certificateHash) { $hash = [System.BitConverter]::ToString($bind.certificateHash).Replace("-","").ToUpper() }

                if ($hash -and $certMap.ContainsKey($hash)) {
                    $c = $certMap[$hash]; $days = [math]::Round(($c.NotAfter-(Get-Date)).TotalDays)
                    if ($days -lt 0) { $grade = "F" } elseif ($days -lt 30) { $grade = "B" }
                    $certData = [pscustomobject]@{ Sub=$c.Subject; Days=$days }
                } else { $grade = "F" }
            }
            elseif ($bind.protocol -eq "http") { $hasHttp = $true }

            $results += [pscustomobject]@{ 
                ServerName=$env:COMPUTERNAME; SiteName=$site.Name; Protocol=$bind.protocol; Port=$port;
                CertSubject=if($certData){$certData.Sub}else{"N/A"}; DaysLeft=if($certData){$certData.Days}else{$null}; 
                Grade=$grade; Risk=($risk -join ",")
            }
        }
        if ($hasHttp -and $hasHttps -and !$redirect) {
            $results += [pscustomobject]@{ ServerName=$env:COMPUTERNAME; SiteName=$site.Name; Protocol="GAP"; Port="80"; CertSubject="N/A"; DaysLeft=$null; Grade="C"; Risk="InsecureHTTP" }
        }
    }
    return $results
}

Write-Host "[*] Auditing $($OnlineServers.Count) servers..." -ForegroundColor Cyan
$Inventory = Invoke-Command -ComputerName $OnlineServers -Credential $Credential -ScriptBlock $RemoteScript -ArgumentList $WarningDays -ThrottleLimit 20 -ErrorAction SilentlyContinue | 
             Where-Object { $_.ServerName } | 
             Select-Object ServerName, SiteName, Protocol, Port, CertSubject, DaysLeft, Grade, Risk

# 4) Dashboard Prep
$Total = $Inventory.Count
$Health = "{0:P0}" -f (($Inventory | Where-Object {$_.Grade -match "A|B"}).Count / $Total)
$Dash = @(
    [pscustomobject]@{ Metric = "Fleet Health Score"; Value = $Health }
    [pscustomobject]@{ Metric = "Total Bindings"; Value = $Total }
)

# -------------------------------------------------------------------------
# 5) The Bridge Export (CSV -> Excel)
# -------------------------------------------------------------------------
try {
    Write-Host "[*] Saving final report..." -ForegroundColor Cyan
    
    # Write to CSV first (Atomic and safe)
    $Inventory | Export-Csv -Path $TempCsv -NoTypeInformation
    
    # Import CSV and save as Excel (Starts a fresh Excel handle)
    $FinalInventory = Import-Csv $TempCsv
    $FinalInventory | Sort-Object Grade -Descending | Export-Excel -Path $ExcelPath -WorksheetName "Inventory" -TableStyle Medium2 -AutoSize -BoldTopRow
    
    # Add Dashboard
    $Dash | Export-Excel -Path $ExcelPath -WorksheetName "Dashboard" -Title "POSTURE SUMMARY" -AutoSize
    
    # Only format if data actually exists in the columns
    $Pkg = Open-ExcelPackage -Path $ExcelPath
    $Pkg.Workbook.Worksheets.MoveToStart("Dashboard")
    $ws = $Pkg.Workbook.Worksheets["Inventory"]
    
    # Grade is in Column G for this reduced property list
    if ($ws.Dimension.Rows -gt 1) {
        Add-ConditionalFormatting -Worksheet $ws -Address "G2:G$($ws.Dimension.Rows)" -RuleType Equal -ConditionValue "A" -ForegroundColor White -BackgroundColor Green
        Add-ConditionalFormatting -Worksheet $ws -Address "G2:G$($ws.Dimension.Rows)" -RuleType Equal -ConditionValue "C" -ForegroundColor Black -BackgroundColor Orange
        Add-ConditionalFormatting -Worksheet $ws -Address "G2:G$($ws.Dimension.Rows)" -RuleType Equal -ConditionValue "F" -ForegroundColor White -BackgroundColor Red
    }
    
    Close-ExcelPackage -ExcelPackage $Pkg
    if (Test-Path $TempCsv) { Remove-Item $TempCsv }
    
    Write-Host "[+] Success! Report saved: $ExcelPath" -ForegroundColor Green
} catch {
    Write-Error "Export failed: $($_.Exception.Message)"
}