<#
.SYNOPSIS
    IISentinel Pro v3.7 - Robust Export Styling
    Fix: Uses native Export-Excel conditional formatting to avoid null dimension errors.
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

# 2) Discovery (Working)
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
$OnlineServers = $UniqueTargets | Where-Object { Test-Connection -ComputerName $_ -Count 1 -Quiet }

if (-not $OnlineServers) { Write-Error "No servers responded to ping."; return }

# 3) Remote Audit Logic (Working)
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
        foreach ($bind in $site.Bindings.Collection) {
            $port = ($bind.bindingInformation -split ":")[1]
            $grade = "A"; $risk = @(); $certData = $null
            
            if ($bind.protocol -eq "https") {
                if ($port -ne "443") { $grade = "B"; $risk += "NonStandardPort" }
                if ($weakTLS) { $grade = "C"; $risk += "WeakTLS" }

                $hash = if ($bind.certificateHash) { [System.BitConverter]::ToString($bind.certificateHash).Replace("-","").ToUpper() } else { "" }
                if ($hash -and $certMap.ContainsKey($hash)) {
                    $c = $certMap[$hash]
                    $days = [math]::Round(($c.NotAfter-(Get-Date)).TotalDays)
                    $sanList = ($c.Extensions | Where-Object { $_.Oid.FriendlyName -match "Subject Alternative Name" }).Format($false)
                    if ($days -lt 0) { $grade = "F" } elseif ($days -lt 30) { $grade = "B" }
                    $certData = [pscustomobject]@{ Sub=$c.Subject; SAN=$sanList; Days=$days }
                } else { $grade = "F" }
            }
            $results += [pscustomobject]@{ 
                ServerName=$env:COMPUTERNAME; SiteName=$site.Name; Protocol=$bind.protocol; Port=$port;
                CertSubject=if($certData){$certData.Sub}else{"N/A"}; SAN=if($certData){$certData.SAN}else{"N/A"};
                DaysLeft=if($certData){$certData.Days}else{$null}; Grade=$grade; Risk=($risk -join ",")
            }
        }
    }
    return $results
}

Write-Host "[*] Auditing $($OnlineServers.Count) servers via WinRM..." -ForegroundColor Cyan
$Inventory = Invoke-Command -ComputerName $OnlineServers -Credential $Credential -ScriptBlock $RemoteScript -ArgumentList $WarningDays -ThrottleLimit 20 -ErrorAction SilentlyContinue | 
             Where-Object { $_.ServerName } | 
             Select-Object ServerName, SiteName, Protocol, Port, CertSubject, SAN, DaysLeft, Grade, Risk

# 4) Analytics
$TotalSites = if ($Inventory) { $Inventory.Count } else { 0 }
if ($TotalSites -eq 0) { Write-Error "No IIS data returned."; return }

$HealthScore = "{0:P0}" -f (($Inventory | Where-Object { $_.Grade -match "A|B" }).Count / $TotalSites)
$DashboardData = @(
    [pscustomobject]@{ Metric = "Fleet Health Score"; Value = $HealthScore }
    [pscustomobject]@{ Metric = "Total Bindings Audited"; Value = $TotalSites }
    [pscustomobject]@{ Metric = "Security Issues (C/F)"; Value = ($Inventory | Where-Object {$_.Grade -match "C|F"}).Count }
)

# 5) Stable Export Logic
try {
    Write-Host "[*] Saving Security Audit Report..." -ForegroundColor Cyan
    
    # Define Conditional Formatting Rules first
    $CondFormat = @()
    $CondFormat += New-ConditionalFormattingIconSet -Range "H:H" -ConditionalFormat Grade -IconType ThreeTrafficLights1
    # Alternative direct color rules
    $RuleA = New-ConditionalText -Text "A" -BackgroundColor Green -ForegroundColor White
    $RuleC = New-ConditionalText -Text "C" -BackgroundColor Orange -ForegroundColor Black
    $RuleF = New-ConditionalText -Text "F" -BackgroundColor Red -ForegroundColor White

    # Export Inventory with Rules built-in
    $Inventory | Sort-Object Grade -Descending | Export-Excel -Path $ExcelPath -WorksheetName "Inventory" `
        -TableStyle Medium2 -AutoSize -BoldTopRow -ConditionalText $RuleA, $RuleC, $RuleF

    # Export Dashboard
    $DashboardData | Export-Excel -Path $ExcelPath -WorksheetName "Dashboard" -Title "POSTURE SUMMARY" -TitleBold -AutoSize

    # Final cleanup: Move Dashboard to front
    $Pkg = Open-ExcelPackage -Path $ExcelPath
    $Pkg.Workbook.Worksheets.MoveToStart("Dashboard")
    Close-ExcelPackage -ExcelPackage $Pkg
    
    Write-Host "[+] Success! Report saved: $ExcelPath" -ForegroundColor Green
} catch {
    Write-Error "Export failed: $($_.Exception.Message)"
}