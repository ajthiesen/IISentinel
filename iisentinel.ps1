<#
.SYNOPSIS
    IISentinel Pro - Executive Edition v2.7
    Features: Simple 2-Sheet Design (Dashboard + Inventory)
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
$OnlineServers = $Targets | Where-Object { Test-Connection -ComputerName $_ -Count 1 -Quiet }

if (-not $OnlineServers) { Write-Error "No servers online."; return }

# 3) Remote Audit Logic
$RemoteScript = {
    param($WarningDays)
    Import-Module WebAdministration -ErrorAction SilentlyContinue
    function Norm-Thumb ($t) { if($t){$t.Replace(" ","").Replace(":","").ToUpper()} }
    
    $certMap = @{}
    Get-ChildItem Cert:\LocalMachine -Recurse | Where-Object { $_.Thumbprint } | ForEach-Object {
        if (-not $certMap.ContainsKey($_.Thumbprint)) { $certMap[$_.Thumbprint] = $_ }
    }
    
    $results = @()
    foreach ($site in (Get-ChildItem IIS:\Sites)) {
        foreach ($bind in $site.Bindings.Collection) {
            if ($bind.protocol -ne "https") { continue }
            $grade = "A"; $guidance = "Healthy"; $risk = @(); $certData = $null
            
            $hash = Norm-Thumb (($bind.certificateHash | ForEach-Object { $_.ToString("X2") }) -join "")
            if ([string]::IsNullOrEmpty($hash)) {
                $sni = Get-Item "IIS:\SslBindings\*!$($bind.bindingInformation.Split(':')[1])" -ErrorAction SilentlyContinue
                $hash = Norm-Thumb $sni.Thumbprint
            }

            if ($hash -and $certMap.ContainsKey($hash)) {
                $c = $certMap[$hash]
                $days = [math]::Round(($c.NotAfter-(Get-Date)).TotalDays)
                if ($days -lt 0) { $grade = "F"; $guidance = "EXPIRED" }
                elseif ($days -lt 30) { $grade = "B"; $guidance = "Renew Soon" }
                
                $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
                if (-not $chain.Build($c)) { $grade = "C"; $risk += "UntrustedChain" }

                $certData = [pscustomobject]@{ Sub=$c.Subject; Days=$days }
            } else { $grade = "F"; $guidance = "Missing Cert" }
            
            $results += [pscustomobject]@{ 
                ServerName=$env:COMPUTERNAME; SiteName=$site.Name; 
                CertSubject=if($certData){$certData.Sub}else{"N/A"}; 
                DaysLeft=if($certData){$certData.Days}else{$null}; 
                Grade=$grade; Guidance=$guidance 
            }
        }
    }
    return $results
}

Write-Host "[*] Auditing $($OnlineServers.Count) servers..." -ForegroundColor Cyan
$Inventory = Invoke-Command -ComputerName $OnlineServers -Credential $Credential -ScriptBlock $RemoteScript -ArgumentList $WarningDays -ThrottleLimit 20 -ErrorAction SilentlyContinue

# 4) Dashboard Prep
$TotalSites = $Inventory.Count
$HealthScore = "{0:P0}" -f (($Inventory | Where-Object { $_.Grade -match "A|B" }).Count / $TotalSites)
$DashboardData = @(
    [pscustomobject]@{ "Metric" = "Fleet Health Score"; "Value" = $HealthScore }
    [pscustomobject]@{ "Metric" = "Total Sites Audited"; "Value" = $TotalSites }
    [pscustomobject]@{ "Metric" = "Critical Issues (F)"; "Value" = ($Inventory | Where-Object {$_.Grade -eq "F"}).Count }
)

# ------------------------------------------------------------
# 5) The Simplified 2-Sheet Export
# ------------------------------------------------------------
try {
    Write-Host "[*] Saving Simple 2-Sheet Report..." -ForegroundColor Cyan
    
    # Export Sheet 1: Inventory
    $Inventory | Sort Grade -Descending | Export-Excel -Path $ExcelPath -WorksheetName "Inventory" -TableStyle Medium2 -AutoSize -BoldTopRow
    
    # Export Sheet 2: Dashboard (Adding to the existing file)
    $DashboardData | Export-Excel -Path $ExcelPath -WorksheetName "Dashboard" -Title "POSTURE SUMMARY" -TitleBold -TitleSize 16 -AutoSize
    
    # Final cleanup: Move Dashboard to front and set colors
    $Pkg = Open-ExcelPackage -Path $ExcelPath
    $Pkg.Workbook.Worksheets.MoveToStart("Dashboard")
    $Pkg.Workbook.Worksheets["Dashboard"].View.TabSelected = $true
    
    $invSheet = $Pkg.Workbook.Worksheets["Inventory"]
    # Column E is Grade in this simplified version
    Add-ConditionalFormatting -Worksheet $invSheet -Address "E:E" -RuleType Equal -ConditionValue "A" -ForegroundColor White -BackgroundColor Green
    Add-ConditionalFormatting -Worksheet $invSheet -Address "E:E" -RuleType Equal -ConditionValue "F" -ForegroundColor White -BackgroundColor Red
    
    Close-ExcelPackage -ExcelPackage $Pkg
    
    Write-Host "[+] Success! Report saved to $ExcelPath" -ForegroundColor Green
}
catch {
    Write-Error "Excel processing failed: $($_.Exception.Message)"
}