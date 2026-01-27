<#
.SYNOPSIS
    IISentinel Pro - Security Auditor Edition v2.9
    Features: Port & Protocol Drift Detection, Domain Analysis, Remediation.
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

# 2) Target Discovery
Write-Host "[*] Discovering and verifying targets..." -ForegroundColor Cyan
$Targets = [System.Collections.Generic.List[string]]::new()
if ($ServerNames) { $Targets.AddRange($ServerNames) }
if ($OU) {
    try {
        $adComputers = Get-ADComputer -SearchBase $OU -SearchScope Subtree -Filter { Enabled -eq $true } | Select-Object -ExpandProperty Name
        if ($adComputers) { [string[]]$adArray = $adComputers; $Targets.AddRange($adArray) }
    } catch { Write-Warning "AD Search failed." }
}
$OnlineServers = $Targets | Sort-Object -Unique | Where-Object { Test-Connection -ComputerName $_ -Count 1 -Quiet }

# 3) Remote Audit Logic (Enhanced for Protocol Drift)
$RemoteScript = {
    param($WarningDays)
    Import-Module WebAdministration -ErrorAction SilentlyContinue
    function Norm-Thumb ($t) { if($t){$t.Replace(" ","").Replace(":","").ToUpper()} }
    
    $certMap = @{}
    Get-ChildItem Cert:\LocalMachine -Recurse | Where-Object { $_.Thumbprint } | ForEach-Object {
        if (-not $certMap.ContainsKey($_.Thumbprint)) { $certMap[$_.Thumbprint] = $_ }
    }
    
    $results = @()
    $sites = Get-ChildItem IIS:\Sites
    foreach ($site in $sites) {
        $hasHttps = $false; $hasHttp = $false; $hasRedirect = $false
        
        # Check for HTTP Redirect Configuration
        $config = Get-WebConfigurationProperty -pspath "IIS:\Sites\$($site.Name)" -filter "system.webServer/httpRedirect" -name "enabled"
        if ($config.Value -eq $true) { $hasRedirect = $true }

        foreach ($bind in $site.Bindings.Collection) {
            $parts = $bind.bindingInformation -split ":"
            $port = $parts[1]
            $grade = "A"; $guidance = "Healthy"; $risk = @(); $certData = $null
            
            if ($bind.protocol -eq "https") {
                $hasHttps = $true
                # --- Port Drift Check ---
                if ($port -ne "443") { $grade = "B"; $risk += "NonStandardPort($port)"; $guidance = "Verify if port $port is required for production." }

                $hash = Norm-Thumb (($bind.certificateHash | ForEach-Object { $_.ToString("X2") }) -join "")
                if ([string]::IsNullOrEmpty($hash)) {
                    $sni = Get-Item "IIS:\SslBindings\*!$port" -ErrorAction SilentlyContinue
                    $hash = Norm-Thumb $sni.Thumbprint
                }

                if ($hash -and $certMap.ContainsKey($hash)) {
                    $c = $certMap[$hash]; $days = [math]::Round(($c.NotAfter-(Get-Date)).TotalDays)
                    if ($days -lt 0) { $grade = "F"; $guidance = "EXPIRED: Replace immediately." }
                    elseif ($days -lt 30) { $grade = "B"; $guidance = "Renew within 30 days." }
                    $certData = [pscustomobject]@{ Sub=$c.Subject; Days=$days }
                } else { $grade = "F"; $guidance = "CRITICAL: Cert missing from store." }
            }
            elseif ($bind.protocol -eq "http") { $hasHttp = $true }

            # Report Binding
            $results += [pscustomobject]@{ 
                ServerName=$env:COMPUTERNAME; SiteName=$site.Name; Protocol=$bind.protocol; Port=$port;
                CertSubject=if($certData){$certData.Sub}else{"N/A"}; DaysLeft=if($certData){$certData.Days}else{$null}; 
                Grade=$grade; Remediation=$guidance; Risk=($risk -join ",")
            }
        }

        # --- Protocol Drift Check: HTTP without Redirect ---
        if ($hasHttp -and $hasHttps -and -not $hasRedirect) {
            $results += [pscustomobject]@{ 
                ServerName=$env:COMPUTERNAME; SiteName=$site.Name; Protocol="SECURITY_GAP"; Port="80";
                CertSubject="N/A"; DaysLeft=$null; Grade="C"; 
                Remediation="INSECURE: Port 80 is open but HTTP Redirect is NOT enabled."; Risk="MissingRedirect"
            }
        }
    }
    return $results
}

Write-Host "[*] Auditing $($OnlineServers.Count) servers for Certs and Drift..." -ForegroundColor Cyan
$Inventory = Invoke-Command -ComputerName $OnlineServers -Credential $Credential -ScriptBlock $RemoteScript -ArgumentList $WarningDays -ThrottleLimit 20 -ErrorAction SilentlyContinue | Select-Object * -ExcludeProperty PSComputerName, RunspaceId

# 4) Analytics
$DomainSummary = $Inventory | Where-Object { $_.CertSubject -ne "N/A" } | Group-Object CertSubject | 
                 Select-Object @{N="Certificate Domain";E={$_.Name}}, @{N="Usage Count";E={$_.Count}} | 
                 Sort Usage Count -Des | Select -First 10

$DriftCount = ($Inventory | Where-Object { $_.Risk -match "MissingRedirect|NonStandardPort" }).Count

$DashboardData = @(
    [pscustomobject]@{ "Metric" = "Fleet Health Score"; "Value" = "{0:P0}" -f (($Inventory | Where-Object {$_.Grade -match "A|B"}).Count / $Inventory.Count) }
    [pscustomobject]@{ "Metric" = "Protocol/Port Drift Issues"; "Value" = $DriftCount }
    [pscustomobject]@{ "Metric" = "Critical Cert Failures (F)"; "Value" = ($Inventory | Where-Object {$_.Grade -eq "F"}).Count }
)

# 5) Export
try {
    Write-Host "[*] Saving Security Audit Report..." -ForegroundColor Cyan
    $Inventory | Sort Grade -Descending | Export-Excel -Path $ExcelPath -WorksheetName "Inventory" -TableStyle Medium2 -AutoSize -BoldTopRow
    $DashboardData | Export-Excel -Path $ExcelPath -WorksheetName "Dashboard" -Title "SECURITY POSTURE SUMMARY" -TitleBold -TitleSize 16 -AutoSize
    $DomainSummary | Export-Excel -Path $ExcelPath -WorksheetName "Dashboard" -StartRow 7 -TableName "DomainUsage" -AutoSize

    $Pkg = Open-ExcelPackage -Path $ExcelPath
    $Pkg.Workbook.Worksheets.MoveToStart("Dashboard")
    $Pkg.Workbook.Worksheets["Dashboard"].View.TabSelected = $true
    Add-ConditionalFormatting -Worksheet $Pkg.Workbook.Worksheets["Inventory"] -Address "G:G" -RuleType Equal -ConditionValue "A" -ForegroundColor White -BackgroundColor Green
    Add-ConditionalFormatting -Worksheet $Pkg.Workbook.Worksheets["Inventory"] -Address "G:G" -RuleType Equal -ConditionValue "C" -ForegroundColor Black -BackgroundColor Orange
    Add-ConditionalFormatting -Worksheet $Pkg.Workbook.Worksheets["Inventory"] -Address "G:G" -RuleType Equal -ConditionValue "F" -ForegroundColor White -BackgroundColor Red
    Close-ExcelPackage -ExcelPackage $Pkg
    Write-Host "[+] Success! Report saved: $ExcelPath" -ForegroundColor Green
} catch { Write-Error "Export failed: $($_.Exception.Message)" }