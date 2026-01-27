<#
.SYNOPSIS
    IISentinel Pro v3.1 - Full Security & Protocol Auditor
    Restored: Full Discovery, SAN, Domain Analysis, Remediation.
    Added: TLS 1.0/1.1 Detection, Protocol Drift, Stable Export.
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
if (-not (Get-Module -ListAvailable -Name ImportExcel)) { Throw "ImportExcel module required." }

$RunDate = Get-Date
$TimeStamp = $RunDate.ToString("yyyyMMdd-HHmm")
$ExcelPath = Join-Path $OutputPath "IISentinel_Security_Audit_$TimeStamp.xlsx"

# 2) Full Discovery Logic (Restored)
Write-Host "[*] Discovering targets..." -ForegroundColor Cyan
$Targets = [System.Collections.Generic.List[string]]::new()
if ($ServerNames) { $Targets.AddRange($ServerNames) }
if ($OU) {
    try {
        $adComputers = Get-ADComputer -SearchBase $OU -SearchScope Subtree -Filter { Enabled -eq $true } | Select-Object -ExpandProperty Name
        if ($adComputers) { [string[]]$adArray = $adComputers; $Targets.AddRange($adArray) }
    } catch { Write-Warning "AD Search failed. Check RSAT tools." }
}
$UniqueTargets = $Targets | Sort-Object -Unique

Write-Host "[*] Verifying connectivity for $($UniqueTargets.Count) servers..." -ForegroundColor Cyan
$OnlineServers = $UniqueTargets | Where-Object { Test-Connection -ComputerName $_ -Count 1 -Quiet }

if (-not $OnlineServers) { Write-Error "No servers responded to ping. Exiting."; return }

# 3) Remote Audit Logic (Full Restored + TLS Add-on)
$RemoteScript = {
    param($WarningDays)
    Import-Module WebAdministration -ErrorAction SilentlyContinue
    function Norm-Thumb ($t) { if($t){$t.Replace(" ","").Replace(":","").ToUpper()} }
    
    # TLS Check
    $tls10 = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -Name Enabled -ErrorAction SilentlyContinue
    $tls11 = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" -Name Enabled -ErrorAction SilentlyContinue
    $weakTLS = ($tls10.Enabled -eq 1 -or $tls11.Enabled -eq 1)

    $certMap = @{}
    Get-ChildItem Cert:\LocalMachine -Recurse | Where-Object { $_.Thumbprint } | ForEach-Object {
        if (-not $certMap.ContainsKey($_.Thumbprint)) { $certMap[$_.Thumbprint] = $_ }
    }
    
    $results = @()
    $sites = Get-ChildItem IIS:\Sites
    foreach ($site in $sites) {
        $hasHttps = $false; $hasHttp = $false
        $redirect = (Get-WebConfigurationProperty -pspath "IIS:\Sites\$($site.Name)" -filter "system.webServer/httpRedirect" -name "enabled").Value

        foreach ($bind in $site.Bindings.Collection) {
            $parts = $bind.bindingInformation -split ":"
            $port = $parts[1]
            $grade = "A"; $guidance = "Healthy"; $risk = @(); $certData = $null
            
            if ($bind.protocol -eq "https") {
                $hasHttps = $true
                if ($port -ne "443") { $grade = "B"; $risk += "NonStandardPort($port)" }
                if ($weakTLS) { $grade = "C"; $risk += "WeakTLS(1.0/1.1)" }

                $hash = Norm-Thumb (($bind.certificateHash | ForEach-Object { $_.ToString("X2") }) -join "")
                if ([string]::IsNullOrEmpty($hash)) {
                    $sni = Get-Item "IIS:\SslBindings\*!$port" -ErrorAction SilentlyContinue
                    $hash = Norm-Thumb $sni.Thumbprint
                }

                if ($hash -and $certMap.ContainsKey($hash)) {
                    $c = $certMap[$hash]; $days = [math]::Round(($c.NotAfter-(Get-Date)).TotalDays)
                    
                    # SAN Expansion
                    $sanList = ""
                    $sanExt = $c.Extensions | Where-Object { $_.Oid.FriendlyName -match "Subject Alternative Name" }
                    if ($sanExt) { $sanList = ($sanExt.Format($false) -split "," | ForEach-Object { $_.Trim().Replace("DNS Name=", "") }) -join ", " }

                    if ($days -lt 0) { $grade = "F"; $guidance = "EXPIRED: Replace immediately." }
                    elseif ($days -lt 30) { $grade = "B"; $guidance = "Renew within 30 days." }
                    $certData = [pscustomobject]@{ Sub=$c.Subject; SAN=$sanList; Days=$days }
                } else { $grade = "F"; $guidance = "CRITICAL: Cert missing from store." }
            }
            elseif ($bind.protocol -eq "http") { $hasHttp = $true }

            $results += [pscustomobject]@{ 
                ServerName=$env:COMPUTERNAME; SiteName=$site.Name; Protocol=$bind.protocol; Port=$port;
                CertSubject=if($certData){$certData.Sub}else{"N/A"}; SAN=if($certData){$certData.SAN}else{"N/A"};
                DaysLeft=if($certData){$certData.Days}else{$null}; Grade=$grade; Remediation=$guidance; Risk=($risk -join ",")
            }
        }
        if ($hasHttp -and $hasHttps -and -not $redirect) {
            $results += [pscustomobject]@{ 
                ServerName=$env:COMPUTERNAME; SiteName=$site.Name; Protocol="SECURITY_GAP"; Port="80";
                CertSubject="N/A"; SAN="N/A"; DaysLeft=$null; Grade="C"; 
                Remediation="INSECURE: Port 80 open without Redirect."; Risk="MissingRedirect"
            }
        }
    }
    return $results
}

Write-Host "[*] Auditing $($OnlineServers.Count) servers via WinRM..." -ForegroundColor Cyan
$Inventory = Invoke-Command -ComputerName $OnlineServers -Credential $Credential -ScriptBlock $RemoteScript -ArgumentList $WarningDays -ThrottleLimit 20 -ErrorAction SilentlyContinue | Select-Object ServerName, SiteName, Protocol, Port, CertSubject, SAN, DaysLeft, Grade, Remediation, Risk

# 4) Analytics
$DomainSummary = $Inventory | Where-Object { $_.CertSubject -ne "N/A" } | Group-Object CertSubject | 
                 Select-Object @{N="Certificate Domain";E={$_.Name}}, @{N="UsageCount";E={$_.Count}} | 
                 Sort-Object UsageCount -Descending | Select-Object -First 10

$HealthScore = "{0:P0}" -f (($Inventory | Where-Object {$_.Grade -match "A|B"}).Count / $Inventory.Count)

$DashboardData = @(
    [pscustomobject]@{ "Metric" = "Fleet Health Score"; "Value" = $HealthScore }
    [pscustomobject]@{ "Metric" = "Total Bindings Audited"; "Value" = $Inventory.Count }
    [pscustomobject]@{ "Metric" = "Total Security Issues (C/F)"; "Value" = ($Inventory | Where-Object {$_.Grade -match "C|F"}).Count }
)

# 5) Consolidated Export (One-Pass, No re-opening)
try {
    Write-Host "[*] Saving Comprehensive Security Audit..." -ForegroundColor Cyan
    
    # First sheet establishes the file
    $Pkg = $Inventory | Sort-Object Grade -Descending | Export-Excel -Path $ExcelPath -WorksheetName "Inventory" -TableStyle Medium2 -AutoSize -BoldTopRow -PassThru
    
    # Add Dashboard
    $DashboardData | Export-Excel -ExcelPackage $Pkg -WorksheetName "Dashboard" -Title "POSTURE SUMMARY" -TitleBold -TitleSize 16 -AutoSize
    
    # Add Domain Analysis
    $DomainSummary | Export-Excel -ExcelPackage $Pkg -WorksheetName "Dashboard" -StartRow 7 -TableName "DomainUsage" -AutoSize

    # Cleanup & Formatting
    $Pkg.Workbook.Worksheets.MoveToStart("Dashboard")
    $Pkg.Workbook.Worksheets["Dashboard"].View.TabSelected = $true
    
    $invSheet = $Pkg.Workbook.Worksheets["Inventory"]
    if ($invSheet) {
        # Column H is Grade in this full layout
        Add-ConditionalFormatting -Worksheet $invSheet -Address "H:H" -RuleType Equal -ConditionValue "A" -ForegroundColor White -BackgroundColor Green
        Add-ConditionalFormatting -Worksheet $invSheet -Address "H:H" -RuleType Equal -ConditionValue "C" -ForegroundColor Black -BackgroundColor Orange
        Add-ConditionalFormatting -Worksheet $invSheet -Address "H:H" -RuleType Equal -ConditionValue "F" -ForegroundColor White -BackgroundColor Red
    }
    
    Close-ExcelPackage -ExcelPackage $Pkg
    Write-Host "[+] Success! Report saved: $ExcelPath" -ForegroundColor Green
} catch { Write-Error "Export failed: $($_.Exception.Message)" }