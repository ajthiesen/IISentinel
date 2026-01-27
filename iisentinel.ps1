<#
.SYNOPSIS
    IISentinel Pro v3.1.2 - Data Recovery & Full Auditor
    Fix: Forced module loading and direct provider access to ensure data return.
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

# 2) Full Discovery Logic
Write-Host "[*] Discovering targets..." -ForegroundColor Cyan
$Targets = [System.Collections.Generic.List[string]]::new()
if ($ServerNames) { $Targets.AddRange($ServerNames) }
if ($OU) {
    try {
        $adComputers = Get-ADComputer -SearchBase $OU -SearchScope Subtree -Filter { Enabled -eq $true } | Select-Object -ExpandProperty Name
        if ($adComputers) { [string[]]$adArray = $adComputers; $Targets.AddRange($adArray) }
    } catch { Write-Warning "AD Search failed." }
}
$UniqueTargets = $Targets | Sort-Object -Unique

Write-Host "[*] Verifying connectivity for $($UniqueTargets.Count) servers..." -ForegroundColor Cyan
$OnlineServers = $UniqueTargets | Where-Object { Test-Connection -ComputerName $_ -Count 1 -Quiet }

if (-not $OnlineServers) { Write-Error "No servers responded to ping."; return }

# 3) Remote Audit Logic (Hardened)
$RemoteScript = {
    param($WarningDays)
    $results = @()
    # Force load the module or use the WebAdministration drive directly
    if (-not (Get-Module -Name WebAdministration)) {
        Import-Module WebAdministration -ErrorAction SilentlyContinue
    }
    
    # Validation Check: If IIS provider isn't available, we can't scan
    if (-not (Test-Path IIS:\Sites)) {
        return [pscustomobject]@{ ServerName=$env:COMPUTERNAME; SiteName="ERROR"; Protocol="IIS_NOT_FOUND"; Port="N/A"; Grade="F"; Remediation="IIS Module failed to load or IIS not installed."; Risk="ConfigError" }
    }

    function Norm-Thumb ($t) { if($t){$t.Replace(" ","").Replace(":","").ToUpper()} }
    
    # TLS Check
    $tls10 = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -Name Enabled -ErrorAction SilentlyContinue
    $tls11 = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" -Name Enabled -ErrorAction SilentlyContinue
    $weakTLS = ($tls10.Enabled -eq 1 -or $tls11.Enabled -eq 1)

    $certMap = @{}
    Get-ChildItem Cert:\LocalMachine -Recurse | Where-Object { $_.Thumbprint } | ForEach-Object {
        if (-not $certMap.ContainsKey($_.Thumbprint)) { $certMap[$_.Thumbprint] = $_ }
    }
    
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
                if ($port -ne "443") { $grade = "B"; $risk += "NonStandardPort" }
                if ($weakTLS) { $grade = "C"; $risk += "WeakTLS" }

                $hash = Norm-Thumb (($bind.certificateHash | ForEach-Object { $_.ToString("X2") }) -join "")
                if ([string]::IsNullOrEmpty($hash)) {
                    $sni = Get-Item "IIS:\SslBindings\*!$port" -ErrorAction SilentlyContinue
                    $hash = Norm-Thumb $sni.Thumbprint
                }

                if ($hash -and $certMap.ContainsKey($hash)) {
                    $c = $certMap[$hash]; $days = [math]::Round(($c.NotAfter-(Get-Date)).TotalDays)
                    $sanList = ""
                    $sanExt = $c.Extensions | Where-Object { $_.Oid.FriendlyName -match "Subject Alternative Name" }
                    if ($sanExt) { $sanList = ($sanExt.Format($false) -split "," | ForEach-Object { $_.Trim().Replace("DNS Name=", "") }) -join ", " }

                    if ($days -lt 0) { $grade = "F"; $guidance = "EXPIRED" }
                    elseif ($days -lt 30) { $grade = "B"; $guidance = "Renew Soon" }
                    $certData = [pscustomobject]@{ Sub=$c.Subject; SAN=$sanList; Days=$days }
                } else { $grade = "F"; $guidance = "Cert missing." }
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
                Remediation="Missing HTTPS Redirect."; Risk="InsecureHTTP"
            }
        }
    }
    # Fallback: If a server has sites but none were HTTPS, at least return the HTTP sites so we know it scanned
    return $results
}

Write-Host "[*] Auditing $($OnlineServers.Count) servers via WinRM..." -ForegroundColor Cyan
# Capture the output into an array explicitly
$RawInventory = Invoke-Command -ComputerName $OnlineServers -Credential $Credential -ScriptBlock $RemoteScript -ArgumentList $WarningDays -ThrottleLimit 20 
$Inventory = $RawInventory | Select-Object ServerName, SiteName, Protocol, Port, CertSubject, SAN, DaysLeft, Grade, Remediation, Risk

# 4) Analytics
$TotalSites = if ($Inventory) { $Inventory.Count } else { 0 }

if ($TotalSites -gt 0) {
    $HealthScore = "{0:P0}" -f (($Inventory | Where-Object { $_.Grade -match "A|B" }).Count / $TotalSites)
    $DomainSummary = $Inventory | Where-Object { $_.CertSubject -ne "N/A" } | Group-Object CertSubject | 
                     Select-Object @{N="Certificate Domain";E={$_.Name}}, @{N="UsageCount";E={$_.Count}} | 
                     Sort-Object UsageCount -Descending | Select-Object -First 10
} else {
    $HealthScore = "0%"; $DomainSummary = @()
}

$DashboardData = @(
    [pscustomobject]@{ "Metric" = "Fleet Health Score"; "Value" = $HealthScore }
    [pscustomobject]@{ "Metric" = "Total Bindings Audited"; "Value" = $TotalSites }
    [pscustomobject]@{ "Metric" = "Security Issues (C/F)"; "Value" = if($Inventory){($Inventory | Where-Object {$_.Grade -match "C|F"}).Count}else{0} }
)

# 5) Consolidated Export
try {
    Write-Host "[*] Saving Comprehensive Security Audit..." -ForegroundColor Cyan
    # Build everything in one pass to avoid the Range error
    $Pkg = $Inventory | Sort-Object Grade -Descending | Export-Excel -Path $ExcelPath -WorksheetName "Inventory" -TableStyle Medium2 -AutoSize -BoldTopRow -PassThru
    $DashboardData | Export-Excel -ExcelPackage $Pkg -WorksheetName "Dashboard" -Title "POSTURE SUMMARY" -TitleBold -TitleSize 16 -AutoSize
    if ($DomainSummary) { $DomainSummary | Export-Excel -ExcelPackage $Pkg -WorksheetName "Dashboard" -StartRow 7 -TableName "DomainUsage" -AutoSize }

    $Pkg.Workbook.Worksheets.MoveToStart("Dashboard")
    $ws = $Pkg.Workbook.Worksheets["Inventory"]
    if ($ws) {
        Add-ConditionalFormatting -Worksheet $ws -Address "H:H" -RuleType Equal -ConditionValue "A" -ForegroundColor White -BackgroundColor Green
        Add-ConditionalFormatting -Worksheet $ws -Address "H:H" -RuleType Equal -ConditionValue "C" -ForegroundColor Black -BackgroundColor Orange
        Add-ConditionalFormatting -Worksheet $ws -Address "H:H" -RuleType Equal -ConditionValue "F" -ForegroundColor White -BackgroundColor Red
    }
    Close-ExcelPackage -ExcelPackage $Pkg
    Write-Host "[+] Success! Report saved: $ExcelPath" -ForegroundColor Green
} catch { Write-Error "Export failed: $($_.Exception.Message)" }