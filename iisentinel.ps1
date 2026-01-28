<#
.SYNOPSIS
    IISentinel Pro v3.3 - Atomic Export Edition
    Fix: Uses a single ExcelPackage session to prevent "Worksheet Not Found" errors.
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
$ExcelPath = Join-Path $OutputPath "IISentinel_Security_Audit_$TimeStamp.xlsx"

# 2) Discovery
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
$OnlineServers = $UniqueTargets | Where-Object { Test-Connection -ComputerName $_ -Count 1 -Quiet }

if (-not $OnlineServers) { Write-Error "No servers responded to ping."; return }

# 3) Remote Audit Logic
$RemoteScript = {
    param($WarningDays)
    $results = @()
    if (-not (Get-Module -Name WebAdministration)) { Import-Module WebAdministration -ErrorAction SilentlyContinue }
    if (-not (Test-Path IIS:\Sites)) { return $null }

    $tls10 = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -Name Enabled -ErrorAction SilentlyContinue
    $tls11 = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" -Name Enabled -ErrorAction SilentlyContinue
    $weakTLS = ($tls10.Enabled -eq 1 -or $tls11.Enabled -eq 1)

    $certMap = @{}
    Get-ChildItem Cert:\LocalMachine -Recurse | Where-Object { $_.Thumbprint } | ForEach-Object {
        if (-not $certMap.ContainsKey($_.Thumbprint)) { $certMap[$_.Thumbprint] = $_ }
    }
    
    foreach ($site in (Get-ChildItem IIS:\Sites)) {
        $hasHttps = $false; $hasHttp = $false
        $redirect = (Get-WebConfigurationProperty -pspath "IIS:\Sites\$($site.Name)" -filter "system.webServer/httpRedirect" -name "enabled").Value

        foreach ($bind in $site.Bindings.Collection) {
            $port = ($bind.bindingInformation -split ":")[1]
            $grade = "A"; $guidance = "Healthy"; $risk = @(); $certData = $null
            
            if ($bind.protocol -eq "https") {
                $hasHttps = $true
                if ($port -ne "443") { $grade = "B"; $risk += "NonStandardPort" }
                if ($weakTLS) { $grade = "C"; $risk += "WeakTLS" }

                $hash = ""
                if ($bind.certificateHash) { $hash = [System.BitConverter]::ToString($bind.certificateHash).Replace("-","").ToUpper() }

                if ($hash -and $certMap.ContainsKey($hash)) {
                    $c = $certMap[$hash]; $days = [math]::Round(($c.NotAfter-(Get-Date)).TotalDays)
                    $sanList = ""
                    $sanExt = $c.Extensions | Where-Object { $_.Oid.FriendlyName -match "Subject Alternative Name" }
                    if ($sanExt) { $sanList = ($sanExt.Format($false) -split "," | ForEach-Object { $_.Trim().Replace("DNS Name=", "") }) -join ", " }

                    if ($days -lt 0) { $grade = "F"; $guidance = "EXPIRED" }
                    elseif ($days -lt 30) { $grade = "B"; $guidance = "Renew Soon" }
                    $certData = [pscustomobject]@{ Sub=$c.Subject; SAN=$sanList; Days=$days }
                } else { $grade = "F"; $guidance = "Cert Missing" }
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
                CertSubject="N/A"; SAN="N/A"; DaysLeft=$null; Grade="C"; Remediation="Missing Redirect"; Risk="InsecureHTTP"
            }
        }
    }
    return $results
}

Write-Host "[*] Auditing $($OnlineServers.Count) servers via WinRM..." -ForegroundColor Cyan
$Inventory = Invoke-Command -ComputerName $OnlineServers -Credential $Credential -ScriptBlock $RemoteScript -ArgumentList $WarningDays -ThrottleLimit 20 -ErrorAction SilentlyContinue | 
             Where-Object { $_.ServerName } | 
             Select-Object ServerName, SiteName, Protocol, Port, CertSubject, SAN, DaysLeft, Grade, Remediation, Risk

# 4) Analytics
$TotalSites = if ($Inventory) { $Inventory.Count } else { 0 }
if ($TotalSites -eq 0) { Write-Error "No IIS data returned."; return }

$HealthScore = "{0:P0}" -f (($Inventory | Where-Object { $_.Grade -match "A|B" }).Count / $TotalSites)
$DomainSummary = $Inventory | Where-Object { $_.CertSubject -ne "N/A" } | Group-Object CertSubject | 
                 Select-Object @{N="Certificate Domain";E={$_.Name}}, @{N="UsageCount";E={$_.Count}} | 
                 Sort-Object UsageCount -Descending | Select-Object -First 10

$DashboardData = @(
    [pscustomobject]@{ "Metric" = "Fleet Health Score"; "Value" = $HealthScore }
    [pscustomobject]@{ "Metric" = "Total Bindings Audited"; "Value" = $TotalSites }
    [pscustomobject]@{ "Metric" = "Security Issues (C/F)"; "Value" = ($Inventory | Where-Object {$_.Grade -match "C|F"}).Count }
)

# -------------------------------------------------------------------------
# 5) Atomic Export (The "One-Save" Method)
# -------------------------------------------------------------------------
try {
    Write-Host "[*] Generating Report in memory..." -ForegroundColor Cyan
    
    # 1. Create a blank Excel Package object first
    $Pkg = New-Object OfficeOpenXml.ExcelPackage

    # 2. Add Dashboard Sheet and Data
    $DashSheet = $Pkg.Workbook.Worksheets.Add("Dashboard")
    $DashboardData | Export-Excel -ExcelPackage $Pkg -WorksheetName "Dashboard" -Title "POSTURE SUMMARY" -TitleBold -TitleSize 16 -AutoSize
    $DomainSummary | Export-Excel -ExcelPackage $Pkg -WorksheetName "Dashboard" -StartRow 7 -TableName "DomainUsage" -AutoSize

    # 3. Add Inventory Sheet and Data
    $InvSheet = $Pkg.Workbook.Worksheets.Add("Inventory")
    $Inventory | Sort-Object Grade -Descending | Export-Excel -ExcelPackage $Pkg -WorksheetName "Inventory" -TableStyle Medium2 -AutoSize -BoldTopRow

    # 4. Apply Formatting while the package is still in memory
    # Note: Using Column H for Grade
    Add-ConditionalFormatting -Worksheet $InvSheet -Address "H:H" -RuleType Equal -ConditionValue "A" -ForegroundColor White -BackgroundColor Green
    Add-ConditionalFormatting -Worksheet $InvSheet -Address "H:H" -RuleType Equal -ConditionValue "C" -ForegroundColor Black -BackgroundColor Orange
    Add-ConditionalFormatting -Worksheet $InvSheet -Address "H:H" -RuleType Equal -ConditionValue "F" -ForegroundColor White -BackgroundColor Red

    # 5. Save the file ONCE
    Write-Host "[*] Committing to disk: $ExcelPath" -ForegroundColor Cyan
    $Pkg.SaveAs($ExcelPath)
    $Pkg.Dispose()
    
    Write-Host "[+] Success! Report saved." -ForegroundColor Green
} catch {
    Write-Error "Export failed: $($_.Exception.Message)"
}