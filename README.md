# IISentinel

============================================================
 IISENTINEL PRO v4.9 - SECURITY AUDIT SUITE
============================================================

[OVERVIEW]
This tool audits IIS Web Servers for SSL/TLS security configuration.
It generates a professional Excel report with:
 - Dashboard (Health Score & Charts)
 - Inventory (Deep configuration scan)
 - Remediation Plan (PowerShell fixes for identified risks)
 - Connectivity Log (Tracks offline/unreachable assets)

[PREREQUISITES]
1. PowerShell 5.1 or higher.
2. The "ImportExcel" PowerShell module must be installed.
   (Run: Install-Module ImportExcel -Scope CurrentUser)
3. Admin Rights on the target servers (for WinRM access).

[HOW TO RUN]
1. Double-click "Run_Audit.cmd".
2. Enter the Client Name (this brands the report).
3. Choose your target method:
   - Option 1: Uses 'servers.txt' (Create this file with one server per line).
   - Option 2: Prompts for an Active Directory OU Distinguished Name.
4. Enter your Admin Credentials when prompted.

[TROUBLESHOOTING]
- "N/A" in Inventory: Usually means the server is offline or the certificate 
  is missing from the local store (check the 'Risk' column).
- "WinRM Denied": Verify you have Admin rights and WinRM is enabled on the target.
- "CCS:Managed": The site uses a Centralized Certificate Store (safe to ignore).

[VERSION HISTORY]
v4.9: Clean Inventory (Protocol removed), Universal Hash Fix, WebHosting Search.