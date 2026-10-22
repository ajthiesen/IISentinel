# IISentinel

**IISentinel** is an automated enterprise security auditing suite designed to scan, assess, and report on IIS Web Server configurations and SSL/TLS security health across Active Directory environments.

IISentinel queries target servers over WinRM to collect detailed cryptographic binding profiles, certificate health data, and web application security settings, generating executive-ready Excel reports equipped with risk scores, dynamic charts, and automated PowerShell remediation scripts.

---

## Table of Contents

* [Key Features](#key-features)
* [Report Structure](#report-structure)
* [Architecture & Workflow](#architecture--workflow)
* [Prerequisites](#prerequisites)
* [Installation](#installation)
* [Usage](#usage)
  * [Interactive Execution](#interactive-execution)
  * [Targeting Methods](#targeting-methods)
* [Troubleshooting](#troubleshooting)
* [Version History](#version-history)
* [Contributing](#contributing)
* [License](#license)

---

## Key Features

* **Comprehensive IIS & SSL/TLS Audit**: Audits HTTPS bindings, certificate expiration, signature algorithms, thumbprints, and Centralized Certificate Store (CCS) usage.
* **Automated Excel Reporting**: Generates interactive dashboards with health scores and charts without requiring Microsoft Excel installed locally (powered by `ImportExcel`).
* **Automated Remediation Scripts**: Generates tailored PowerShell scripts to resolve identified SSL/TLS vulnerabilities across target servers.
* **Flexible Target Discovery**: Supports targeted scans via explicit host lists (`servers.txt`) or dynamic Active Directory Organizational Unit (OU) queries.
* **Connectivity & Health Tracking**: Includes a dedicated audit tab for offline or unreachable hosts to streamline network troubleshooting.

---

## Report Structure

The generated Excel workbook includes four dedicated worksheets:

1. **Dashboard**: High-level executive overview featuring a aggregated Health Score, risk distribution summary, and visual charts.
2. **Inventory**: In-depth configuration audit listing web bindings, certificate thumbprints, expiration dates, hash algorithms, and associated security risks.
3. **Remediation Plan**: Actionable PowerShell commands customized to fix identified non-compliant configurations on affected servers.
4. **Connectivity Log**: Audit log tracking unreachable assets, WinRM connection failures, and missing certificates.

---

## Architecture & Workflow

```
                        +---------------------------+
                        |    Launch Run_Audit.cmd   |
                        +-------------+-------------+
                                      |
                                      v
                        +---------------------------+
                        |  Prompt for Client Name & |
                        |    Target Selection Method|
                        +-------------+-------------+
                                      |
                 +--------------------+--------------------+
                 |                                         |
                 v                                         v
       [ Option 1: servers.txt ]                [ Option 2: Active Directory ]
       Read list of hostnames/IPs               Query target OU via LDAP
                 |                                         |
                 +--------------------+--------------------+
                                      |
                                      v
                        +---------------------------+
                        | Execute WinRM Audit Scan  |
                        | (IIS, Binding, Cert Store)|
                        +-------------+-------------+
                                      |
                                      v
                        +---------------------------+
                        |  Generate Excel Report    |
                        | (Dashboard, Fixes, Logs)  |
                        +---------------------------+
```

---

## Prerequisites

Before running IISentinel Pro, ensure the following requirements are met on the host running the audit and on the target servers:

### Management Host Requirements
* **Operating System**: Windows 10/11 or Windows Server 2016+
* **PowerShell**: Version 5.1 or higher
* **PowerShell Module**: `ImportExcel`
  ```powershell
  Install-Module ImportExcel -Scope CurrentUser -Force
  ```

### Target Server Requirements
* **Windows Remote Management (WinRM)** enabled on target IIS servers.
* Administrative privileges on target machines for remote configuration access.

---

## Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/ajthiesen/IISentinel.git
   cd IISentinel
   ```

2. **Verify Prerequisites**:
   Ensure the `ImportExcel` module is installed:
   ```powershell
   Get-Module -ListAvailable ImportExcel
   ```

---

## Usage

### Interactive Execution

1. Double-click **`Run_Audit.cmd`** or launch it from an elevated PowerShell prompt:
   ```cmd
   .\Run_Audit.cmd
   ```
2. Enter the **Client Name** when prompted (used for branding the final Excel report).
3. Select the desired targeting method.
4. Provide administrative credentials when prompted for WinRM authentication.

### Targeting Methods

* **Option 1 (Static List)**: Populate `servers.txt` in the root script folder with one FQDN or IP address per line:
  ```text
  webserver01.corp.domain.com
  webserver02.corp.domain.com
  192.168.1.50
  ```
* **Option 2 (Active Directory OU)**: Enter the Distinguished Name (DN) of an Active Directory OU containing target servers:
  ```text
  OU=WebServers,OU=Servers,DC=corp,DC=domain,DC=com
  ```

---

## Troubleshooting

| Issue / Output | Possible Cause | Resolution |
| :--- | :--- | :--- |
| **"N/A" in Inventory** | Target server is offline or the SSL certificate is missing from the local store. | Check the 'Risk' and 'Connectivity Log' columns to confirm network accessibility. |
| **"WinRM Denied"** | Executing user lacks administrative privileges or WinRM is disabled on the target. | Verify administrative rights and ensure `Enable-PSRemoting` has been executed on the target server. |
| **"CCS:Managed"** | The site uses a Centralized Certificate Store (CCS). | Informational status; CCS certificates are managed centrally and can be evaluated on the CCS share. |

---

## Version History

* **v4.9**
  * Cleaned up Inventory structure (redundant protocol columns removed).
  * Added universal hash computation fix for certificate validation.
  * Enhanced `WebHosting` certificate store search scope.
* **v4.0 - v4.8**
  * Added dynamic Active Directory OU discovery.
  * Integrated executive dashboard with automatic health scoring.
  * Added automated PowerShell remediation script generator.

---

## Contributing

Contributions, feature suggestions, and pull requests are welcome!

1. Fork the repository.
2. Create your feature branch (`git checkout -b feature/NewFeature`).
3. Commit your changes (`git commit -m 'Add NewFeature'`).
4. Push to the branch (`git push origin feature/NewFeature`).
5. Open a Pull Request.

---

## License

This project is licensed under the [MIT License](LICENSE).
