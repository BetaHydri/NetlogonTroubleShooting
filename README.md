# NetlogonTroubleShooting

![PowerShell 5.1](https://img.shields.io/badge/PowerShell-5.1-blue?logo=powershell&logoColor=white)
![PowerShell 7.x](https://img.shields.io/badge/PowerShell-7.x-blue?logo=powershell&logoColor=white)
![Platform: Windows](https://img.shields.io/badge/Platform-Windows-0078D6?logo=windows&logoColor=white)
![License: MIT](https://img.shields.io/badge/License-MIT-green)
![Version: 1.2.0](https://img.shields.io/badge/Version-1.2.0-brightgreen)
![Pester Tests](https://img.shields.io/badge/Pester-Passing-success?logo=dotnet)
![Active Directory](https://img.shields.io/badge/Active%20Directory-Netlogon-orange)

A PowerShell module for diagnosing and troubleshooting **Netlogon** issues in Active Directory environments. It parses event logs (e.g. 5719, 5805), manages Netlogon debug logging, and tests secure channel health — all with human-readable output and actionable remediation guidance.

---

## Features

- **Event Log Parsing** — Query and enrich Netlogon-related events (5719, 5783, 5805, 5722, 5723, 5721, 5781, 3210) with plain-English descriptions and recommended actions.
- **Debug Log Management** — Enable/disable Netlogon debug logging via registry with configurable verbosity levels.
- **Debug Log Reader** — Parse `netlogon.log` into structured objects, filter by category (Authentication, DC Discovery, DNS, Secure Channel), and surface errors.
- **Secure Channel Testing** — Test and repair the Netlogon secure channel with detailed diagnostic output.
- **DC Port Connectivity** — Test all required AD/Netlogon ports (53, 88, 135, 389, 445, 464, 636, 3268, 3269) against discovered DCs.
- **DNS Record Validation** — Verify critical SRV and A records (`_ldap._tcp.dc._msdcs`, `_kerberos._tcp`, `_gc._tcp`, site-specific) are resolvable.
- **Time Synchronization** — Check time skew between a computer and its authenticating DC (Kerberos 5-minute tolerance).
- **DC Locator Diagnostics** — Parsed `nltest /dsgetdc` output with flags for force rediscovery, site, PDC, KDC, time server, and writable DC.
- **AD Site Information** — Show site assignment, subnet mapping, and DCs in the site. Detect `NO_CLIENT_SITE` conditions.
- **Comprehensive Diagnostic Report** — One-shot `Invoke-NetlogonDiagnostic` combining all checks into a text or HTML report.
- **Remote Support** — All commands accept `-ComputerName` for remote execution via PowerShell Remoting (WinRM).

---

## Requirements

| Requirement | Minimum |
|---|---|
| PowerShell | 5.1 |
| OS | Windows (domain-joined or hybrid for full functionality) |
| Privileges | Administrator (for Enable/Disable debug logging) |
| Pester | 5.x (for running tests) |

---

## Installation

```powershell
# Clone or copy to a module path
Copy-Item -Path .\NetlogonTroubleShooting -Destination "$env:USERPROFILE\Documents\PowerShell\Modules\" -Recurse

# Import the module
Import-Module NetlogonTroubleShooting
```

---

## Functions

| Function | Description |
|---|---|
| `Get-NetlogonEvent` | Retrieves and enriches Netlogon events from the System event log |
| `Enable-NetlogonDebug` | Enables Netlogon debug logging (sets DBFlag in registry) |
| `Disable-NetlogonDebug` | Disables Netlogon debug logging |
| `Get-NetlogonDebugStatus` | Checks the current debug logging configuration and log file status |
| `Read-NetlogonDebugLog` | Parses netlogon.log into structured, filterable objects |
| `Get-NetlogonStatus` | Gets comprehensive Netlogon service and secure channel status |
| `Test-NetlogonSecureChannel` | Tests and optionally repairs the secure channel |
| `Test-DCPortConnectivity` | Tests all required AD/Netlogon TCP ports against DCs |
| `Test-NetlogonDnsRecords` | Validates critical AD DNS SRV and A records |
| `Test-TimeSynchronization` | Checks time skew between a computer and its authenticating DC |
| `Get-DCLocatorInfo` | Parsed DC locator output with force rediscovery, site, PDC, KDC flags |
| `Get-ADSiteInfo` | Shows AD site assignment, subnets, and DCs in the site |
| `Invoke-NetlogonDiagnostic` | Runs all checks and produces a consolidated text or HTML report |

---

## Usage & Sample Output

### Get-NetlogonEvent

Retrieves Netlogon-related events from the Windows event log with human-readable summaries and remediation steps.

```powershell
# All Netlogon events from the last 24 hours
Get-NetlogonEvent

# Only Event ID 5719, last 7 days
Get-NetlogonEvent -EventId 5719 -StartTime (Get-Date).AddDays(-7)

# Remote query
Get-NetlogonEvent -ComputerName 'DC01' -MaxEvents 20
```

**Sample Output:**

```
ComputerName : DC01
TimeCreated  : 03/11/2026 08:15:32
EventId      : 5719
Level        : Error
Summary      : No Domain Controller available for secure session setup
Description  : This computer was not able to set up a secure session with a domain
               controller in the domain. This is commonly caused by network connectivity
               issues, DNS resolution failures, or the Netlogon service not running on
               the DC.
Message      : This computer was not able to set up a secure session with a domain
               controller in domain CONTOSO due to the following: There are currently
               no logon servers available to service the logon request.
Action       : Verify network connectivity to domain controllers (ping, tracert).
               Verify DNS resolution: nslookup <domain> and nslookup -type=SRV
               _ldap._tcp.dc._msdcs.<domain>
               Check that the Netlogon service is running on domain controllers.
               Verify the computer account password is in sync (Test-ComputerSecureChannel).
               Check firewall rules for ports 88, 135, 389, 445, 636, 3268, 49152-65535.
ProviderName : NETLOGON
```

---

### Enable-NetlogonDebug / Disable-NetlogonDebug

Manage Netlogon debug logging through the registry. Requires elevation.
Changes are applied dynamically via `nltest /dbflag:` — no service restart required on modern Windows (Server 2012 R2+ / Windows 10+).

```powershell
# Enable full debug logging
Enable-NetlogonDebug

# Enable standard level
Enable-NetlogonDebug -Level Standard

# Enable on remote DCs
Enable-NetlogonDebug -ComputerName 'DC01', 'DC02'

# Disable debug logging
Disable-NetlogonDebug
```

**Sample Output (Enable):**

```
ComputerName : SERVER01
DebugEnabled : True
Level        : Full
DBFlag       : 0x2080FFFF
MaxLogSize   : 268435456
LogPath      : \\SERVER01\admin$\debug\netlogon.log
Restarted    : False

Netlogon debug logging ENABLED on SERVER01 (Level: Full).
Log location: C:\Windows\debug\netlogon.log
```

**Sample Output (Disable):**

```
ComputerName : SERVER01
DebugEnabled : False
Level        : Disabled
DBFlag       : 0x0
Restarted    : False

Netlogon debug logging DISABLED on SERVER01.
```

---

### Get-NetlogonDebugStatus

Check whether debug logging is active, the configured level, and log file sizes.

```powershell
Get-NetlogonDebugStatus
Get-NetlogonDebugStatus -ComputerName 'DC01', 'DC02'
```

**Sample Output:**

```
ComputerName    : DC01
DebugEnabled    : True
Level           : Full
DBFlag          : 0x2080FFFF
MaxLogSizeBytes : 268435456
LogFileExists   : True
LogFileSizeMB   : 42.17
BakFileExists   : True
BakFileSizeMB   : 256.00
LogPath         : C:\Windows\debug\netlogon.log
```

---

### Read-NetlogonDebugLog

Parse the Netlogon debug log into structured objects with error detection and categorisation.

```powershell
# Show only errors
Read-NetlogonDebugLog -ErrorsOnly

# Filter by category
Read-NetlogonDebugLog -Category DCDiscovery -Last 50

# Include the backup log, entries from the last 2 hours
Read-NetlogonDebugLog -IncludeBackup -StartTime (Get-Date).AddHours(-2)

# Pipe errors to a table
Read-NetlogonDebugLog -ErrorsOnly | Format-Table Timestamp, Category, StatusCode, Message -AutoSize
```

**Sample Output:**

```
Found 347 entries (12 errors/failures).

SourceFile : netlogon.log
LineNumber : 1842
Timestamp  : 03/11/2026 09:22:14
LogType    : CRITICAL
ProcessId  : 1044
Category   : Authentication
IsError    : True
StatusCode : STATUS_NO_TRUST_SAM_ACCOUNT
Message    : NlPrintRpcDebug: Couldn't authenticate to \\DC02.contoso.com:
             STATUS_NO_TRUST_SAM_ACCOUNT
RawLine    : 03/11 09:22:14 [CRITICAL] [1044] NlPrintRpcDebug: Couldn't authenticate
             to \\DC02.contoso.com: STATUS_NO_TRUST_SAM_ACCOUNT
```

**Tabular errors view:**

```
Timestamp            Category       StatusCode                    Message
---------            --------       ----------                    -------
03/11/2026 09:22:14  Authentication STATUS_NO_TRUST_SAM_ACCOUNT   NlPrintRpcDebug: Couldn't auth...
03/11/2026 09:23:01  DCDiscovery    STATUS_NO_LOGON_SERVERS        DsGetDc: CONTOSO FAILED Status...
03/11/2026 09:25:44  SiteInfo       NO_CLIENT_SITE                 NO_CLIENT_SITE for 10.1.50.22
```

**Available categories:** `All`, `Authentication`, `DCDiscovery`, `SiteInfo`, `DnsRegistration`, `SecureChannel`

**Screenshot:**

![Read-NetlogonDebugLog sample output](docs/ReadNetlogon_sample.png)

---

### Get-NetlogonStatus

Get a comprehensive overview of the Netlogon service, secure channel, authenticating DC, site, and trusted domains.

```powershell
Get-NetlogonStatus
Get-NetlogonStatus -ComputerName 'Server01'
```

**Sample Output:**

```
ComputerName         : SERVER01
ServiceStatus        : Running
ServiceStartType     : Automatic
DomainName           : contoso.com
AuthenticatingDC     : DC01.contoso.com
DCAddress            : 10.0.0.10
SiteName             : Default-First-Site-Name
SecureChannelHealthy : True
SecureChannelTest    : True
DebugLoggingEnabled  : False
DebugLevel           : Disabled
SecureChannelDetails : Flags: 30 HAS_IP HAS_TIMESERV
                       Trusted DC Name \\DC01.contoso.com
                       Trusted DC Connection Status Status = 0 0x0 NERR_Success
TrustedDomains       : List of domain trusts:
                           0: CONTOSO contoso.com (NT 5) (Forest Tree Root) (Primary Domain)
                           1: CHILD child.contoso.com (NT 5) (Forest: 0)
```

---

### Test-NetlogonSecureChannel

Test the secure channel and optionally repair it if broken.

```powershell
# Test only
Test-NetlogonSecureChannel

# Test and repair
Test-NetlogonSecureChannel -Repair -Credential (Get-Credential)
```

**Sample Output (Healthy):**

```
ComputerName    : SERVER01
TestTime        : 03/11/2026 10:30:15
SecureChannelOK : True
NltestResult    : Flags: 30 HAS_IP HAS_TIMESERV
                  Trusted DC Name \\DC01.contoso.com
                  Trusted DC Connection Status Status = 0 0x0 NERR_Success
                  The command completed successfully
RepairAttempted : False
RepairResult    :
DCName          : DC01.contoso.com
Recommendations :

Secure channel on SERVER01 is HEALTHY.
```

**Screenshot (Healthy):**

![Test-NetlogonSecureChannel sample output](docs/NetlogonSChannelSample.png)

**Sample Output (Broken):**

```
ComputerName    : SERVER01
TestTime        : 03/11/2026 10:30:15
SecureChannelOK : False
NltestResult    : Flags: 0
                  Trusted DC Connection Status Status = 5 0x5 ERROR_ACCESS_DENIED
RepairAttempted : False
RepairResult    :
DCName          :
Recommendations : {Run: Test-ComputerSecureChannel -Repair -Credential (Get-Credential),
                  If repair fails, rejoin the domain: Remove-Computer then Add-Computer,
                  Check AD replication: repadmin /replsummary,
                  Verify the computer account is not disabled in AD,
                  Check time synchronization (w32tm /query /status)}

Secure channel on SERVER01 is BROKEN.

Recommendations:
  - Run: Test-ComputerSecureChannel -Repair -Credential (Get-Credential)
  - If repair fails, rejoin the domain: Remove-Computer then Add-Computer
  - Check AD replication: repadmin /replsummary
  - Verify the computer account is not disabled in AD
  - Check time synchronization (w32tm /query /status)
```

---

### Test-DCPortConnectivity

Test TCP connectivity to domain controllers on all required AD/Netlogon ports.

```powershell
# Test all ports to all discovered DCs
Test-DCPortConnectivity

# Test specific ports on a specific DC
Test-DCPortConnectivity -DomainController 'DC01.contoso.com' -Port 389,636

# Test from a remote machine
Test-DCPortConnectivity -ComputerName 'Server01'
```

**Sample Output:**

```
SourceComputer   DomainController   Port  Service               Reachable
--------------   ----------------   ----  -------               ---------
SERVER01         DC01.contoso.com     53  DNS                        True
SERVER01         DC01.contoso.com     88  Kerberos                   True
SERVER01         DC01.contoso.com    135  RPC Endpoint Mapper        True
SERVER01         DC01.contoso.com    389  LDAP                       True
SERVER01         DC01.contoso.com    445  SMB                        True
SERVER01         DC01.contoso.com    464  Kerberos Password          True
SERVER01         DC01.contoso.com    636  LDAPS                      True
SERVER01         DC01.contoso.com   3268  Global Catalog             True
SERVER01         DC01.contoso.com   3269  Global Catalog SSL         True
```

---

### Test-NetlogonDnsRecords

Verify that all critical DNS SRV and A records required by the DC locator are resolvable.

```powershell
# Check DNS for current domain and site
Test-NetlogonDnsRecords

# Check a specific domain and site
Test-NetlogonDnsRecords -DomainName 'contoso.com' -SiteName 'NYC'

# Use a specific DNS server
Test-NetlogonDnsRecords -DnsServer '10.0.0.10'
```

**Sample Output:**

```
RecordName                                          RecordType Purpose                   Resolved ResultCount Targets
----------                                          ---------- -------                   -------- ----------- -------
_ldap._tcp.dc._msdcs.contoso.com                    SRV        DC Locator (LDAP)             True           2 DC01...:389; DC02...:389
_kerberos._tcp.dc._msdcs.contoso.com                SRV        DC Locator (Kerberos)         True           2 DC01...:88; DC02...:88
_ldap._tcp.contoso.com                              SRV        LDAP Service                  True           2 DC01...:389; DC02...:389
_kerberos._tcp.contoso.com                          SRV        Kerberos Service              True           2 DC01...:88; DC02...:88
_gc._tcp.contoso.com                                SRV        Global Catalog                True           1 DC01...:3268
_ldap._tcp.pdc._msdcs.contoso.com                   SRV        PDC Locator                   True           1 DC01...:389
contoso.com                                         A          Domain A Record               True           2 10.0.0.10; 10.0.0.11
_ldap._tcp.NYC._sites.dc._msdcs.contoso.com         SRV        Site DC Locator (NYC)          True           1 DC01...:389
```

---

### Test-TimeSynchronization

Check time skew between a computer and its authenticating DC. Kerberos fails at >5 minutes drift.

```powershell
# Check local machine
Test-TimeSynchronization

# Check with custom threshold (2 minutes)
Test-TimeSynchronization -MaxSkewSeconds 120

# Check specific DC
Test-TimeSynchronization -DomainController 'DC01.contoso.com'
```

**Sample Output:**

```
ComputerName     : SERVER01
DomainController : DC01.contoso.com
LocalTime        : 03/11/2026 10:30:15
DCTime           : 03/11/2026 10:30:14
SkewSeconds      : 0.87
WithinThreshold  : True
ThresholdSeconds : 300
TimeSource       : DC01.contoso.com
W32TimeStatus    : Leap Indicator: 0(no warning)...

Time synchronization on SERVER01: OK (skew: 0.9s).
```

---

### Get-DCLocatorInfo

Retrieve parsed DC locator results via `nltest /dsgetdc` with flags for force rediscovery, site, PDC, KDC, or time server.

```powershell
# Default DC discovery
Get-DCLocatorInfo

# Force rediscovery for a specific site
Get-DCLocatorInfo -ForceRediscovery -SiteName 'NYC'

# Find the PDC emulator
Get-DCLocatorInfo -PDC

# Find a KDC
Get-DCLocatorInfo -KDC

# Find a writable DC (not an RODC)
Get-DCLocatorInfo -WritableRequired
```

**Sample Output:**

```
ComputerName     : SERVER01
DomainName       : contoso.com
DCName           : DC01.contoso.com
DCAddress        : 10.0.0.10
DCSiteName       : NYC
ClientSiteName   : NYC
DomainGuid       : a1b2c3d4-e5f6-7890-abcd-ef1234567890
Flags            : PDC GC DS LDAP KDC TIMESERV GTIMESERV WRITABLE DNS_DC DNS_DOMAIN FULL_SECRET
ForceRediscovery : False
RequestedSite    :
Success          : True

DC located: DC01.contoso.com (10.0.0.10) in site NYC.
```

---

### Get-ADSiteInfo

Show which AD site the computer is assigned to, its subnet mapping, and the DCs in the site. Detect `NO_CLIENT_SITE` conditions.

```powershell
# Local machine site info
Get-ADSiteInfo

# Query a specific site
Get-ADSiteInfo -SiteName 'London'

# Multiple computers
Get-ADSiteInfo -ComputerName 'Server01','Server02'
```

**Sample Output:**

```
ComputerName : SERVER01
ClientIP     : 10.1.20.50
AssignedSite : NYC
NltestSite   : NYC
NoClientSite : False
Subnets      : 10.1.20.0/24; 10.1.21.0/24
SubnetCount  : 2
DCs          : DC01.contoso.com; DC02.contoso.com
DCCount      : 2
SiteLinks    : NYC-London; NYC-Chicago

SERVER01: Site 'NYC' (2 DCs, 2 subnets).
```

**Sample Output (NO_CLIENT_SITE):**

```
ComputerName : SERVER03
ClientIP     : 10.1.50.22
AssignedSite : NO_CLIENT_SITE
NoClientSite : True

SERVER03: NO_CLIENT_SITE detected! The computer IP (10.1.50.22) does not match any AD subnet.
  Create a subnet in AD Sites and Services covering this IP range.
```

---

### Invoke-NetlogonDiagnostic

Run **all** checks in a single command and produce a consolidated report. Ideal for one-shot diagnostics that can be saved, emailed, or attached to a ticket.

```powershell
# Text report to console
Invoke-NetlogonDiagnostic

# HTML report saved to file
Invoke-NetlogonDiagnostic -OutputFormat HTML -OutputPath 'C:\Reports\netlogon_diag.html'

# Diagnose a remote server
Invoke-NetlogonDiagnostic -ComputerName 'Server01'

# Save text report to file
Invoke-NetlogonDiagnostic -OutputFormat Text -OutputPath 'C:\Reports\netlogon_diag.txt'
```

**The report includes all of the following checks:**

| # | Check | Description |
|---|---|---|
| 1 | Netlogon Service Status | Service state, domain, authenticating DC, debug logging |
| 2 | Secure Channel Health | Secure channel OK/broken, DC name, recommendations |
| 3 | DC Locator | Discovered DC, address, site, flags |
| 4 | AD Site Information | Assigned site, subnets, DCs in site, NO_CLIENT_SITE detection |
| 5 | DNS Record Validation | All critical SRV/A records with pass/fail |
| 6 | DC Port Connectivity | All AD ports tested per DC with open/blocked |
| 7 | Time Synchronization | Time skew, time source, threshold check |
| 8 | Recent Netlogon Events | Last 24h of Netlogon events from the event log |

**Sample Text Report (excerpt):**

```
========================================================================
  NETLOGON DIAGNOSTIC REPORT
  Computer : SERVER01
  Generated: 03/11/2026 10:45:00
========================================================================

--- Netlogon Service Status ---
  Service         : Running
  Domain          : contoso.com
  Auth DC         : DC01.contoso.com
  Secure Channel  : Healthy
  Debug Logging   : Disabled

--- DC Locator ---
  DC Name     : DC01.contoso.com
  DC Address  : 10.0.0.10
  DC Site     : NYC
  Client Site : NYC
  Flags       : PDC GC DS LDAP KDC TIMESERV WRITABLE DNS_DC

--- DNS Record Validation ---
  [OK]   DC Locator (LDAP): _ldap._tcp.dc._msdcs.contoso.com
  [OK]   Kerberos Service: _kerberos._tcp.contoso.com
  [FAIL] Site DC Locator (NYC): _ldap._tcp.NYC._sites.dc._msdcs.contoso.com
         Error: DNS name does not exist

--- DC Port Connectivity ---
  DC: DC01.contoso.com
    [OK]   Port 53 (DNS)
    [OK]   Port 88 (Kerberos)
    [OK]   Port 389 (LDAP)
    [FAIL] Port 3269 (Global Catalog SSL)

--- Time Synchronization ---
  DC             : DC01.contoso.com
  Skew           : 0.87s
  Within Limit   : Yes
  Time Source    : DC01.contoso.com
========================================================================
  End of Netlogon Diagnostic Report
========================================================================
```

---

## Single Domain Controller / Lab Environments

> **Note:** When running `Test-NetlogonSecureChannel` on a domain controller that is the **only DC** in the domain, the test will report the secure channel as failing with `ERROR_NO_SUCH_DOMAIN` (0x54b). **This is expected behaviour and not a real error.**
>
> A domain controller validates its secure channel against a *partner* DC. In a single-DC environment there is no partner to contact, so the test will always fail. The module detects this scenario automatically and displays an informational message instead of a "BROKEN" warning.
>
> This applies to:
> - Small lab / test environments with a single DC
> - Newly deployed domains before a second DC is promoted
> - Isolated / disaster-recovery DCs
>
> ```
> Secure channel test on DC01 is NOT APPLICABLE (single domain controller).
>
> Note:
>   - This computer is the only domain controller in the domain.
>   - A secure channel test requires a partner DC to validate against.
>   - In single-DC environments this test is expected to fail — this is normal and not an error.
>   - Add a second DC to enable secure channel validation between domain controllers.
> ```

---

## Event ID Reference

| Event ID | Summary | Severity |
|---|---|---|
| **5719** | No Domain Controller available for secure session setup | Critical |
| **5783** | DC session not responsive | Error |
| **5805** | Machine account authentication failure | Error |
| **5722** | No trust account in security database | Error |
| **5723** | Session setup failed — security database issue | Error |
| **5721** | No local security database account for computer | Error |
| **5781** | DNS dynamic registration/deregistration failure | Warning |
| **3210** | Authentication with DC failed | Error |

---

## Running Tests

Tests use **Pester 5.x** and are fully mocked — no domain membership required.

```powershell
# Install Pester if needed
Install-Module Pester -MinimumVersion 5.0 -Force -Scope CurrentUser

# Run all tests
Invoke-Pester -Path .\Tests\NetlogonTroubleShooting.Tests.ps1 -Output Detailed
```

---

## Project Structure

```
NetlogonTroubleShooting/
├── NetlogonTroubleShooting.psd1      # Module manifest
├── NetlogonTroubleShooting.psm1      # All functions
├── LICENSE                           # MIT License
├── README.md                         # This file
└── Tests/
    └── NetlogonTroubleShooting.Tests.ps1   # Pester tests (mocked)
```

---

## License

This project is licensed under the [MIT License](LICENSE).

---

## Author

**Jan Tiedemann** — Microsoft
