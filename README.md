# NetlogonTroubleShooting

![PowerShell 5.1](https://img.shields.io/badge/PowerShell-5.1-blue?logo=powershell&logoColor=white)
![PowerShell 7.x](https://img.shields.io/badge/PowerShell-7.x-blue?logo=powershell&logoColor=white)
![Platform: Windows](https://img.shields.io/badge/Platform-Windows-0078D6?logo=windows&logoColor=white)
![License: MIT](https://img.shields.io/badge/License-MIT-green)
![Version: 1.1.0](https://img.shields.io/badge/Version-1.1.0-brightgreen)
![Pester Tests](https://img.shields.io/badge/Pester-Passing-success?logo=dotnet)
![Active Directory](https://img.shields.io/badge/Active%20Directory-Netlogon-orange)

A PowerShell module for diagnosing and troubleshooting **Netlogon** issues in Active Directory environments. It parses event logs (e.g. 5719, 5805), manages Netlogon debug logging, and tests secure channel health — all with human-readable output and actionable remediation guidance.

---

## Features

- **Event Log Parsing** — Query and enrich Netlogon-related events (5719, 5783, 5805, 5722, 5723, 5721, 5781, 3210) with plain-English descriptions and recommended actions.
- **Debug Log Management** — Enable/disable Netlogon debug logging via registry with configurable verbosity levels.
- **Debug Log Reader** — Parse `netlogon.log` into structured objects, filter by category (Authentication, DC Discovery, DNS, Secure Channel), and surface errors.
- **Secure Channel Testing** — Test and repair the Netlogon secure channel with detailed diagnostic output.
- **Remote Support** — All commands accept `-ComputerName` for remote execution via PowerShell Remoting.

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
