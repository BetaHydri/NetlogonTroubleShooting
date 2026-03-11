@{
    RootModule        = 'NetlogonTroubleShooting.psm1'
    ModuleVersion     = '1.2.0'
    GUID              = 'a3f7b2c1-4d5e-6f78-9a0b-c1d2e3f4a5b6'
    Author            = 'Jan Tiedemann'
    CompanyName       = 'Microsoft'
    Copyright         = '(c) 2026 Microsoft. All rights reserved.'
    Description       = 'PowerShell module for troubleshooting Netlogon issues including event log parsing, debug logging, and secure channel diagnostics.'
    PowerShellVersion = '5.1'

    FunctionsToExport = @(
        'Get-NetlogonEvent',
        'Enable-NetlogonDebug',
        'Disable-NetlogonDebug',
        'Get-NetlogonDebugStatus',
        'Read-NetlogonDebugLog',
        'Get-NetlogonStatus',
        'Test-NetlogonSecureChannel',
        'Test-DCPortConnectivity',
        'Test-NetlogonDnsRecords',
        'Test-TimeSynchronization',
        'Get-DCLocatorInfo',
        'Get-ADSiteInfo',
        'Invoke-NetlogonDiagnostic'
    )

    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()

    PrivateData       = @{
        PSData = @{
            Tags       = @('Netlogon', 'ActiveDirectory', 'Troubleshooting', 'EventLog', 'Debug')
            ProjectUri = ''
        }
    }
}
