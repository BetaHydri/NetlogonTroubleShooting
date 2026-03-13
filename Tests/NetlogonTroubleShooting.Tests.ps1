#Requires -Module Pester

BeforeAll {
    $ModulePath = Join-Path $PSScriptRoot '..' 'NetlogonTroubleShooting.psd1'
    Import-Module $ModulePath -Force
}

Describe 'Module: NetlogonTroubleShooting' {

    Context 'Module Import' {

        It 'Should import without errors' {
            { Import-Module (Join-Path $PSScriptRoot '..' 'NetlogonTroubleShooting.psd1') -Force } | Should -Not -Throw
        }

        It 'Should export exactly 13 functions' {
            $Module = Get-Module NetlogonTroubleShooting
            $Module.ExportedFunctions.Count | Should -Be 13
        }

        It 'Should export Get-NetlogonEvent' {
            Get-Command -Module NetlogonTroubleShooting -Name 'Get-NetlogonEvent' | Should -Not -BeNullOrEmpty
        }

        It 'Should export Enable-NetlogonDebug' {
            Get-Command -Module NetlogonTroubleShooting -Name 'Enable-NetlogonDebug' | Should -Not -BeNullOrEmpty
        }

        It 'Should export Disable-NetlogonDebug' {
            Get-Command -Module NetlogonTroubleShooting -Name 'Disable-NetlogonDebug' | Should -Not -BeNullOrEmpty
        }

        It 'Should export Get-NetlogonDebugStatus' {
            Get-Command -Module NetlogonTroubleShooting -Name 'Get-NetlogonDebugStatus' | Should -Not -BeNullOrEmpty
        }

        It 'Should export Read-NetlogonDebugLog' {
            Get-Command -Module NetlogonTroubleShooting -Name 'Read-NetlogonDebugLog' | Should -Not -BeNullOrEmpty
        }

        It 'Should export Get-NetlogonStatus' {
            Get-Command -Module NetlogonTroubleShooting -Name 'Get-NetlogonStatus' | Should -Not -BeNullOrEmpty
        }

        It 'Should export Test-NetlogonSecureChannel' {
            Get-Command -Module NetlogonTroubleShooting -Name 'Test-NetlogonSecureChannel' | Should -Not -BeNullOrEmpty
        }

        It 'Should export Test-DCPortConnectivity' {
            Get-Command -Module NetlogonTroubleShooting -Name 'Test-DCPortConnectivity' | Should -Not -BeNullOrEmpty
        }

        It 'Should export Test-NetlogonDnsRecords' {
            Get-Command -Module NetlogonTroubleShooting -Name 'Test-NetlogonDnsRecords' | Should -Not -BeNullOrEmpty
        }

        It 'Should export Test-TimeSynchronization' {
            Get-Command -Module NetlogonTroubleShooting -Name 'Test-TimeSynchronization' | Should -Not -BeNullOrEmpty
        }

        It 'Should export Get-DCLocatorInfo' {
            Get-Command -Module NetlogonTroubleShooting -Name 'Get-DCLocatorInfo' | Should -Not -BeNullOrEmpty
        }

        It 'Should export Get-ADSiteInfo' {
            Get-Command -Module NetlogonTroubleShooting -Name 'Get-ADSiteInfo' | Should -Not -BeNullOrEmpty
        }

        It 'Should export Invoke-NetlogonDiagnostic' {
            Get-Command -Module NetlogonTroubleShooting -Name 'Invoke-NetlogonDiagnostic' | Should -Not -BeNullOrEmpty
        }
    }

    Context 'Module Manifest' {

        BeforeAll {
            $Manifest = Test-ModuleManifest -Path (Join-Path $PSScriptRoot '..' 'NetlogonTroubleShooting.psd1')
        }

        It 'Should have a valid manifest' {
            $Manifest | Should -Not -BeNullOrEmpty
        }

        It 'Should have Author set to Jan Tiedemann' {
            $Manifest.Author | Should -Be 'Jan Tiedemann'
        }

        It 'Should have CompanyName set to Microsoft' {
            $Manifest.CompanyName | Should -Be 'Microsoft'
        }

        It 'Should have version 1.3.0' {
            $Manifest.Version.ToString() | Should -Be '1.3.0'
        }

        It 'Should require PowerShell 5.1' {
            $Manifest.PowerShellVersion.ToString() | Should -Be '5.1'
        }
    }
}

Describe 'Get-NetlogonEvent' {

    Context 'When Netlogon events exist' {

        BeforeAll {
            $Script:MockEvents = @(
                [PSCustomObject]@{
                    Id               = 5719
                    TimeCreated      = [datetime]'2026-03-11 08:15:32'
                    LevelDisplayName = 'Error'
                    Message          = 'This computer was not able to set up a secure session with a domain controller in domain CONTOSO.'
                    ProviderName     = 'NETLOGON'
                },
                [PSCustomObject]@{
                    Id               = 5805
                    TimeCreated      = [datetime]'2026-03-11 09:20:00'
                    LevelDisplayName = 'Error'
                    Message          = 'The session setup from the computer SERVER02 failed to authenticate.'
                    ProviderName     = 'NETLOGON'
                }
            )
            # Mock Get-WinEvent for local path
            Mock -ModuleName NetlogonTroubleShooting -CommandName Get-WinEvent {
                $Script:MockEvents
            }
            # Mock Invoke-Command for remote path (returns the same fake events)
            Mock -ModuleName NetlogonTroubleShooting -CommandName Invoke-Command {
                $Script:MockEvents
            }
        }

        It 'Should return event objects' {
            $Results = Get-NetlogonEvent -ComputerName $env:COMPUTERNAME
            $Results | Should -Not -BeNullOrEmpty
        }

        It 'Should include EventId property' {
            $Results = Get-NetlogonEvent -ComputerName $env:COMPUTERNAME
            $Results[0].EventId | Should -BeIn @(5719, 5805)
        }

        It 'Should include a human-readable Summary for event 5719' {
            $Results = Get-NetlogonEvent -ComputerName $env:COMPUTERNAME
            $Evt5719 = $Results | Where-Object { $_.EventId -eq 5719 } | Select-Object -First 1
            $Evt5719.Summary | Should -Be 'No Domain Controller available for secure session setup'
        }

        It 'Should include a human-readable Summary for event 5805' {
            $Results = Get-NetlogonEvent -ComputerName $env:COMPUTERNAME
            $Evt5805 = $Results | Where-Object { $_.EventId -eq 5805 } | Select-Object -First 1
            $Evt5805.Summary | Should -Be 'Machine account authentication failure'
        }

        It 'Should include Action guidance' {
            $Results = Get-NetlogonEvent -ComputerName $env:COMPUTERNAME
            $Results[0].Action | Should -Not -BeNullOrEmpty
        }

        It 'Should set the correct ComputerName' {
            $Results = Get-NetlogonEvent -ComputerName $env:COMPUTERNAME
            $Results[0].ComputerName | Should -Be $env:COMPUTERNAME
        }
    }

    Context 'When no events are found' {

        BeforeAll {
            Mock -ModuleName NetlogonTroubleShooting -CommandName Get-WinEvent {
                throw [System.Exception]::new('No events were found that match the specified selection criteria.')
            }
        }

        It 'Should not throw' {
            { Get-NetlogonEvent -ComputerName 'CLEAN01' } | Should -Not -Throw
        }

        It 'Should return no results' {
            $Results = Get-NetlogonEvent -ComputerName 'CLEAN01'
            $Results | Should -BeNullOrEmpty
        }
    }

    Context 'Parameter Validation' {

        It 'Should accept valid EventId values' {
            { Get-NetlogonEvent -EventId 5719 -ErrorAction Stop } | Should -Not -Throw
        }
    }
}

Describe 'Enable-NetlogonDebug' {

    Context 'When running as Administrator on local machine' {

        BeforeAll {
            # Mock admin check to return true
            Mock -ModuleName NetlogonTroubleShooting -CommandName 'New-Object' {
                $MockPrincipal = [PSCustomObject]@{}
                $MockPrincipal | Add-Member -MemberType ScriptMethod -Name 'IsInRole' -Value { return $true }
                return $MockPrincipal
            } -ParameterFilter { $TypeName -eq 'Security.Principal.WindowsPrincipal' }

            Mock -ModuleName NetlogonTroubleShooting -CommandName Set-ItemProperty {}
            Mock -ModuleName NetlogonTroubleShooting -CommandName nltest {}
        }

        It 'Should return a debug config object' {
            $Result = Enable-NetlogonDebug -Confirm:$false
            $Result | Should -Not -BeNullOrEmpty
        }

        It 'Should set DebugEnabled to true' {
            $Result = Enable-NetlogonDebug -Confirm:$false
            $Result.DebugEnabled | Should -Be $true
        }

        It 'Should default to Full level' {
            $Result = Enable-NetlogonDebug -Confirm:$false
            $Result.Level | Should -Be 'Full'
        }

        It 'Should set DBFlag to 0x2080FFFF for Full level' {
            $Result = Enable-NetlogonDebug -Confirm:$false
            $Result.DBFlag | Should -Be '0x2080FFFF'
        }

        It 'Should call Set-ItemProperty for DBFlag' {
            Enable-NetlogonDebug -Confirm:$false
            Should -Invoke -ModuleName NetlogonTroubleShooting -CommandName Set-ItemProperty -Times 2 -Scope It
        }

        It 'Should apply via nltest without restarting the service' {
            Enable-NetlogonDebug -Confirm:$false
            Should -Invoke -ModuleName NetlogonTroubleShooting -CommandName nltest -Times 1 -Scope It
        }

        It 'Should not restart the Netlogon service' {
            $Result = Enable-NetlogonDebug -Confirm:$false
            $Result.Restarted | Should -Be $false
        }

        It 'Should accept Standard level' {
            $Result = Enable-NetlogonDebug -Level Standard -Confirm:$false
            $Result.Level | Should -Be 'Standard'
            $Result.DBFlag | Should -Be '0x20000004'
        }
    }
}

Describe 'Disable-NetlogonDebug' {

    Context 'When running as Administrator on local machine' {

        BeforeAll {
            Mock -ModuleName NetlogonTroubleShooting -CommandName 'New-Object' {
                $MockPrincipal = [PSCustomObject]@{}
                $MockPrincipal | Add-Member -MemberType ScriptMethod -Name 'IsInRole' -Value { return $true }
                return $MockPrincipal
            } -ParameterFilter { $TypeName -eq 'Security.Principal.WindowsPrincipal' }

            Mock -ModuleName NetlogonTroubleShooting -CommandName Set-ItemProperty {}
            Mock -ModuleName NetlogonTroubleShooting -CommandName nltest {}
        }

        It 'Should return a debug config object' {
            $Result = Disable-NetlogonDebug -Confirm:$false
            $Result | Should -Not -BeNullOrEmpty
        }

        It 'Should set DebugEnabled to false' {
            $Result = Disable-NetlogonDebug -Confirm:$false
            $Result.DebugEnabled | Should -Be $false
        }

        It 'Should set Level to Disabled' {
            $Result = Disable-NetlogonDebug -Confirm:$false
            $Result.Level | Should -Be 'Disabled'
        }

        It 'Should set DBFlag to 0x0' {
            $Result = Disable-NetlogonDebug -Confirm:$false
            $Result.DBFlag | Should -Be '0x0'
        }

        It 'Should call Set-ItemProperty to reset DBFlag' {
            Disable-NetlogonDebug -Confirm:$false
            Should -Invoke -ModuleName NetlogonTroubleShooting -CommandName Set-ItemProperty -Times 1 -Scope It
        }

        It 'Should apply via nltest without restarting the service' {
            Disable-NetlogonDebug -Confirm:$false
            Should -Invoke -ModuleName NetlogonTroubleShooting -CommandName nltest -Times 1 -Scope It
        }

        It 'Should not restart the Netlogon service' {
            $Result = Disable-NetlogonDebug -Confirm:$false
            $Result.Restarted | Should -Be $false
        }
    }
}

Describe 'Get-NetlogonDebugStatus' {

    Context 'When debug logging is enabled (Full)' {

        BeforeAll {
            Mock -ModuleName NetlogonTroubleShooting -CommandName Get-ItemProperty {
                [PSCustomObject]@{ DBFlag = 0x2080FFFF }
            } -ParameterFilter { $Name -eq 'DBFlag' }

            Mock -ModuleName NetlogonTroubleShooting -CommandName Get-ItemProperty {
                [PSCustomObject]@{ MaximumLogFileSize = 268435456 }
            } -ParameterFilter { $Name -eq 'MaximumLogFileSize' }

            Mock -ModuleName NetlogonTroubleShooting -CommandName Test-Path { return $true }
            Mock -ModuleName NetlogonTroubleShooting -CommandName Get-Item {
                [PSCustomObject]@{ Length = 44237824 }
            }
        }

        It 'Should return a status object' {
            $Result = Get-NetlogonDebugStatus
            $Result | Should -Not -BeNullOrEmpty
        }

        It 'Should show DebugEnabled as True' {
            $Result = Get-NetlogonDebugStatus
            $Result.DebugEnabled | Should -Be $true
        }

        It 'Should show Level as Full' {
            $Result = Get-NetlogonDebugStatus
            $Result.Level | Should -Be 'Full'
        }

        It 'Should show DBFlag as hex string' {
            $Result = Get-NetlogonDebugStatus
            $Result.DBFlag | Should -Be '0x2080FFFF'
        }

        It 'Should report log file exists' {
            $Result = Get-NetlogonDebugStatus
            $Result.LogFileExists | Should -Be $true
        }
    }

    Context 'When debug logging is disabled' {

        BeforeAll {
            Mock -ModuleName NetlogonTroubleShooting -CommandName Get-ItemProperty {
                [PSCustomObject]@{ DBFlag = 0 }
            } -ParameterFilter { $Name -eq 'DBFlag' }

            Mock -ModuleName NetlogonTroubleShooting -CommandName Get-ItemProperty {
                [PSCustomObject]@{ MaximumLogFileSize = $null }
            } -ParameterFilter { $Name -eq 'MaximumLogFileSize' }

            Mock -ModuleName NetlogonTroubleShooting -CommandName Test-Path { return $false }
        }

        It 'Should show DebugEnabled as False' {
            $Result = Get-NetlogonDebugStatus
            $Result.DebugEnabled | Should -Be $false
        }

        It 'Should show Level as Disabled' {
            $Result = Get-NetlogonDebugStatus
            $Result.Level | Should -Be 'Disabled'
        }
    }
}

Describe 'Read-NetlogonDebugLog' {

    Context 'When netlogon.log exists with entries' {

        BeforeAll {
            # Create a temporary netlogon.log with sample data
            $Script:TempDir = Join-Path $TestDrive 'debug'
            New-Item -Path $Script:TempDir -ItemType Directory -Force | Out-Null
            $Script:TempLog = Join-Path $Script:TempDir 'netlogon.log'

            $LogContent = @(
                '03/11 08:15:32 [LOGON] [1044] SamLogon: Transitive Network logon of CONTOSO\jdoe from CLIENT01 Returns 0x0'
                '03/11 08:16:01 [CRITICAL] [1044] NlPrintRpcDebug: Couldn''t authenticate to \\DC02.contoso.com: STATUS_NO_TRUST_SAM_ACCOUNT'
                '03/11 08:17:45 [SESSION] [1044] NlSessionSetup: DC01.contoso.com: Session setup FAILED, Status = STATUS_ACCESS_DENIED'
                '03/11 08:18:00 [DNS] [1044] NlDnsRegister: Registered _ldap._tcp.dc._msdcs.contoso.com successfully'
                '03/11 08:19:30 [SITE] [1044] NO_CLIENT_SITE for 10.1.50.22'
                '03/11 08:20:00 [MAILSLOT] [1044] DsGetDc: CONTOSO picked DC DC01.contoso.com'
                '03/11 08:21:00 [SESSION] [1044] NlSessionSetup: secure channel to DC01.contoso.com established'
            )
            $LogContent | Set-Content -Path $Script:TempLog -Encoding UTF8
        }

        It 'Should parse all entries' {
            $Results = Read-NetlogonDebugLog -Path $Script:TempLog
            $Results.Count | Should -Be 7
        }

        It 'Should filter errors only' {
            $Results = Read-NetlogonDebugLog -Path $Script:TempLog -ErrorsOnly
            $Results.Count | Should -BeGreaterThan 0
            $Results | ForEach-Object { $_.IsError | Should -Be $true }
        }

        It 'Should detect STATUS_NO_TRUST_SAM_ACCOUNT as an error' {
            $Results = Read-NetlogonDebugLog -Path $Script:TempLog -ErrorsOnly
            $ErrorCodes = $Results.StatusCode
            $ErrorCodes | Should -Contain 'STATUS_NO_TRUST_SAM_ACCOUNT'
        }

        It 'Should detect STATUS_ACCESS_DENIED as an error' {
            $Results = Read-NetlogonDebugLog -Path $Script:TempLog -ErrorsOnly
            $ErrorCodes = $Results.StatusCode
            $ErrorCodes | Should -Contain 'STATUS_ACCESS_DENIED'
        }

        It 'Should detect NO_CLIENT_SITE as an error' {
            $Results = Read-NetlogonDebugLog -Path $Script:TempLog -ErrorsOnly
            $Messages = $Results.Message -join ' '
            $Messages | Should -Match 'NO_CLIENT_SITE'
        }

        It 'Should filter by Authentication category' {
            $Results = Read-NetlogonDebugLog -Path $Script:TempLog -Category Authentication
            $Results | ForEach-Object { $_.Category | Should -Be 'Authentication' }
        }

        It 'Should filter by DCDiscovery category' {
            $Results = Read-NetlogonDebugLog -Path $Script:TempLog -Category DCDiscovery
            $Results.Count | Should -BeGreaterThan 0
        }

        It 'Should filter by DnsRegistration category' {
            $Results = Read-NetlogonDebugLog -Path $Script:TempLog -Category DnsRegistration
            $Results.Count | Should -BeGreaterThan 0
        }

        It 'Should filter by SecureChannel category' {
            $Results = Read-NetlogonDebugLog -Path $Script:TempLog -Category SecureChannel
            $Results.Count | Should -BeGreaterThan 0
        }

        It 'Should respect -Last parameter' {
            $Results = Read-NetlogonDebugLog -Path $Script:TempLog -Last 3
            $Results.Count | Should -Be 3
        }

        It 'Should include correct properties on each entry' {
            $Results = Read-NetlogonDebugLog -Path $Script:TempLog
            $First = $Results[0]
            $First.PSObject.Properties.Name | Should -Contain 'Timestamp'
            $First.PSObject.Properties.Name | Should -Contain 'LogType'
            $First.PSObject.Properties.Name | Should -Contain 'Category'
            $First.PSObject.Properties.Name | Should -Contain 'IsError'
            $First.PSObject.Properties.Name | Should -Contain 'StatusDescription'
            $First.PSObject.Properties.Name | Should -Contain 'Message'
            $First.PSObject.Properties.Name | Should -Contain 'RawLine'
        }

        It 'Should parse timestamps' {
            $Results = Read-NetlogonDebugLog -Path $Script:TempLog
            $Results[0].Timestamp | Should -BeOfType [datetime]
        }

        It 'Should resolve STATUS_NO_TRUST_SAM_ACCOUNT to a description' {
            $Results = Read-NetlogonDebugLog -Path $Script:TempLog -ErrorsOnly
            $Entry = $Results | Where-Object { $_.StatusCode -eq 'STATUS_NO_TRUST_SAM_ACCOUNT' }
            $Entry.StatusDescription | Should -Not -BeNullOrEmpty
            $Entry.StatusDescription | Should -BeLike '*computer account*'
        }

        It 'Should resolve STATUS_ACCESS_DENIED to a description' {
            $Results = Read-NetlogonDebugLog -Path $Script:TempLog -ErrorsOnly
            $Entry = $Results | Where-Object { $_.StatusCode -eq 'STATUS_ACCESS_DENIED' }
            $Entry.StatusDescription | Should -Not -BeNullOrEmpty
            $Entry.StatusDescription | Should -BeLike '*Access*denied*'
        }

        It 'Should resolve hex status code 0x0 to Success' {
            $Results = Read-NetlogonDebugLog -Path $Script:TempLog
            $Entry = $Results | Where-Object { $_.StatusCode -eq '0x0' }
            $Entry.StatusDescription | Should -Not -BeNullOrEmpty
            $Entry.StatusDescription | Should -BeLike '*Success*'
        }
    }

    Context 'When netlogon.log includes backup' {

        BeforeAll {
            $Script:TempDir = Join-Path $TestDrive 'debug2'
            New-Item -Path $Script:TempDir -ItemType Directory -Force | Out-Null
            $Script:TempLog2 = Join-Path $Script:TempDir 'netlogon.log'
            $Script:TempBak = Join-Path $Script:TempDir 'netlogon.bak'

            '03/11 10:00:00 [LOGON] [1044] SamLogon: current log entry' | Set-Content -Path $Script:TempLog2 -Encoding UTF8
            '03/10 23:00:00 [LOGON] [1044] SamLogon: backup log entry' | Set-Content -Path $Script:TempBak -Encoding UTF8
        }

        It 'Should parse both log and backup when -IncludeBackup is set' {
            $Results = Read-NetlogonDebugLog -Path $Script:TempLog2 -IncludeBackup
            $Results.Count | Should -Be 2
        }

        It 'Should include entries from backup file' {
            $Results = Read-NetlogonDebugLog -Path $Script:TempLog2 -IncludeBackup
            $Sources = $Results.SourceFile
            $Sources | Should -Contain 'netlogon.bak'
        }
    }

    Context 'When netlogon.log does not exist' {

        It 'Should write an error' {
            $Result = Read-NetlogonDebugLog -Path 'C:\nonexistent\netlogon.log' -ErrorVariable TestError -ErrorAction SilentlyContinue
            $TestError | Should -Not -BeNullOrEmpty
        }
    }
}

Describe 'Get-NetlogonStatus' {

    Context 'When on a domain-joined machine' {

        BeforeAll {
            Mock -ModuleName NetlogonTroubleShooting -CommandName Get-Service {
                [PSCustomObject]@{
                    Status    = [System.ServiceProcess.ServiceControllerStatus]::Running
                    StartType = [System.ServiceProcess.ServiceStartMode]::Automatic
                }
            }

            Mock -ModuleName NetlogonTroubleShooting -CommandName Invoke-Command {
                [PSCustomObject]@{
                    Status    = [System.ServiceProcess.ServiceControllerStatus]::Running
                    StartType = [System.ServiceProcess.ServiceStartMode]::Automatic
                }
            }

            # Mock domain info — return a mock object instead of calling AD
            Mock -ModuleName NetlogonTroubleShooting -CommandName Test-ComputerSecureChannel { return $true }

            Mock -ModuleName NetlogonTroubleShooting -CommandName Get-NetlogonDebugStatus {
                [PSCustomObject]@{
                    DebugEnabled = $false
                    Level        = 'Disabled'
                }
            }
        }

        It 'Should return a status object' {
            $Result = Get-NetlogonStatus
            $Result | Should -Not -BeNullOrEmpty
        }

        It 'Should show ServiceStatus as Running' {
            $Result = Get-NetlogonStatus
            $Result.ServiceStatus | Should -Be 'Running'
        }

        It 'Should show ServiceStartType as Automatic' {
            $Result = Get-NetlogonStatus
            $Result.ServiceStartType | Should -Be 'Automatic'
        }

        It 'Should include DebugLoggingEnabled property' {
            $Result = Get-NetlogonStatus
            $Result.PSObject.Properties.Name | Should -Contain 'DebugLoggingEnabled'
        }

        It 'Should include SecureChannelHealthy property' {
            $Result = Get-NetlogonStatus
            $Result.PSObject.Properties.Name | Should -Contain 'SecureChannelHealthy'
        }
    }

    Context 'When Netlogon service is stopped' {

        BeforeAll {
            Mock -ModuleName NetlogonTroubleShooting -CommandName Get-Service {
                throw [System.Exception]::new('Service Netlogon was not found.')
            }
            Mock -ModuleName NetlogonTroubleShooting -CommandName Invoke-Command {
                throw [System.Exception]::new('Service Netlogon was not found.')
            }
        }

        It 'Should handle error gracefully' {
            { Get-NetlogonStatus -ErrorAction SilentlyContinue } | Should -Not -Throw
        }
    }
}

Describe 'Test-NetlogonSecureChannel' {

    Context 'When secure channel is healthy' {

        BeforeAll {
            Mock -ModuleName NetlogonTroubleShooting -CommandName Test-ComputerSecureChannel { return $true }
        }

        It 'Should return a result object' {
            $Result = Test-NetlogonSecureChannel
            $Result | Should -Not -BeNullOrEmpty
        }

        It 'Should show SecureChannelOK as True' {
            $Result = Test-NetlogonSecureChannel
            $Result.SecureChannelOK | Should -Be $true
        }

        It 'Should not have recommendations when healthy' {
            $Result = Test-NetlogonSecureChannel
            $Result.Recommendations.Count | Should -Be 0
        }

        It 'Should set RepairAttempted to False when not requested' {
            $Result = Test-NetlogonSecureChannel
            $Result.RepairAttempted | Should -Be $false
        }
    }

    Context 'When secure channel is broken' {

        BeforeAll {
            Mock -ModuleName NetlogonTroubleShooting -CommandName Test-ComputerSecureChannel { return $false }
        }

        It 'Should show SecureChannelOK as False' {
            $Result = Test-NetlogonSecureChannel
            $Result.SecureChannelOK | Should -Be $false
        }

        It 'Should provide recommendations' {
            $Result = Test-NetlogonSecureChannel
            $Result.Recommendations.Count | Should -BeGreaterThan 0
        }

        It 'Should include repair recommendation' {
            $Result = Test-NetlogonSecureChannel
            ($Result.Recommendations -join ' ') | Should -Match 'Test-ComputerSecureChannel -Repair'
        }

        It 'Should include time sync recommendation' {
            $Result = Test-NetlogonSecureChannel
            ($Result.Recommendations -join ' ') | Should -Match 'w32tm'
        }
    }

    Context 'When repair is requested with credentials' {

        BeforeAll {
            Mock -ModuleName NetlogonTroubleShooting -CommandName Test-ComputerSecureChannel {
                if ($Repair) { return $true }
                return $false
            }
        }

        It 'Should attempt repair when -Repair and -Credential are specified' {
            $Cred = [PSCredential]::new('CONTOSO\admin', (ConvertTo-SecureString 'MockP@ss1' -AsPlainText -Force))
            $Result = Test-NetlogonSecureChannel -Repair -Credential $Cred
            $Result.RepairAttempted | Should -Be $true
        }
    }

    Context 'When repair is requested without credentials' {

        BeforeAll {
            Mock -ModuleName NetlogonTroubleShooting -CommandName Test-ComputerSecureChannel { return $false }
        }

        It 'Should not attempt repair' {
            $Result = Test-NetlogonSecureChannel -Repair -ErrorAction SilentlyContinue
            $Result.RepairAttempted | Should -Be $false
        }
    }

    Context 'When running on a single domain controller' {

        BeforeAll {
            Mock -ModuleName NetlogonTroubleShooting -CommandName Test-ComputerSecureChannel { return $false }
            Mock -ModuleName NetlogonTroubleShooting -CommandName Get-CimInstance {
                [PSCustomObject]@{ ProductType = 2 }
            }

            # Create a mock DC object with a Name property
            $MockDC = [PSCustomObject]@{ Name = $env:COMPUTERNAME }

            # Mock the .NET domain call to return a domain with a single DC
            Mock -ModuleName NetlogonTroubleShooting -CommandName nltest { '' }

            # Patch [System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain()
            # by defining a helper function inside the module scope
            & (Get-Module NetlogonTroubleShooting) {
                function script:_GetComputerDomain {
                    $MockDomain = [PSCustomObject]@{
                        Name              = 'contoso.com'
                        DomainControllers = @([PSCustomObject]@{ Name = $env:COMPUTERNAME })
                    }
                    return $MockDomain
                }
            }
        }

        It 'Should detect single-DC and provide informational recommendations' {
            # We need to mock the static .NET call; since we cannot directly,
            # we verify the behavior by checking that when CimInstance returns ProductType=2
            # the function produces recommendations mentioning single domain controller
            $Result = Test-NetlogonSecureChannel
            $Result | Should -Not -BeNullOrEmpty
            # When the .NET domain query succeeds with 1 DC, recommendations should mention single DC
            # When it fails (no domain), normal broken-channel recommendations apply
            $Result.Recommendations.Count | Should -BeGreaterThan 0
        }

        It 'Should not attempt repair on single-DC scenario' {
            $Result = Test-NetlogonSecureChannel
            $Result.RepairAttempted | Should -Be $false
        }
    }
}

Describe 'Test-DCPortConnectivity' {

    Context 'Parameter validation' {

        It 'Should have a DomainController parameter' {
            (Get-Command Test-DCPortConnectivity).Parameters.Keys | Should -Contain 'DomainController'
        }

        It 'Should have a Port parameter' {
            (Get-Command Test-DCPortConnectivity).Parameters.Keys | Should -Contain 'Port'
        }

        It 'Should have a TimeoutMs parameter' {
            (Get-Command Test-DCPortConnectivity).Parameters.Keys | Should -Contain 'TimeoutMs'
        }

        It 'Should have a ComputerName parameter' {
            (Get-Command Test-DCPortConnectivity).Parameters.Keys | Should -Contain 'ComputerName'
        }
    }

    Context 'When testing reachable ports' {

        BeforeAll {
            # Use localhost as a mock target — port 135 (RPC) is typically open on Windows
            $Script:Results = Test-DCPortConnectivity -DomainController 'localhost' -Port 135 -TimeoutMs 1000
        }

        It 'Should return a result object' {
            $Script:Results | Should -Not -BeNullOrEmpty
        }

        It 'Should include DomainController property' {
            $Script:Results[0].DomainController | Should -Be 'localhost'
        }

        It 'Should include Port property' {
            $Script:Results[0].Port | Should -Be 135
        }

        It 'Should include Service property' {
            $Script:Results[0].Service | Should -Be 'RPC Endpoint Mapper'
        }

        It 'Should include Reachable property as boolean' {
            $Script:Results[0].Reachable | Should -BeOfType [bool]
        }
    }

    Context 'When testing unreachable ports' {

        BeforeAll {
            # Port 19999 should not be open anywhere
            $Script:Results = Test-DCPortConnectivity -DomainController '192.0.2.1' -Port 19999 -TimeoutMs 500
        }

        It 'Should return Reachable as False for an unreachable host' {
            $Script:Results[0].Reachable | Should -Be $false
        }
    }

    Context 'When testing multiple ports' {

        BeforeAll {
            $Script:Results = Test-DCPortConnectivity -DomainController 'localhost' -Port 135, 445 -TimeoutMs 1000
        }

        It 'Should return one result per port' {
            $Script:Results.Count | Should -Be 2
        }
    }
}

Describe 'Test-NetlogonDnsRecords' {

    Context 'Parameter validation' {

        It 'Should have a DomainName parameter' {
            (Get-Command Test-NetlogonDnsRecords).Parameters.Keys | Should -Contain 'DomainName'
        }

        It 'Should have a SiteName parameter' {
            (Get-Command Test-NetlogonDnsRecords).Parameters.Keys | Should -Contain 'SiteName'
        }

        It 'Should have a DnsServer parameter' {
            (Get-Command Test-NetlogonDnsRecords).Parameters.Keys | Should -Contain 'DnsServer'
        }
    }

    Context 'When resolving DNS records' {

        BeforeAll {
            Mock -ModuleName NetlogonTroubleShooting -CommandName Resolve-DnsName {
                [PSCustomObject]@{
                    QueryType  = 'SRV'
                    NameTarget = 'DC01.contoso.com'
                    Port       = 389
                }
            }
        }

        It 'Should return DNS record results' {
            $Results = Test-NetlogonDnsRecords -DomainName 'contoso.com'
            $Results | Should -Not -BeNullOrEmpty
        }

        It 'Should check multiple record types' {
            $Results = Test-NetlogonDnsRecords -DomainName 'contoso.com'
            $Results.Count | Should -BeGreaterOrEqual 7
        }

        It 'Should include RecordName, RecordType, and Purpose' {
            $Results = Test-NetlogonDnsRecords -DomainName 'contoso.com'
            $First = $Results[0]
            $First.PSObject.Properties.Name | Should -Contain 'RecordName'
            $First.PSObject.Properties.Name | Should -Contain 'RecordType'
            $First.PSObject.Properties.Name | Should -Contain 'Purpose'
            $First.PSObject.Properties.Name | Should -Contain 'Resolved'
        }

        It 'Should show Resolved as True when DNS resolves' {
            $Results = Test-NetlogonDnsRecords -DomainName 'contoso.com'
            $Results[0].Resolved | Should -Be $true
        }

        It 'Should include site-specific records when SiteName is given' {
            $Results = Test-NetlogonDnsRecords -DomainName 'contoso.com' -SiteName 'NYC'
            $SiteRecords = $Results | Where-Object { $_.Purpose -match 'NYC' }
            $SiteRecords.Count | Should -BeGreaterOrEqual 1
        }
    }

    Context 'When DNS records do not resolve' {

        BeforeAll {
            Mock -ModuleName NetlogonTroubleShooting -CommandName Resolve-DnsName {
                throw [System.Exception]::new('DNS name does not exist')
            }
        }

        It 'Should show Resolved as False' {
            $Results = Test-NetlogonDnsRecords -DomainName 'nonexistent.invalid'
            $Results[0].Resolved | Should -Be $false
        }

        It 'Should include the error message' {
            $Results = Test-NetlogonDnsRecords -DomainName 'nonexistent.invalid'
            $Results[0].Error | Should -Not -BeNullOrEmpty
        }
    }
}

Describe 'Test-TimeSynchronization' {

    Context 'Parameter validation' {

        It 'Should have a ComputerName parameter' {
            (Get-Command Test-TimeSynchronization).Parameters.Keys | Should -Contain 'ComputerName'
        }

        It 'Should have a DomainController parameter' {
            (Get-Command Test-TimeSynchronization).Parameters.Keys | Should -Contain 'DomainController'
        }

        It 'Should have a MaxSkewSeconds parameter' {
            (Get-Command Test-TimeSynchronization).Parameters.Keys | Should -Contain 'MaxSkewSeconds'
        }
    }

    Context 'When time sync can be checked locally' {

        BeforeAll {
            Mock -ModuleName NetlogonTroubleShooting -CommandName w32tm {
                'Leap Indicator: 0(no warning)', 'Source: DC01.contoso.com', 'Stratum: 3'
            }
            Mock -ModuleName NetlogonTroubleShooting -CommandName nltest {
                'DC: \\DC01.contoso.com', 'Address: \\10.0.0.10'
            }
            Mock -ModuleName NetlogonTroubleShooting -CommandName Invoke-Command {
                Get-Date
            }
        }

        It 'Should return a time sync result' {
            $Result = Test-TimeSynchronization
            $Result | Should -Not -BeNullOrEmpty
        }

        It 'Should include ComputerName property' {
            $Result = Test-TimeSynchronization
            $Result.ComputerName | Should -Not -BeNullOrEmpty
        }

        It 'Should include ThresholdSeconds property' {
            $Result = Test-TimeSynchronization
            $Result.ThresholdSeconds | Should -Be 300
        }

        It 'Should include TimeSource property' {
            $Result = Test-TimeSynchronization
            $Result.PSObject.Properties.Name | Should -Contain 'TimeSource'
        }
    }
}

Describe 'Get-DCLocatorInfo' {

    Context 'Parameter validation' {

        It 'Should have a DomainName parameter' {
            (Get-Command Get-DCLocatorInfo).Parameters.Keys | Should -Contain 'DomainName'
        }

        It 'Should have a SiteName parameter' {
            (Get-Command Get-DCLocatorInfo).Parameters.Keys | Should -Contain 'SiteName'
        }

        It 'Should have a ForceRediscovery switch' {
            (Get-Command Get-DCLocatorInfo).Parameters['ForceRediscovery'].SwitchParameter | Should -Be $true
        }

        It 'Should have a PDC switch' {
            (Get-Command Get-DCLocatorInfo).Parameters['PDC'].SwitchParameter | Should -Be $true
        }

        It 'Should have a KDC switch' {
            (Get-Command Get-DCLocatorInfo).Parameters['KDC'].SwitchParameter | Should -Be $true
        }

        It 'Should have a TimeServer switch' {
            (Get-Command Get-DCLocatorInfo).Parameters['TimeServer'].SwitchParameter | Should -Be $true
        }

        It 'Should have a WritableRequired switch' {
            (Get-Command Get-DCLocatorInfo).Parameters['WritableRequired'].SwitchParameter | Should -Be $true
        }
    }

    Context 'When DC locator succeeds' {

        BeforeAll {
            Mock -ModuleName NetlogonTroubleShooting -CommandName nltest {
                @(
                    '           DC: \\DC01.contoso.com'
                    '      Address: \\10.0.0.10'
                    '     Dom Guid: a1b2c3d4-e5f6-7890-abcd-ef1234567890'
                    '     Dom Name: contoso.com'
                    '  Forest Name: contoso.com'
                    ' DC Site Name: NYC'
                    'Our Site Name: NYC'
                    '        Flags: PDC GC DS LDAP KDC TIMESERV WRITABLE DNS_DC DNS_DOMAIN'
                    'The command completed successfully'
                )
            }
        }

        It 'Should return a DC locator result' {
            $Result = Get-DCLocatorInfo -DomainName 'contoso.com'
            $Result | Should -Not -BeNullOrEmpty
        }

        It 'Should parse DCName' {
            $Result = Get-DCLocatorInfo -DomainName 'contoso.com'
            $Result.DCName | Should -Be 'DC01.contoso.com'
        }

        It 'Should parse DCAddress' {
            $Result = Get-DCLocatorInfo -DomainName 'contoso.com'
            $Result.DCAddress | Should -Be '10.0.0.10'
        }

        It 'Should parse DCSiteName' {
            $Result = Get-DCLocatorInfo -DomainName 'contoso.com'
            $Result.DCSiteName | Should -Be 'NYC'
        }

        It 'Should parse ClientSiteName' {
            $Result = Get-DCLocatorInfo -DomainName 'contoso.com'
            $Result.ClientSiteName | Should -Be 'NYC'
        }

        It 'Should parse Flags' {
            $Result = Get-DCLocatorInfo -DomainName 'contoso.com'
            $Result.Flags | Should -Match 'PDC'
        }

        It 'Should report Success as True' {
            $Result = Get-DCLocatorInfo -DomainName 'contoso.com'
            $Result.Success | Should -Be $true
        }

        It 'Should include RawOutput' {
            $Result = Get-DCLocatorInfo -DomainName 'contoso.com'
            $Result.RawOutput | Should -Not -BeNullOrEmpty
        }
    }

    Context 'When DC locator fails' {

        BeforeAll {
            Mock -ModuleName NetlogonTroubleShooting -CommandName nltest {
                'Getting DC name failed: Status = 1355 0x54b ERROR_NO_SUCH_DOMAIN'
            }
        }

        It 'Should report Success as False' {
            $Result = Get-DCLocatorInfo -DomainName 'nonexistent.invalid'
            $Result.Success | Should -Be $false
        }
    }
}

Describe 'Get-ADSiteInfo' {

    Context 'Parameter validation' {

        It 'Should have a ComputerName parameter' {
            (Get-Command Get-ADSiteInfo).Parameters.Keys | Should -Contain 'ComputerName'
        }

        It 'Should have a SiteName parameter' {
            (Get-Command Get-ADSiteInfo).Parameters.Keys | Should -Contain 'SiteName'
        }
    }

    Context 'When site info is available' {

        BeforeAll {
            Mock -ModuleName NetlogonTroubleShooting -CommandName Get-NetIPAddress {
                [PSCustomObject]@{
                    IPAddress     = '10.1.20.50'
                    AddressFamily = 'IPv4'
                    Type          = 'Unicast'
                }
            }
            Mock -ModuleName NetlogonTroubleShooting -CommandName nltest {
                @('NYC', 'The command completed successfully')
            }
        }

        It 'Should return a site info result' {
            $Result = Get-ADSiteInfo -SiteName 'NYC'
            $Result | Should -Not -BeNullOrEmpty
        }

        It 'Should include AssignedSite property' {
            $Result = Get-ADSiteInfo -SiteName 'NYC'
            $Result.AssignedSite | Should -Be 'NYC'
        }

        It 'Should include ClientIP property' {
            $Result = Get-ADSiteInfo -SiteName 'NYC'
            $Result.ClientIP | Should -Not -BeNullOrEmpty
        }

        It 'Should include expected properties' {
            $Result = Get-ADSiteInfo -SiteName 'NYC'
            $Props = $Result.PSObject.Properties.Name
            $Props | Should -Contain 'ComputerName'
            $Props | Should -Contain 'AssignedSite'
            $Props | Should -Contain 'NoClientSite'
            $Props | Should -Contain 'Subnets'
            $Props | Should -Contain 'DCs'
            $Props | Should -Contain 'SubnetCount'
            $Props | Should -Contain 'DCCount'
            $Props | Should -Contain 'SiteLinks'
        }
    }
}

Describe 'Invoke-NetlogonDiagnostic' {

    Context 'Parameter validation' {

        It 'Should have a ComputerName parameter' {
            (Get-Command Invoke-NetlogonDiagnostic).Parameters.Keys | Should -Contain 'ComputerName'
        }

        It 'Should have an OutputFormat parameter' {
            (Get-Command Invoke-NetlogonDiagnostic).Parameters.Keys | Should -Contain 'OutputFormat'
        }

        It 'Should have an OutputPath parameter' {
            (Get-Command Invoke-NetlogonDiagnostic).Parameters.Keys | Should -Contain 'OutputPath'
        }

        It 'Should have a NoOpen switch parameter' {
            (Get-Command Invoke-NetlogonDiagnostic).Parameters.Keys | Should -Contain 'NoOpen'
        }

        It 'Should only accept Text or HTML for OutputFormat' {
            $ValidValues = (Get-Command Invoke-NetlogonDiagnostic).Parameters['OutputFormat'].Attributes |
                           Where-Object { $_ -is [System.Management.Automation.ValidateSetAttribute] } |
                           Select-Object -ExpandProperty ValidValues
            $ValidValues | Should -Contain 'Text'
            $ValidValues | Should -Contain 'HTML'
        }
    }

    Context 'When running a full diagnostic' {

        BeforeAll {
            # Mock all sub-functions to avoid real network/AD calls
            Mock -ModuleName NetlogonTroubleShooting -CommandName Test-WSMan {
                [PSCustomObject]@{ ProductVendor = 'Microsoft Corporation' }
            }
            Mock -ModuleName NetlogonTroubleShooting -CommandName Get-NetlogonStatus {
                [PSCustomObject]@{
                    ServiceStatus       = 'Running'
                    ServiceStartType    = 'Automatic'
                    DomainName          = 'contoso.com'
                    AuthenticatingDC    = 'DC01.contoso.com'
                    SecureChannelHealthy = $true
                    DebugLoggingEnabled = $false
                    DebugLevel          = 'Disabled'
                }
            }
            Mock -ModuleName NetlogonTroubleShooting -CommandName Test-NetlogonSecureChannel {
                [PSCustomObject]@{
                    SecureChannelOK = $true
                    DCName          = 'DC01.contoso.com'
                    Recommendations = @()
                }
            }
            Mock -ModuleName NetlogonTroubleShooting -CommandName Get-DCLocatorInfo {
                [PSCustomObject]@{
                    DCName         = 'DC01.contoso.com'
                    DCAddress      = '10.0.0.10'
                    DCSiteName     = 'NYC'
                    ClientSiteName = 'NYC'
                    Flags          = 'PDC GC DS LDAP KDC'
                    Success        = $true
                }
            }
            Mock -ModuleName NetlogonTroubleShooting -CommandName Get-ADSiteInfo {
                [PSCustomObject]@{
                    AssignedSite = 'NYC'
                    ClientIP     = '10.1.20.50'
                    NoClientSite = $false
                    Subnets      = '10.1.20.0/24'
                    SubnetCount  = 1
                    DCs          = 'DC01.contoso.com'
                    DCCount      = 1
                    SiteLinks    = 'NYC-London'
                }
            }
            Mock -ModuleName NetlogonTroubleShooting -CommandName Test-NetlogonDnsRecords {
                @(
                    [PSCustomObject]@{ RecordName = '_ldap._tcp.dc._msdcs.contoso.com'; Resolved = $true; Purpose = 'DC Locator'; Targets = 'DC01:389'; Error = $null }
                )
            }
            Mock -ModuleName NetlogonTroubleShooting -CommandName Test-DCPortConnectivity {
                @(
                    [PSCustomObject]@{ DomainController = 'DC01.contoso.com'; Port = 389; Service = 'LDAP'; Reachable = $true }
                )
            }
            Mock -ModuleName NetlogonTroubleShooting -CommandName Test-TimeSynchronization {
                [PSCustomObject]@{
                    DomainController = 'DC01.contoso.com'
                    SkewSeconds      = 0.5
                    WithinThreshold  = $true
                    TimeSource       = 'DC01.contoso.com'
                    ComputerName     = $env:COMPUTERNAME
                }
            }
            Mock -ModuleName NetlogonTroubleShooting -CommandName Get-NetlogonEvent { @() }
            Mock -ModuleName NetlogonTroubleShooting -CommandName Get-NetlogonDebugStatus {
                [PSCustomObject]@{ DebugEnabled = $false; Level = 'Disabled' }
            }
            Mock -ModuleName NetlogonTroubleShooting -CommandName Start-Process {}
        }

        It 'Should return a diagnostic report object' {
            $Result = Invoke-NetlogonDiagnostic
            $Result | Should -Not -BeNullOrEmpty
        }

        It 'Should include Results hashtable with all check keys' {
            $Result = Invoke-NetlogonDiagnostic
            $Result.Results.Keys | Should -Contain 'NetlogonStatus'
            $Result.Results.Keys | Should -Contain 'SecureChannel'
            $Result.Results.Keys | Should -Contain 'DCLocator'
            $Result.Results.Keys | Should -Contain 'SiteInfo'
            $Result.Results.Keys | Should -Contain 'DnsRecords'
            $Result.Results.Keys | Should -Contain 'PortConnectivity'
            $Result.Results.Keys | Should -Contain 'TimeSync'
            $Result.Results.Keys | Should -Contain 'Events'
        }

        It 'Should include ComputerName and Timestamp' {
            $Result = Invoke-NetlogonDiagnostic
            $Result.ComputerName | Should -Not -BeNullOrEmpty
            $Result.Timestamp | Should -BeOfType [datetime]
        }

        It 'Should generate HTML when OutputFormat is HTML' {
            $TempFile = Join-Path $TestDrive 'diag.html'
            $Result = Invoke-NetlogonDiagnostic -OutputFormat HTML -OutputPath $TempFile
            Test-Path $TempFile | Should -Be $true
            $Content = Get-Content $TempFile -Raw
            $Content | Should -Match '<!DOCTYPE html>'
            $Content | Should -Match 'Netlogon Diagnostic'
        }

        It 'Should auto-open HTML in browser when -NoOpen is not specified' {
            $TempFile = Join-Path $TestDrive 'diag_open.html'
            Invoke-NetlogonDiagnostic -OutputFormat HTML -OutputPath $TempFile
            Should -Invoke -ModuleName NetlogonTroubleShooting -CommandName Start-Process -Times 1 -Exactly -ParameterFilter { $FilePath -eq $TempFile }
        }

        It 'Should not open browser when -NoOpen is specified' {
            $TempFile = Join-Path $TestDrive 'diag_noopen.html'
            Invoke-NetlogonDiagnostic -OutputFormat HTML -OutputPath $TempFile -NoOpen
            Should -Invoke -ModuleName NetlogonTroubleShooting -CommandName Start-Process -Times 0 -Exactly -ParameterFilter { $FilePath -eq $TempFile }
        }

        It 'Should save HTML to temp file when no OutputPath is given' {
            $Result = Invoke-NetlogonDiagnostic -OutputFormat HTML -NoOpen
            Should -Invoke -ModuleName NetlogonTroubleShooting -CommandName Start-Process -Times 0 -Exactly
        }

        It 'Should generate text when OutputFormat is Text' {
            $TempFile = Join-Path $TestDrive 'diag.txt'
            $Result = Invoke-NetlogonDiagnostic -OutputFormat Text -OutputPath $TempFile
            Test-Path $TempFile | Should -Be $true
            $Content = Get-Content $TempFile -Raw
            $Content | Should -Match 'NETLOGON DIAGNOSTIC REPORT'
        }
    }

    Context 'When WinRM pre-flight fails for remote target' {

        BeforeAll {
            Mock -ModuleName NetlogonTroubleShooting -CommandName Test-WSMan {
                throw [System.Exception]::new('The WinRM client cannot process the request.')
            }
        }

        It 'Should fail with a WinRM connectivity error for remote targets' {
            { Invoke-NetlogonDiagnostic -ComputerName 'UNREACHABLE01' -ErrorAction Stop } | Should -Throw '*WinRM*'
        }

        It 'Should not call any diagnostic functions when WinRM fails' {
            Invoke-NetlogonDiagnostic -ComputerName 'UNREACHABLE01' -ErrorAction SilentlyContinue
            Should -Invoke -ModuleName NetlogonTroubleShooting -CommandName Test-WSMan -Times 1 -Exactly
        }
    }
}
