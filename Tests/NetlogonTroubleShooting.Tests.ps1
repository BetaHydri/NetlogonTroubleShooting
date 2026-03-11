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

        It 'Should export exactly 7 functions' {
            $Module = Get-Module NetlogonTroubleShooting
            $Module.ExportedFunctions.Count | Should -Be 7
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

        It 'Should have version 1.1.0' {
            $Manifest.Version.ToString() | Should -Be '1.1.0'
        }

        It 'Should require PowerShell 5.1' {
            $Manifest.PowerShellVersion.ToString() | Should -Be '5.1'
        }
    }
}

Describe 'Get-NetlogonEvent' {

    Context 'When Netlogon events exist' {

        BeforeAll {
            # Mock Get-WinEvent to return fake 5719 and 5805 events
            Mock -ModuleName NetlogonTroubleShooting -CommandName Get-WinEvent {
                @(
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
            }
        }

        It 'Should return event objects' {
            $Results = Get-NetlogonEvent -ComputerName 'DC01'
            $Results | Should -Not -BeNullOrEmpty
        }

        It 'Should include EventId property' {
            $Results = Get-NetlogonEvent -ComputerName 'DC01'
            $Results[0].EventId | Should -BeIn @(5719, 5805)
        }

        It 'Should include a human-readable Summary for event 5719' {
            $Results = Get-NetlogonEvent -ComputerName 'DC01'
            $Evt5719 = $Results | Where-Object { $_.EventId -eq 5719 } | Select-Object -First 1
            $Evt5719.Summary | Should -Be 'No Domain Controller available for secure session setup'
        }

        It 'Should include a human-readable Summary for event 5805' {
            $Results = Get-NetlogonEvent -ComputerName 'DC01'
            $Evt5805 = $Results | Where-Object { $_.EventId -eq 5805 } | Select-Object -First 1
            $Evt5805.Summary | Should -Be 'Machine account authentication failure'
        }

        It 'Should include Action guidance' {
            $Results = Get-NetlogonEvent -ComputerName 'DC01'
            $Results[0].Action | Should -Not -BeNullOrEmpty
        }

        It 'Should set the correct ComputerName' {
            $Results = Get-NetlogonEvent -ComputerName 'DC01'
            $Results[0].ComputerName | Should -Be 'DC01'
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
}
