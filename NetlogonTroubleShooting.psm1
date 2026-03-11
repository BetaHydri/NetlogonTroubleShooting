#Requires -Version 5.1

#region Get-NetlogonEvent

function Get-NetlogonEvent {
    <#
    .SYNOPSIS
        Retrieves and parses Netlogon-related events from the System and Netlogon event logs.

    .DESCRIPTION
        Queries the System and Microsoft-Windows-Netlogon event logs for common Netlogon
        error events (5719, 5783, 5805, 5722, 5723, 5721, 5781, 3210) and presents
        them with human-readable descriptions and recommended actions.

    .PARAMETER ComputerName
        The computer to query. Defaults to the local computer.

    .PARAMETER EventId
        One or more specific Event IDs to filter on. If not specified, all known
        Netlogon event IDs are returned.

    .PARAMETER StartTime
        Only return events after this date/time. Defaults to the last 24 hours.

    .PARAMETER EndTime
        Only return events before this date/time. Defaults to now.

    .PARAMETER MaxEvents
        Maximum number of events to return. Defaults to 100.

    .EXAMPLE
        Get-NetlogonEvent
        Returns all Netlogon-related events from the last 24 hours.

    .EXAMPLE
        Get-NetlogonEvent -EventId 5719 -StartTime (Get-Date).AddDays(-7)
        Returns Event ID 5719 entries from the last 7 days.

    .EXAMPLE
        Get-NetlogonEvent -ComputerName 'Server01' -MaxEvents 50
        Returns up to 50 Netlogon events from Server01.
    #>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string[]]$ComputerName = $env:COMPUTERNAME,

        [ValidateSet(5719, 5783, 5805, 5722, 5723, 5721, 5781, 3210)]
        [int[]]$EventId,

        [datetime]$StartTime = (Get-Date).AddDays(-1),

        [datetime]$EndTime = (Get-Date),

        [int]$MaxEvents = 100
    )

    begin {
        # Known Netlogon event descriptions and remediation guidance
        $EventDescriptions = @{
            5719 = @{
                Summary     = 'No Domain Controller available for secure session setup'
                Description = 'This computer was not able to set up a secure session with a domain controller in the domain. This is commonly caused by network connectivity issues, DNS resolution failures, or the Netlogon service not running on the DC.'
                Action      = @(
                    'Verify network connectivity to domain controllers (ping, tracert).'
                    'Verify DNS resolution: nslookup <domain> and nslookup -type=SRV _ldap._tcp.dc._msdcs.<domain>'
                    'Check that the Netlogon service is running on domain controllers.'
                    'Verify the computer account password is in sync (Test-ComputerSecureChannel).'
                    'Check firewall rules for ports 88, 135, 389, 445, 636, 3268, 49152-65535.'
                )
            }
            5783 = @{
                Summary     = 'DC session not responsive'
                Description = 'The session setup to the domain controller is not responsive. The trust relationship between the workstation and the primary domain may have failed.'
                Action      = @(
                    'Check network latency and packet loss to the DC.'
                    'Verify the DC is not overloaded (CPU, memory, disk).'
                    'Run nltest /sc_query:<domain> to check the secure channel.'
                    'Consider resetting the computer account password with Reset-ComputerMachinePassword.'
                )
            }
            5805 = @{
                Summary     = 'Machine account authentication failure'
                Description = 'The session setup from a remote computer failed to authenticate. The account or password may be out of sync.'
                Action      = @(
                    'Reset the computer account password: Reset-ComputerMachinePassword -Credential (Get-Credential)'
                    'Or rejoin the domain: Remove-Computer / Add-Computer'
                    'Check for duplicate SPNs: setspn -X'
                )
            }
            5722 = @{
                Summary     = 'No trust account in security database'
                Description = 'The session setup failed because there is no trust account in the security database for the source computer.'
                Action      = @(
                    'Verify the computer account exists in Active Directory.'
                    'Check AD replication: repadmin /replsummary'
                    'Reset or recreate the computer account.'
                )
            }
            5723 = @{
                Summary     = 'Session setup failed - security database issue'
                Description = 'The session setup failed because the security database does not contain a trust account for the referenced computer.'
                Action      = @(
                    'Verify the computer account exists and is not disabled in AD.'
                    'Check AD replication consistency.'
                    'Rejoin the computer to the domain if needed.'
                )
            }
            5721 = @{
                Summary     = 'No local security database account for computer'
                Description = 'The session setup to the DC for the domain failed because the referenced computer does not have a local security database account.'
                Action      = @(
                    'Reset the secure channel: Test-ComputerSecureChannel -Repair -Credential (Get-Credential)'
                    'Verify the computer account is present on the authenticating DC.'
                )
            }
            5781 = @{
                Summary     = 'DNS dynamic registration/deregistration failure'
                Description = 'Dynamic registration or deregistration of one or more DNS records failed. This can cause DC locator failures.'
                Action      = @(
                    'Check DNS server connectivity and permissions.'
                    'Run ipconfig /registerdns to force re-registration.'
                    'Verify the DNS zone allows dynamic updates.'
                    'Check the DHCP configuration if using DHCP-based DNS registration.'
                )
            }
            3210 = @{
                Summary     = 'Authentication with DC failed'
                Description = 'Failed to authenticate with the domain controller. This may indicate a broken trust relationship or network issue.'
                Action      = @(
                    'Run nltest /sc_verify:<domain> to check the secure channel.'
                    'Test with Test-ComputerSecureChannel -Verbose.'
                    'If broken, repair with Test-ComputerSecureChannel -Repair -Credential (Get-Credential).'
                )
            }
        }

        $KnownEventIds = @(5719, 5783, 5805, 5722, 5723, 5721, 5781, 3210)
        if ($EventId) {
            $FilterIds = $EventId
        }
        else {
            $FilterIds = $KnownEventIds
        }
    }

    process {
        foreach ($Computer in $ComputerName) {
            Write-Verbose "Querying Netlogon events on $Computer..."

            # Build filter hashtables for both log sources
            $LogSources = @(
                @{ LogName = 'System'; ProviderName = 'NETLOGON' }
                @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Security-Netlogon' }
            )

            foreach ($Source in $LogSources) {
                $FilterHash = @{
                    LogName   = $Source.LogName
                    StartTime = $StartTime
                    EndTime   = $EndTime
                    Id        = $FilterIds
                }

                try {
                    $Events = Get-WinEvent -FilterHashtable $FilterHash -ComputerName $Computer -MaxEvents $MaxEvents -ErrorAction SilentlyContinue

                    foreach ($Event in $Events) {
                        $Info = $EventDescriptions[$Event.Id]
                        [PSCustomObject]@{
                            PSTypeName   = 'NetlogonTroubleShooting.Event'
                            ComputerName = $Computer
                            TimeCreated  = $Event.TimeCreated
                            EventId      = $Event.Id
                            Level        = $Event.LevelDisplayName
                            Summary      = if ($Info) { $Info.Summary } else { 'Unknown Netlogon Event' }
                            Description  = if ($Info) { $Info.Description } else { $Event.Message }
                            Message      = $Event.Message
                            Action       = if ($Info) { $Info.Action -join "`n" } else { 'Review the event message for details.' }
                            ProviderName = $Event.ProviderName
                        }
                    }
                }
                catch {
                    if ($_.Exception.Message -notmatch 'No events were found') {
                        Write-Warning "Error querying $Computer ($($Source.LogName)): $_"
                    }
                }
            }
        }
    }
}

#endregion

#region Enable-NetlogonDebug

function Enable-NetlogonDebug {
    <#
    .SYNOPSIS
        Enables Netlogon debug logging.

    .DESCRIPTION
        Configures the Netlogon service to write detailed debug logs to
        %systemroot%\debug\netlogon.log by setting the DBFlag registry value.
        Requires elevation (Run as Administrator). On modern Windows (Server
        2012 R2+ / Windows 10+) the change is applied dynamically via
        nltest /dbflag: without restarting the Netlogon service.

    .PARAMETER ComputerName
        The computer to enable debug logging on. Defaults to the local computer.

    .PARAMETER Level
        The debug level to enable.
        - Full:    0x2080FFFF (all debug flags, most verbose)
        - Standard: 0x20000004 (basic DC discovery and authentication logging)
        Defaults to Full.

    .PARAMETER MaxLogSizeBytes
        Maximum size of the netlogon.log file in bytes before it rolls over
        to netlogon.bak. Defaults to 256 MB (268435456 bytes).

    .EXAMPLE
        Enable-NetlogonDebug
        Enables full Netlogon debug logging on the local machine. The change
        is applied dynamically via nltest without restarting the service.

    .EXAMPLE
        Enable-NetlogonDebug -Level Standard
        Enables standard-level debug logging on the local machine.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param(
        [Parameter(ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string[]]$ComputerName = $env:COMPUTERNAME,

        [ValidateSet('Full', 'Standard')]
        [string]$Level = 'Full',

        [int]$MaxLogSizeBytes = 268435456
    )

    begin {
        $DebugFlags = @{
            'Full'     = 0x2080FFFF
            'Standard' = 0x20000004
        }
        $RegPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'
    }

    process {
        foreach ($Computer in $ComputerName) {
            $IsLocal = ($Computer -eq $env:COMPUTERNAME) -or ($Computer -eq 'localhost') -or ($Computer -eq '.')

            if ($PSCmdlet.ShouldProcess($Computer, "Enable Netlogon debug logging (Level: $Level)")) {
                try {
                    if ($IsLocal) {
                        # Verify running as administrator
                        $CurrentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
                        $Principal = New-Object Security.Principal.WindowsPrincipal($CurrentUser)
                        if (-not $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
                            Write-Error "This command requires elevation. Run PowerShell as Administrator."
                            return
                        }

                        Set-ItemProperty -Path $RegPath -Name 'DBFlag' -Value $DebugFlags[$Level] -Type DWord -Force
                        Set-ItemProperty -Path $RegPath -Name 'MaximumLogFileSize' -Value $MaxLogSizeBytes -Type DWord -Force

                        # Apply dynamically via nltest (no service restart needed on modern OS)
                        $null = & nltest /dbflag:"0x$($DebugFlags[$Level].ToString('X'))"
                        Write-Verbose "Registry values set and applied on $Computer (DBFlag=0x$($DebugFlags[$Level].ToString('X')), MaxLogSize=$MaxLogSizeBytes)"
                    }
                    else {
                        Invoke-Command -ComputerName $Computer -ScriptBlock {
                            param($RegPathRemote, $FlagValue, $MaxSize)
                            Set-ItemProperty -Path $RegPathRemote -Name 'DBFlag' -Value $FlagValue -Type DWord -Force
                            Set-ItemProperty -Path $RegPathRemote -Name 'MaximumLogFileSize' -Value $MaxSize -Type DWord -Force
                            $null = & nltest /dbflag:"0x$($FlagValue.ToString('X'))"
                        } -ArgumentList $RegPath, $DebugFlags[$Level], $MaxLogSizeBytes
                    }

                    [PSCustomObject]@{
                        PSTypeName   = 'NetlogonTroubleShooting.DebugConfig'
                        ComputerName = $Computer
                        DebugEnabled = $true
                        Level        = $Level
                        DBFlag       = '0x{0:X}' -f $DebugFlags[$Level]
                        MaxLogSize   = $MaxLogSizeBytes
                        LogPath      = "\\$Computer\admin$\debug\netlogon.log"
                        Restarted    = $false
                    }

                    Write-Host "Netlogon debug logging ENABLED on $Computer (Level: $Level)." -ForegroundColor Green
                    Write-Host "Log location: $env:SystemRoot\debug\netlogon.log" -ForegroundColor Cyan
                }
                catch {
                    Write-Error "Failed to enable Netlogon debug on $Computer : $_"
                }
            }
        }
    }
}

#endregion

#region Disable-NetlogonDebug

function Disable-NetlogonDebug {
    <#
    .SYNOPSIS
        Disables Netlogon debug logging.

    .DESCRIPTION
        Removes the DBFlag registry value to stop Netlogon debug logging.
        Requires elevation (Run as Administrator). On modern Windows (Server
        2012 R2+ / Windows 10+) the change is applied dynamically via
        nltest /dbflag: without restarting the Netlogon service.

    .PARAMETER ComputerName
        The computer to disable debug logging on. Defaults to the local computer.

    .EXAMPLE
        Disable-NetlogonDebug
        Disables Netlogon debug logging on the local machine.

    .EXAMPLE
        Disable-NetlogonDebug -ComputerName 'Server01', 'Server02'
        Disables Netlogon debug logging on multiple remote computers.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param(
        [Parameter(ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string[]]$ComputerName = $env:COMPUTERNAME
    )

    begin {
        $RegPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'
    }

    process {
        foreach ($Computer in $ComputerName) {
            $IsLocal = ($Computer -eq $env:COMPUTERNAME) -or ($Computer -eq 'localhost') -or ($Computer -eq '.')

            if ($PSCmdlet.ShouldProcess($Computer, "Disable Netlogon debug logging")) {
                try {
                    if ($IsLocal) {
                        $CurrentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
                        $Principal = New-Object Security.Principal.WindowsPrincipal($CurrentUser)
                        if (-not $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
                            Write-Error "This command requires elevation. Run PowerShell as Administrator."
                            return
                        }

                        Set-ItemProperty -Path $RegPath -Name 'DBFlag' -Value 0 -Type DWord -Force

                        # Apply dynamically via nltest (no service restart needed on modern OS)
                        $null = & nltest /dbflag:0x0
                        Write-Verbose "DBFlag set to 0 and applied on $Computer"
                    }
                    else {
                        Invoke-Command -ComputerName $Computer -ScriptBlock {
                            param($RegPathRemote)
                            Set-ItemProperty -Path $RegPathRemote -Name 'DBFlag' -Value 0 -Type DWord -Force
                            $null = & nltest /dbflag:0x0
                        } -ArgumentList $RegPath
                    }

                    [PSCustomObject]@{
                        PSTypeName   = 'NetlogonTroubleShooting.DebugConfig'
                        ComputerName = $Computer
                        DebugEnabled = $false
                        Level        = 'Disabled'
                        DBFlag       = '0x0'
                        Restarted    = $false
                    }

                    Write-Host "Netlogon debug logging DISABLED on $Computer." -ForegroundColor Yellow
                }
                catch {
                    Write-Error "Failed to disable Netlogon debug on $Computer : $_"
                }
            }
        }
    }
}

#endregion

#region Get-NetlogonDebugStatus

function Get-NetlogonDebugStatus {
    <#
    .SYNOPSIS
        Checks whether Netlogon debug logging is currently enabled.

    .DESCRIPTION
        Reads the DBFlag and MaximumLogFileSize registry values to determine
        the current Netlogon debug logging configuration. Also checks for
        the existence and size of the netlogon.log file.

    .PARAMETER ComputerName
        The computer to check. Defaults to the local computer.

    .EXAMPLE
        Get-NetlogonDebugStatus
        Returns the current Netlogon debug logging status on the local machine.

    .EXAMPLE
        Get-NetlogonDebugStatus -ComputerName 'DC01', 'DC02'
        Checks debug status on multiple domain controllers.
    #>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string[]]$ComputerName = $env:COMPUTERNAME
    )

    begin {
        $RegPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'
    }

    process {
        foreach ($Computer in $ComputerName) {
            $IsLocal = ($Computer -eq $env:COMPUTERNAME) -or ($Computer -eq 'localhost') -or ($Computer -eq '.')

            try {
                if ($IsLocal) {
                    $DBFlag = (Get-ItemProperty -Path $RegPath -Name 'DBFlag' -ErrorAction SilentlyContinue).DBFlag
                    $MaxSize = (Get-ItemProperty -Path $RegPath -Name 'MaximumLogFileSize' -ErrorAction SilentlyContinue).MaximumLogFileSize
                    $LogPath = Join-Path $env:SystemRoot 'debug\netlogon.log'
                    $BakPath = Join-Path $env:SystemRoot 'debug\netlogon.bak'
                }
                else {
                    $Result = Invoke-Command -ComputerName $Computer -ScriptBlock {
                        param($RegPathRemote)
                        $Flag = (Get-ItemProperty -Path $RegPathRemote -Name 'DBFlag' -ErrorAction SilentlyContinue).DBFlag
                        $Max = (Get-ItemProperty -Path $RegPathRemote -Name 'MaximumLogFileSize' -ErrorAction SilentlyContinue).MaximumLogFileSize
                        $LogFile = Join-Path $env:SystemRoot 'debug\netlogon.log'
                        $BakFile = Join-Path $env:SystemRoot 'debug\netlogon.bak'
                        @{
                            DBFlag    = $Flag
                            MaxSize   = $Max
                            LogPath   = $LogFile
                            BakPath   = $BakFile
                            LogExists = Test-Path $LogFile
                            LogSize   = if (Test-Path $LogFile) { (Get-Item $LogFile).Length } else { 0 }
                            BakExists = Test-Path $BakFile
                            BakSize   = if (Test-Path $BakFile) { (Get-Item $BakFile).Length } else { 0 }
                        }
                    } -ArgumentList $RegPath

                    $DBFlag = $Result.DBFlag
                    $MaxSize = $Result.MaxSize
                    $LogPath = $Result.LogPath
                    $BakPath = $Result.BakPath
                }

                # Determine debug level from flag value
                $DebugLevel = switch ($DBFlag) {
                    0x2080FFFF { 'Full' }
                    0x20000004 { 'Standard' }
                    0 { 'Disabled' }
                    $null { 'Disabled' }
                    default { "Custom (0x$($DBFlag.ToString('X')))" }
                }

                # Get log file info for local queries
                if ($IsLocal) {
                    $LogExists = Test-Path $LogPath
                    $LogSize = if ($LogExists) { (Get-Item $LogPath).Length } else { 0 }
                    $BakExists = Test-Path $BakPath
                    $BakSize = if ($BakExists) { (Get-Item $BakPath).Length } else { 0 }
                }
                else {
                    $LogExists = $Result.LogExists
                    $LogSize = $Result.LogSize
                    $BakExists = $Result.BakExists
                    $BakSize = $Result.BakSize
                }

                [PSCustomObject]@{
                    PSTypeName      = 'NetlogonTroubleShooting.DebugStatus'
                    ComputerName    = $Computer
                    DebugEnabled    = ($null -ne $DBFlag -and $DBFlag -ne 0)
                    Level           = $DebugLevel
                    DBFlag          = if ($null -ne $DBFlag) { '0x{0:X}' -f $DBFlag } else { 'Not Set' }
                    MaxLogSizeBytes = $MaxSize
                    LogFileExists   = $LogExists
                    LogFileSizeMB   = [math]::Round($LogSize / 1MB, 2)
                    BakFileExists   = $BakExists
                    BakFileSizeMB   = [math]::Round($BakSize / 1MB, 2)
                    LogPath         = $LogPath
                }
            }
            catch {
                Write-Error "Failed to get Netlogon debug status from $Computer : $_"
            }
        }
    }
}

#endregion

#region Read-NetlogonDebugLog

function Read-NetlogonDebugLog {
    <#
    .SYNOPSIS
        Parses the Netlogon debug log file for errors, warnings, and key events.

    .DESCRIPTION
        Reads and parses %systemroot%\debug\netlogon.log (and optionally netlogon.bak),
        extracting structured entries. Filters for errors, authentication failures,
        DC discovery issues, site problems, and other notable events.

    .PARAMETER Path
        Path to the Netlogon log file. Defaults to $env:SystemRoot\debug\netlogon.log.

    .PARAMETER IncludeBackup
        Also parse the netlogon.bak rollover file.

    .PARAMETER ErrorsOnly
        Only return entries that contain errors, failures, or critical issues.

    .PARAMETER Category
        Filter by specific category of log entries:
        - Authentication: Authentication and trust-related entries
        - DCDiscovery:    Domain controller discovery/locator entries
        - SiteInfo:       Site and subnet related entries
        - DnsRegistration: DNS registration entries
        - SecureChannel:  Secure channel establishment entries
        - All:            All categories (default)

    .PARAMETER Last
        Only return the last N entries. Useful for tailing the log.

    .PARAMETER StartTime
        Only return entries after this date/time.

    .EXAMPLE
        Read-NetlogonDebugLog -ErrorsOnly
        Returns only error entries from the current Netlogon debug log.

    .EXAMPLE
        Read-NetlogonDebugLog -Category DCDiscovery -Last 50
        Returns the last 50 DC discovery-related entries.

    .EXAMPLE
        Read-NetlogonDebugLog -IncludeBackup -StartTime (Get-Date).AddHours(-2)
        Parses both log and backup file for entries from the last 2 hours.
    #>
    [CmdletBinding()]
    param(
        [string]$Path,

        [switch]$IncludeBackup,

        [switch]$ErrorsOnly,

        [ValidateSet('All', 'Authentication', 'DCDiscovery', 'SiteInfo', 'DnsRegistration', 'SecureChannel')]
        [string]$Category = 'All',

        [int]$Last,

        [datetime]$StartTime
    )

    begin {
        if (-not $Path) {
            $Path = Join-Path $env:SystemRoot 'debug\netlogon.log'
        }

        $BakPath = $Path -replace '\.log$', '.bak'

        # Patterns that indicate errors or problems
        $ErrorPatterns = @(
            'NO_CLIENT_SITE'
            'FATAL'
            'ERROR'
            'FAILED'
            'FAILURE'
            'STATUS_ACCESS_DENIED'
            'STATUS_NO_TRUST_SAM_ACCOUNT'
            'STATUS_WRONG_PASSWORD'
            'STATUS_NO_SUCH_USER'
            'STATUS_ACCOUNT_DISABLED'
            'STATUS_ACCOUNT_LOCKED_OUT'
            'STATUS_NO_LOGON_SERVERS'
            'STATUS_TRUSTED_DOMAIN_FAILURE'
            'STATUS_NETLOGON_NOT_STARTED'
            'STATUS_NO_SUCH_DOMAIN'
            'STATUS_BAD_NETWORK_PATH'
            'STATUS_NETWORK_UNREACHABLE'
            'STATUS_HOST_UNREACHABLE'
            'STATUS_CONNECTION_REFUSED'
            'STATUS_IO_TIMEOUT'
        )
        $ErrorRegex = ($ErrorPatterns | ForEach-Object { [regex]::Escape($_) }) -join '|'

        # Category-based keyword patterns
        $CategoryPatterns = @{
            'Authentication'  = 'NlPrintRpcDebug|LOGON|AUTHENTICATE|PASSWORD|TRUST|CREDENTIAL|SAM_ACCOUNT'
            'DCDiscovery'     = 'SITE_LESS_DC|DcGetDc|LOCATOR|DC_DISCOVERY|DsGetDc|DC_LIST|PICK_DC'
            'SiteInfo'        = 'NO_CLIENT_SITE|SITE|SUBNET|DsrGetSiteName|NlGetAssignedSiteName'
            'DnsRegistration' = 'DNS|DnsRegister|DnsDeregister|NlDns|_ldap\._tcp|_kerberos'
            'SecureChannel'   = 'SECURE_CHANNEL|NlSessionSetup|NlSetServerClientSession|SC_|CHANGELOG'
        }

        # NTSTATUS / Win32 / Netlogon status code descriptions
        $StatusDescriptions = @{
            # NTSTATUS codes (symbolic names)
            'STATUS_SUCCESS'                           = 'The operation completed successfully.'
            'STATUS_ACCESS_DENIED'                     = 'Access is denied. The caller does not have the required permissions.'
            'STATUS_NO_TRUST_SAM_ACCOUNT'              = 'The SAM database on the domain controller does not have a computer account for this workstation trust relationship.'
            'STATUS_WRONG_PASSWORD'                    = 'The specified network password is incorrect.'
            'STATUS_NO_SUCH_USER'                      = 'The specified user does not exist.'
            'STATUS_ACCOUNT_DISABLED'                  = 'The referenced account is currently disabled.'
            'STATUS_ACCOUNT_LOCKED_OUT'                = 'The referenced account is currently locked out and may not be logged on to.'
            'STATUS_NO_LOGON_SERVERS'                  = 'There are currently no logon servers available to service the logon request.'
            'STATUS_TRUSTED_DOMAIN_FAILURE'            = 'The trust relationship between this workstation and the primary domain failed.'
            'STATUS_NETLOGON_NOT_STARTED'              = 'An attempt was made to logon, but the Netlogon service was not started.'
            'STATUS_NO_SUCH_DOMAIN'                    = 'The specified domain did not exist.'
            'STATUS_BAD_NETWORK_PATH'                  = 'The network path was not found.'
            'STATUS_NETWORK_UNREACHABLE'               = 'The remote network is not reachable by the transport.'
            'STATUS_HOST_UNREACHABLE'                  = 'The remote system is not reachable by the transport.'
            'STATUS_CONNECTION_REFUSED'                = 'The remote system refused the network connection.'
            'STATUS_IO_TIMEOUT'                        = 'The specified I/O operation was not completed before the time-out period expired.'
            'STATUS_OBJECT_NAME_NOT_FOUND'             = 'The object name is not found.'
            'STATUS_INSUFFICIENT_RESOURCES'            = 'Insufficient system resources exist to complete the API.'
            'STATUS_TRUSTED_RELATIONSHIP_FAILURE'      = 'The trust relationship between the workstation and the domain failed.'
            'STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT' = 'The account used is a computer account and workstation trust account logon is not allowed.'
            'STATUS_INVALID_COMPUTER_NAME'             = 'The specified computer name contains invalid characters.'
            'STATUS_DS_SAM_INIT_FAILURE'               = 'The Directory Service failed to initialize the SAM subsystem.'
            'STATUS_TIME_DIFFERENCE_AT_DC'             = 'There is a time and/or date difference between the client and server.'
            'STATUS_NOLOGON_SERVER_TRUST_ACCOUNT'      = 'The account used is a server trust account and cannot be used to log on.'
            'STATUS_NOLOGON_INTERDOMAIN_TRUST_ACCOUNT' = 'The account used is an interdomain trust account and cannot be used to log on.'
            'STATUS_DOMAIN_TRUST_INCONSISTENT'         = 'The name or SID of the domain specified is inconsistent with the trust information for that domain.'
            # Common hex status codes (NTSTATUS / Win32 numeric)
            '0x0'                                      = 'Success (STATUS_SUCCESS)'
            '0x5'                                      = 'Access denied (ERROR_ACCESS_DENIED)'
            '0x35'                                     = 'The network path was not found (ERROR_BAD_NETPATH)'
            '0x6D9'                                    = 'There are no more endpoints available from the endpoint mapper (EPT_S_NOT_REGISTERED)'
            '0x6BA'                                    = 'The RPC server is unavailable (RPC_S_SERVER_UNAVAILABLE)'
            '0x6BF'                                    = 'The RPC server is too busy (RPC_S_SERVER_TOO_BUSY)'
            '0x51F'                                    = 'No logon servers available (ERROR_NO_LOGON_SERVERS)'
            '0x52E'                                    = 'Logon failure: unknown user name or bad password (ERROR_LOGON_FAILURE)'
            '0x701'                                    = 'The trust relationship failed (ERROR_TRUSTED_DOMAIN_FAILURE)'
            '0x721'                                    = 'The session setup failed with STATUS_NO_TRUST_SAM_ACCOUNT'
            '0x2A300'                                  = 'DnsFailedDeregisterTimeout — DNS deregistration timeout exceeded. DNS records may be stale.'
            '0xC000005E'                               = 'No logon servers available (STATUS_NO_LOGON_SERVERS)'
            '0xC0000022'                               = 'Access denied (STATUS_ACCESS_DENIED)'
            '0xC000006D'                               = 'Logon failure (STATUS_LOGON_FAILURE)'
            '0xC000006A'                               = 'Wrong password (STATUS_WRONG_PASSWORD)'
            '0xC0000064'                               = 'No such user (STATUS_NO_SUCH_USER)'
            '0xC0000072'                               = 'Account disabled (STATUS_ACCOUNT_DISABLED)'
            '0xC0000234'                               = 'Account locked out (STATUS_ACCOUNT_LOCKED_OUT)'
            '0xC000018B'                               = 'No trust SAM account (STATUS_NO_TRUST_SAM_ACCOUNT)'
            '0xC000018D'                               = 'Trusted relationship failure (STATUS_TRUSTED_RELATIONSHIP_FAILURE)'
            '0xC000019B'                               = 'Netlogon not started (STATUS_NETLOGON_NOT_STARTED)'
            '0xC00000DF'                               = 'The specified domain did not exist (STATUS_NO_SUCH_DOMAIN)'
            '0xC00000B5'                               = 'I/O timeout (STATUS_IO_TIMEOUT)'
            '0xC0000203'                               = 'Time difference at DC (STATUS_TIME_DIFFERENCE_AT_DC)'
        }

        # Netlogon.log line format: MM/DD HH:MM:SS [TYPE] [PID] Message
        $LineRegex = '^(\d{2}/\d{2}(?:/\d{2,4})?\s+\d{2}:\d{2}:\d{2})\s+\[(\w+)\]\s+(?:\[(\d+)\]\s+)?(.*)$'
    }

    process {
        $FilesToParse = @()

        if ($IncludeBackup -and (Test-Path $BakPath)) {
            $FilesToParse += $BakPath
        }

        if (Test-Path $Path) {
            $FilesToParse += $Path
        }
        else {
            Write-Error "Netlogon log file not found at $Path. Enable debug logging first with Enable-NetlogonDebug."
            return
        }

        $AllEntries = [System.Collections.Generic.List[PSObject]]::new()

        foreach ($File in $FilesToParse) {
            Write-Verbose "Parsing $File..."
            $FileInfo = Get-Item $File
            $LineNumber = 0

            try {
                # Open with FileShare.ReadWrite so we can read while Netlogon has the file locked
                $FileStream = [System.IO.FileStream]::new($File, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
                $Reader = [System.IO.StreamReader]::new($FileStream, [System.Text.Encoding]::UTF8, $true)
                try {
                    while ($null -ne ($Line = $Reader.ReadLine())) {
                        $LineNumber++

                        if ($Line -match $LineRegex) {
                            $TimestampStr = $Matches[1]
                            $LogType = $Matches[2]
                            $ProcessId = $Matches[3]
                            $Message = $Matches[4]

                            # Parse timestamp - netlogon.log uses MM/DD HH:MM:SS or MM/DD/YYYY HH:MM:SS
                            [datetime]$ParsedTime = [datetime]::MinValue
                            $Formats = @(
                                'MM/dd HH:mm:ss'
                                'MM/dd/yyyy HH:mm:ss'
                                'MM/dd/yy HH:mm:ss'
                            )
                            foreach ($Fmt in $Formats) {
                                if ([datetime]::TryParseExact($TimestampStr, $Fmt,
                                        [System.Globalization.CultureInfo]::InvariantCulture,
                                        [System.Globalization.DateTimeStyles]::None,
                                        [ref]$ParsedTime)) {
                                    # If year is missing, assume current year
                                    if ($ParsedTime.Year -eq 1) {
                                        $ParsedTime = $ParsedTime.AddYears((Get-Date).Year - 1)
                                    }
                                    break
                                }
                            }

                            # Apply time filter
                            if ($StartTime -and $ParsedTime -ne [datetime]::MinValue -and $ParsedTime -lt $StartTime) {
                                continue
                            }

                            # Determine if this is an error line
                            $IsError = [regex]::IsMatch($Message, $ErrorRegex, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)

                            # Apply error filter
                            if ($ErrorsOnly -and -not $IsError) {
                                continue
                            }

                            # Apply category filter
                            if ($Category -ne 'All') {
                                $CatPattern = $CategoryPatterns[$Category]
                                if (-not [regex]::IsMatch($Message, $CatPattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)) {
                                    continue
                                }
                            }

                            # Classify the entry
                            $EntryCategory = 'General'
                            foreach ($CatName in $CategoryPatterns.Keys) {
                                if ([regex]::IsMatch($Message, $CategoryPatterns[$CatName], [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)) {
                                    $EntryCategory = $CatName
                                    break
                                }
                            }

                            # Extract NTSTATUS or error code if present
                            $StatusCode = $null
                            if ($Message -match '(STATUS_\w+)') {
                                $StatusCode = $Matches[1]
                            }
                            elseif ($Message -match '(0x[0-9A-Fa-f]+)') {
                                $StatusCode = $Matches[1]
                            }

                            # Resolve status code to human-readable description
                            $StatusDescription = $null
                            if ($StatusCode) {
                                # Try exact match first
                                if ($StatusDescriptions.ContainsKey($StatusCode)) {
                                    $StatusDescription = $StatusDescriptions[$StatusCode]
                                }
                                elseif ($StatusCode -match '^0x') {
                                    # Normalize hex to uppercase for lookup
                                    $NormalizedHex = '0x' + $StatusCode.Substring(2).TrimStart('0').ToUpper()
                                    if ($NormalizedHex -eq '0x') { $NormalizedHex = '0x0' }
                                    foreach ($Key in $StatusDescriptions.Keys) {
                                        if ($Key -match '^0x') {
                                            $KeyNorm = '0x' + $Key.Substring(2).TrimStart('0').ToUpper()
                                            if ($KeyNorm -eq '0x') { $KeyNorm = '0x0' }
                                            if ($KeyNorm -eq $NormalizedHex) {
                                                $StatusDescription = $StatusDescriptions[$Key]
                                                break
                                            }
                                        }
                                    }
                                }
                            }

                            $Entry = [PSCustomObject]@{
                                PSTypeName        = 'NetlogonTroubleShooting.LogEntry'
                                SourceFile        = $FileInfo.Name
                                LineNumber        = $LineNumber
                                Timestamp         = $ParsedTime
                                LogType           = $LogType
                                ProcessId         = $ProcessId
                                Category          = $EntryCategory
                                IsError           = $IsError
                                StatusCode        = $StatusCode
                                StatusDescription = $StatusDescription
                                Message           = $Message.Trim()
                                RawLine           = $Line
                            }

                            $AllEntries.Add($Entry)
                        }
                    }
                }
                finally {
                    $Reader.Dispose()
                    $FileStream.Dispose()
                }
            }
            catch {
                Write-Error "Failed to read $File : $_"
            }
        }

        # Apply -Last filter
        if ($Last -and $Last -gt 0 -and $AllEntries.Count -gt $Last) {
            $AllEntries = $AllEntries | Select-Object -Last $Last
        }

        # Output summary
        $ErrorCount = ($AllEntries | Where-Object { $_.IsError }).Count
        $TotalCount = $AllEntries.Count

        if ($TotalCount -eq 0) {
            Write-Host "No matching entries found in Netlogon debug log." -ForegroundColor Yellow
        }
        else {
            Write-Host "Found $TotalCount entries ($ErrorCount errors/failures)." -ForegroundColor Cyan
        }

        $AllEntries
    }
}

#endregion

#region Get-NetlogonStatus

function Get-NetlogonStatus {
    <#
    .SYNOPSIS
        Gets the current Netlogon service status and secure channel information.

    .DESCRIPTION
        Retrieves comprehensive Netlogon status including service state, secure channel
        status, trusted domain list, DC discovery info, and Netlogon-related DNS records.

    .PARAMETER ComputerName
        The computer to check. Defaults to the local computer.

    .EXAMPLE
        Get-NetlogonStatus
        Returns the Netlogon status for the local machine.

    .EXAMPLE
        Get-NetlogonStatus -ComputerName 'Server01'
        Returns the Netlogon status for Server01.
    #>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string[]]$ComputerName = $env:COMPUTERNAME
    )

    process {
        foreach ($Computer in $ComputerName) {
            Write-Verbose "Checking Netlogon status on $Computer..."

            try {
                # Get Netlogon service status
                $IsLocal = ($Computer -eq $env:COMPUTERNAME) -or ($Computer -eq 'localhost') -or ($Computer -eq '.')
                if ($IsLocal) {
                    $Service = Get-Service -Name 'Netlogon' -ErrorAction Stop
                }
                else {
                    $Service = Invoke-Command -ComputerName $Computer -ScriptBlock { Get-Service -Name 'Netlogon' } -ErrorAction Stop
                }

                # Get domain info
                $DomainInfo = $null
                try {
                    $DomainInfo = [System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain()
                }
                catch {
                    Write-Verbose "Could not retrieve domain information: $_"
                }

                # Run nltest commands for detailed info
                $SecureChannelResult = $null
                $DCInfo = $null
                $TrustedDomains = $null

                try {
                    $NltestSC = nltest /sc_query:$($DomainInfo.Name) 2>&1
                    $SecureChannelResult = ($NltestSC | Out-String).Trim()
                }
                catch {
                    $SecureChannelResult = "Failed to query secure channel: $_"
                }

                try {
                    $NltestDC = nltest /dsgetdc:$($DomainInfo.Name) 2>&1
                    $DCInfo = ($NltestDC | Out-String).Trim()
                }
                catch {
                    $DCInfo = "Failed to query DC info: $_"
                }

                try {
                    $NltestTrusted = nltest /trusted_domains 2>&1
                    $TrustedDomains = ($NltestTrusted | Out-String).Trim()
                }
                catch {
                    $TrustedDomains = "Failed to query trusted domains: $_"
                }

                # Parse secure channel status
                $SCHealthy = $false
                if ($SecureChannelResult -match 'NERR_Success') {
                    $SCHealthy = $true
                }

                # Extract DC name from nltest output
                $AuthenticatingDC = $null
                if ($DCInfo -match 'DC:\s*\\\\(\S+)') {
                    $AuthenticatingDC = $Matches[1]
                }

                # Extract DC address
                $DCAddress = $null
                if ($DCInfo -match 'Address:\s*\\\\(\S+)') {
                    $DCAddress = $Matches[1]
                }

                # Extract site name
                $SiteName = $null
                if ($DCInfo -match 'Client Site Name:\s*(\S+)') {
                    $SiteName = $Matches[1]
                }
                elseif ($DCInfo -match 'Our Site Name:\s*(\S+)') {
                    $SiteName = $Matches[1]
                }

                # Test secure channel via PowerShell
                $SecureChannelTest = $null
                try {
                    $SecureChannelTest = Test-ComputerSecureChannel -ErrorAction SilentlyContinue
                }
                catch {
                    Write-Verbose "Test-ComputerSecureChannel failed: $_"
                }

                # Get debug status summary
                $DebugStatus = Get-NetlogonDebugStatus -ComputerName $Computer -ErrorAction SilentlyContinue

                [PSCustomObject]@{
                    PSTypeName           = 'NetlogonTroubleShooting.Status'
                    ComputerName         = $Computer
                    ServiceStatus        = $Service.Status.ToString()
                    ServiceStartType     = $Service.StartType.ToString()
                    DomainName           = if ($DomainInfo) { $DomainInfo.Name } else { 'N/A' }
                    AuthenticatingDC     = $AuthenticatingDC
                    DCAddress            = $DCAddress
                    SiteName             = $SiteName
                    SecureChannelHealthy = $SCHealthy
                    SecureChannelTest    = $SecureChannelTest
                    DebugLoggingEnabled  = if ($DebugStatus) { $DebugStatus.DebugEnabled } else { $false }
                    DebugLevel           = if ($DebugStatus) { $DebugStatus.Level } else { 'Unknown' }
                    SecureChannelDetails = $SecureChannelResult
                    TrustedDomains       = $TrustedDomains
                }
            }
            catch {
                Write-Error "Failed to get Netlogon status from $Computer : $_"
            }
        }
    }
}

#endregion

#region Test-NetlogonSecureChannel

function Test-NetlogonSecureChannel {
    <#
    .SYNOPSIS
        Tests and optionally repairs the Netlogon secure channel.

    .DESCRIPTION
        Tests the secure channel between the local computer and its domain controller.
        Can also attempt to repair a broken secure channel. Provides detailed diagnostic
        output beyond the built-in Test-ComputerSecureChannel cmdlet.

    .PARAMETER ComputerName
        The computer to test. Defaults to the local computer.

    .PARAMETER Repair
        Attempt to repair the secure channel if it is broken. Requires Domain Admin
        credentials (use -Credential).

    .PARAMETER Credential
        Credentials with permission to reset the computer account password.
        Required when using -Repair.

    .EXAMPLE
        Test-NetlogonSecureChannel
        Tests the secure channel on the local machine.

    .EXAMPLE
        Test-NetlogonSecureChannel -Repair -Credential (Get-Credential)
        Tests and repairs the secure channel if broken.
    #>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string[]]$ComputerName = $env:COMPUTERNAME,

        [switch]$Repair,

        [PSCredential]$Credential
    )

    process {
        foreach ($Computer in $ComputerName) {
            Write-Verbose "Testing Netlogon secure channel on $Computer..."

            $IsLocal = ($Computer -eq $env:COMPUTERNAME) -or ($Computer -eq 'localhost') -or ($Computer -eq '.')

            try {
                $Result = [ordered]@{
                    PSTypeName      = 'NetlogonTroubleShooting.SecureChannelTest'
                    ComputerName    = $Computer
                    TestTime        = Get-Date
                    SecureChannelOK = $false
                    NltestResult    = $null
                    RepairAttempted = $false
                    RepairResult    = $null
                    DCName          = $null
                    Recommendations = @()
                }

                if ($IsLocal) {
                    # Detect if this machine is a domain controller
                    $IsDC = $false
                    $IsSingleDC = $false
                    try {
                        $OSInfo = Get-CimInstance -ClassName Win32_OperatingSystem -Property ProductType -ErrorAction Stop
                        # ProductType 2 = Domain Controller
                        $IsDC = ($OSInfo.ProductType -eq 2)
                    }
                    catch {
                        Write-Verbose "Could not determine product type: $_"
                    }

                    # If this is a DC, check if it is the only one in the domain
                    if ($IsDC) {
                        try {
                            $DomainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain()
                            $AllDCs = @($DomainObj.DomainControllers)
                            if ($AllDCs.Count -le 1) {
                                $IsSingleDC = $true
                            }
                        }
                        catch {
                            Write-Verbose "Could not enumerate domain controllers: $_"
                        }
                    }

                    # Test with Test-ComputerSecureChannel
                    try {
                        $SCTest = Test-ComputerSecureChannel -ErrorAction Stop
                        $Result.SecureChannelOK = $SCTest
                    }
                    catch {
                        $Result.SecureChannelOK = $false
                        Write-Verbose "Test-ComputerSecureChannel failed: $_"
                    }

                    # Get nltest details
                    try {
                        $Domain = ([System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain()).Name
                        $NltestOutput = nltest /sc_verify:$Domain 2>&1 | Out-String
                        $Result.NltestResult = $NltestOutput.Trim()

                        if ($NltestOutput -match 'Trusted DC Name\s*\\\\(\S+)') {
                            $Result.DCName = $Matches[1]
                        }
                    }
                    catch {
                        $Result.NltestResult = "nltest failed: $_"
                    }

                    # Handle single-DC scenario: the test is expected to fail
                    if ($IsSingleDC -and -not $Result.SecureChannelOK) {
                        $Result.Recommendations = @(
                            'This computer is the only domain controller in the domain.'
                            'A secure channel test requires a partner DC to validate against.'
                            'In single-DC environments this test is expected to fail — this is normal and not an error.'
                            'Add a second DC to enable secure channel validation between domain controllers.'
                        )
                    }
                    else {
                        # Repair if requested
                        if ($Repair -and -not $Result.SecureChannelOK) {
                            if (-not $Credential) {
                                Write-Error "The -Credential parameter is required for repair. Use -Credential (Get-Credential)."
                                $Result.RepairAttempted = $false
                            }
                            else {
                                $Result.RepairAttempted = $true
                                try {
                                    $RepairOK = Test-ComputerSecureChannel -Repair -Credential $Credential -ErrorAction Stop
                                    $Result.RepairResult = if ($RepairOK) { 'Repair succeeded' } else { 'Repair failed' }
                                    $Result.SecureChannelOK = $RepairOK
                                }
                                catch {
                                    $Result.RepairResult = "Repair failed: $_"
                                }
                            }
                        }

                        # Build recommendations
                        if (-not $Result.SecureChannelOK) {
                            $Result.Recommendations = @(
                                'Run: Test-ComputerSecureChannel -Repair -Credential (Get-Credential)'
                                'If repair fails, rejoin the domain: Remove-Computer then Add-Computer'
                                'Check AD replication: repadmin /replsummary'
                                'Verify the computer account is not disabled in AD'
                                'Check time synchronization (w32tm /query /status)'
                            )
                        }
                    }
                }
                else {
                    # Remote test via nltest
                    try {
                        $NltestOutput = nltest /server:$Computer /sc_query:* 2>&1 | Out-String
                        $Result.NltestResult = $NltestOutput.Trim()
                        $Result.SecureChannelOK = $NltestOutput -match 'NERR_Success'

                        if ($NltestOutput -match 'Trusted DC Name\s*\\\\(\S+)') {
                            $Result.DCName = $Matches[1]
                        }
                    }
                    catch {
                        $Result.NltestResult = "Remote nltest failed: $_"
                    }
                }

                [PSCustomObject]$Result

                # Console output
                if ($Result.SecureChannelOK) {
                    Write-Host "Secure channel on $Computer is HEALTHY." -ForegroundColor Green
                }
                elseif ($IsSingleDC) {
                    Write-Host "Secure channel test on $Computer is NOT APPLICABLE (single domain controller)." -ForegroundColor Cyan
                    Write-Host "`nNote:" -ForegroundColor Yellow
                    $Result.Recommendations | ForEach-Object { Write-Host "  - $_" -ForegroundColor Yellow }
                }
                else {
                    Write-Host "Secure channel on $Computer is BROKEN." -ForegroundColor Red
                    if ($Result.Recommendations.Count -gt 0) {
                        Write-Host "`nRecommendations:" -ForegroundColor Yellow
                        $Result.Recommendations | ForEach-Object { Write-Host "  - $_" -ForegroundColor Yellow }
                    }
                }
            }
            catch {
                Write-Error "Failed to test secure channel on $Computer : $_"
            }
        }
    }
}

#endregion

#region Test-DCPortConnectivity

function Test-DCPortConnectivity {
    <#
    .SYNOPSIS
        Tests network connectivity to domain controllers on all required AD/Netlogon ports.

    .DESCRIPTION
        Tests TCP connectivity to one or more domain controllers on the ports required
        for Active Directory and Netlogon communication: DNS (53), Kerberos (88),
        RPC Endpoint Mapper (135), LDAP (389), SMB (445), Kerberos Password (464),
        LDAPS (636), Global Catalog (3268), and Global Catalog SSL (3269).

        If no DomainController is specified, the function discovers DCs via
        nltest /dclist:<domain>.

    .PARAMETER DomainController
        One or more domain controller hostnames or IP addresses to test.
        If not specified, DCs are discovered automatically from the current domain.

    .PARAMETER Port
        One or more specific ports to test. If not specified, all standard AD ports
        are tested.

    .PARAMETER TimeoutMs
        Connection timeout in milliseconds. Defaults to 2000 (2 seconds).

    .PARAMETER ComputerName
        The computer to run the port tests from. Defaults to the local computer.

    .EXAMPLE
        Test-DCPortConnectivity
        Tests all AD ports against all discovered domain controllers.

    .EXAMPLE
        Test-DCPortConnectivity -DomainController 'DC01.contoso.com' -Port 389,636
        Tests only LDAP and LDAPS ports against a specific DC.
    #>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string[]]$DomainController,

        [int[]]$Port,

        [int]$TimeoutMs = 2000,

        [string]$ComputerName = $env:COMPUTERNAME
    )

    begin {
        $PortDefinitions = @{
            53   = 'DNS'
            88   = 'Kerberos'
            135  = 'RPC Endpoint Mapper'
            389  = 'LDAP'
            445  = 'SMB'
            464  = 'Kerberos Password'
            636  = 'LDAPS'
            3268 = 'Global Catalog'
            3269 = 'Global Catalog SSL'
        }

        if ($Port) {
            $PortsToTest = $Port
        }
        else {
            $PortsToTest = $PortDefinitions.Keys
        }
    }

    process {
        $IsLocal = ($ComputerName -eq $env:COMPUTERNAME) -or ($ComputerName -eq 'localhost') -or ($ComputerName -eq '.')

        # Discover DCs if none specified
        if (-not $DomainController) {
            try {
                $Domain = ([System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain()).Name
                $DCListOutput = nltest /dclist:$Domain 2>&1 | Out-String
                $DomainController = [regex]::Matches($DCListOutput, '\\\\(\S+)') | ForEach-Object { $_.Groups[1].Value } | Where-Object { $_ -and $_ -ne 'The' }

                if (-not $DomainController) {
                    Write-Error 'Could not discover domain controllers. Specify -DomainController manually.'
                    return
                }
                Write-Verbose "Discovered DCs: $($DomainController -join ', ')"
            }
            catch {
                Write-Error "Failed to discover domain controllers: $_. Specify -DomainController manually."
                return
            }
        }

        foreach ($DC in $DomainController) {
            foreach ($P in $PortsToTest) {
                $PortName = if ($PortDefinitions.ContainsKey($P)) { $PortDefinitions[$P] } else { 'Custom' }

                try {
                    if ($IsLocal) {
                        $TcpClient = [System.Net.Sockets.TcpClient]::new()
                        try {
                            $ConnectTask = $TcpClient.ConnectAsync($DC, $P)
                            $Connected = $ConnectTask.Wait($TimeoutMs)
                        }
                        finally {
                            $TcpClient.Dispose()
                        }
                    }
                    else {
                        $Connected = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                            param($TargetDC, $TargetPort, $Timeout)
                            $Tcp = [System.Net.Sockets.TcpClient]::new()
                            try {
                                $Task = $Tcp.ConnectAsync($TargetDC, $TargetPort)
                                return $Task.Wait($Timeout)
                            }
                            finally {
                                $Tcp.Dispose()
                            }
                        } -ArgumentList $DC, $P, $TimeoutMs
                    }

                    [PSCustomObject]@{
                        PSTypeName       = 'NetlogonTroubleShooting.PortTest'
                        SourceComputer   = $ComputerName
                        DomainController = $DC
                        Port             = $P
                        Service          = $PortName
                        Reachable        = $Connected
                        TimeoutMs        = $TimeoutMs
                    }
                }
                catch {
                    [PSCustomObject]@{
                        PSTypeName       = 'NetlogonTroubleShooting.PortTest'
                        SourceComputer   = $ComputerName
                        DomainController = $DC
                        Port             = $P
                        Service          = $PortName
                        Reachable        = $false
                        TimeoutMs        = $TimeoutMs
                    }
                }
            }
        }
    }
}

#endregion

#region Test-NetlogonDnsRecords

function Test-NetlogonDnsRecords {
    <#
    .SYNOPSIS
        Verifies that critical Netlogon/AD DNS SRV and A records are resolvable.

    .DESCRIPTION
        Queries DNS for the SRV records required by the DC locator process:
        _ldap._tcp.dc._msdcs.<domain>, _kerberos._tcp.<domain>,
        _ldap._tcp.<site>._sites.dc._msdcs.<domain>, and the forest
        Global Catalog record _gc._tcp.<forest>. Also checks the domain A record.

    .PARAMETER DomainName
        The domain FQDN to check. Defaults to the current computer domain.

    .PARAMETER SiteName
        AD site name for site-specific SRV record checks. If not specified, the
        current site is detected automatically.

    .PARAMETER DnsServer
        A specific DNS server to query instead of the default.

    .EXAMPLE
        Test-NetlogonDnsRecords
        Checks all critical DNS records for the current domain and site.

    .EXAMPLE
        Test-NetlogonDnsRecords -DomainName 'contoso.com' -SiteName 'NYC'
        Checks DNS records for the contoso.com domain scoped to the NYC site.
    #>
    [CmdletBinding()]
    param(
        [string]$DomainName,

        [string]$SiteName,

        [string]$DnsServer
    )

    begin {
        # Discover domain if not specified
        if (-not $DomainName) {
            try {
                $DomainName = ([System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain()).Name
            }
            catch {
                Write-Error "Cannot determine domain name. Specify -DomainName. Error: $_"
                return
            }
        }

        # Discover forest root
        $ForestName = $null
        try {
            $ForestName = ([System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()).Name
        }
        catch {
            $ForestName = $DomainName
            Write-Verbose "Could not determine forest name, using domain name."
        }

        # Discover site if not specified
        if (-not $SiteName) {
            try {
                $SiteName = [System.DirectoryServices.ActiveDirectory.ActiveDirectorySite]::GetComputerSite().Name
            }
            catch {
                Write-Verbose "Could not detect AD site automatically."
            }
        }
    }

    process {
        # Build list of records to check
        $Records = @(
            @{ Name = "_ldap._tcp.dc._msdcs.$DomainName"; Type = 'SRV'; Purpose = 'DC Locator (LDAP)' }
            @{ Name = "_kerberos._tcp.dc._msdcs.$DomainName"; Type = 'SRV'; Purpose = 'DC Locator (Kerberos)' }
            @{ Name = "_ldap._tcp.$DomainName"; Type = 'SRV'; Purpose = 'LDAP Service' }
            @{ Name = "_kerberos._tcp.$DomainName"; Type = 'SRV'; Purpose = 'Kerberos Service' }
            @{ Name = "_gc._tcp.$ForestName"; Type = 'SRV'; Purpose = 'Global Catalog' }
            @{ Name = "_ldap._tcp.pdc._msdcs.$DomainName"; Type = 'SRV'; Purpose = 'PDC Locator' }
            @{ Name = $DomainName; Type = 'A'; Purpose = 'Domain A Record' }
        )

        # Add site-specific records if site is known
        if ($SiteName) {
            $Records += @(
                @{ Name = "_ldap._tcp.$SiteName._sites.dc._msdcs.$DomainName"; Type = 'SRV'; Purpose = "Site DC Locator ($SiteName)" }
                @{ Name = "_kerberos._tcp.$SiteName._sites.dc._msdcs.$DomainName"; Type = 'SRV'; Purpose = "Site Kerberos Locator ($SiteName)" }
            )
        }

        foreach ($Rec in $Records) {
            $Resolved = $false
            $Results = $null
            $ErrorMsg = $null

            try {
                $DnsParams = @{
                    Name        = $Rec.Name
                    Type        = $Rec.Type
                    ErrorAction = 'Stop'
                }
                if ($DnsServer) {
                    $DnsParams['Server'] = $DnsServer
                }

                $Results = Resolve-DnsName @DnsParams
                $Resolved = $true
            }
            catch {
                $ErrorMsg = $_.Exception.Message
            }

            $TargetHosts = @()
            if ($Results) {
                if ($Rec.Type -eq 'SRV') {
                    $TargetHosts = $Results | Where-Object { $_.QueryType -eq 'SRV' } | ForEach-Object { "$($_.NameTarget):$($_.Port)" }
                }
                else {
                    $TargetHosts = $Results | Where-Object { $_.QueryType -eq 'A' -or $_.QueryType -eq 'AAAA' } | ForEach-Object { $_.IPAddress }
                }
            }

            [PSCustomObject]@{
                PSTypeName  = 'NetlogonTroubleShooting.DnsRecord'
                RecordName  = $Rec.Name
                RecordType  = $Rec.Type
                Purpose     = $Rec.Purpose
                Resolved    = $Resolved
                ResultCount = ($TargetHosts | Measure-Object).Count
                Targets     = ($TargetHosts -join '; ')
                Error       = $ErrorMsg
            }
        }
    }
}

#endregion

#region Test-TimeSynchronization

function Test-TimeSynchronization {
    <#
    .SYNOPSIS
        Checks time synchronization between the local computer and its authenticating DC.

    .DESCRIPTION
        Compares the local system time against the authenticating domain controller.
        Kerberos authentication fails when the time skew exceeds 5 minutes (default
        MaxClockSkew). Reports the w32time service status and current time source.

    .PARAMETER ComputerName
        The computer to check. Defaults to the local computer.

    .PARAMETER DomainController
        A specific DC to compare time against. If not specified, the authenticating
        DC is used.

    .PARAMETER MaxSkewSeconds
        The warning threshold in seconds. Defaults to 300 (5 minutes, the Kerberos default).

    .EXAMPLE
        Test-TimeSynchronization
        Checks time sync of the local machine against its authenticating DC.

    .EXAMPLE
        Test-TimeSynchronization -ComputerName 'Server01' -MaxSkewSeconds 120
        Checks time sync on Server01 with a 2-minute warning threshold.
    #>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string[]]$ComputerName = $env:COMPUTERNAME,

        [string]$DomainController,

        [int]$MaxSkewSeconds = 300
    )

    process {
        foreach ($Computer in $ComputerName) {
            $IsLocal = ($Computer -eq $env:COMPUTERNAME) -or ($Computer -eq 'localhost') -or ($Computer -eq '.')

            try {
                # Get w32time status
                $W32TimeSource = $null
                $W32TimeStatus = $null

                if ($IsLocal) {
                    try {
                        $W32Output = w32tm /query /status 2>&1 | Out-String
                        $W32TimeStatus = $W32Output.Trim()
                        if ($W32Output -match 'Source:\s*(.+)') {
                            $W32TimeSource = $Matches[1].Trim()
                        }
                    }
                    catch {
                        $W32TimeStatus = "w32tm query failed: $_"
                    }
                }
                else {
                    try {
                        $W32Output = Invoke-Command -ComputerName $Computer -ScriptBlock {
                            w32tm /query /status 2>&1 | Out-String
                        }
                        $W32TimeStatus = $W32Output.Trim()
                        if ($W32Output -match 'Source:\s*(.+)') {
                            $W32TimeSource = $Matches[1].Trim()
                        }
                    }
                    catch {
                        $W32TimeStatus = "Remote w32tm query failed: $_"
                    }
                }

                # Determine DC to compare against
                $TargetDC = $DomainController
                if (-not $TargetDC) {
                    try {
                        $Domain = ([System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain()).Name
                        $DsGetDc = nltest /dsgetdc:$Domain 2>&1 | Out-String
                        if ($DsGetDc -match 'DC:\s*\\\\(\S+)') {
                            $TargetDC = $Matches[1]
                        }
                    }
                    catch {
                        Write-Verbose "Could not auto-detect authenticating DC."
                    }
                }

                # Compare time
                $LocalTime = $null
                $DCTime = $null
                $SkewSeconds = $null

                if ($IsLocal) {
                    $LocalTime = Get-Date
                }
                else {
                    $LocalTime = Invoke-Command -ComputerName $Computer -ScriptBlock { Get-Date }
                }

                if ($TargetDC) {
                    try {
                        $DCTime = Invoke-Command -ComputerName $TargetDC -ScriptBlock { Get-Date }
                        $SkewSeconds = [math]::Abs(($LocalTime - $DCTime).TotalSeconds)
                    }
                    catch {
                        Write-Verbose "Could not get time from DC $TargetDC via WinRM: $_"
                        # Fallback: use w32tm /stripchart for a single sample
                        try {
                            if ($IsLocal) {
                                $StripChart = w32tm /stripchart /computer:$TargetDC /samples:1 /dataonly 2>&1 | Out-String
                            }
                            else {
                                $StripChart = Invoke-Command -ComputerName $Computer -ScriptBlock {
                                    param($DC)
                                    w32tm /stripchart /computer:$DC /samples:1 /dataonly 2>&1 | Out-String
                                } -ArgumentList $TargetDC
                            }
                            if ($StripChart -match '([+-]?\d+\.\d+)s') {
                                $SkewSeconds = [math]::Abs([double]$Matches[1])
                            }
                        }
                        catch {
                            Write-Verbose "w32tm stripchart also failed: $_"
                        }
                    }
                }

                $SkewOK = if ($null -ne $SkewSeconds) { $SkewSeconds -lt $MaxSkewSeconds } else { $null }

                [PSCustomObject]@{
                    PSTypeName       = 'NetlogonTroubleShooting.TimeSync'
                    ComputerName     = $Computer
                    DomainController = $TargetDC
                    LocalTime        = $LocalTime
                    DCTime           = $DCTime
                    SkewSeconds      = if ($null -ne $SkewSeconds) { [math]::Round($SkewSeconds, 2) } else { $null }
                    WithinThreshold  = $SkewOK
                    ThresholdSeconds = $MaxSkewSeconds
                    TimeSource       = $W32TimeSource
                    W32TimeStatus    = $W32TimeStatus
                }

                # Console feedback
                if ($null -eq $SkewSeconds) {
                    Write-Host "Time synchronization on $Computer : could not determine skew." -ForegroundColor Yellow
                }
                elseif ($SkewOK) {
                    Write-Host "Time synchronization on $Computer : OK (skew: $([math]::Round($SkewSeconds,1))s)." -ForegroundColor Green
                }
                else {
                    Write-Host "Time synchronization on $Computer : WARNING — skew $([math]::Round($SkewSeconds,1))s exceeds ${MaxSkewSeconds}s threshold!" -ForegroundColor Red
                }
            }
            catch {
                Write-Error "Failed to check time synchronization on $Computer : $_"
            }
        }
    }
}

#endregion

#region Get-DCLocatorInfo

function Get-DCLocatorInfo {
    <#
    .SYNOPSIS
        Retrieves parsed DC locator information via nltest /dsgetdc.

    .DESCRIPTION
        Runs nltest /dsgetdc:<domain> and parses the output into a structured object.
        Supports flags for force rediscovery, specific site, PDC only, KDC only, time
        server only, and writable DC only. Helps diagnose "wrong DC" or "no DC found".

    .PARAMETER DomainName
        The domain to query. Defaults to the current computer domain.

    .PARAMETER SiteName
        Restrict DC discovery to a specific AD site.

    .PARAMETER ForceRediscovery
        Force a fresh DC discovery bypassing the cache.

    .PARAMETER PDC
        Return only the PDC emulator.

    .PARAMETER KDC
        Return only a Kerberos Distribution Center.

    .PARAMETER TimeServer
        Return only a time server.

    .PARAMETER WritableRequired
        Return only a writable (non-RODC) domain controller.

    .PARAMETER ComputerName
        The computer to run the DC locator from. Defaults to the local computer.

    .EXAMPLE
        Get-DCLocatorInfo
        Returns DC locator info for the current domain.

    .EXAMPLE
        Get-DCLocatorInfo -ForceRediscovery -SiteName 'NYC'
        Forces fresh DC discovery for the NYC site.

    .EXAMPLE
        Get-DCLocatorInfo -PDC
        Returns only the PDC emulator.
    #>
    [CmdletBinding()]
    param(
        [string]$DomainName,

        [string]$SiteName,

        [switch]$ForceRediscovery,

        [switch]$PDC,

        [switch]$KDC,

        [switch]$TimeServer,

        [switch]$WritableRequired,

        [Parameter(ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string]$ComputerName = $env:COMPUTERNAME
    )

    process {
        $IsLocal = ($ComputerName -eq $env:COMPUTERNAME) -or ($ComputerName -eq 'localhost') -or ($ComputerName -eq '.')

        # Discover domain if not specified
        if (-not $DomainName) {
            try {
                $DomainName = ([System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain()).Name
            }
            catch {
                Write-Error "Cannot determine domain name. Specify -DomainName. Error: $_"
                return
            }
        }

        # Build nltest arguments
        $NltestArgs = @("/dsgetdc:$DomainName")
        if ($ForceRediscovery) { $NltestArgs += '/force' }
        if ($SiteName) { $NltestArgs += "/site:$SiteName" }
        if ($PDC) { $NltestArgs += '/pdc' }
        if ($KDC) { $NltestArgs += '/kdc' }
        if ($TimeServer) { $NltestArgs += '/timeserv' }
        if ($WritableRequired) { $NltestArgs += '/writable' }

        try {
            if ($IsLocal) {
                $Output = & nltest @NltestArgs 2>&1 | Out-String
            }
            else {
                $Output = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                    param($Args)
                    & nltest @Args 2>&1 | Out-String
                } -ArgumentList (, $NltestArgs)
            }

            $OutputTrimmed = $Output.Trim()

            # Parse fields
            $DCName = $null
            $DCAddress = $null
            $DomainGuid = $null
            $DCSiteName = $null
            $ClientSiteName = $null
            $DCFlags = $null

            if ($OutputTrimmed -match 'DC:\s*\\\\(\S+)') { $DCName = $Matches[1] }
            if ($OutputTrimmed -match 'Address:\s*\\\\(\S+)') { $DCAddress = $Matches[1] }
            if ($OutputTrimmed -match 'Dom Guid:\s*(\S+)') { $DomainGuid = $Matches[1] }
            if ($OutputTrimmed -match 'DC Site Name:\s*(\S+)') { $DCSiteName = $Matches[1] }
            if ($OutputTrimmed -match 'Our Site Name:\s*(\S+)') { $ClientSiteName = $Matches[1] }
            if ($OutputTrimmed -match 'Flags:\s*(.+)') { $DCFlags = $Matches[1].Trim() }

            $Success = $OutputTrimmed -match 'NERR_Success' -or $null -ne $DCName

            [PSCustomObject]@{
                PSTypeName       = 'NetlogonTroubleShooting.DCLocator'
                ComputerName     = $ComputerName
                DomainName       = $DomainName
                DCName           = $DCName
                DCAddress        = $DCAddress
                DCSiteName       = $DCSiteName
                ClientSiteName   = $ClientSiteName
                DomainGuid       = $DomainGuid
                Flags            = $DCFlags
                ForceRediscovery = $ForceRediscovery.IsPresent
                RequestedSite    = $SiteName
                Success          = $Success
                RawOutput        = $OutputTrimmed
            }

            if ($Success) {
                Write-Host "DC located: $DCName ($DCAddress) in site $DCSiteName." -ForegroundColor Green
                if ($ClientSiteName -and $DCSiteName -and $ClientSiteName -ne $DCSiteName) {
                    Write-Host "WARNING: Client site '$ClientSiteName' differs from DC site '$DCSiteName'. Cross-site authentication." -ForegroundColor Yellow
                }
            }
            else {
                Write-Host "DC locator FAILED for $DomainName." -ForegroundColor Red
                Write-Host $OutputTrimmed -ForegroundColor Red
            }
        }
        catch {
            Write-Error "DC locator failed on $ComputerName : $_"
        }
    }
}

#endregion

#region Get-ADSiteInfo

function Get-ADSiteInfo {
    <#
    .SYNOPSIS
        Shows AD site assignment, subnet mapping, and DCs in the site.

    .DESCRIPTION
        Retrieves the AD site the computer is assigned to, lists all subnets
        associated with that site, and enumerates the domain controllers
        in the site. Helps detect NO_CLIENT_SITE conditions where the client
        IP does not match any defined AD subnet.

    .PARAMETER ComputerName
        The computer to check. Defaults to the local computer.

    .PARAMETER SiteName
        Query a specific site instead of the computer's assigned site.

    .EXAMPLE
        Get-ADSiteInfo
        Shows site information for the local computer.

    .EXAMPLE
        Get-ADSiteInfo -SiteName 'NYC'
        Shows information about the NYC site.

    .EXAMPLE
        Get-ADSiteInfo -ComputerName 'Server01','Server02'
        Shows site information for multiple computers.
    #>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string[]]$ComputerName = $env:COMPUTERNAME,

        [string]$SiteName
    )

    process {
        foreach ($Computer in $ComputerName) {
            $IsLocal = ($Computer -eq $env:COMPUTERNAME) -or ($Computer -eq 'localhost') -or ($Computer -eq '.')

            try {
                # Determine the site for this computer
                $AssignedSite = $SiteName
                $ClientIP = $null
                $NoClientSite = $false

                if (-not $AssignedSite) {
                    try {
                        if ($IsLocal) {
                            $AssignedSite = [System.DirectoryServices.ActiveDirectory.ActiveDirectorySite]::GetComputerSite().Name
                        }
                        else {
                            $AssignedSite = Invoke-Command -ComputerName $Computer -ScriptBlock {
                                [System.DirectoryServices.ActiveDirectory.ActiveDirectorySite]::GetComputerSite().Name
                            }
                        }
                    }
                    catch {
                        $NoClientSite = $true
                        Write-Verbose "Could not determine site for $Computer : $_"
                    }
                }

                # Get client IP
                if ($IsLocal) {
                    $ClientIP = (Get-NetIPAddress -AddressFamily IPv4 -Type Unicast -ErrorAction SilentlyContinue |
                        Where-Object { $_.IPAddress -ne '127.0.0.1' } |
                        Select-Object -First 1).IPAddress
                }
                else {
                    try {
                        $ClientIP = Invoke-Command -ComputerName $Computer -ScriptBlock {
                            (Get-NetIPAddress -AddressFamily IPv4 -Type Unicast -ErrorAction SilentlyContinue |
                            Where-Object { $_.IPAddress -ne '127.0.0.1' } |
                            Select-Object -First 1).IPAddress
                        }
                    }
                    catch {
                        Write-Verbose "Could not get IP from $Computer : $_"
                    }
                }

                # Get site details via System.DirectoryServices
                $SiteSubnets = @()
                $SiteDCs = @()
                $SiteLinks = @()

                if ($AssignedSite) {
                    try {
                        $DirectoryContext = [System.DirectoryServices.ActiveDirectory.DirectoryContext]::new(
                            [System.DirectoryServices.ActiveDirectory.DirectoryContextType]::Forest
                        )
                        $Forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetForest($DirectoryContext)
                        $AllSites = $Forest.Sites

                        $Site = $AllSites | Where-Object { $_.Name -eq $AssignedSite }

                        if ($Site) {
                            $SiteSubnets = @($Site.Subnets | ForEach-Object { $_.Name })
                            $SiteDCs = @($Site.Servers | ForEach-Object { $_.Name })
                            $SiteLinks = @($Site.SiteLinks | ForEach-Object { $_.Name })
                        }
                    }
                    catch {
                        Write-Verbose "Could not enumerate site details: $_"

                        # Fallback: use nltest /dsgetsite and /dclist
                        try {
                            $DomainName = ([System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain()).Name
                            $DCListOutput = nltest /dclist:$DomainName 2>&1 | Out-String
                            $SiteDCs = [regex]::Matches($DCListOutput, '\\\\(\S+)') |
                            ForEach-Object { $_.Groups[1].Value } |
                            Where-Object { $_ -and $_ -ne 'The' }
                        }
                        catch {
                            Write-Verbose "Fallback nltest also failed: $_"
                        }
                    }
                }

                # Also check via nltest /dsgetsite for the canonical site assignment
                $NltestSite = $null
                try {
                    if ($IsLocal) {
                        $NltestSiteOutput = nltest /dsgetsite 2>&1 | Out-String
                    }
                    else {
                        $NltestSiteOutput = Invoke-Command -ComputerName $Computer -ScriptBlock {
                            nltest /dsgetsite 2>&1 | Out-String
                        }
                    }
                    # First line is the site name
                    $NltestSite = ($NltestSiteOutput.Trim() -split "`n")[0].Trim()
                }
                catch {
                    Write-Verbose "nltest /dsgetsite failed: $_"
                }

                [PSCustomObject]@{
                    PSTypeName   = 'NetlogonTroubleShooting.SiteInfo'
                    ComputerName = $Computer
                    ClientIP     = $ClientIP
                    AssignedSite = if ($AssignedSite) { $AssignedSite } else { 'NO_CLIENT_SITE' }
                    NltestSite   = $NltestSite
                    NoClientSite = $NoClientSite
                    Subnets      = $SiteSubnets -join '; '
                    SubnetCount  = $SiteSubnets.Count
                    DCs          = $SiteDCs -join '; '
                    DCCount      = $SiteDCs.Count
                    SiteLinks    = $SiteLinks -join '; '
                }

                # Console feedback
                if ($NoClientSite) {
                    Write-Host "$Computer : NO_CLIENT_SITE detected! The computer IP ($ClientIP) does not match any AD subnet." -ForegroundColor Red
                    Write-Host "  Create a subnet in AD Sites and Services covering this IP range." -ForegroundColor Yellow
                }
                else {
                    Write-Host "$Computer : Site '$AssignedSite' ($($SiteDCs.Count) DCs, $($SiteSubnets.Count) subnets)." -ForegroundColor Green
                }
            }
            catch {
                Write-Error "Failed to get site info for $Computer : $_"
            }
        }
    }
}

#endregion

#region Invoke-NetlogonDiagnostic

function Invoke-NetlogonDiagnostic {
    <#
    .SYNOPSIS
        Runs a comprehensive Netlogon diagnostic check and produces a consolidated report.

    .DESCRIPTION
        Executes all diagnostic functions in the NetlogonTroubleShooting module in a
        single pass and produces a consolidated text or HTML report. Checks include:
        - Netlogon service status
        - Secure channel health
        - DC locator results
        - AD site assignment
        - DNS record validation
        - DC port connectivity
        - Time synchronization
        - Debug logging status
        - Recent Netlogon events

    .PARAMETER ComputerName
        The computer to diagnose. Defaults to the local computer.

    .PARAMETER OutputFormat
        The report format: Text (default) or HTML.

    .PARAMETER OutputPath
        If specified, saves the report to this file path. Otherwise outputs to console/pipeline.

    .EXAMPLE
        Invoke-NetlogonDiagnostic
        Runs all checks and displays a text report.

    .EXAMPLE
        Invoke-NetlogonDiagnostic -OutputFormat HTML -OutputPath 'C:\Reports\netlogon.html'
        Generates an HTML diagnostic report and saves it.

    .EXAMPLE
        Invoke-NetlogonDiagnostic -ComputerName 'Server01'
        Diagnoses Server01 remotely.
    #>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string]$ComputerName = $env:COMPUTERNAME,

        [ValidateSet('Text', 'HTML')]
        [string]$OutputFormat = 'Text',

        [string]$OutputPath
    )

    process {
        $Timestamp = Get-Date
        $IsLocal = ($ComputerName -eq $env:COMPUTERNAME) -or ($ComputerName -eq 'localhost') -or ($ComputerName -eq '.')

        Write-Host "`n========================================" -ForegroundColor Cyan
        Write-Host " Netlogon Diagnostic Report" -ForegroundColor Cyan
        Write-Host " Computer : $ComputerName" -ForegroundColor Cyan
        Write-Host " Time     : $Timestamp" -ForegroundColor Cyan
        Write-Host "========================================`n" -ForegroundColor Cyan

        $Report = [ordered]@{}

        # 1. Netlogon Service Status
        Write-Host "[1/8] Netlogon Service Status..." -ForegroundColor White
        try {
            $Report['NetlogonStatus'] = Get-NetlogonStatus -ComputerName $ComputerName -ErrorAction Stop
        }
        catch {
            $Report['NetlogonStatus'] = "Error: $_"
            Write-Warning "Netlogon status check failed: $_"
        }

        # 2. Secure Channel
        Write-Host "[2/8] Secure Channel Health..." -ForegroundColor White
        try {
            $Report['SecureChannel'] = Test-NetlogonSecureChannel -ComputerName $ComputerName -ErrorAction Stop
        }
        catch {
            $Report['SecureChannel'] = "Error: $_"
            Write-Warning "Secure channel check failed: $_"
        }

        # 3. DC Locator
        Write-Host "[3/8] DC Locator..." -ForegroundColor White
        try {
            $Report['DCLocator'] = Get-DCLocatorInfo -ComputerName $ComputerName -ErrorAction Stop
        }
        catch {
            $Report['DCLocator'] = "Error: $_"
            Write-Warning "DC locator check failed: $_"
        }

        # 4. AD Site Info
        Write-Host "[4/8] AD Site Information..." -ForegroundColor White
        try {
            $Report['SiteInfo'] = Get-ADSiteInfo -ComputerName $ComputerName -ErrorAction Stop
        }
        catch {
            $Report['SiteInfo'] = "Error: $_"
            Write-Warning "Site info check failed: $_"
        }

        # 5. DNS Records
        Write-Host "[5/8] DNS Record Validation..." -ForegroundColor White
        try {
            $Report['DnsRecords'] = Test-NetlogonDnsRecords -ErrorAction Stop
        }
        catch {
            $Report['DnsRecords'] = "Error: $_"
            Write-Warning "DNS record check failed: $_"
        }

        # 6. DC Port Connectivity
        Write-Host "[6/8] DC Port Connectivity..." -ForegroundColor White
        try {
            $Report['PortConnectivity'] = Test-DCPortConnectivity -ComputerName $ComputerName -ErrorAction Stop
        }
        catch {
            $Report['PortConnectivity'] = "Error: $_"
            Write-Warning "Port connectivity check failed: $_"
        }

        # 7. Time Sync
        Write-Host "[7/8] Time Synchronization..." -ForegroundColor White
        try {
            $Report['TimeSync'] = Test-TimeSynchronization -ComputerName $ComputerName -ErrorAction Stop
        }
        catch {
            $Report['TimeSync'] = "Error: $_"
            Write-Warning "Time sync check failed: $_"
        }

        # 8. Recent Netlogon Events
        Write-Host "[8/8] Recent Netlogon Events (last 24h)..." -ForegroundColor White
        try {
            $Report['Events'] = Get-NetlogonEvent -ComputerName $ComputerName -MaxEvents 20 -ErrorAction SilentlyContinue
        }
        catch {
            $Report['Events'] = "Error: $_"
        }

        # Also capture debug logging status
        try {
            $Report['DebugStatus'] = Get-NetlogonDebugStatus -ComputerName $ComputerName -ErrorAction SilentlyContinue
        }
        catch {
            $Report['DebugStatus'] = $null
        }

        # Build output
        if ($OutputFormat -eq 'HTML') {
            $Html = _Format-DiagnosticHtml -Report $Report -ComputerName $ComputerName -Timestamp $Timestamp
            if ($OutputPath) {
                $Html | Set-Content -Path $OutputPath -Encoding UTF8 -Force
                Write-Host "`nHTML report saved to: $OutputPath" -ForegroundColor Green
            }
            else {
                $Html
            }
        }
        else {
            $Text = _Format-DiagnosticText -Report $Report -ComputerName $ComputerName -Timestamp $Timestamp
            if ($OutputPath) {
                $Text | Set-Content -Path $OutputPath -Encoding UTF8 -Force
                Write-Host "`nText report saved to: $OutputPath" -ForegroundColor Green
            }
            else {
                $Text
            }
        }

        # Return structured data as well
        [PSCustomObject]@{
            PSTypeName   = 'NetlogonTroubleShooting.DiagnosticReport'
            ComputerName = $ComputerName
            Timestamp    = $Timestamp
            Results      = $Report
        }
    }
}

# Private helper: format text report
function _Format-DiagnosticText {
    param(
        [hashtable]$Report,
        [string]$ComputerName,
        [datetime]$Timestamp
    )

    $Sb = [System.Text.StringBuilder]::new()
    $null = $Sb.AppendLine('=' * 72)
    $null = $Sb.AppendLine("  NETLOGON DIAGNOSTIC REPORT")
    $null = $Sb.AppendLine("  Computer : $ComputerName")
    $null = $Sb.AppendLine("  Generated: $Timestamp")
    $null = $Sb.AppendLine('=' * 72)
    $null = $Sb.AppendLine()

    # -- Netlogon Status --
    $null = $Sb.AppendLine('--- Netlogon Service Status ---')
    $Status = $Report['NetlogonStatus']
    if ($Status -is [PSObject] -and $Status.ServiceStatus) {
        $null = $Sb.AppendLine("  Service         : $($Status.ServiceStatus)")
        $null = $Sb.AppendLine("  Start Type      : $($Status.ServiceStartType)")
        $null = $Sb.AppendLine("  Domain          : $($Status.DomainName)")
        $null = $Sb.AppendLine("  Auth DC         : $($Status.AuthenticatingDC)")
        $null = $Sb.AppendLine("  Secure Channel  : $(if ($Status.SecureChannelHealthy) { 'Healthy' } else { 'UNHEALTHY' })")
        $null = $Sb.AppendLine("  Debug Logging   : $(if ($Status.DebugLoggingEnabled) { "$($Status.DebugLevel)" } else { 'Disabled' })")
    }
    else {
        $null = $Sb.AppendLine("  $Status")
    }
    $null = $Sb.AppendLine()

    # -- Secure Channel --
    $null = $Sb.AppendLine('--- Secure Channel ---')
    $SC = $Report['SecureChannel']
    if ($SC -is [PSObject] -and $null -ne $SC.SecureChannelOK) {
        $null = $Sb.AppendLine("  Status : $(if ($SC.SecureChannelOK) { 'OK' } else { 'BROKEN' })")
        $null = $Sb.AppendLine("  DC     : $($SC.DCName)")
        if ($SC.Recommendations.Count -gt 0) {
            $null = $Sb.AppendLine("  Recommendations:")
            foreach ($Rec in $SC.Recommendations) {
                $null = $Sb.AppendLine("    - $Rec")
            }
        }
    }
    else {
        $null = $Sb.AppendLine("  $SC")
    }
    $null = $Sb.AppendLine()

    # -- DC Locator --
    $null = $Sb.AppendLine('--- DC Locator ---')
    $DCL = $Report['DCLocator']
    if ($DCL -is [PSObject] -and $DCL.DCName) {
        $null = $Sb.AppendLine("  DC Name     : $($DCL.DCName)")
        $null = $Sb.AppendLine("  DC Address  : $($DCL.DCAddress)")
        $null = $Sb.AppendLine("  DC Site     : $($DCL.DCSiteName)")
        $null = $Sb.AppendLine("  Client Site : $($DCL.ClientSiteName)")
        $null = $Sb.AppendLine("  Flags       : $($DCL.Flags)")
    }
    else {
        $null = $Sb.AppendLine("  $DCL")
    }
    $null = $Sb.AppendLine()

    # -- Site Info --
    $null = $Sb.AppendLine('--- AD Site Information ---')
    $SI = $Report['SiteInfo']
    if ($SI -is [PSObject] -and $SI.AssignedSite) {
        $null = $Sb.AppendLine("  Assigned Site  : $($SI.AssignedSite)")
        $null = $Sb.AppendLine("  Client IP      : $($SI.ClientIP)")
        $null = $Sb.AppendLine("  NO_CLIENT_SITE : $(if ($SI.NoClientSite) { 'YES — action required!' } else { 'No' })")
        $null = $Sb.AppendLine("  Subnets ($($SI.SubnetCount)): $($SI.Subnets)")
        $null = $Sb.AppendLine("  DCs ($($SI.DCCount))    : $($SI.DCs)")
        $null = $Sb.AppendLine("  Site Links     : $($SI.SiteLinks)")
    }
    else {
        $null = $Sb.AppendLine("  $SI")
    }
    $null = $Sb.AppendLine()

    # -- DNS Records --
    $null = $Sb.AppendLine('--- DNS Record Validation ---')
    $DNS = $Report['DnsRecords']
    if ($DNS -is [System.Array] -or $DNS -is [PSObject[]]) {
        foreach ($D in $DNS) {
            $StatusMark = if ($D.Resolved) { '[OK]  ' } else { '[FAIL]' }
            $null = $Sb.AppendLine("  $StatusMark $($D.Purpose): $($D.RecordName)")
            if ($D.Resolved) {
                $null = $Sb.AppendLine("         Targets: $($D.Targets)")
            }
            else {
                $null = $Sb.AppendLine("         Error: $($D.Error)")
            }
        }
    }
    else {
        $null = $Sb.AppendLine("  $DNS")
    }
    $null = $Sb.AppendLine()

    # -- Port Connectivity --
    $null = $Sb.AppendLine('--- DC Port Connectivity ---')
    $Ports = $Report['PortConnectivity']
    if ($Ports -is [System.Array] -or $Ports -is [PSObject[]]) {
        $GroupedByDC = $Ports | Group-Object DomainController
        foreach ($DCGroup in $GroupedByDC) {
            $null = $Sb.AppendLine("  DC: $($DCGroup.Name)")
            foreach ($PT in $DCGroup.Group) {
                $StatusMark = if ($PT.Reachable) { '[OK]  ' } else { '[FAIL]' }
                $null = $Sb.AppendLine("    $StatusMark Port $($PT.Port) ($($PT.Service))")
            }
        }
    }
    else {
        $null = $Sb.AppendLine("  $Ports")
    }
    $null = $Sb.AppendLine()

    # -- Time Sync --
    $null = $Sb.AppendLine('--- Time Synchronization ---')
    $TS = $Report['TimeSync']
    if ($TS -is [PSObject] -and $null -ne $TS.SkewSeconds) {
        $null = $Sb.AppendLine("  DC             : $($TS.DomainController)")
        $null = $Sb.AppendLine("  Skew           : $($TS.SkewSeconds)s")
        $null = $Sb.AppendLine("  Within Limit   : $(if ($TS.WithinThreshold) { 'Yes' } else { 'NO — Kerberos may fail!' })")
        $null = $Sb.AppendLine("  Time Source    : $($TS.TimeSource)")
    }
    elseif ($TS -is [PSObject]) {
        $null = $Sb.AppendLine("  Time Source    : $($TS.TimeSource)")
        $null = $Sb.AppendLine("  Skew           : Could not determine")
    }
    else {
        $null = $Sb.AppendLine("  $TS")
    }
    $null = $Sb.AppendLine()

    # -- Recent Events --
    $null = $Sb.AppendLine('--- Recent Netlogon Events (last 24h) ---')
    $Evts = $Report['Events']
    if ($Evts -is [System.Array] -and $Evts.Count -gt 0) {
        foreach ($E in $Evts | Select-Object -First 20) {
            $null = $Sb.AppendLine("  [$($E.TimeCreated)] EventID $($E.EventId) — $($E.Summary)")
        }
    }
    else {
        $null = $Sb.AppendLine("  No Netlogon events found in the last 24 hours.")
    }
    $null = $Sb.AppendLine()
    $null = $Sb.AppendLine('=' * 72)
    $null = $Sb.AppendLine("  End of Netlogon Diagnostic Report")
    $null = $Sb.AppendLine('=' * 72)

    $Sb.ToString()
}

# Private helper: format HTML report
function _Format-DiagnosticHtml {
    param(
        [hashtable]$Report,
        [string]$ComputerName,
        [datetime]$Timestamp
    )

    $Sb = [System.Text.StringBuilder]::new()
    $null = $Sb.AppendLine(@"
<!DOCTYPE html>
<html><head>
<meta charset="utf-8">
<title>Netlogon Diagnostic — $([System.Net.WebUtility]::HtmlEncode($ComputerName))</title>
<style>
  body { font-family: Segoe UI, Calibri, sans-serif; margin: 2em; background: #f5f5f5; }
  h1 { color: #0078d4; }
  h2 { color: #333; border-bottom: 2px solid #0078d4; padding-bottom: 4px; }
  table { border-collapse: collapse; width: 100%; margin-bottom: 1.5em; }
  th, td { border: 1px solid #ccc; padding: 6px 10px; text-align: left; }
  th { background: #0078d4; color: #fff; }
  tr:nth-child(even) { background: #e9e9e9; }
  .ok { color: green; font-weight: bold; }
  .fail { color: red; font-weight: bold; }
  .warn { color: orange; font-weight: bold; }
  .section { background: #fff; padding: 1em 1.5em; margin-bottom: 1em; border-radius: 6px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
</style>
</head><body>
<h1>Netlogon Diagnostic Report</h1>
<p><strong>Computer:</strong> $([System.Net.WebUtility]::HtmlEncode($ComputerName)) &nbsp;|&nbsp; <strong>Generated:</strong> $([System.Net.WebUtility]::HtmlEncode($Timestamp.ToString()))</p>
"@)

    # Netlogon Status
    $Status = $Report['NetlogonStatus']
    $null = $Sb.AppendLine('<div class="section"><h2>Netlogon Service Status</h2>')
    if ($Status -is [PSObject] -and $Status.ServiceStatus) {
        $SCClass = if ($Status.SecureChannelHealthy) { 'ok' } else { 'fail' }
        $null = $Sb.AppendLine("<table><tr><th>Property</th><th>Value</th></tr>")
        $null = $Sb.AppendLine("<tr><td>Service</td><td>$([System.Net.WebUtility]::HtmlEncode($Status.ServiceStatus))</td></tr>")
        $null = $Sb.AppendLine("<tr><td>Domain</td><td>$([System.Net.WebUtility]::HtmlEncode($Status.DomainName))</td></tr>")
        $null = $Sb.AppendLine("<tr><td>Auth DC</td><td>$([System.Net.WebUtility]::HtmlEncode($Status.AuthenticatingDC))</td></tr>")
        $null = $Sb.AppendLine("<tr><td>Secure Channel</td><td class='$SCClass'>$(if ($Status.SecureChannelHealthy) { 'Healthy' } else { 'UNHEALTHY' })</td></tr>")
        $null = $Sb.AppendLine("</table>")
    }
    else { $null = $Sb.AppendLine("<p>$([System.Net.WebUtility]::HtmlEncode("$Status"))</p>") }
    $null = $Sb.AppendLine('</div>')

    # DC Locator
    $DCL = $Report['DCLocator']
    $null = $Sb.AppendLine('<div class="section"><h2>DC Locator</h2>')
    if ($DCL -is [PSObject] -and $DCL.DCName) {
        $null = $Sb.AppendLine("<table><tr><th>Property</th><th>Value</th></tr>")
        $null = $Sb.AppendLine("<tr><td>DC Name</td><td>$([System.Net.WebUtility]::HtmlEncode($DCL.DCName))</td></tr>")
        $null = $Sb.AppendLine("<tr><td>DC Address</td><td>$([System.Net.WebUtility]::HtmlEncode($DCL.DCAddress))</td></tr>")
        $null = $Sb.AppendLine("<tr><td>DC Site</td><td>$([System.Net.WebUtility]::HtmlEncode($DCL.DCSiteName))</td></tr>")
        $null = $Sb.AppendLine("<tr><td>Client Site</td><td>$([System.Net.WebUtility]::HtmlEncode($DCL.ClientSiteName))</td></tr>")
        $null = $Sb.AppendLine("<tr><td>Flags</td><td>$([System.Net.WebUtility]::HtmlEncode($DCL.Flags))</td></tr>")
        $null = $Sb.AppendLine("</table>")
    }
    else { $null = $Sb.AppendLine("<p>$([System.Net.WebUtility]::HtmlEncode("$DCL"))</p>") }
    $null = $Sb.AppendLine('</div>')

    # Site Info
    $SI = $Report['SiteInfo']
    $null = $Sb.AppendLine('<div class="section"><h2>AD Site Information</h2>')
    if ($SI -is [PSObject] -and $SI.AssignedSite) {
        $SiteClass = if ($SI.NoClientSite) { 'fail' } else { 'ok' }
        $null = $Sb.AppendLine("<table><tr><th>Property</th><th>Value</th></tr>")
        $null = $Sb.AppendLine("<tr><td>Assigned Site</td><td class='$SiteClass'>$([System.Net.WebUtility]::HtmlEncode($SI.AssignedSite))</td></tr>")
        $null = $Sb.AppendLine("<tr><td>Client IP</td><td>$([System.Net.WebUtility]::HtmlEncode($SI.ClientIP))</td></tr>")
        $null = $Sb.AppendLine("<tr><td>Subnets</td><td>$([System.Net.WebUtility]::HtmlEncode($SI.Subnets))</td></tr>")
        $null = $Sb.AppendLine("<tr><td>DCs in Site</td><td>$([System.Net.WebUtility]::HtmlEncode($SI.DCs))</td></tr>")
        $null = $Sb.AppendLine("<tr><td>Site Links</td><td>$([System.Net.WebUtility]::HtmlEncode($SI.SiteLinks))</td></tr>")
        $null = $Sb.AppendLine("</table>")
    }
    else { $null = $Sb.AppendLine("<p>$([System.Net.WebUtility]::HtmlEncode("$SI"))</p>") }
    $null = $Sb.AppendLine('</div>')

    # DNS Records
    $DNS = $Report['DnsRecords']
    $null = $Sb.AppendLine('<div class="section"><h2>DNS Record Validation</h2>')
    if ($DNS -is [System.Array] -or $DNS -is [PSObject[]]) {
        $null = $Sb.AppendLine("<table><tr><th>Status</th><th>Purpose</th><th>Record</th><th>Targets</th></tr>")
        foreach ($D in $DNS) {
            $DClass = if ($D.Resolved) { 'ok' } else { 'fail' }
            $DStatus = if ($D.Resolved) { 'OK' } else { 'FAIL' }
            $DTargets = if ($D.Resolved) { [System.Net.WebUtility]::HtmlEncode($D.Targets) } else { [System.Net.WebUtility]::HtmlEncode($D.Error) }
            $null = $Sb.AppendLine("<tr><td class='$DClass'>$DStatus</td><td>$([System.Net.WebUtility]::HtmlEncode($D.Purpose))</td><td>$([System.Net.WebUtility]::HtmlEncode($D.RecordName))</td><td>$DTargets</td></tr>")
        }
        $null = $Sb.AppendLine("</table>")
    }
    else { $null = $Sb.AppendLine("<p>$([System.Net.WebUtility]::HtmlEncode("$DNS"))</p>") }
    $null = $Sb.AppendLine('</div>')

    # Port Connectivity
    $Ports = $Report['PortConnectivity']
    $null = $Sb.AppendLine('<div class="section"><h2>DC Port Connectivity</h2>')
    if ($Ports -is [System.Array] -or $Ports -is [PSObject[]]) {
        $null = $Sb.AppendLine("<table><tr><th>DC</th><th>Port</th><th>Service</th><th>Status</th></tr>")
        foreach ($PT in $Ports) {
            $PClass = if ($PT.Reachable) { 'ok' } else { 'fail' }
            $PStatus = if ($PT.Reachable) { 'Open' } else { 'BLOCKED' }
            $null = $Sb.AppendLine("<tr><td>$([System.Net.WebUtility]::HtmlEncode($PT.DomainController))</td><td>$($PT.Port)</td><td>$([System.Net.WebUtility]::HtmlEncode($PT.Service))</td><td class='$PClass'>$PStatus</td></tr>")
        }
        $null = $Sb.AppendLine("</table>")
    }
    else { $null = $Sb.AppendLine("<p>$([System.Net.WebUtility]::HtmlEncode("$Ports"))</p>") }
    $null = $Sb.AppendLine('</div>')

    # Time Sync
    $TS = $Report['TimeSync']
    $null = $Sb.AppendLine('<div class="section"><h2>Time Synchronization</h2>')
    if ($TS -is [PSObject] -and $null -ne $TS.ComputerName) {
        $TClass = if ($TS.WithinThreshold -eq $true) { 'ok' } elseif ($null -eq $TS.WithinThreshold) { 'warn' } else { 'fail' }
        $null = $Sb.AppendLine("<table><tr><th>Property</th><th>Value</th></tr>")
        $null = $Sb.AppendLine("<tr><td>DC</td><td>$([System.Net.WebUtility]::HtmlEncode($TS.DomainController))</td></tr>")
        $null = $Sb.AppendLine("<tr><td>Skew</td><td class='$TClass'>$(if ($null -ne $TS.SkewSeconds) { "$($TS.SkewSeconds)s" } else { 'Unknown' })</td></tr>")
        $null = $Sb.AppendLine("<tr><td>Time Source</td><td>$([System.Net.WebUtility]::HtmlEncode($TS.TimeSource))</td></tr>")
        $null = $Sb.AppendLine("</table>")
    }
    else { $null = $Sb.AppendLine("<p>$([System.Net.WebUtility]::HtmlEncode("$TS"))</p>") }
    $null = $Sb.AppendLine('</div>')

    # Recent Events
    $Evts = $Report['Events']
    $null = $Sb.AppendLine('<div class="section"><h2>Recent Netlogon Events (last 24h)</h2>')
    if ($Evts -is [System.Array] -and $Evts.Count -gt 0) {
        $null = $Sb.AppendLine("<table><tr><th>Time</th><th>EventID</th><th>Level</th><th>Summary</th></tr>")
        foreach ($E in $Evts | Select-Object -First 20) {
            $null = $Sb.AppendLine("<tr><td>$([System.Net.WebUtility]::HtmlEncode($E.TimeCreated.ToString()))</td><td>$($E.EventId)</td><td>$([System.Net.WebUtility]::HtmlEncode($E.Level))</td><td>$([System.Net.WebUtility]::HtmlEncode($E.Summary))</td></tr>")
        }
        $null = $Sb.AppendLine("</table>")
    }
    else {
        $null = $Sb.AppendLine("<p>No Netlogon events found in the last 24 hours.</p>")
    }
    $null = $Sb.AppendLine('</div>')

    $null = $Sb.AppendLine("</body></html>")
    $Sb.ToString()
}

#endregion
