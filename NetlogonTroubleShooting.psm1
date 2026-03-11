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
        Requires elevation (Run as Administrator). The Netlogon service is
        restarted to apply the change.

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

    .PARAMETER NoRestart
        If specified, the Netlogon service will not be restarted. The debug
        setting takes effect on next service restart.

    .EXAMPLE
        Enable-NetlogonDebug
        Enables full Netlogon debug logging on the local machine and restarts the service.

    .EXAMPLE
        Enable-NetlogonDebug -Level Standard -NoRestart
        Enables standard-level debug logging without restarting the Netlogon service.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param(
        [Parameter(ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string[]]$ComputerName = $env:COMPUTERNAME,

        [ValidateSet('Full', 'Standard')]
        [string]$Level = 'Full',

        [int]$MaxLogSizeBytes = 268435456,

        [switch]$NoRestart
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

                        Write-Verbose "Registry values set on $Computer (DBFlag=0x$($DebugFlags[$Level].ToString('X')), MaxLogSize=$MaxLogSizeBytes)"

                        if (-not $NoRestart) {
                            Write-Verbose "Restarting Netlogon service on $Computer..."
                            Restart-Service -Name 'Netlogon' -Force
                            Write-Verbose "Netlogon service restarted."
                        }
                    }
                    else {
                        Invoke-Command -ComputerName $Computer -ScriptBlock {
                            param($RegPathRemote, $FlagValue, $MaxSize, $SkipRestart)
                            Set-ItemProperty -Path $RegPathRemote -Name 'DBFlag' -Value $FlagValue -Type DWord -Force
                            Set-ItemProperty -Path $RegPathRemote -Name 'MaximumLogFileSize' -Value $MaxSize -Type DWord -Force
                            if (-not $SkipRestart) {
                                Restart-Service -Name 'Netlogon' -Force
                            }
                        } -ArgumentList $RegPath, $DebugFlags[$Level], $MaxLogSizeBytes, $NoRestart.IsPresent
                    }

                    [PSCustomObject]@{
                        PSTypeName   = 'NetlogonTroubleShooting.DebugConfig'
                        ComputerName = $Computer
                        DebugEnabled = $true
                        Level        = $Level
                        DBFlag       = '0x{0:X}' -f $DebugFlags[$Level]
                        MaxLogSize   = $MaxLogSizeBytes
                        LogPath      = "\\$Computer\admin$\debug\netlogon.log"
                        Restarted    = -not $NoRestart.IsPresent
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
        Requires elevation (Run as Administrator). The Netlogon service is
        restarted to apply the change.

    .PARAMETER ComputerName
        The computer to disable debug logging on. Defaults to the local computer.

    .PARAMETER NoRestart
        If specified, the Netlogon service will not be restarted.

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
        [string[]]$ComputerName = $env:COMPUTERNAME,

        [switch]$NoRestart
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

                        Write-Verbose "DBFlag set to 0 on $Computer"

                        if (-not $NoRestart) {
                            Write-Verbose "Restarting Netlogon service on $Computer..."
                            Restart-Service -Name 'Netlogon' -Force
                            Write-Verbose "Netlogon service restarted."
                        }
                    }
                    else {
                        Invoke-Command -ComputerName $Computer -ScriptBlock {
                            param($RegPathRemote, $SkipRestart)
                            Set-ItemProperty -Path $RegPathRemote -Name 'DBFlag' -Value 0 -Type DWord -Force
                            if (-not $SkipRestart) {
                                Restart-Service -Name 'Netlogon' -Force
                            }
                        } -ArgumentList $RegPath, $NoRestart.IsPresent
                    }

                    [PSCustomObject]@{
                        PSTypeName   = 'NetlogonTroubleShooting.DebugConfig'
                        ComputerName = $Computer
                        DebugEnabled = $false
                        Level        = 'Disabled'
                        DBFlag       = '0x0'
                        Restarted    = -not $NoRestart.IsPresent
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

                            $Entry = [PSCustomObject]@{
                                PSTypeName = 'NetlogonTroubleShooting.LogEntry'
                                SourceFile = $FileInfo.Name
                                LineNumber = $LineNumber
                                Timestamp  = $ParsedTime
                                LogType    = $LogType
                                ProcessId  = $ProcessId
                                Category   = $EntryCategory
                                IsError    = $IsError
                                StatusCode = $StatusCode
                                Message    = $Message.Trim()
                                RawLine    = $Line
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
