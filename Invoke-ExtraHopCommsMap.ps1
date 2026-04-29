<#
.SYNOPSIS
    Queries ExtraHop REST API to build a communication map for a list of servers.

.DESCRIPTION
    Reads a CSV of server IPs, resolves each in ExtraHop, discovers peers/protocols/metrics,
    and exports a comprehensive communication map as both CSV and interactive HTML.

.PARAMETER InputCsv
    Path to input CSV file with ip, hostname, description columns.

.PARAMETER ExtraHopHost
    ExtraHop appliance base URL (e.g., https://extrahop.company.local).

.PARAMETER ApiKey
    ExtraHop API key for authentication.

.PARAMETER LookbackMinutes
    How far back to query for activity (default: 1440 = 24 hours).

.PARAMETER OutputDir
    Directory for output files (default: .\output).

.PARAMETER SkipSslVerify
    Disable SSL certificate validation.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$InputCsv = ".\input\servers.csv",

    [Parameter()]
    [string]$ExtraHopHost,

    [Parameter()]
    [string]$ApiKey,

    [Parameter()]
    [int]$LookbackMinutes = 0,

    [Parameter()]
    [string]$OutputDir,

    [Parameter()]
    [switch]$SkipSslVerify
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

#region ============ CONFIGURATION ============

# Parameters override env vars; env vars override defaults
$script:Config = @{
    Host            = if ($ExtraHopHost) { $ExtraHopHost } elseif ($env:EXTRAHOP_HOST) { $env:EXTRAHOP_HOST } else { "https://extrahop.company.local" }
    ApiKey          = if ($ApiKey) { $ApiKey.Trim() } elseif ($env:EXTRAHOP_API_KEY) { $env:EXTRAHOP_API_KEY.Trim() } else { "" }
    VerifySsl       = if ($SkipSslVerify) { $false } elseif ($env:EXTRAHOP_VERIFY_SSL) { $env:EXTRAHOP_VERIFY_SSL -ne "false" } else { $true }
    LookbackMinutes = if ($LookbackMinutes -gt 0) { $LookbackMinutes } elseif ($env:EXTRAHOP_LOOKBACK_MINUTES) { [int]$env:EXTRAHOP_LOOKBACK_MINUTES } else { 1440 }
    OutputDir       = if ($OutputDir) { $OutputDir } elseif ($env:EXTRAHOP_OUTPUT_DIR) { $env:EXTRAHOP_OUTPUT_DIR } else { ".\output" }
}

$script:LookbackMs = $script:Config.LookbackMinutes * 60 * 1000

#endregion

#region ============ SSL HANDLING ============

function Disable-SslVerification {
    <#
    .SYNOPSIS
        Disables SSL certificate validation for the current session.
    #>
    if ($PSVersionTable.PSVersion.Major -ge 7) {
        # PS7+ handles this per-request with -SkipCertificateCheck
        Write-Verbose "PowerShell 7+ detected -- will use -SkipCertificateCheck on requests"
    }
    else {
        # PS5.1: override the validation callback
        # Note: C# code passed as string to avoid PS parsing 'using' as a PowerShell directive
        $csSource = 'using System.Net;using System.Security.Cryptography.X509Certificates;public class TrustAllCertsPolicy : ICertificatePolicy { public bool CheckValidationResult(ServicePoint srvPoint, X509Certificate certificate, WebRequest request, int certificateProblem) { return true; } }'
        Add-Type -TypeDefinition $csSource
        [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
        Write-Verbose "PowerShell 5.1 detected -- SSL validation disabled via CertificatePolicy"
    }
}

#endregion

#region ============ API FUNCTIONS ============

function Invoke-EHRequest {
    <#
    .SYNOPSIS
        Base HTTP wrapper for ExtraHop API with retry/backoff/error handling.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Endpoint,
        [Parameter()][string]$Method = "GET",
        [Parameter()][object]$Body,
        [Parameter()][int]$MaxRetries = 3
    )

    $uri = "$($script:Config.Host)$Endpoint"
    $headers = @{
        "Authorization" = "ExtraHop apikey=$($script:Config.ApiKey)"
        "Accept"        = "application/json"
    }

    $attempt = 0
    while ($attempt -lt $MaxRetries) {
        $attempt++
        try {
            $params = @{
                Uri         = $uri
                Method      = $Method
                Headers     = $headers
                ContentType = "application/json"
                ErrorAction = "Stop"
            }

            if ($Body) {
                $params["Body"] = if ($Body -is [string]) { $Body } else { $Body | ConvertTo-Json -Depth 10 }
            }

            if (-not $script:Config.VerifySsl -and $PSVersionTable.PSVersion.Major -ge 7) {
                $params["SkipCertificateCheck"] = $true
            }

            $response = Invoke-RestMethod @params
            return @{ Success = $true; Data = $response; StatusCode = 200 }
        }
        catch {
            $statusCode = 0
            if ($_.Exception.Response) {
                $statusCode = [int]$_.Exception.Response.StatusCode
            }

            # 401: auth failure — exit immediately
            if ($statusCode -eq 401) {
                Write-Error "ExtraHop API authentication failed (401). Check EXTRAHOP_API_KEY. Host: $($script:Config.Host)"
                return @{ Success = $false; StatusCode = 401; Error = "Authentication failed" }
            }

            # 404: not found — don't retry
            if ($statusCode -eq 404) {
                return @{ Success = $false; StatusCode = 404; Error = "Not found" }
            }

            # 429: rate limited — exponential backoff
            if ($statusCode -eq 429) {
                $wait = [math]::Pow(2, $attempt) * 1000
                Write-Verbose "Rate limited (429). Waiting $($wait)ms before retry $attempt/$MaxRetries"
                Start-Sleep -Milliseconds $wait
                continue
            }

            # 5xx: server error — retry once
            if ($statusCode -ge 500) {
                if ($attempt -lt $MaxRetries) {
                    Write-Verbose "Server error ($statusCode). Retry $attempt/$MaxRetries"
                    Start-Sleep -Seconds 5
                    continue
                }
                return @{ Success = $false; StatusCode = $statusCode; Error = "Server error: $statusCode" }
            }

            # Connection error — retry once with 5s delay
            if ($attempt -lt 2) {
                Write-Verbose "Connection error. Retrying in 5s..."
                Start-Sleep -Seconds 5
                continue
            }

            return @{ Success = $false; StatusCode = $statusCode; Error = $_.Exception.Message }
        }
    }

    return @{ Success = $false; StatusCode = 0; Error = "Max retries exceeded" }
}

function Get-EHDeviceByIp {
    <#
    .SYNOPSIS
        Resolves an ExtraHop device ID from an IP address.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$IpAddress)

    $encoded = [System.Uri]::EscapeDataString($IpAddress)
    $endpoint = "/api/v1/devices?search_type=ip%20address&value=$encoded&active_from=-$($script:LookbackMs)&active_until=0&limit=50"

    $result = Invoke-EHRequest -Endpoint $endpoint
    if (-not $result.Success) { return $result }

    $devices = $result.Data
    if (-not $devices -or ($devices | Measure-Object).Count -eq 0) {
        return @{ Success = $false; StatusCode = 404; Error = "No device found for IP $IpAddress" }
    }

    # Find exact match
    $match = $devices | Where-Object { $_.ipaddr4 -eq $IpAddress -or $_.ipaddr6 -eq $IpAddress } |
        Sort-Object -Property mod_time -Descending | Select-Object -First 1

    if (-not $match) {
        $match = $devices | Sort-Object -Property mod_time -Descending | Select-Object -First 1
    }

    return @{ Success = $true; Data = $match; StatusCode = 200 }
}

function Get-EHDeviceByHostname {
    <#
    .SYNOPSIS
        Resolves an ExtraHop device ID from a hostname/DNS name.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Hostname)

    $encoded = [System.Uri]::EscapeDataString($Hostname)
    $endpoint = "/api/v1/devices?search_type=name&value=$encoded&active_from=-$($script:LookbackMs)&active_until=0&limit=50"

    $result = Invoke-EHRequest -Endpoint $endpoint
    if (-not $result.Success) { return $result }

    $devices = $result.Data
    if (-not $devices -or ($devices | Measure-Object).Count -eq 0) {
        return @{ Success = $false; StatusCode = 404; Error = "No device found for hostname $Hostname" }
    }

    # Prefer exact match on display_name or dns_name
    $match = $devices | Where-Object {
        $_.display_name -eq $Hostname -or $_.dns_name -eq $Hostname -or
        $_.display_name -ieq $Hostname -or $_.dns_name -ieq $Hostname
    } | Sort-Object -Property mod_time -Descending | Select-Object -First 1

    if (-not $match) {
        $match = $devices | Sort-Object -Property mod_time -Descending | Select-Object -First 1
    }

    return @{ Success = $true; Data = $match; StatusCode = 200 }
}

function Resolve-EHDevice {
    <#
    .SYNOPSIS
        Resolves an ExtraHop device by IP first, then falls back to hostname.
        Returns the resolved device or a failure result.
    #>
    [CmdletBinding()]
    param(
        [Parameter()][string]$IpAddress,
        [Parameter()][string]$Hostname
    )

    # Try IP first if available
    if ($IpAddress) {
        $result = Get-EHDeviceByIp -IpAddress $IpAddress
        if ($result.Success) { return $result }
    }

    # Fall back to hostname lookup
    if ($Hostname) {
        $result = Get-EHDeviceByHostname -Hostname $Hostname
        if ($result.Success) { return $result }
    }

    # Both failed
    $identifier = if ($IpAddress) { $IpAddress } else { $Hostname }
    return @{ Success = $false; StatusCode = 404; Error = "No device found for $identifier" }
}

function Get-EHDevicePeerMetrics {
    <#
    .SYNOPSIS
        Discovers peers via POST /metrics using detail metrics that break down
        traffic by peer IP address. Tries multiple metric categories in order
        of reliability: net_detail, tcp, net.
        Returns the raw metrics response with per-peer key/value breakdowns.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][long]$DeviceId)

    # Try detail metric categories that break down by peer IP
    $categories = @("net_detail", "tcp", "net")

    foreach ($category in $categories) {
        $body = @{
            cycle           = "auto"
            from            = -$script:LookbackMs
            until           = 0
            metric_category = $category
            metric_specs    = @(
                @{ name = "bytes_out" }
            )
            object_type     = "device"
            object_ids      = @($DeviceId)
        }

        $result = Invoke-EHRequest -Endpoint "/api/v1/metrics" -Method "POST" -Body $body
        if ($result.Success -and $result.Data -and $result.Data.stats) {
            # Check if this response has detail (per-peer) data
            # Detail metrics have values that are arrays of {key:{...}, value:N} objects
            # Aggregate metrics have values that are simple numbers
            $firstStat = $result.Data.stats | Select-Object -First 1
            if ($firstStat -and $firstStat.values) {
                $firstVal = $firstStat.values | Select-Object -First 1
                # Detail metric: value is an object with .key property
                if ($firstVal -and $firstVal.key) {
                    Write-Verbose "  Peer detail found via metric_category=$category"
                    return @{ Success = $true; Data = $result.Data; Category = $category; StatusCode = 200 }
                }
            }
        }
    }

    return @{ Success = $false; StatusCode = 404; Error = "No detail peer metrics found" }
}

function Get-EHDeviceActivity {
    <#
    .SYNOPSIS
        Gets active metric categories (protocols) for a device via GET /devices/{id}/activity.
        Returns stat_name values like "extrahop.device.http_client" indicating active protocols.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][long]$DeviceId)

    $endpoint = "/api/v1/devices/$DeviceId/activity"
    return Invoke-EHRequest -Endpoint $endpoint
}

function Get-EHDeviceById {
    <#
    .SYNOPSIS
        Gets full device object by ExtraHop device ID.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][long]$DeviceId)

    $endpoint = "/api/v1/devices/$DeviceId"
    return Invoke-EHRequest -Endpoint $endpoint
}

function Get-EHDeviceMetrics {
    <#
    .SYNOPSIS
        Gets traffic metrics (bytes/packets) for a device via POST /metrics.
        Uses metric_category "net" for L2/L3 network stats.
        Time values are in milliseconds (negative = relative to now).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][long]$DeviceId)

    $body = @{
        cycle           = "auto"
        from            = -$script:LookbackMs
        until           = 0
        metric_category = "net"
        metric_specs    = @(
            @{ name = "bytes_in" },
            @{ name = "bytes_out" },
            @{ name = "pkts_in" },
            @{ name = "pkts_out" }
        )
        object_type     = "device"
        object_ids      = @($DeviceId)
    }

    return Invoke-EHRequest -Endpoint "/api/v1/metrics" -Method "POST" -Body $body
}

#endregion

#region ============ DATA COLLECTION ============

function ConvertFrom-DetailMetrics {
    <#
    .SYNOPSIS
        Parses POST /metrics detail response into a list of peer IPs with byte counts.
        Detail metrics return values as arrays of {key:{addr:"x.x.x.x"}, value:N} objects.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$MetricsData)

    $peerMap = @{}

    if (-not $MetricsData.stats) { return $peerMap }

    foreach ($stat in $MetricsData.stats) {
        if (-not $stat.values) { continue }
        foreach ($entry in $stat.values) {
            $peerAddr = $null
            $bytes = 0

            # Detail metric format: entry has .key and .value
            if ($entry.key) {
                # Key can be {addr:"x.x.x.x"} or {str:"hostname"} or just a string
                if ($entry.key.addr) {
                    $peerAddr = $entry.key.addr
                }
                elseif ($entry.key.str) {
                    $peerAddr = $entry.key.str
                }
                elseif ($entry.key -is [string]) {
                    $peerAddr = $entry.key
                }

                $bytes = if ($entry.value) { [long]$entry.value } else { 0 }
            }

            if ($peerAddr) {
                if ($peerMap.ContainsKey($peerAddr)) {
                    $peerMap[$peerAddr] += $bytes
                }
                else {
                    $peerMap[$peerAddr] = $bytes
                }
            }
        }
    }

    return $peerMap
}

function ConvertFrom-DeviceActivity {
    <#
    .SYNOPSIS
        Converts GET /devices/{id}/activity response into a protocol name list.
        stat_name format: "extrahop.device.<metric_category>" — extract the category
        and map common categories to human-readable protocol names.
    #>
    [CmdletBinding()]
    param([Parameter()][array]$ActivityData)

    $protoMap = @{
        "http_client"   = "HTTP"; "http_server"   = "HTTP"
        "ssl_client"    = "SSL/TLS"; "ssl_server"  = "SSL/TLS"
        "dns_client"    = "DNS"; "dns_server"     = "DNS"
        "tcp"           = "TCP"
        "udp"           = "UDP"
        "ssh_client"    = "SSH"; "ssh_server"     = "SSH"
        "smb_client"    = "SMB"; "smb_server"     = "SMB"
        "nfs_client"    = "NFS"; "nfs_server"     = "NFS"
        "ftp_client"    = "FTP"; "ftp_server"     = "FTP"
        "ldap_client"   = "LDAP"; "ldap_server"   = "LDAP"
        "dhcp_client"   = "DHCP"; "dhcp_server"   = "DHCP"
        "rdp_client"    = "RDP"; "rdp_server"     = "RDP"
        "db_client"     = "Database"; "db_server"  = "Database"
        "smtp_client"   = "SMTP"; "smtp_server"   = "SMTP"
        "citrix_client" = "Citrix"; "citrix_server" = "Citrix"
        "ica_client"    = "ICA"; "ica_server"     = "ICA"
        "net"           = "Network"
    }

    $protocols = @()
    if (-not $ActivityData) { return $protocols }

    foreach ($activity in $ActivityData) {
        if ($activity.stat_name) {
            # Extract category after last dot: "extrahop.device.http_client" -> "http_client"
            $parts = $activity.stat_name -split "\."
            $category = $parts[-1]

            $displayName = if ($protoMap.ContainsKey($category)) { $protoMap[$category] } else { $category.ToUpper() }
            if ($displayName -notin $protocols) {
                $protocols += $displayName
            }
        }
    }

    return $protocols
}

function Invoke-EHDataCollection {
    <#
    .SYNOPSIS
        Main data collection loop — queries ExtraHop for each input device.
        Uses POST /metrics with detail metrics for peer discovery (per-peer IP breakdown),
        GET /devices/{id}/activity for protocol detection,
        and POST /metrics with aggregate metrics for total traffic volume.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][array]$Devices
    )

    $results = [System.Collections.ArrayList]::new()
    $warnings = [System.Collections.ArrayList]::new()
    $total = ($Devices | Measure-Object).Count
    $peerDeviceCache = @{}  # Cache resolved peer device objects to avoid duplicate lookups

    for ($i = 0; $i -lt $total; $i++) {
        $device = $Devices[$i]
        $ip = $device.ip
        $hostname = if ($device.hostname) { $device.hostname } else { "" }
        $description = if ($device.description) { $device.description } else { "" }
        $prefix = "[$($i + 1)/$total]"

        # Resolve device in ExtraHop (try IP first, fall back to hostname)
        $resolved = Resolve-EHDevice -IpAddress $ip -Hostname $hostname
        $displayIdentifier = if ($ip) { "$ip ($hostname)" } else { $hostname }
        if (-not $resolved.Success) {
            if ($resolved.StatusCode -eq 404) {
                Write-Host "$prefix $displayIdentifier... " -NoNewline
                Write-Host "NOT FOUND in ExtraHop" -ForegroundColor Yellow
                [void]$warnings.Add(@{ Ip = $ip; Hostname = $hostname; Reason = "Device not found in ExtraHop (tried IP and hostname)" })
            }
            else {
                Write-Host "$prefix $displayIdentifier... " -NoNewline
                Write-Host "API error ($($resolved.StatusCode)) skipping" -ForegroundColor Red
                [void]$warnings.Add(@{ Ip = $ip; Hostname = $hostname; Reason = "API error: $($resolved.Error)" })
            }

            [void]$results.Add([PSCustomObject]@{
                source_ip                    = $ip
                source_hostname              = $hostname
                source_description           = $description
                source_extrahop_display_name = ""
                source_extrahop_device_type  = ""
                peer_ip                      = ""
                peer_hostname                = ""
                peer_extrahop_display_name   = ""
                peer_extrahop_device_type    = ""
                peer_role                    = ""
                traffic_direction            = ""
                protocols                    = ""
                ports                        = ""
                bytes_in                     = ""
                bytes_out                    = ""
                pkts_in                      = ""
                pkts_out                     = ""
                first_seen                   = ""
                last_seen                    = ""
            })
            continue
        }

        $ehDevice = $resolved.Data
        $deviceId = $ehDevice.id
        $displayName = if ($ehDevice.display_name) { $ehDevice.display_name } else { "" }
        $deviceType = if ($ehDevice.device_class) { $ehDevice.device_class } else { "" }

        # If resolved by hostname and we didn't have an IP, populate from ExtraHop
        if (-not $ip -and $ehDevice.ipaddr4) { $ip = $ehDevice.ipaddr4 }

        # === PEER DISCOVERY via detail metrics ===
        # Detail metrics break down traffic by peer IP in the key field
        $peerResult = Get-EHDevicePeerMetrics -DeviceId $deviceId
        $peerMap = @{}
        if ($peerResult.Success -and $peerResult.Data) {
            # Diagnostic: dump first successful detail response
            if ($i -lt 3 -and -not $script:detailDumped) {
                $script:detailDumped = $true
                $dumpPath = Join-Path $script:Config.OutputDir "debug_detail_metrics.json"
                try {
                    $peerResult.Data | ConvertTo-Json -Depth 10 | Out-File -FilePath $dumpPath -Encoding UTF8
                    Write-Host "  DEBUG: detail metrics (category=$($peerResult.Category)) dumped to $dumpPath" -ForegroundColor Magenta
                }
                catch {
                    $dumpPath = Join-Path $script:Config.OutputDir "debug_detail_metrics.txt"
                    "$($peerResult.Data.GetType().FullName)`n---`n$($peerResult.Data)" | Out-File -FilePath $dumpPath -Encoding UTF8
                    Write-Host "  DEBUG: raw response dumped to $dumpPath" -ForegroundColor Magenta
                }
            }
            $peerMap = ConvertFrom-DetailMetrics -MetricsData $peerResult.Data
        }

        # Get active protocols via /devices/{id}/activity
        $activityResult = Get-EHDeviceActivity -DeviceId $deviceId
        $deviceProtocols = @()
        if ($activityResult.Success -and $activityResult.Data) {
            $deviceProtocols = ConvertFrom-DeviceActivity -ActivityData $activityResult.Data
        }
        $protoString = ($deviceProtocols | Sort-Object) -join ", "

        # Get aggregate metrics via POST /metrics
        $metricsResult = Get-EHDeviceMetrics -DeviceId $deviceId
        $totalBytesIn = 0; $totalBytesOut = 0; $totalPktsIn = 0; $totalPktsOut = 0
        if ($metricsResult.Success -and $metricsResult.Data -and $metricsResult.Data.stats) {
            foreach ($stat in $metricsResult.Data.stats) {
                if ($stat.values) {
                    $vals = $stat.values
                    if (($vals | Measure-Object).Count -ge 4) {
                        $totalBytesIn += if ($vals[0]) { $vals[0] } else { 0 }
                        $totalBytesOut += if ($vals[1]) { $vals[1] } else { 0 }
                        $totalPktsIn += if ($vals[2]) { $vals[2] } else { 0 }
                        $totalPktsOut += if ($vals[3]) { $vals[3] } else { 0 }
                    }
                }
            }
        }

        $peerCount = ($peerMap.Keys | Measure-Object).Count
        Write-Host "$prefix $displayIdentifier... " -NoNewline
        Write-Host "found (id=$deviceId) -> $peerCount peers" -ForegroundColor Green

        if ($peerCount -eq 0) {
            [void]$results.Add([PSCustomObject]@{
                source_ip                    = $ip
                source_hostname              = $hostname
                source_description           = $description
                source_extrahop_display_name = $displayName
                source_extrahop_device_type  = $deviceType
                peer_ip                      = ""
                peer_hostname                = ""
                peer_extrahop_display_name   = ""
                peer_extrahop_device_type    = ""
                peer_role                    = ""
                traffic_direction            = ""
                protocols                    = $protoString
                ports                        = ""
                bytes_in                     = $totalBytesIn
                bytes_out                    = $totalBytesOut
                pkts_in                      = $totalPktsIn
                pkts_out                     = $totalPktsOut
                first_seen                   = ""
                last_seen                    = ""
            })
            continue
        }

        # Process each peer from the detail metrics
        foreach ($peerAddr in $peerMap.Keys) {
            $peerBytesOut = $peerMap[$peerAddr]

            # Try to resolve peer IP to a device in ExtraHop (with caching)
            $peerHostname = ""; $peerDisplayName = ""; $peerDeviceType = ""
            if ($peerDeviceCache.ContainsKey($peerAddr)) {
                $cached = $peerDeviceCache[$peerAddr]
                $peerHostname = $cached.hostname
                $peerDisplayName = $cached.display_name
                $peerDeviceType = $cached.device_class
            }
            else {
                # Only resolve if it looks like an IP address
                if ($peerAddr -match "^[\d.]+$" -or $peerAddr -match ":") {
                    $peerResolved = Get-EHDeviceByIp -IpAddress $peerAddr
                    if ($peerResolved.Success -and $peerResolved.Data) {
                        $pd = $peerResolved.Data
                        $peerHostname = if ($pd.dns_name) { $pd.dns_name } else { "" }
                        $peerDisplayName = if ($pd.display_name) { $pd.display_name } else { "" }
                        $peerDeviceType = if ($pd.device_class) { $pd.device_class } else { "" }
                    }
                    $peerDeviceCache[$peerAddr] = @{
                        hostname     = $peerHostname
                        display_name = $peerDisplayName
                        device_class = $peerDeviceType
                    }
                }
            }

            # Direction: we queried bytes_out from source, so these are outbound peers
            $direction = "outbound"
            $peerRole = "server"

            [void]$results.Add([PSCustomObject]@{
                source_ip                    = $ip
                source_hostname              = $hostname
                source_description           = $description
                source_extrahop_display_name = $displayName
                source_extrahop_device_type  = $deviceType
                peer_ip                      = $peerAddr
                peer_hostname                = $peerHostname
                peer_extrahop_display_name   = $peerDisplayName
                peer_extrahop_device_type    = $peerDeviceType
                peer_role                    = $peerRole
                traffic_direction            = $direction
                protocols                    = $protoString
                ports                        = ""
                bytes_in                     = 0
                bytes_out                    = $peerBytesOut
                pkts_in                      = 0
                pkts_out                     = 0
                first_seen                   = ""
                last_seen                    = ""
            })
        }
    }

    return @{ Results = $results; Warnings = $warnings }
}

#endregion

#region ============ EXPORT FUNCTIONS ============

function Export-EHCsv {
    <#
    .SYNOPSIS
        Exports communication map data to CSV.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][System.Collections.ArrayList]$Data,
        [Parameter(Mandatory)][string]$OutputPath
    )

    $sorted = $Data | Sort-Object -Property @(
        @{ Expression = "source_ip"; Ascending = $true },
        @{ Expression = "bytes_out"; Descending = $true }
    )

    $sorted | Select-Object source_ip, source_hostname, source_description, source_extrahop_display_name,
        source_extrahop_device_type, peer_ip, peer_hostname, peer_extrahop_display_name,
        peer_extrahop_device_type, peer_role, traffic_direction, protocols, ports,
        bytes_in, bytes_out, pkts_in, pkts_out, first_seen, last_seen |
        Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

    Write-Host "CSV exported: $OutputPath" -ForegroundColor Cyan
}

function Export-EHHtml {
    <#
    .SYNOPSIS
        Generates self-contained interactive HTML report.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][System.Collections.ArrayList]$Data,
        [Parameter(Mandatory)][System.Collections.ArrayList]$Warnings,
        [Parameter(Mandatory)][string]$OutputPath
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $queryWindow = "$($script:Config.LookbackMinutes) minutes ($([math]::Round($script:Config.LookbackMinutes / 60, 1)) hours)"

    # Compute summary stats
    $sourceDevices = ($Data | Select-Object -Property source_ip -Unique | Measure-Object).Count
    $uniquePeers = ($Data | Where-Object { $_.peer_ip -ne "" } | Select-Object -Property peer_ip -Unique | Measure-Object).Count
    $allPorts = @()
    foreach ($row in $Data) {
        if ($row.ports) {
            $allPorts += ($row.ports -split ",\s*")
        }
    }
    $uniquePorts = ($allPorts | Select-Object -Unique | Measure-Object).Count
    $totalBytes = ($Data | ForEach-Object { [long]$_.bytes_in + [long]$_.bytes_out } | Measure-Object -Sum).Sum
    $totalBytesFormatted = if ($totalBytes -ge 1GB) { "{0:N2} GB" -f ($totalBytes / 1GB) } elseif ($totalBytes -ge 1MB) { "{0:N2} MB" -f ($totalBytes / 1MB) } else { "{0:N0} bytes" -f $totalBytes }
    $notFoundCount = ($Warnings | Measure-Object).Count
    $totalRelationships = ($Data | Where-Object { $_.peer_ip -ne "" } | Measure-Object).Count

    # Group data by source device
    $grouped = $Data | Group-Object -Property source_ip

    # Collect all device types and protocols for filters
    $allDeviceTypes = @()
    $allProtocols = @()
    foreach ($row in $Data) {
        if ($row.peer_extrahop_device_type -and $row.peer_extrahop_device_type -notin $allDeviceTypes) {
            $allDeviceTypes += $row.peer_extrahop_device_type
        }
        if ($row.protocols) {
            foreach ($p in ($row.protocols -split ",\s*")) {
                if ($p -and $p -notin $allProtocols) { $allProtocols += $p }
            }
        }
    }
    $allDeviceTypes = $allDeviceTypes | Sort-Object
    $allProtocols = $allProtocols | Sort-Object

    $deviceTypeOptions = ($allDeviceTypes | ForEach-Object { "<option value=`"$_`">$_</option>" }) -join "`n"
    $protocolOptions = ($allProtocols | ForEach-Object { "<option value=`"$_`">$_</option>" }) -join "`n"

    # Build per-device card HTML
    $cardsHtml = ""
    foreach ($group in $grouped) {
        $sourceIp = $group.Name
        $rows = $group.Group
        $firstRow = $rows[0]
        $peerRows = $rows | Where-Object { $_.peer_ip -ne "" }
        $peerCount = ($peerRows | Measure-Object).Count
        $cardBytes = ($rows | ForEach-Object { [long]$_.bytes_in + [long]$_.bytes_out } | Measure-Object -Sum).Sum
        $cardBytesFormatted = if ($cardBytes -ge 1GB) { "{0:N2} GB" -f ($cardBytes / 1GB) } elseif ($cardBytes -ge 1MB) { "{0:N2} MB" -f ($cardBytes / 1MB) } else { "{0:N0} B" -f $cardBytes }

        $tableRows = ""
        # Calculate top 10% threshold for high-traffic highlighting
        $allPeerBytes = $peerRows | ForEach-Object { [long]$_.bytes_in + [long]$_.bytes_out } | Sort-Object -Descending
        $peerByteCount = ($allPeerBytes | Measure-Object).Count
        $top10Threshold = if ($peerByteCount -gt 0) { $allPeerBytes[[math]::Max(0, [math]::Floor($peerByteCount * 0.1))] } else { [long]::MaxValue }

        foreach ($row in $peerRows) {
            $rowTotal = [long]$row.bytes_in + [long]$row.bytes_out
            $borderClass = switch ($row.traffic_direction) {
                "outbound"      { "border-outbound" }
                "inbound"       { "border-inbound" }
                "bidirectional" { "border-bidi" }
                default         { "" }
            }
            if ($rowTotal -ge $top10Threshold -and $top10Threshold -gt 0) {
                $borderClass = "border-high"
            }

            $bytesInFmt = if ($row.bytes_in) { "{0:N0}" -f [long]$row.bytes_in } else { "0" }
            $bytesOutFmt = if ($row.bytes_out) { "{0:N0}" -f [long]$row.bytes_out } else { "0" }

            $tableRows += @"
<tr class="peer-row $borderClass" data-ip="$($row.peer_ip)" data-hostname="$($row.peer_hostname)" data-type="$($row.peer_extrahop_device_type)" data-role="$($row.peer_role)" data-direction="$($row.traffic_direction)" data-protocols="$($row.protocols)" data-ports="$($row.ports)">
<td>$($row.peer_ip)</td>
<td>$($row.peer_hostname)</td>
<td><span class="badge badge-type">$($row.peer_extrahop_device_type)</span></td>
<td>$($row.peer_role)</td>
<td>$($row.traffic_direction)</td>
<td>$($row.protocols)</td>
<td>$($row.ports)</td>
<td class="num">$bytesInFmt</td>
<td class="num">$bytesOutFmt</td>
<td>$($row.last_seen)</td>
</tr>
"@
        }

        $cardsHtml += @"
<div class="device-card" data-source-ip="$sourceIp">
<div class="card-header" onclick="toggleCard(this)">
<div class="card-title">
<span class="expand-icon">&#9654;</span>
<strong>$sourceIp</strong>
<span class="card-meta">$($firstRow.source_hostname)</span>
<span class="card-meta">$($firstRow.source_description)</span>
<span class="badge badge-type">$($firstRow.source_extrahop_device_type)</span>
</div>
<div class="card-stats">
<span class="stat">$peerCount peers</span>
<span class="stat">$cardBytesFormatted</span>
</div>
</div>
<div class="card-body" style="display:none">
<table class="peer-table">
<thead>
<tr>
<th data-sort="ip">Peer IP</th>
<th data-sort="hostname">Peer Hostname</th>
<th data-sort="type">Device Type</th>
<th data-sort="role">Role</th>
<th data-sort="direction">Direction</th>
<th data-sort="protocols">Protocols</th>
<th data-sort="ports">Ports</th>
<th data-sort="bytes_in" class="num">Bytes In</th>
<th data-sort="bytes_out" class="num">Bytes Out</th>
<th data-sort="last_seen">Last Seen</th>
</tr>
</thead>
<tbody>
$tableRows
</tbody>
</table>
</div>
</div>
"@
    }

    # Build warnings HTML
    $warningsHtml = ""
    if (($Warnings | Measure-Object).Count -gt 0) {
        $warningRows = ""
        foreach ($w in $Warnings) {
            $warningRows += "<tr><td>$($w.Ip)</td><td>$($w.Hostname)</td><td><span class='badge badge-warning'>$($w.Reason)</span></td></tr>"
        }
        $warningsHtml = @"
<div class="warnings-section">
<h2>Warnings</h2>
<table class="warnings-table">
<thead><tr><th>IP</th><th>Hostname</th><th>Reason</th></tr></thead>
<tbody>$warningRows</tbody>
</table>
</div>
"@
    }

    # Full HTML document
    $html = @"
<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ExtraHop Communication Map</title>
<style>
:root {
    --bg: #1a1a2e;
    --surface: #16213e;
    --surface-hover: #1a2744;
    --text: #e0e0e0;
    --text-muted: #888;
    --border: #2a2a4a;
    --accent: #4fc3f7;
    --green: #66bb6a;
    --blue: #42a5f5;
    --yellow: #ffca28;
    --red: #ef5350;
    --orange: #ff7043;
}
[data-theme="light"] {
    --bg: #f5f5f5;
    --surface: #ffffff;
    --surface-hover: #fafafa;
    --text: #212121;
    --text-muted: #666;
    --border: #e0e0e0;
    --accent: #1976d2;
    --green: #388e3c;
    --blue: #1565c0;
    --yellow: #f9a825;
    --red: #c62828;
    --orange: #e64a19;
}
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: var(--bg); color: var(--text); line-height: 1.5; min-width: 1280px; }
.header { background: var(--surface); border-bottom: 1px solid var(--border); padding: 16px 24px; display: flex; justify-content: space-between; align-items: center; }
.header h1 { font-size: 1.4rem; color: var(--accent); }
.header .subtitle { font-size: 0.85rem; color: var(--text-muted); margin-top: 2px; }
.theme-toggle { background: var(--border); border: none; color: var(--text); padding: 8px 14px; border-radius: 6px; cursor: pointer; font-size: 0.85rem; }
.theme-toggle:hover { background: var(--accent); color: #fff; }
.kpi-row { display: flex; gap: 12px; padding: 16px 24px; flex-wrap: wrap; }
.kpi-card { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 12px 18px; flex: 1; min-width: 150px; }
.kpi-card .kpi-value { font-size: 1.5rem; font-weight: 700; color: var(--accent); }
.kpi-card .kpi-label { font-size: 0.75rem; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.5px; }
.kpi-card.warning .kpi-value { color: var(--orange); }
.filter-bar { position: sticky; top: 0; z-index: 100; background: var(--surface); border-bottom: 1px solid var(--border); padding: 12px 24px; display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
.filter-bar input, .filter-bar select { background: var(--bg); border: 1px solid var(--border); color: var(--text); padding: 6px 10px; border-radius: 4px; font-size: 0.85rem; }
.filter-bar input { width: 200px; }
.filter-bar select { min-width: 120px; }
.filter-bar button { background: var(--border); border: none; color: var(--text); padding: 6px 12px; border-radius: 4px; cursor: pointer; font-size: 0.85rem; }
.filter-bar button:hover { background: var(--red); color: #fff; }
.content { padding: 16px 24px; }
.device-card { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; margin-bottom: 12px; overflow: hidden; }
.card-header { padding: 12px 18px; cursor: pointer; display: flex; justify-content: space-between; align-items: center; transition: background 0.15s; }
.card-header:hover { background: var(--surface-hover); }
.card-title { display: flex; align-items: center; gap: 10px; }
.card-meta { color: var(--text-muted); font-size: 0.85rem; }
.card-stats { display: flex; gap: 16px; }
.card-stats .stat { font-size: 0.85rem; color: var(--text-muted); }
.expand-icon { font-size: 0.7rem; transition: transform 0.2s; display: inline-block; }
.card-header.expanded .expand-icon { transform: rotate(90deg); }
.card-body { padding: 0 18px 16px; }
.peer-table { width: 100%; border-collapse: collapse; font-size: 0.82rem; }
.peer-table th { text-align: left; padding: 8px 6px; border-bottom: 2px solid var(--border); color: var(--text-muted); cursor: pointer; white-space: nowrap; user-select: none; }
.peer-table th:hover { color: var(--accent); }
.peer-table td { padding: 6px; border-bottom: 1px solid var(--border); }
.peer-table tr:nth-child(even) { background: rgba(255,255,255,0.02); }
.peer-table .num { text-align: right; font-variant-numeric: tabular-nums; }
.border-outbound { border-left: 3px solid var(--green); }
.border-inbound { border-left: 3px solid var(--blue); }
.border-bidi { border-left: 3px solid var(--yellow); }
.border-high { border-left: 3px solid var(--red); }
.badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.72rem; font-weight: 500; }
.badge-type { background: rgba(79,195,247,0.15); color: var(--accent); }
.badge-warning { background: rgba(255,112,67,0.15); color: var(--orange); }
.warnings-section { margin-top: 24px; padding: 16px; background: var(--surface); border: 1px solid var(--border); border-radius: 8px; }
.warnings-section h2 { font-size: 1rem; margin-bottom: 12px; color: var(--orange); }
.warnings-table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
.warnings-table th, .warnings-table td { padding: 8px; border-bottom: 1px solid var(--border); text-align: left; }
.footer { padding: 24px; text-align: center; font-size: 0.75rem; color: var(--text-muted); border-top: 1px solid var(--border); margin-top: 32px; }
</style>
</head>
<body>

<div class="header">
<div>
<h1>ExtraHop Communication Map</h1>
<div class="subtitle">Query window: $queryWindow | Generated: $timestamp | $sourceDevices source devices | $totalRelationships peer relationships</div>
</div>
<button class="theme-toggle" onclick="toggleTheme()">Toggle Light/Dark</button>
</div>

<div class="kpi-row">
<div class="kpi-card"><div class="kpi-value">$sourceDevices</div><div class="kpi-label">Source Devices</div></div>
<div class="kpi-card"><div class="kpi-value">$uniquePeers</div><div class="kpi-label">Unique Peers</div></div>
<div class="kpi-card"><div class="kpi-value">$uniquePorts</div><div class="kpi-label">Unique Ports</div></div>
<div class="kpi-card"><div class="kpi-value">$totalBytesFormatted</div><div class="kpi-label">Total Traffic</div></div>
<div class="kpi-card warning"><div class="kpi-value">$notFoundCount</div><div class="kpi-label">Not Found</div></div>
<div class="kpi-card"><div class="kpi-value">$totalRelationships</div><div class="kpi-label">Relationships</div></div>
</div>

<div class="filter-bar">
<input type="text" id="searchFilter" placeholder="Search IPs / hostnames..." oninput="applyFilters()">
<select id="typeFilter" onchange="applyFilters()"><option value="">All Device Types</option>$deviceTypeOptions</select>
<select id="protocolFilter" onchange="applyFilters()"><option value="">All Protocols</option>$protocolOptions</select>
<select id="directionFilter" onchange="applyFilters()">
<option value="">All Directions</option>
<option value="inbound">Inbound</option>
<option value="outbound">Outbound</option>
<option value="bidirectional">Bidirectional</option>
</select>
<input type="text" id="portFilter" placeholder="Port..." oninput="applyFilters()" style="width:80px">
<button onclick="resetFilters()">Reset Filters</button>
</div>

<div class="content">
$cardsHtml
$warningsHtml
</div>

<div class="footer">
Generated by: Invoke-ExtraHopCommsMap.ps1 | ExtraHop: $($script:Config.Host) | Window: $queryWindow | $timestamp
</div>

<script>
function toggleTheme() {
    var html = document.documentElement;
    html.setAttribute('data-theme', html.getAttribute('data-theme') === 'dark' ? 'light' : 'dark');
}

function toggleCard(header) {
    var body = header.nextElementSibling;
    var isOpen = body.style.display !== 'none';
    body.style.display = isOpen ? 'none' : 'block';
    header.classList.toggle('expanded', !isOpen);
}

function applyFilters() {
    var search = document.getElementById('searchFilter').value.toLowerCase();
    var typeF = document.getElementById('typeFilter').value.toLowerCase();
    var protoF = document.getElementById('protocolFilter').value.toLowerCase();
    var dirF = document.getElementById('directionFilter').value.toLowerCase();
    var portF = document.getElementById('portFilter').value.toLowerCase();

    var rows = document.querySelectorAll('.peer-row');
    rows.forEach(function(row) {
        var ip = (row.getAttribute('data-ip') || '').toLowerCase();
        var hostname = (row.getAttribute('data-hostname') || '').toLowerCase();
        var type = (row.getAttribute('data-type') || '').toLowerCase();
        var direction = (row.getAttribute('data-direction') || '').toLowerCase();
        var protocols = (row.getAttribute('data-protocols') || '').toLowerCase();
        var ports = (row.getAttribute('data-ports') || '').toLowerCase();

        var card = row.closest('.device-card');
        var sourceIp = (card.getAttribute('data-source-ip') || '').toLowerCase();

        var show = true;
        if (search && ip.indexOf(search) === -1 && hostname.indexOf(search) === -1 && sourceIp.indexOf(search) === -1) show = false;
        if (typeF && type.indexOf(typeF) === -1) show = false;
        if (protoF && protocols.indexOf(protoF) === -1) show = false;
        if (dirF && direction !== dirF) show = false;
        if (portF && ports.indexOf(portF) === -1) show = false;

        row.style.display = show ? '' : 'none';
    });

    // Hide cards with no visible rows
    document.querySelectorAll('.device-card').forEach(function(card) {
        var visibleRows = card.querySelectorAll('.peer-row:not([style*="display: none"])');
        card.style.display = visibleRows.length > 0 || !search && !typeF && !protoF && !dirF && !portF ? '' : 'none';
    });
}

function resetFilters() {
    document.getElementById('searchFilter').value = '';
    document.getElementById('typeFilter').value = '';
    document.getElementById('protocolFilter').value = '';
    document.getElementById('directionFilter').value = '';
    document.getElementById('portFilter').value = '';
    applyFilters();
}

// Column sorting
document.querySelectorAll('.peer-table th').forEach(function(th) {
    th.addEventListener('click', function() {
        var table = th.closest('table');
        var tbody = table.querySelector('tbody');
        var rows = Array.from(tbody.querySelectorAll('tr'));
        var colIdx = Array.from(th.parentNode.children).indexOf(th);
        var asc = th.getAttribute('data-dir') !== 'asc';
        th.setAttribute('data-dir', asc ? 'asc' : 'desc');

        // Clear other headers
        th.parentNode.querySelectorAll('th').forEach(function(h) { if (h !== th) h.removeAttribute('data-dir'); });

        rows.sort(function(a, b) {
            var aVal = a.children[colIdx].textContent.trim();
            var bVal = b.children[colIdx].textContent.trim();
            var aNum = parseFloat(aVal.replace(/,/g, ''));
            var bNum = parseFloat(bVal.replace(/,/g, ''));
            if (!isNaN(aNum) && !isNaN(bNum)) {
                return asc ? aNum - bNum : bNum - aNum;
            }
            return asc ? aVal.localeCompare(bVal) : bVal.localeCompare(aVal);
        });

        rows.forEach(function(row) { tbody.appendChild(row); });
    });
});
</script>
</body>
</html>
"@

    $html | Out-File -FilePath $OutputPath -Encoding UTF8
    Write-Host "HTML report exported: $OutputPath" -ForegroundColor Cyan
}

#endregion

#region ============ MAIN EXECUTION ============

# Disable SSL if requested
if (-not $script:Config.VerifySsl) {
    Disable-SslVerification
}

# Validate API key
if (-not $script:Config.ApiKey) {
    Write-Error "EXTRAHOP_API_KEY environment variable or -ApiKey parameter is required."
    exit 1
}

# Ensure output directory exists
if (-not (Test-Path $script:Config.OutputDir)) {
    New-Item -Path $script:Config.OutputDir -ItemType Directory -Force | Out-Null
}

# Read and validate input CSV
if (-not (Test-Path $InputCsv)) {
    Write-Error "Input CSV not found: $InputCsv"
    exit 1
}

Write-Host "`n=== ExtraHop Communication Map ===" -ForegroundColor Cyan
Write-Host "Host: $($script:Config.Host)"
Write-Host "Lookback: $($script:Config.LookbackMinutes) minutes"
Write-Host "Input: $InputCsv"
Write-Host "Output: $($script:Config.OutputDir)"
Write-Host "SSL Verify: $($script:Config.VerifySsl)`n"

$rawCsv = Import-Csv -Path $InputCsv -Encoding UTF8

# Normalize column headers (handle case/whitespace variations)
$devices = [System.Collections.ArrayList]::new()
$seenIps = @{}

foreach ($row in $rawCsv) {
    # Get IP from various column name formats
    $ip = $null
    $hostname = ""; $description = ""
    foreach ($prop in $row.PSObject.Properties) {
        $key = $prop.Name.Trim().ToLower()
        if ($key -eq "ip") { $ip = if ($prop.Value) { $prop.Value.Trim() } else { "" } }
        if ($key -eq "hostname") { $hostname = if ($prop.Value) { $prop.Value.Trim() } else { "" } }
        if ($key -eq "description") { $description = if ($prop.Value) { $prop.Value.Trim() } else { "" } }
    }

    # Must have at least IP or hostname
    if (-not $ip -and -not $hostname) {
        Write-Host "SKIP: Row with no IP and no hostname" -ForegroundColor Yellow
        continue
    }

    # Handle comma-separated IPs in a single field (e.g., "10.1.1.50, 10.1.1.51")
    $ipList = @()
    if ($ip -and $ip -match ",") {
        $ipList = $ip -split "\s*,\s*" | Where-Object { $_ }
    }
    elseif ($ip) {
        $ipList = @($ip)
    }
    else {
        $ipList = @("")  # hostname-only entry
    }

    foreach ($singleIp in $ipList) {
        $currentIp = $singleIp.Trim()

        # Validate IP if present
        if ($currentIp) {
            # Skip CIDR notation
            if ($currentIp -match "/\d+$") {
                Write-Host "SKIP: CIDR notation not supported: $currentIp" -ForegroundColor Yellow
                continue
            }

            # Skip invalid IPs
            if ($currentIp -notmatch "^[\d.:a-fA-F]+$") {
                Write-Host "SKIP: Invalid IP format: $currentIp" -ForegroundColor Yellow
                continue
            }
        }

        # Deduplicate by IP (if present) or hostname
        $dedupeKey = if ($currentIp) { $currentIp } else { $hostname.ToLower() }
        if ($seenIps.ContainsKey($dedupeKey)) {
            Write-Host "SKIP: Duplicate entry: $dedupeKey" -ForegroundColor Yellow
            continue
        }
        $seenIps[$dedupeKey] = $true

        [void]$devices.Add(@{ ip = $currentIp; hostname = $hostname; description = $description })
    }
}

if (($devices | Measure-Object).Count -eq 0) {
    Write-Error "No valid devices found in input CSV. Ensure 'ip' and/or 'hostname' columns exist."
    exit 1
}

# Check required columns — need at least one of ip or hostname
$hasIpColumn = $false; $hasHostnameColumn = $false
foreach ($prop in $rawCsv[0].PSObject.Properties) {
    $key = $prop.Name.Trim().ToLower()
    if ($key -eq "ip") { $hasIpColumn = $true }
    if ($key -eq "hostname") { $hasHostnameColumn = $true }
}
if (-not $hasIpColumn -and -not $hasHostnameColumn) {
    Write-Error "Input CSV missing required columns. Must have at least 'ip' or 'hostname' column."
    exit 1
}

Write-Host "Found $(($devices | Measure-Object).Count) unique devices to query`n" -ForegroundColor Green

# Run data collection
$collection = Invoke-EHDataCollection -Devices $devices.ToArray()
$results = $collection.Results
$warnings = $collection.Warnings

# Export CSV
$csvPath = Join-Path $script:Config.OutputDir "extrahop_comms_map.csv"
Export-EHCsv -Data $results -OutputPath $csvPath

# Export HTML
$htmlPath = Join-Path $script:Config.OutputDir "extrahop_comms_map.html"
Export-EHHtml -Data $results -Warnings $warnings -OutputPath $htmlPath

# Summary
Write-Host "`n=== Summary ===" -ForegroundColor Cyan
Write-Host "Devices queried: $(($devices | Measure-Object).Count)"
Write-Host "Peer relationships found: $(($results | Where-Object { $_.peer_ip -ne '' } | Measure-Object).Count)"
Write-Host "Warnings: $(($warnings | Measure-Object).Count)"
Write-Host "CSV: $csvPath"
Write-Host "HTML: $htmlPath"
Write-Host ""

#endregion
