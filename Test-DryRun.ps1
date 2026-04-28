<#
.SYNOPSIS
    Dry-run validation of Invoke-ExtraHopCommsMap.ps1 with mocked API functions.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$scriptDir = $PSScriptRoot
$scriptPath = Join-Path $scriptDir "Invoke-ExtraHopCommsMap.ps1"

Write-Host "=== VALIDATION STEP 1: Parse Check ===" -ForegroundColor Cyan

$parseErrors = $null
$tokens = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    (Resolve-Path $scriptPath),
    [ref]$tokens,
    [ref]$parseErrors
)

if ($parseErrors.Count -gt 0) {
    Write-Host "PARSE ERRORS FOUND:" -ForegroundColor Red
    foreach ($err in $parseErrors) {
        Write-Host "  Line $($err.Extent.StartLineNumber): $($err.Message)" -ForegroundColor Red
    }
    exit 1
}
else {
    Write-Host "  No parse errors found. Script syntax is valid." -ForegroundColor Green
}

Write-Host "`n=== VALIDATION STEP 2: Dry-Run with Mocked APIs ===" -ForegroundColor Cyan

# Set up env vars for mock run
$env:EXTRAHOP_HOST = "https://extrahop-mock.local"
$env:EXTRAHOP_API_KEY = "mock-api-key-12345"
$env:EXTRAHOP_VERIFY_SSL = "true"
$env:EXTRAHOP_LOOKBACK_MINUTES = "1440"
$env:EXTRAHOP_OUTPUT_DIR = Join-Path $scriptDir "output"

# We need to mock the API functions. We'll dot-source the script with a mock approach.
# Since the script calls exit on missing API key and runs immediately, we'll use a different approach:
# Source just the functions, then mock the HTTP layer.

# Create a wrapper that overrides Invoke-EHRequest to return mock data
$mockScript = @'
# Override the base HTTP function to return mock data
function Invoke-EHRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Endpoint,
        [Parameter()][string]$Method = "GET",
        [Parameter()][object]$Body,
        [Parameter()][int]$MaxRetries = 3
    )

    # Mock device search
    if ($Endpoint -match "/api/v1/devices\?search_type") {
        $ip = if ($Endpoint -match "value=([^&]+)") { [System.Uri]::UnescapeDataString($Matches[1]) } else { "" }

        # Simulate not-found for third device
        if ($ip -eq "10.1.1.52") {
            return @{ Success = $false; StatusCode = 404; Error = "No device found for IP $ip" }
        }

        $deviceId = if ($ip -eq "10.1.1.50") { 1001 } else { 1002 }
        $mockDevice = [PSCustomObject]@{
            id           = $deviceId
            ipaddr4      = $ip
            ipaddr6      = ""
            display_name = "mock-device-$deviceId"
            device_class = "node"
            dns_name     = "mock-$deviceId.local"
            mod_time     = (Get-Date).ToFileTimeUtc()
        }
        return @{ Success = $true; Data = @($mockDevice); StatusCode = 200 }
    }

    # Mock peers
    if ($Endpoint -match "/api/v1/devices/(\d+)/peers") {
        $mockPeers = @(
            [PSCustomObject]@{
                ipaddr4      = "192.168.1.10"
                ipaddr6      = ""
                dns_name     = "peer-web-01.local"
                display_name = "peer-web-01"
                device_class = "node"
                role         = "server"
                bytes_in     = 1048576
                bytes_out    = 2097152
                pkts_in      = 1024
                pkts_out     = 2048
                first_seen   = "2026-04-27T10:00:00Z"
                last_seen    = "2026-04-28T09:00:00Z"
                protocols    = $null
            },
            [PSCustomObject]@{
                ipaddr4      = "192.168.1.20"
                ipaddr6      = ""
                dns_name     = "peer-db-01.local"
                display_name = "peer-db-01"
                device_class = "node"
                role         = "client"
                bytes_in     = 524288
                bytes_out    = 131072
                pkts_in      = 512
                pkts_out     = 128
                first_seen   = "2026-04-27T12:00:00Z"
                last_seen    = "2026-04-28T08:30:00Z"
                protocols    = $null
            },
            [PSCustomObject]@{
                ipaddr4      = "10.0.0.1"
                ipaddr6      = ""
                dns_name     = "gateway.local"
                display_name = "gateway"
                device_class = "gateway"
                role         = "other"
                bytes_in     = 8388608
                bytes_out    = 4194304
                pkts_in      = 8192
                pkts_out     = 4096
                first_seen   = "2026-04-26T00:00:00Z"
                last_seen    = "2026-04-28T09:30:00Z"
                protocols    = $null
            }
        )
        return @{ Success = $true; Data = $mockPeers; StatusCode = 200 }
    }

    # Mock protocols
    if ($Endpoint -match "/api/v1/devices/(\d+)/protocols") {
        $mockProtos = @(
            [PSCustomObject]@{ proto = "HTTPS"; port = "443" },
            [PSCustomObject]@{ proto = "HTTP"; port = "80" },
            [PSCustomObject]@{ proto = "SSH"; port = "22" },
            [PSCustomObject]@{ proto = "DNS"; port = "53" }
        )
        return @{ Success = $true; Data = $mockProtos; StatusCode = 200 }
    }

    # Mock metrics
    if ($Endpoint -eq "/api/v1/metrics") {
        $mockMetrics = [PSCustomObject]@{
            stats = @(
                [PSCustomObject]@{ values = @(5242880, 10485760, 5120, 10240) }
            )
        }
        return @{ Success = $true; Data = $mockMetrics; StatusCode = 200 }
    }

    return @{ Success = $false; StatusCode = 404; Error = "Unknown endpoint" }
}
'@

# Write a temp runner script that sources the main script with mocked Invoke-EHRequest
$runnerPath = Join-Path $scriptDir "_test_runner.ps1"
$mainContent = Get-Content $scriptPath -Raw

# Replace the Invoke-EHRequest function with our mock, then run
# Strategy: dot-source the script but intercept at the function level
# Simpler: just inject the mock before calling

$runnerContent = @"
Set-StrictMode -Version Latest
`$ErrorActionPreference = "Stop"

# Mock Invoke-RestMethod globally
function Invoke-RestMethod {
    param([string]`$Uri, [string]`$Method, [hashtable]`$Headers, [string]`$ContentType, [string]`$Body, [switch]`$SkipCertificateCheck)
    throw "Invoke-RestMethod should not be called in mock mode"
}

# Source the mock functions
$mockScript

# Now source everything from the main script EXCEPT Invoke-EHRequest and the main execution
# Instead, let's just run the main script with a pre-loaded mock

# Set config
`$env:EXTRAHOP_HOST = "https://extrahop-mock.local"
`$env:EXTRAHOP_API_KEY = "mock-api-key-12345"
`$env:EXTRAHOP_VERIFY_SSL = "true"
`$env:EXTRAHOP_LOOKBACK_MINUTES = "1440"
`$env:EXTRAHOP_OUTPUT_DIR = "$($scriptDir.Replace('\','/'))/output"
"@

# Actually, the simplest approach: override Invoke-RestMethod at the PowerShell level
# and let the real script call through. But that's complex with the error handling.
# Let's use a different approach: manually run the data pipeline with mocks.

$testContent = @"
Set-StrictMode -Version Latest
`$ErrorActionPreference = "Stop"

`$scriptDir = "$($scriptDir.Replace('\','\\'))"

# Load the script's functions by dot-sourcing in a special way
# We'll parse and extract functions, then override Invoke-EHRequest

`$env:EXTRAHOP_HOST = "https://extrahop-mock.local"
`$env:EXTRAHOP_API_KEY = "mock-api-key-12345"
`$env:EXTRAHOP_VERIFY_SSL = "true"
`$env:EXTRAHOP_LOOKBACK_MINUTES = "1440"
`$env:EXTRAHOP_OUTPUT_DIR = Join-Path `$scriptDir "output"

# Source the script content as a script block, but we need to mock Invoke-RestMethod
# Simplest: just replace Invoke-RestMethod with a mock that returns appropriate data

function Global:Invoke-RestMethod {
    param(
        [string]`$Uri,
        [string]`$Method = "GET",
        [hashtable]`$Headers,
        [string]`$ContentType,
        [string]`$Body,
        [switch]`$SkipCertificateCheck,
        [string]`$ErrorAction
    )

    # Mock device search
    if (`$Uri -match "/api/v1/devices\?search_type") {
        `$ip = if (`$Uri -match "value=([^&]+)") { [System.Uri]::UnescapeDataString(`$Matches[1]) } else { "" }
        if (`$ip -eq "10.1.1.52") { throw "The remote server returned an error: (404) Not Found." }
        `$deviceId = if (`$ip -eq "10.1.1.50") { 1001 } else { 1002 }
        return @([PSCustomObject]@{
            id = `$deviceId; ipaddr4 = `$ip; ipaddr6 = ""; display_name = "mock-device-`$deviceId"
            device_class = "node"; dns_name = "mock-`$deviceId.local"; mod_time = (Get-Date).Ticks
        })
    }

    # Mock peers
    if (`$Uri -match "/api/v1/devices/\d+/peers") {
        return @(
            [PSCustomObject]@{ ipaddr4="192.168.1.10"; ipaddr6=""; dns_name="peer-web-01.local"; display_name="peer-web-01"; device_class="node"; role="server"; bytes_in=1048576; bytes_out=2097152; pkts_in=1024; pkts_out=2048; first_seen="2026-04-27T10:00:00Z"; last_seen="2026-04-28T09:00:00Z"; protocols=`$null },
            [PSCustomObject]@{ ipaddr4="192.168.1.20"; ipaddr6=""; dns_name="peer-db-01.local"; display_name="peer-db-01"; device_class="node"; role="client"; bytes_in=524288; bytes_out=131072; pkts_in=512; pkts_out=128; first_seen="2026-04-27T12:00:00Z"; last_seen="2026-04-28T08:30:00Z"; protocols=`$null },
            [PSCustomObject]@{ ipaddr4="10.0.0.1"; ipaddr6=""; dns_name="gateway.local"; display_name="gateway"; device_class="gateway"; role="other"; bytes_in=8388608; bytes_out=4194304; pkts_in=8192; pkts_out=4096; first_seen="2026-04-26T00:00:00Z"; last_seen="2026-04-28T09:30:00Z"; protocols=`$null }
        )
    }

    # Mock protocols
    if (`$Uri -match "/api/v1/devices/\d+/protocols") {
        return @(
            [PSCustomObject]@{ proto="HTTPS"; port="443" },
            [PSCustomObject]@{ proto="HTTP"; port="80" },
            [PSCustomObject]@{ proto="SSH"; port="22" },
            [PSCustomObject]@{ proto="DNS"; port="53" }
        )
    }

    # Mock metrics
    if (`$Uri -match "/api/v1/metrics") {
        return [PSCustomObject]@{ stats = @([PSCustomObject]@{ values = @(5242880, 10485760, 5120, 10240) }) }
    }

    throw "Unexpected URI: `$Uri"
}

# Now run the actual script
& (Join-Path `$scriptDir "Invoke-ExtraHopCommsMap.ps1") -InputCsv (Join-Path `$scriptDir "input/servers.csv")
"@

Set-Content -Path $runnerPath -Value $testContent -Encoding UTF8

Write-Host "  Running dry-run with mocked API..." -ForegroundColor Yellow
try {
    & pwsh -NoProfile -File $runnerPath 2>&1 | ForEach-Object { Write-Host "  $_" }
    $dryRunSuccess = $true
}
catch {
    Write-Host "  Dry-run error: $_" -ForegroundColor Red
    $dryRunSuccess = $false
}

# Clean up runner
Remove-Item $runnerPath -Force -ErrorAction SilentlyContinue

Write-Host "`n=== VALIDATION STEP 3: Verify Outputs ===" -ForegroundColor Cyan

$csvPath = Join-Path $scriptDir "output/extrahop_comms_map.csv"
$htmlPath = Join-Path $scriptDir "output/extrahop_comms_map.html"

$csvExists = Test-Path $csvPath
$htmlExists = Test-Path $htmlPath

Write-Host "  CSV exists: $csvExists" -ForegroundColor $(if ($csvExists) { "Green" } else { "Red" })
Write-Host "  HTML exists: $htmlExists" -ForegroundColor $(if ($htmlExists) { "Green" } else { "Red" })

if ($csvExists) {
    $csvContent = Import-Csv $csvPath
    Write-Host "  CSV rows: $($csvContent.Count)" -ForegroundColor Green
    Write-Host "  CSV columns: $(($csvContent[0].PSObject.Properties | Measure-Object).Count)" -ForegroundColor Green
}

if ($htmlExists) {
    $htmlContent = Get-Content $htmlPath -Raw
    $hasTitle = $htmlContent -match "ExtraHop Communication Map"
    $hasFilterBar = $htmlContent -match "filter-bar"
    $hasCards = $htmlContent -match "device-card"
    $hasThemeToggle = $htmlContent -match "toggleTheme"
    $hasSortable = $htmlContent -match "data-sort"
    Write-Host "  HTML has title: $hasTitle" -ForegroundColor $(if ($hasTitle) { "Green" } else { "Red" })
    Write-Host "  HTML has filter bar: $hasFilterBar" -ForegroundColor $(if ($hasFilterBar) { "Green" } else { "Red" })
    Write-Host "  HTML has device cards: $hasCards" -ForegroundColor $(if ($hasCards) { "Green" } else { "Red" })
    Write-Host "  HTML has theme toggle: $hasThemeToggle" -ForegroundColor $(if ($hasThemeToggle) { "Green" } else { "Red" })
    Write-Host "  HTML has sortable cols: $hasSortable" -ForegroundColor $(if ($hasSortable) { "Green" } else { "Red" })
}

Write-Host "`n=== VALIDATION STEP 4: File Tree ===" -ForegroundColor Cyan
Get-ChildItem -Path $scriptDir -Recurse | Where-Object { $_.Name -ne "_test_runner.ps1" } | ForEach-Object {
    $indent = "  " * ($_.FullName.Replace($scriptDir, "").Split([IO.Path]::DirectorySeparatorChar).Count - 1)
    $icon = if ($_.PSIsContainer) { "[DIR]" } else { "[FILE] $("{0:N1} KB" -f ($_.Length / 1KB))" }
    Write-Host "  $indent$($_.Name) $icon"
}

Write-Host "`n=== VALIDATION COMPLETE ===" -ForegroundColor Cyan

# Clean env vars
Remove-Item Env:\EXTRAHOP_HOST -ErrorAction SilentlyContinue
Remove-Item Env:\EXTRAHOP_API_KEY -ErrorAction SilentlyContinue
Remove-Item Env:\EXTRAHOP_VERIFY_SSL -ErrorAction SilentlyContinue
Remove-Item Env:\EXTRAHOP_LOOKBACK_MINUTES -ErrorAction SilentlyContinue
Remove-Item Env:\EXTRAHOP_OUTPUT_DIR -ErrorAction SilentlyContinue
