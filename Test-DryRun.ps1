<#
.SYNOPSIS
    Dry-run validation of Invoke-ExtraHopCommsMap.ps1 with mocked API functions.
    Mocks Invoke-RestMethod to simulate ExtraHop API responses using the correct
    API endpoints: POST /activitymaps/query, GET /devices/{id}/activity, POST /metrics.
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

# Write a temp runner script that overrides Invoke-RestMethod globally
$runnerPath = Join-Path $scriptDir "_test_runner.ps1"

$testContent = @'
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$scriptDir = $PSScriptRoot

# Override Invoke-RestMethod to return mock data matching actual ExtraHop API
function Global:Invoke-RestMethod {
    param(
        [string]$Uri,
        [string]$Method = "GET",
        [hashtable]$Headers,
        [string]$ContentType,
        [string]$Body,
        [switch]$SkipCertificateCheck,
        [string]$ErrorAction
    )

    # GET /api/v1/devices?search_type=ip%20address&value=<ip>
    if ($Uri -match "/api/v1/devices\?search_type=ip" -and $Method -eq "GET") {
        $ip = if ($Uri -match "value=([^&]+)") { [System.Uri]::UnescapeDataString($Matches[1]) } else { "" }
        # Simulate not-found for third device
        if ($ip -eq "10.1.1.52") {
            $ex = New-Object System.Net.WebException "The remote server returned an error: (404) Not Found."
            $resp = [PSCustomObject]@{ StatusCode = [System.Net.HttpStatusCode]::NotFound }
            $ex | Add-Member -NotePropertyName Response -NotePropertyValue $resp -Force
            throw $ex
        }
        $deviceId = if ($ip -eq "10.1.1.50") { 1001 } else { 1002 }
        return @([PSCustomObject]@{
            id            = $deviceId
            ipaddr4       = $ip
            ipaddr6       = ""
            display_name  = "mock-device-$deviceId"
            device_class  = "node"
            dns_name      = "mock-$deviceId.local"
            mod_time      = (Get-Date).Ticks
            extrahop_id   = "eh-$deviceId"
            last_seen_time = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
        })
    }

    # GET /api/v1/devices?search_type=name&value=<hostname>
    if ($Uri -match "/api/v1/devices\?search_type=name" -and $Method -eq "GET") {
        $hostname = if ($Uri -match "value=([^&]+)") { [System.Uri]::UnescapeDataString($Matches[1]) } else { "" }
        return @([PSCustomObject]@{
            id            = 1003
            ipaddr4       = "10.1.1.99"
            ipaddr6       = ""
            display_name  = $hostname
            device_class  = "node"
            dns_name      = "$hostname.local"
            mod_time      = (Get-Date).Ticks
            extrahop_id   = "eh-1003"
            last_seen_time = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
        })
    }

    # GET /api/v1/devices/{id} — individual device lookup
    if ($Uri -match "/api/v1/devices/(\d+)$" -and $Method -eq "GET") {
        $did = [int]$Matches[1]
        $peerIps = @{ 2001 = "192.168.1.10"; 2002 = "192.168.1.20"; 2003 = "10.0.0.1" }
        $peerNames = @{ 2001 = "peer-web-01"; 2002 = "peer-db-01"; 2003 = "gateway" }
        $peerTypes = @{ 2001 = "node"; 2002 = "node"; 2003 = "gateway" }
        return [PSCustomObject]@{
            id           = $did
            ipaddr4      = if ($peerIps.ContainsKey($did)) { $peerIps[$did] } else { "10.0.0.$did" }
            ipaddr6      = ""
            display_name = if ($peerNames.ContainsKey($did)) { $peerNames[$did] } else { "device-$did" }
            device_class = if ($peerTypes.ContainsKey($did)) { $peerTypes[$did] } else { "node" }
            dns_name     = if ($peerNames.ContainsKey($did)) { "$($peerNames[$did]).local" } else { "device-$did.local" }
            mod_time     = (Get-Date).Ticks
        }
    }

    # GET /api/v1/devices/{id}/activity
    if ($Uri -match "/api/v1/devices/\d+/activity" -and $Method -eq "GET") {
        return @(
            [PSCustomObject]@{ id = 1; device_id = 1001; stat_name = "extrahop.device.http_client"; from_time = 1700000000000; until_time = 1700100000000; mod_time = 1700100000000 },
            [PSCustomObject]@{ id = 2; device_id = 1001; stat_name = "extrahop.device.ssl_client"; from_time = 1700000000000; until_time = 1700100000000; mod_time = 1700100000000 },
            [PSCustomObject]@{ id = 3; device_id = 1001; stat_name = "extrahop.device.dns_client"; from_time = 1700000000000; until_time = 1700100000000; mod_time = 1700100000000 },
            [PSCustomObject]@{ id = 4; device_id = 1001; stat_name = "extrahop.device.tcp"; from_time = 1700000000000; until_time = 1700100000000; mod_time = 1700100000000 },
            [PSCustomObject]@{ id = 5; device_id = 1001; stat_name = "extrahop.device.ssh_client"; from_time = 1700000000000; until_time = 1700100000000; mod_time = 1700100000000 }
        )
    }

    # POST /api/v1/activitymaps/query — topology query
    if ($Uri -match "/api/v1/activitymaps/query" -and $Method -eq "POST") {
        # Return mock topology with nodes and edges
        return [PSCustomObject]@{
            nodes = @(
                [PSCustomObject]@{ id = 2001; ipaddr4 = "192.168.1.10"; ipaddr6 = ""; display_name = "peer-web-01"; device_class = "node"; dns_name = "peer-web-01.local" },
                [PSCustomObject]@{ id = 2002; ipaddr4 = "192.168.1.20"; ipaddr6 = ""; display_name = "peer-db-01"; device_class = "node"; dns_name = "peer-db-01.local" },
                [PSCustomObject]@{ id = 2003; ipaddr4 = "10.0.0.1"; ipaddr6 = ""; display_name = "gateway"; device_class = "gateway"; dns_name = "gateway.local" }
            )
            edges = @(
                [PSCustomObject]@{ from = 1001; to = 2001; weight = 3145728; protocols = @("HTTP", "HTTPS"); annotations = [PSCustomObject]@{ protocols = @("HTTP", "HTTPS"); appearances = [PSCustomObject]@{ from = "2026-04-27T10:00:00Z"; until = "2026-04-28T09:00:00Z" } } },
                [PSCustomObject]@{ from = 2002; to = 1001; weight = 655360; protocols = @("TCP"); annotations = [PSCustomObject]@{ protocols = @("TCP", "DNS"); appearances = [PSCustomObject]@{ from = "2026-04-27T12:00:00Z"; until = "2026-04-28T08:30:00Z" } } },
                [PSCustomObject]@{ from = 1001; to = 2003; weight = 12582912; protocols = @("TCP"); annotations = [PSCustomObject]@{ protocols = @("TCP"); appearances = [PSCustomObject]@{ from = "2026-04-26T00:00:00Z"; until = "2026-04-28T09:30:00Z" } } }
            )
        }
    }

    # POST /api/v1/metrics
    if ($Uri -match "/api/v1/metrics" -and $Method -eq "POST") {
        return [PSCustomObject]@{
            stats = @(
                [PSCustomObject]@{ oid = 1001; time = 1700000000000; duration = 30000; values = @(5242880, 10485760, 5120, 10240) },
                [PSCustomObject]@{ oid = 1001; time = 1700000030000; duration = 30000; values = @(2621440, 5242880, 2560, 5120) }
            )
        }
    }

    throw "Unexpected API call: $Method $Uri"
}

# Set environment and run
$env:EXTRAHOP_HOST = "https://extrahop-mock.local"
$env:EXTRAHOP_API_KEY = "mock-api-key-12345"
$env:EXTRAHOP_VERIFY_SSL = "true"
$env:EXTRAHOP_LOOKBACK_MINUTES = "1440"
$env:EXTRAHOP_OUTPUT_DIR = Join-Path $scriptDir "output"

& (Join-Path $scriptDir "Invoke-ExtraHopCommsMap.ps1") -InputCsv (Join-Path $scriptDir "input/servers.csv")
'@

Set-Content -Path $runnerPath -Value $testContent -Encoding UTF8

Write-Host "  Running dry-run with mocked API (activitymaps/query model)..." -ForegroundColor Yellow
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
    Write-Host "  Sample source IPs: $(($csvContent | Select-Object -ExpandProperty source_ip -Unique) -join ', ')" -ForegroundColor Green
}

if ($htmlExists) {
    $htmlContent = Get-Content $htmlPath -Raw
    $checks = @{
        "Title"        = $htmlContent -match "ExtraHop Communication Map"
        "Filter bar"   = $htmlContent -match "filter-bar"
        "Device cards" = $htmlContent -match "device-card"
        "Theme toggle" = $htmlContent -match "toggleTheme"
        "Sortable cols" = $htmlContent -match "data-sort"
        "KPI cards"    = $htmlContent -match "kpi-card"
        "Warnings"     = $htmlContent -match "warnings"
    }
    foreach ($check in $checks.GetEnumerator()) {
        Write-Host "  HTML has $($check.Key): $($check.Value)" -ForegroundColor $(if ($check.Value) { "Green" } else { "Red" })
    }
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
