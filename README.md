# ExtraHop Communication Map Generator

Queries ExtraHop's REST API to build a comprehensive communication map for a list of servers, showing every peer IP, port, protocol, and traffic direction. Outputs an interactive HTML report and a flat CSV.

## Requirements

- PowerShell 5.1+ (Windows) or PowerShell 7+ (cross-platform)
- No external modules required
- Network access to your ExtraHop appliance REST API

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `EXTRAHOP_HOST` | `https://extrahop.company.local` | ExtraHop appliance URL |
| `EXTRAHOP_API_KEY` | *(required)* | API key for authentication |
| `EXTRAHOP_VERIFY_SSL` | `true` | Set to `false` for self-signed certs |
| `EXTRAHOP_LOOKBACK_MINUTES` | `1440` | Query window (default: 24 hours) |
| `EXTRAHOP_OUTPUT_DIR` | `.\output` | Output directory |

### Direct Parameters

All config can also be passed as script parameters (overrides env vars):

```powershell
.\Invoke-ExtraHopCommsMap.ps1 `
    -InputCsv ".\input\servers.csv" `
    -ExtraHopHost "https://extrahop.company.local" `
    -ApiKey "your-api-key" `
    -LookbackMinutes 1440 `
    -OutputDir ".\output" `
    -SkipSslVerify
```

## Input CSV

Create `.\input\servers.csv` with at minimum an `ip` column:

```csv
ip,hostname,description
10.1.1.50,server-prod-01,Production web server
10.1.1.51,server-prod-02,Production app server
10.1.1.52,db-primary-01,Primary database
192.168.1.100,workstation-01,Developer machine
```

- `ip` — Required. IPv4 or IPv6 address.
- `hostname` — Optional. Display label.
- `description` — Optional. Friendly description for the report.

Column names are case-insensitive and trimmed of whitespace.

## How to Run

### Using environment variables:

```powershell
$env:EXTRAHOP_HOST = "https://extrahop.company.local"
$env:EXTRAHOP_API_KEY = "your-api-key-here"
$env:EXTRAHOP_VERIFY_SSL = "false"

.\Invoke-ExtraHopCommsMap.ps1
```

### Using parameters:

```powershell
.\Invoke-ExtraHopCommsMap.ps1 -ExtraHopHost "https://extrahop.myorg.com" -ApiKey "abc123" -SkipSslVerify
```

### Custom lookback window (7 days):

```powershell
.\Invoke-ExtraHopCommsMap.ps1 -LookbackMinutes 10080
```

## Output

| File | Description |
|------|-------------|
| `.\output\extrahop_comms_map.csv` | Flat CSV with all peer relationships, sorted by source IP then bytes out |
| `.\output\extrahop_comms_map.html` | Self-contained interactive HTML report with dark/light mode, filtering, sorting |

### HTML Report Features

- Dark mode default with light mode toggle
- KPI summary cards (devices, peers, ports, traffic, warnings)
- Collapsible per-device cards with peer tables
- Global filter bar: search, device type, protocol, direction, port
- Color-coded row borders (green=outbound, blue=inbound, yellow=bidirectional, red=high traffic)
- Sortable columns (click header)
- Warnings section for unresolved devices

## SSL Note

For ExtraHop appliances with self-signed certificates:

```powershell
# Via environment variable:
$env:EXTRAHOP_VERIFY_SSL = "false"

# Via parameter:
.\Invoke-ExtraHopCommsMap.ps1 -SkipSslVerify
```

The script auto-detects PowerShell version and applies the correct SSL bypass method:
- PowerShell 5.1: Sets `ServerCertificateValidationCallback`
- PowerShell 7+: Uses `-SkipCertificateCheck` on each request

## Known Limitations

- ExtraHop peer API returns peers seen within the lookback window only; historical connections outside the window are not captured.
- Per-peer byte counts may be estimated (divided evenly) when the ExtraHop API doesn't provide per-peer granularity in the metrics endpoint.
- CIDR notation in the input CSV is not supported — provide individual IPs.
- The script queries sequentially (one device at a time) to avoid rate limiting. For large input lists (100+), consider increasing the lookback window rather than querying frequently.
- IPv6 addresses are supported but may have limited device resolution depending on ExtraHop configuration.

## File Structure

```
extrahop-comms-map/
├── Invoke-ExtraHopCommsMap.ps1   # Main script
├── README.md                      # This file
├── input/
│   └── servers.csv               # Your input device list
└── output/
    ├── extrahop_comms_map.csv    # Generated CSV output
    └── extrahop_comms_map.html   # Generated HTML report
```
