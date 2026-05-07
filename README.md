# ExtraHop Communication Map Generator

Queries ExtraHop's REST API to build a comprehensive communication map for a list of servers, showing every peer IP, service (port/protocol), traffic direction, and byte counts. Outputs an interactive HTML report and a flat CSV.

## Requirements

- PowerShell 5.1+ (Windows) or PowerShell 7+ (cross-platform)
- No external modules required
- Network access to your ExtraHop appliance REST API
- ExtraHop recordstore (EXA 5300 or CrowdStrike LogScale) for peer/port discovery via Records API

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

Create `.\input\servers.csv` with at minimum an `ip` or `hostname` column (or both):

```csv
ip,hostname,description
10.1.1.50,server-prod-01,Production web server
10.1.1.51,server-prod-02,Production app server
10.1.1.52,db-primary-01,Primary database
192.168.1.100,workstation-01,Developer machine
,sccm-primary,SCCM server (hostname-only lookup)
```

- `ip` — IPv4 or IPv6 address. If provided, used as primary lookup.
- `hostname` — Device hostname/DNS name. Used as fallback if IP lookup fails, or as primary lookup if no IP is provided.
- `description` — Optional. Friendly description for the report.

**Lookup logic**: The script tries IP-based resolution first. If that fails (or no IP is provided), it falls back to hostname-based resolution using ExtraHop's name search. This means you can query devices even when you only know the hostname.

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

Output files are timestamped to preserve history across runs:

| File | Description |
|------|-------------|
| `.\output\extrahop_comms_map_2026-05-07_143022.csv` | Flat CSV with all peer relationships |
| `.\output\extrahop_comms_map_2026-05-07_143022.html` | Self-contained interactive HTML report |

### CSV Columns

| Column | Description |
|--------|-------------|
| `source_ip` | IP of the queried device |
| `source_hostname` | Hostname from input CSV |
| `source_description` | Description from input CSV |
| `source_extrahop_display_name` | Display name from ExtraHop |
| `source_extrahop_device_type` | Device class from ExtraHop |
| `peer_ip` | Discovered peer IP address |
| `peer_hostname` | Peer DNS name from ExtraHop |
| `peer_extrahop_display_name` | Peer display name from ExtraHop |
| `peer_extrahop_device_type` | Peer device class from ExtraHop |
| `peer_role` | Peer's role: `client`, `server`, or `any` |
| `traffic_direction` | `inbound`, `outbound`, or `bidirectional` |
| `services` | Port/protocol pairs: `443/HTTPS, 22/SSH, 445/SMB` |
| `protocols` | Detected protocols: `HTTPS, SSH, SMB` |
| `ports` | Raw port numbers: `443, 22, 445` |
| `bytes_in` | Bytes received from peer |
| `bytes_out` | Bytes sent to peer |

### Services Column

Each peer connection shows services as port/protocol pairs. Protocol resolution uses three sources in priority order:

1. **ExtraHop L7 detection** — Record type (`~ssl` -> SSL, `~http` -> HTTP, `~dns` -> DNS) and `l7proto` field
2. **Well-known port mapping** — 50+ ports mapped including SSH (22), HTTPS (443), SMB (445), RDP (3389), LDAP (389), MSSQL (1433), Kerberos (88), WinRM (5985/5986), NFS (2049), and more
3. **TCP/UDP fallback** — Used only when neither ExtraHop nor the port map can identify the service

Examples:
```
22/SSH, 443/HTTPS, 445/SMB
80/HTTP, 8080/HTTP-PROXY
389/LDAP, 636/LDAPS, 3268/LDAP-GC
1433/MSSQL, 5432/POSTGRESQL
3389/RDP, 5985/WINRM-HTTP
```

### HTML Report Features

- Dark mode default with light mode toggle
- KPI summary cards (devices, peers, services, traffic, warnings)
- Collapsible per-device cards with peer tables
- Combined "Services (Port/Protocol)" column showing port/protocol pairs
- Global filter bar: search, device type, protocol, direction, port
- Color-coded row borders (green=outbound, blue=inbound, yellow=bidirectional, red=high traffic)
- Sortable columns (click header)
- Warnings section for unresolved devices

## Data Collection Pipeline

```
For each device in CSV:
  1. Resolve device in ExtraHop (by IP, fallback to hostname)
  2. Query POST /records/search for flow records involving the device IP
  3. Parse records → extract peer IP, port, protocol, bytes, direction
  4. Resolve port/protocol pairs (L7 detection → well-known port map → TCP/UDP)
  5. Query GET /devices/{id}/activity for device-level protocol list (fallback)
  6. Resolve peer hostnames via GET /devices (cached to avoid duplicate lookups)
  7. Emit results per peer with services, bytes, direction
```

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

- Requires an ExtraHop recordstore (EXA 5300 or CrowdStrike LogScale) for the Records API. Systems without a recordstore cannot discover per-peer port data.
- ExtraHop returns peers seen within the lookback window only; historical connections outside the window are not captured.
- CIDR notation in the input CSV is not supported — provide individual IPs.
- The script queries sequentially (one device at a time) to avoid rate limiting. For large input lists (100+), consider increasing the lookback window rather than querying frequently.
- IPv6 addresses are supported but may have limited device resolution depending on ExtraHop configuration.
- Protocol detection depends on ExtraHop creating typed records (SSL, HTTP, DNS). Generic flow records (`~flow`) rely on the well-known port mapping for protocol identification.

## File Structure

```
extrahop-comms-map/
├── Invoke-ExtraHopCommsMap.ps1   # Main script (~1600 lines)
├── README.md                      # This file
├── input/
│   └── servers.csv               # Your input device list
└── output/
    ├── extrahop_comms_map_2026-05-07_143022.csv    # Timestamped CSV
    └── extrahop_comms_map_2026-05-07_143022.html   # Timestamped HTML report
```
