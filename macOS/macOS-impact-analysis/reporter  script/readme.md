## Consolidated Reporting

### Get-macOSServiceReport.ps1

The main reporting script. Connects to Microsoft Graph API, retrieves device run states for all deployed custom attribute scripts, and generates a consolidated **CSV** and **HTML** report with category-based navigation.

**Prerequisites:**
```powershell
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
```

**Usage:**
```powershell
# Default — all categories, saves to ./service_reports/
.\Get-macOSServiceReport.ps1

# iCloud services only
.\Get-macOSServiceReport.ps1 -Categories icloud

# Multiple categories
.\Get-macOSServiceReport.ps1 -Categories icloud,sharing

# AI & Assistant only, custom output path
.\Get-macOSServiceReport.ps1 -Categories ai -OutputPath "C:\Reports"

# Non-interactive (for automation), no banner
.\Get-macOSServiceReport.ps1 -Force -NoBanner

# Custom Intune script names
.\Get-macOSServiceReport.ps1 -AirDropName "Custom AirDrop Check" -SiriName "Custom Siri Check"
```

**Parameters:**

| Parameter | Default | Description |
|-----------|---------|-------------|
| `-OutputPath` | `service_reports` | Directory for CSV and HTML output |
| `-Categories` | `all` | Which categories to query: `all`, `icloud`, `sharing`, `ai` (accepts multiple) |
| `-DesktopDocsSyncName` | `macOS - iCloud Desktop Documents Sync` | Intune display name |
| `-DocumentSyncName` | `macOS - iCloud Document Sync` | Intune display name |
| `-KeychainSyncName` | `macOS - iCloud Keychain Sync` | Intune display name |
| `-AirDropName` | `macOS - AirDrop Status` | Intune display name |
| `-AirPlayReceiverName` | `macOS - AirPlay Receiver Status` | Intune display name |
| `-AppleIntelligenceName` | `macOS - Apple Intelligence Status` | Intune display name |
| `-SiriName` | `macOS - Siri Status` | Intune display name |
| `-ThrottleDelayMs` | `100` | Delay between Graph API page requests (0-5000 ms) |
| `-NoBanner` | off | Omit the #DutchCowboy animated GIF banner |
| `-Force` | off | Non-interactive: skip confirmation prompts and console banner |

The script confirms the expected Intune script names before querying the Graph API. Press Enter to continue or `n` to exit and re-run with the correct names.

**Required Graph API permissions:**
- `DeviceManagementConfiguration.Read.All`
- `DeviceManagementManagedDevices.Read.All`

**Output:**
- `service_reports/macOS_Service_Report_YYYY-MM-dd_HHmm.csv` -- flat CSV with one row per device, all script results for the queried categories
- `service_reports/macOS_Service_Report_YYYY-MM-dd_HHmm.html` -- interactive dashboard with category navigation, summary cards, color-coded device table, and compliance reference

Each run creates a new timestamped file (no overwrites). The HTML report opens automatically after generation. Summary statistics are also printed to the console.

**HTML report features:**
- **Category dropdown** -- switches between iCloud Services, Sharing Services, AI & Assistant, and an All Services condensed view (one status column per script). Hidden when only one category has data.
- **Summary cards** -- per-script impact counts with color-coded dots (amber = will be impacted, green = already managed by profile, gray = no impact). Clickable to filter the table — select multiple cards to stack filters (OR within the same script, AND across different scripts). Click an active card again to remove that filter.
- **Search** -- filters across device name and all field values.
- **Sortable columns** -- click any column header to sort ascending/descending.
- **Pagination** -- configurable rows per page (50/100/250/500).
- **Export Current View** -- downloads the currently visible (filtered, sorted) rows as a CSV file directly from the browser. The filename includes the active category and any card filters (e.g., `macOS_Service_Report_iCloud_Services_AD_Enabled.csv`).
- **Footnotes** -- contextual notes displayed below the table (e.g., Keychain detection limitation).
- **Print-friendly** -- toolbar, pagination, and export button hidden in print view.
- **#DutchCowboy animated banner** -- disable with `-NoBanner`.

### Banner GIF

The HTML report embeds `dutchcowboy_matrix_450w_oncerun.gif` as an inline base64 image. The GIF must be in the same directory as the `.ps1` script. If the file is missing, the report is generated without it (with a console warning).
