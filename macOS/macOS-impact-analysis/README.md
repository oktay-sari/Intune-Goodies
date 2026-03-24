# macOS Service Impact Analysis

Intune custom attribute scripts for assessing macOS service usage on managed devices. Deploy these **before** enforcing restriction policies to understand the real-world impact on your fleet.

## Blog

For the full story behind this script and more macOS security content for Intune, check out [allthingscloud.blog](https://allthingscloud.blog/macos-impact-analysis-intune/).


## Purpose

When implementing security baselines like mSCP, BIO, or CIS that restrict macOS services, blindly enforcing the policies can disrupt users who rely on them. These scripts collect anonymized, device-level usage data so you can:

- Identify which devices actively use each service
- Quantify data at risk (folder sizes, evicted file counts)
- See which devices already have managed profiles blocking the feature
- Make informed rollout decisions based on actual impact data

The toolkit covers 7 services across 3 categories:

| Category | Scripts | Compliance Refs |
|----------|---------|-----------------|
| iCloud Services | Desktop & Documents Sync, Document Sync, Keychain Sync | BIO 7.1/7.2/7.3, CIS 2.1.1.1/2.1.1.3 |
| Sharing Services | AirDrop, AirPlay Receiver | CIS 2.3.1.1/2.3.1.2 |
| AI & Assistant | Apple Intelligence, Siri | CIS 2.5.1.x/2.5.2.x |

## Scripts

### icloud_desktop_documents_sync.sh

**Compliance mapping:** BIO 7.3 / CIS 2.1.1.3
**Managed preference:** `com.apple.applicationaccess` -> `allowCloudDesktopAndDocuments`

Detects whether iCloud Desktop & Documents sync is enabled by checking for the sync folders under `~/Library/Mobile Documents/com~apple~CloudDocs/`. Uses `du -smL` (follow symlinks) because macOS creates symlinks rather than copies for Desktop & Documents sync.

**Output format:** `Status|Desktop:X.XXgb|Documents:X.XXgb|Optimize Storage:X|Setting Managed:X`

| Field | Description |
|-------|-------------|
| Status | `Enabled`, `Disabled`, `BlockedByProfile`, `Unknown` |
| Desktop | Desktop folder size (GB when >= 1024mb), `N/A` when blocked by profile, `Unknown` when home dir unavailable |
| Documents | Documents folder size (GB when >= 1024mb), `N/A` when blocked by profile, `Unknown` when home dir unavailable |
| Optimize Storage | Optimize Mac Storage (`Yes`/`No`/`Unknown`/`N/A`) |
| Setting Managed | MDM profile restricts feature (`Yes`/`No`) |

**Example outputs:**
```
Enabled|Desktop:44.16gb|Documents:15.19gb|Optimize Storage:Yes|Setting Managed:No
BlockedByProfile|Desktop:N/A|Documents:N/A|Optimize Storage:N/A|Setting Managed:Yes
Disabled|Desktop:0mb|Documents:0mb|Optimize Storage:Unknown|Setting Managed:No
Unknown|Desktop:Unknown|Documents:Unknown|Optimize Storage:Unknown|Setting Managed:No
```

---

### icloud_document_sync.sh

**Compliance mapping:** BIO 7.1
**Managed preference:** `com.apple.applicationaccess` -> `allowCloudDocumentSync`

Detects whether iCloud Drive is active by inspecting `~/Library/Mobile Documents/` for app-specific containers (Pages, Numbers, Keynote, third-party apps). Size excludes Desktop & Documents folders to avoid double-counting with the BIO 7.3 script.

**Output format:** `Status|Size:X.XXgb|Optimize Storage:X|Setting Managed:X`

| Field | Description |
|-------|-------------|
| Status | `Active`, `Configured`, `Inactive`, `BlockedByProfile`, `Unknown` |
| Size | iCloud Drive size excl. Desktop & Documents (GB when >= 1024mb), `N/A` when blocked by profile, `Unknown` when home dir unavailable |
| Optimize Storage | Optimize Mac Storage (`Yes`/`No`/`Unknown`/`N/A`) |
| Setting Managed | MDM profile restricts feature (`Yes`/`No`) |

**Example outputs:**
```
Active|Size:775mb|Optimize Storage:Yes|Setting Managed:No
Active|Size:2.50gb|Optimize Storage:No|Setting Managed:No
Configured|Size:0mb|Optimize Storage:Unknown|Setting Managed:No
BlockedByProfile|Size:N/A|Optimize Storage:N/A|Setting Managed:Yes
Unknown|Size:Unknown|Optimize Storage:Unknown|Setting Managed:No
```

---

### icloud_keychain_sync.sh

**Compliance mapping:** BIO 7.2 / CIS 2.1.1.1
**Managed preference:** `com.apple.applicationaccess` -> `allowCloudKeychainSync`

Detects whether iCloud Keychain sync is likely active. iCloud Keychain is enabled by default when signing into iCloud (opt-out, not opt-in), so the script infers status from iCloud account presence rather than relying on file artifacts (`cloudkeychainproxy3.plist`, `keychain-2.db-wal`) that are unreliable on modern macOS (Sonoma/Sequoia).

**Detection logic:**
1. Managed preference blocks it -> `BlockedByProfile`
2. `~/Library/Mobile Documents` exists (iCloud signed in) -> `LikelyEnabled`
3. Fallback: `MobileMeAccounts.plist` shows account -> `LikelyEnabled`
4. Neither -> `NoiCloudAccount`

**Output format:** `Status|iCloud Account:X|Setting Managed:X`

| Field | Description |
|-------|-------------|
| Status | `LikelyEnabled`, `BlockedByProfile`, `NoiCloudAccount`, `Unknown` |
| iCloud Account | iCloud is signed in (`Yes`/`No`/`N/A`/`Unknown`) |
| Setting Managed | MDM profile restricts feature (`Yes`/`No`) |

**Example outputs:**
```
LikelyEnabled|iCloud Account:Yes|Setting Managed:No
BlockedByProfile|iCloud Account:N/A|Setting Managed:Yes
NoiCloudAccount|iCloud Account:No|Setting Managed:No
Unknown|iCloud Account:Unknown|Setting Managed:No
```

---

### airdrop_status.sh

**Compliance mapping:** CIS 2.3.1.1 (Level 1)
**Managed preference:** `com.apple.applicationaccess` -> `allowAirDrop`

Detects whether AirDrop is enabled and reports the discoverability setting. Reads the user-level `DiscoverableMode` key from `com.apple.sharingd` to determine if AirDrop is set to Off, Contacts Only, or Everyone. When no preference file exists or the key is missing, reports `Default` (Contacts Only on modern macOS).

**Detection logic:**
1. Managed preference blocks it -> `BlockedByProfile`
2. User set AirDrop discoverability to Off -> `Disabled`
3. Otherwise -> `Enabled` (with discovery mode)

**Output format:** `Status|Discovery:X|Setting Managed:X`

| Field | Description |
|-------|-------------|
| Status | `Enabled`, `Disabled`, `BlockedByProfile`, `Unknown` |
| Discovery | AirDrop discoverability (`Off`/`ContactsOnly`/`Everyone`/`Default`/`N/A`/`Unknown`) |
| Setting Managed | MDM profile restricts feature (`Yes`/`No`) |

**Example outputs:**
```
Enabled|Discovery:ContactsOnly|Setting Managed:No
Enabled|Discovery:Everyone|Setting Managed:No
BlockedByProfile|Discovery:N/A|Setting Managed:Yes
Disabled|Discovery:Off|Setting Managed:No
Unknown|Discovery:Unknown|Setting Managed:No
```

---

### airplay_receiver_status.sh

**Compliance mapping:** CIS 2.3.1.2 (Level 1)
**Managed preference:** `com.apple.applicationaccess` -> `allowAirPlayIncomingRequests`

Detects whether AirPlay Receiver is enabled. AirPlay Receiver was introduced in macOS Monterey (12.0) and allows other Apple devices to share content to the Mac's screen. It is enabled by default. The CIS benchmark recommends disabling it to reduce attack surface from frequent connection requests and information leakage.

Reads the `AirplayRecieverEnabled` key from `com.apple.controlcenter` (note: Apple's own typo in the key name). When the key is missing, the script assumes AirPlay Receiver is enabled (Apple's default behavior).

**Detection logic:**
1. Managed preference blocks it -> `BlockedByProfile`
2. User explicitly enabled -> `Enabled`
3. User explicitly disabled -> `DisabledByUser`
4. Key missing (default on) -> `Enabled`

**Output format:** `Status|Setting Managed:X`

| Field | Description |
|-------|-------------|
| Status | `Enabled`, `DisabledByUser`, `BlockedByProfile`, `Unknown` |
| Setting Managed | MDM profile restricts feature (`Yes`/`No`) |

**Example outputs:**
```
Enabled|Setting Managed:No
DisabledByUser|Setting Managed:No
BlockedByProfile|Setting Managed:Yes
Unknown|Setting Managed:No
```

---

### apple_intelligence_status.sh

**Compliance mapping:** CIS 2.5.1.1 / 2.5.1.2 / 2.5.1.3 / 2.5.1.4 (all Level 1)
**Managed preferences (all under `com.apple.applicationaccess`):**
- `allowWritingTools` -- Writing Tools (rewrite/proofread)
- `allowMailSummary` -- Mail Summarization
- `allowNotesTranscriptionSummary` -- Notes Summarization
- `allowExternalIntelligenceIntegrations` -- External AI (ChatGPT etc.)
- `allowExternalIntelligenceIntegrationsSignIn` -- Sign-in to external AI

Checks all five Apple Intelligence managed preference keys and reports a consolidated status. Each key returns `false` when a profile blocks it, or empty/undefined when no profile is deployed (feature available to user). External AI is considered blocked when either the integration key or the sign-in key is blocked.

**Detection logic:**
1. All five keys blocked -> `AllBlocked`
2. Some keys blocked -> `PartiallyManaged`
3. No keys blocked -> `Available`

**Output format:** `Status|WT:X|Mail:X|Notes:X|ExtAI:X|Setting Managed:X`

| Field | Description |
|-------|-------------|
| Status | `Available`, `PartiallyManaged`, `AllBlocked` |
| WT | Writing Tools available (`Yes`/`No`) |
| Mail | Mail Summary available (`Yes`/`No`) |
| Notes | Notes Summary available (`Yes`/`No`) |
| ExtAI | External AI available (`Yes`/`No`) |
| Setting Managed | MDM profile restricts features (`Yes`/`Partial`/`No`) |

**Example outputs:**
```
Available|WT:Yes|Mail:Yes|Notes:Yes|ExtAI:Yes|Setting Managed:No
PartiallyManaged|WT:Yes|Mail:Yes|Notes:No|ExtAI:No|Setting Managed:Partial
AllBlocked|WT:No|Mail:No|Notes:No|ExtAI:No|Setting Managed:Yes
```

---

### siri_status.sh

**Compliance mapping:** CIS 2.5.2.1 (Level 1) / CIS 2.5.2.2 (Level 1, manual)
**Managed preference:** `com.apple.applicationaccess` -> `allowAssistant`

Detects if Siri is enabled and whether "Listen for Siri" (always-on microphone) is active. The "Listen for Siri" setting (`VoiceTriggerUserEnabled` in `com.apple.Siri`) is a per-user preference that cannot currently be disabled via profile or plist -- CIS 2.5.2.2 is classified as Manual for this reason. The CIS benchmark recommends disabling Siri entirely because of this limitation.

**Detection logic:**
1. Managed preference blocks it -> `BlockedByProfile`
2. User-level Siri enabled -> `Enabled`
3. User explicitly disabled Siri -> `DisabledByUser`
4. Unable to determine -> `Unknown`

**Output format:** `Status|ListenFor:X|Setting Managed:X`

| Field | Description |
|-------|-------------|
| Status | `Enabled`, `DisabledByUser`, `BlockedByProfile`, `Unknown` |
| ListenFor | "Listen for Siri" / "Hey Siri" active (`Yes`/`No`/`Unknown`/`N/A`) |
| Setting Managed | MDM profile restricts feature (`Yes`/`No`) |

**Example outputs:**
```
Enabled|ListenFor:Yes|Setting Managed:No
DisabledByUser|ListenFor:No|Setting Managed:No
BlockedByProfile|ListenFor:N/A|Setting Managed:Yes
Unknown|ListenFor:Unknown|Setting Managed:No
```

## Deployment in Intune

1. Navigate to **Devices > macOS > Custom attributes**
2. Create a new custom attribute for each script
3. **Use the exact display names** listed below (the reporting scripts match on these):

   **iCloud Services:**
   - `macOS - iCloud Desktop Documents Sync`
   - `macOS - iCloud Document Sync`
   - `macOS - iCloud Keychain Sync`

   **Sharing Services:**
   - `macOS - AirDrop Status`
   - `macOS - AirPlay Receiver Status`

   **AI & Assistant:**
   - `macOS - Apple Intelligence Status`
   - `macOS - Siri Status`

4. Set **Data type** to **String**
5. Upload the script

> Custom attribute scripts always run as root. The scripts detect the logged-in console user automatically via `stat -f "%Su" /dev/console`.

> If you use different names, pass the custom names to the report script using the corresponding parameters (e.g., `-AirDropName "My Custom AirDrop Script"`). See the parameter reference in the reporting sections below.

> You do not need to deploy all 7 scripts. The report adapts to what is deployed -- it only shows categories that have at least one script found in the tenant. A single category found produces a clean single-category report with no dropdown.

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

## Design Decisions

### Output length
Intune custom attribute results have a **20 KB** size limit. The scripts intentionally keep output compact (under 200 characters in practice) using pipe-delimited key:value pairs for easy parsing and readability in the Intune portal.

### Human-readable sizes
Sizes are shown in **GB** (with two decimal places) when >= 1024 MB, otherwise in **mb**. For example, `45225mb` becomes `44.16gb`.

### Managed preference detection
All scripts use the same JXA `NSUserDefaults.initWithSuiteName` method to read managed preferences. This is the same approach used by mSCP and works regardless of execution context (root or user) because managed preferences from MDM profiles are system-wide.

### Error handling — managed pref before home dir
The managed preference check is system-wide and does not require the user's home directory. All scripts (except Apple Intelligence, which has no home dir dependency) check the managed preference **first**. If a profile blocks the feature, the script reports `BlockedByProfile` immediately and exits — no home dir needed. This ensures that devices with a missing or temporarily unavailable home directory still report the most important information: whether a profile is already managing the feature.

If the managed preference does not block the feature, the script attempts to resolve the home directory. On failure, it retries once after a 5-second sleep to handle login race conditions (e.g., home directory not yet mounted during login). If the home directory is still unavailable after the retry, the script outputs a degraded result with `Unknown` field values instead of the opaque `Error:NoHomeDir`. This preserves the pipe-delimited output format and renders as gray (no-impact) in the report rather than red (error).

### No user data collected
Scripts report device-level metrics only (folder sizes, file counts, boolean flags). No filenames, file contents, usernames, or email addresses are collected.

### Report architecture
The PowerShell reporter builds a JSON data blob containing the script registry (columns, summary cards, footnotes), category definitions, and all device results. This JSON is injected into a self-contained HTML file. JavaScript renders the active category's summary cards, table headers, and data from the JSON -- enabling category switching in the browser without page reloads or external dependencies. The single-file, zero-dependency philosophy is maintained.

### Adaptive report content
The report adapts to what is actually deployed in the tenant. Only categories with at least one script found are included. When a single category is found, the dropdown is hidden and a clean single-category report is produced. When multiple categories are found, the dropdown includes individual category options plus an "All Services" condensed view.

## Compliance Reference

| Script | BIO Control | CIS Benchmark | mSCP Rule |
|--------|-------------|---------------|-----------|
| Desktop & Documents | 7.3 | 2.1.1.3 (Level 2) | `icloud_sync_disable` |
| Document Sync | 7.1 | - | `icloud_drive_disable` |
| Keychain Sync | 7.2 | 2.1.1.1 (Level 2) | `icloud_keychain_disable` |
| AirDrop | - | 2.3.1.1 (Level 1) | `os_airdrop_disable` |
| AirPlay Receiver | - | 2.3.1.2 (Level 1) | `system_settings_airplay_receiver_disable` |
| Apple Intelligence | - | 2.5.1.1 / 2.5.1.2 / 2.5.1.3 / 2.5.1.4 (Level 1) | - |
| Siri | - | 2.5.2.1 (Level 1) / 2.5.2.2 (Manual) | `system_settings_siri_disable` |

## Code Quality

All scripts pass static analysis and are compatible with macOS BSD userland (no GNU coreutils dependencies).

```bash
# Bash scripts — iCloud Services
shellcheck icloud_desktop_documents_sync.sh
shellcheck icloud_document_sync.sh
shellcheck icloud_keychain_sync.sh

# Bash scripts — Sharing Services
shellcheck airdrop_status.sh
shellcheck airplay_receiver_status.sh

# Bash scripts — AI & Assistant
shellcheck apple_intelligence_status.sh
shellcheck siri_status.sh

# PowerShell report scripts
pwsh -Command "Invoke-ScriptAnalyzer -Path Get-macOSServiceReport.ps1"
pwsh -Command "Invoke-ScriptAnalyzer -Path Generate-ExampleReport.ps1"
```
