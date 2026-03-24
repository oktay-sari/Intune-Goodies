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