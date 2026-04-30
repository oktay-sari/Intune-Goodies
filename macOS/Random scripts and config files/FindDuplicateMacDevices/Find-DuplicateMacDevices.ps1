###############################################################################
# Find-DuplicateMacDevices.ps1
#
# Scan Entra ID and Intune for macOS devices with duplicate registrations.
# Identifies orphaned device records and provides cleanup recommendations.
#
# APPROACH:
#   Uses Intune managed devices as the anchor (serial number is the only
#   stable physical device identifier). Fans out to Entra via azureADDeviceId
#   to find all related device records per physical Mac. Also scans Entra
#   directly for orphaned "macOS" records with no Intune backing.
#
# Author:  Oktay Sari (allthingscloud.blog)
# Date:    2026-02-12
# Version: 1.13
#
# REQUIREMENTS:
#   - PowerShell 7+
#   - Microsoft.Graph module (Install-Module Microsoft.Graph)
#   - Permissions: Device.Read.All, DeviceManagementManagedDevices.Read.All
#                  Optional: User.Read.All (for user status checks, omit with -SkipUserLookup)
#
# USAGE:
#   .\Find-DuplicateMacDevices.ps1
#   .\Find-DuplicateMacDevices.ps1 -StaleThresholdDays 60
#   .\Find-DuplicateMacDevices.ps1 -OutputPath "C:\Temp\DuplicateReport"
#   .\Find-DuplicateMacDevices.ps1 -SkipConnect
#   .\Find-DuplicateMacDevices.ps1 -SkipUserLookup          # Skip user status checks
#   .\Find-DuplicateMacDevices.ps1 -ThrottleDelayMs 200  # For large tenants
#   .\Find-DuplicateMacDevices.ps1 -MaxDisplayItems 50  # Show more items per console section
#
# CODE QUALITY:
#   This script passes PSScriptAnalyzer static analysis.
#   Run: Invoke-ScriptAnalyzer -Path Find-DuplicateMacDevices.ps1
#
#   Intentional suppressions:
#   - PSAvoidUsingWriteHost: Interactive script requires colored console output
#   - PSReviewUnusedParameter: Script-level params accessed via implicit scoping
#
# DISCLAIMER:
#   This script is provided "AS IS", without warranty of any kind, express or
#   implied. The author and contributors are not liable for any damage, data
#   loss, or unintended changes resulting from its use. Scanning is read-only;
#   only the generated cleanup_helper.ps1 can delete devices, and it requires
#   explicit opt-in per device. Deleted device records cannot be recovered.
#   Review every flagged record before enabling deletions.
#   ALWAYS TEST in a controlled environment before deploying to production.
#   You are solely responsible for any actions taken using this script.
#   USE AT YOUR OWN RISK.
#
###############################################################################

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false, HelpMessage = "Days since last sign-in to consider a record stale")]
    [int]$StaleThresholdDays = 30,

    [Parameter(Mandatory = $false, HelpMessage = "Output directory for CSV results (auto-detected if not specified)")]
    [string]$OutputPath,

    [Parameter(Mandatory = $false, HelpMessage = "Skip Graph connection (use existing session)")]
    [switch]$SkipConnect,

    [Parameter(Mandatory = $false, HelpMessage = "Delay in milliseconds between API requests (for large tenants)")]
    [ValidateRange(0, 5000)]
    [int]$ThrottleDelayMs = 100,

    [Parameter(Mandatory = $false, HelpMessage = "Skip user status lookups (removes User.Read.All requirement)")]
    [switch]$SkipUserLookup,

    [Parameter(Mandatory = $false, HelpMessage = "Maximum items shown per console section (full data always in CSV)")]
    [ValidateRange(1, 1000)]
    [int]$MaxDisplayItems = 25
)

#region --- Platform Detection & Output Path ---
function Get-PlatformInfo {
    if ($PSVersionTable.PSVersion.Major -ge 6) {
        if ($IsMacOS) {
            return @{ Platform = "macOS"; Desktop = "$HOME/Desktop" }
        }
        elseif ($IsLinux) {
            return @{ Platform = "Linux"; Desktop = "$HOME/Desktop" }
        }
    }
    # Windows (PowerShell 5.1 or 7+)
    return @{
        Platform = "Windows"
        Desktop  = [Environment]::GetFolderPath('Desktop')
    }
}

$platformInfo = Get-PlatformInfo
if ([string]::IsNullOrEmpty($OutputPath)) {
    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $OutputPath = Join-Path $platformInfo.Desktop "MacOS_DuplicateReport_$timestamp"
}
#endregion

#region --- Configuration ---
$ErrorActionPreference = "Continue"

# Counters for summary
$script:Stats = @{
    TotalIntuneMacs        = 0
    TotalEntraRecords      = 0
    UniqueSerialNumbers    = 0
    DevicesWithDuplicates  = 0
    OrphanRecords          = 0
    StaleRecords           = 0
    RecommendedForCleanup  = 0
    DetachedEntraRecords   = 0
    BYODDevices            = 0
    IntuneDuplicateSerials = 0
    IntuneOrphanRecords    = 0
    IntuneRecommendedCleanup = 0
}

# Track stale serials to avoid double-counting (HashSet for O(1) lookup)
$script:StaleSerials = [System.Collections.Generic.HashSet[string]]::new()

# Cache for user lookups (UPN -> user object) to avoid duplicate API calls
$script:UserCache = @{}

# Results for Intune-side duplicates (separate from Entra results — different fields)
$script:intuneDuplicateResults = @()

# Tenant compliance validity period (populated during scan)
$script:TenantCompliancePeriod = $null
#endregion

#region --- Helper Functions ---
function Write-Step {
    param([string]$Message)
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] " -ForegroundColor Blue -NoNewline
    Write-Host "[OK] " -ForegroundColor Green -NoNewline
    Write-Host $Message
}

function Write-Warn {
    param([string]$Message)
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] " -ForegroundColor Blue -NoNewline
    Write-Host "[!!] " -ForegroundColor Yellow -NoNewline
    Write-Host $Message -ForegroundColor Yellow
}

function Write-Info {
    param([string]$Message)
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] " -ForegroundColor Blue -NoNewline
    Write-Host ">> " -ForegroundColor Cyan -NoNewline
    Write-Host $Message
}

function Write-Header {
    param([string]$Title)
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  $Title" -ForegroundColor Green
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host ""
}

function Invoke-MgGraphPaginatedRequest {
    <#
    .SYNOPSIS
        Retrieve all pages of results from a Graph API endpoint with built-in
        rate limiting, throttle detection, and retry logic for large tenants.

    .PARAMETER Uri
        The Graph API endpoint URI to query.

    .PARAMETER DelayMs
        Milliseconds to wait between page requests (default: 100).
        Increase for large tenants to avoid throttling.

    .PARAMETER MaxRetries
        Maximum number of retries on throttle/transient errors (default: 3).
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uri,

        [Parameter(Mandatory = $false)]
        [int]$DelayMs = 100,

        [Parameter(Mandatory = $false)]
        [int]$MaxRetries = 3
    )

    $allResults = [System.Collections.ArrayList]::new()
    $nextLink = $Uri
    $pageCount = 0

    do {
        $retryCount = 0
        $success = $false

        while (-not $success -and $retryCount -le $MaxRetries) {
            try {
                # Add delay between requests to respect rate limits (skip on first request)
                if ($pageCount -gt 0 -and $DelayMs -gt 0) {
                    Start-Sleep -Milliseconds $DelayMs
                }

                $response = Invoke-MgGraphRequest -Uri $nextLink -Method GET -ErrorAction Stop
                $success = $true
                $pageCount++

                # Add results from this page
                # Note: Check for $null explicitly because empty arrays are falsy in PowerShell
                if ($null -ne $response.value) {
                    foreach ($item in $response.value) {
                        [void]$allResults.Add($item)
                    }
                }
                # Collection endpoints always return .value arrays, so no elseif needed

                # Get next page link
                $nextLink = $response.'@odata.nextLink'
            }
            catch {
                $errorMessage = $_.Exception.Message

                # Check for throttling (HTTP 429) or transient errors
                if ($errorMessage -match '429|throttl|Too Many Requests|Service Unavailable|503|504') {
                    $retryCount++

                    if ($retryCount -le $MaxRetries) {
                        # Extract Retry-After header if available, otherwise use exponential backoff
                        $waitSeconds = 60 * $retryCount  # 60s, 120s, 180s

                        Write-Warn "Rate limit hit (attempt $retryCount/$MaxRetries). Waiting $waitSeconds seconds..."
                        Start-Sleep -Seconds $waitSeconds
                    }
                    else {
                        Write-Error "Max retries exceeded after throttling. Last error: $errorMessage"
                        throw
                    }
                }
                else {
                    # Non-throttle error - don't retry
                    Write-Error "Graph API error: $errorMessage"
                    throw
                }
            }
        }
    } while ($nextLink)

    return $allResults
}

function Get-OwnershipClassification {
    <#
    .SYNOPSIS
        Determine whether a device is Corporate, BYOD, or Indeterminate using
        tiered ownership scoring based on Intune enrollment signals and Entra
        TrustType. Returns a classification object with score, label, and signals.

    .DESCRIPTION
        Ownership Score ranges from -10 (definitely corporate) to +10 (definitely BYOD).

        Tier 1 -- Definitive enrollment type (from Intune):
          deviceEnrollmentType = appleBulkWithUser/appleBulkWithoutUser = -10 (ADE = corporate)
          deviceEnrollmentType = userEnrollment                        = +10 (BYOD channel)

        Tier 2 -- Admin-set ownership and enrollment profile (from Intune):
          managedDeviceOwnerType = "company"  = -5
          managedDeviceOwnerType = "personal" = +5
          enrollmentProfileName is not empty  = -4 (only ADE devices have this)

        Tier 3 -- Supporting signals (from Intune + Entra):
          isSupervised = $true          = -3
          TrustType = "AzureAD" (Entra)  = -2 (PSSO-joined = corporate)
          TrustType = "Workplace" (Entra) = +2 (supporting signal only)

        Thresholds:
          Score <= -3 -> Corporate
          Score >= +3 -> BYOD
          Score -2 to +2 -> Indeterminate (treated as Corporate for safety)

        Admin Override:
          If managedDeviceOwnerType = "company" AND score > -3, force Corporate.
          Rationale: explicit admin decision should be respected.
    #>
    param(
        [Parameter(Mandatory = $false)]
        $IntuneRecord,

        [Parameter(Mandatory = $false)]
        [string]$EntraTrustType
    )

    $score = 0
    $signals = [System.Collections.ArrayList]::new()

    # --- Tier 1: Definitive enrollment type ---
    if ($null -ne $IntuneRecord) {
        $enrollmentType = $IntuneRecord.deviceEnrollmentType

        if ($enrollmentType -eq 'appleBulkWithUser' -or $enrollmentType -eq 'appleBulkWithoutUser') {
            $score += -10
            [void]$signals.Add("Tier1: ADE enrollment ($enrollmentType) = -10")
        }
        elseif ($enrollmentType -eq 'userEnrollment') {
            $score += 10
            [void]$signals.Add("Tier1: User enrollment ($enrollmentType) = +10")
        }

        # --- Tier 2: Admin-set ownership and enrollment profile ---
        $ownerType = $IntuneRecord.managedDeviceOwnerType

        if ($ownerType -eq 'company') {
            $score += -5
            [void]$signals.Add("Tier2: Owner=company = -5")
        }
        elseif ($ownerType -eq 'personal') {
            $score += 5
            [void]$signals.Add("Tier2: Owner=personal = +5")
        }

        if (-not [string]::IsNullOrEmpty($IntuneRecord.enrollmentProfileName)) {
            $score += -4
            [void]$signals.Add("Tier2: EnrollmentProfile present = -4")
        }

        # --- Tier 3: Supervised status ---
        if ($IntuneRecord.isSupervised -eq $true) {
            $score += -3
            [void]$signals.Add("Tier3: Supervised = -3")
        }
    }

    # --- Tier 3: Entra TrustType ---
    if ($EntraTrustType -eq 'AzureAD') {
        $score += -2
        [void]$signals.Add("Tier3: TrustType=AzureAD = -2")
    }
    elseif ($EntraTrustType -eq 'Workplace') {
        $score += 2
        [void]$signals.Add("Tier3: TrustType=Workplace = +2")
    }

    # --- Classification ---
    $rawScore = $score
    if ($score -le -3) {
        $classification = "Corporate"
    }
    elseif ($score -ge 3) {
        $classification = "BYOD"
    }
    else {
        $classification = "Indeterminate"
    }

    # --- Admin Override ---
    $adminOverride = $false
    if ($null -ne $IntuneRecord -and $IntuneRecord.managedDeviceOwnerType -eq 'company' -and $classification -ne 'Corporate') {
        $classification = "Corporate"
        $adminOverride = $true
        [void]$signals.Add("Admin override: ownership set to company")
    }

    # Indeterminate treated as Corporate for safety
    if ($classification -eq 'Indeterminate') {
        [void]$signals.Add("Indeterminate treated as Corporate (safety default)")
    }

    $isBYOD = $classification -eq 'BYOD'

    return [PSCustomObject]@{
        Score          = $rawScore
        Classification = $classification
        Signals        = ($signals -join "; ")
        IsBYOD         = $isBYOD
        AdminOverride  = $adminOverride
    }
}

function Get-TenantComplianceValidityPeriod {
    <#
    .SYNOPSIS
        Query the tenant's device compliance validity period from Intune settings.
        This is the number of days a device can go without check-in before being
        marked non-compliant. Default is 30 days.
    #>
    Write-Info "Querying tenant compliance validity period..."

    try {
        $uri = "https://graph.microsoft.com/beta/deviceManagement/settings"
        $response = Invoke-MgGraphRequest -Uri $uri -Method GET -ErrorAction Stop

        # The deviceComplianceCheckinThresholdDays setting controls this
        $period = $response.deviceComplianceCheckinThresholdDays
        if ($null -eq $period) {
            $period = 30  # Default if not set
        }

        Write-Step "Tenant compliance validity period: $period days"
        return $period
    }
    catch {
        Write-Warn "Could not query tenant compliance settings: $($_.Exception.Message)"
        Write-Info "  Using default assumption of 30 days"
        return 30
    }
}

function Invoke-UserStatusBatch {
    <#
    .SYNOPSIS
        Look up an array of UPNs in batches of 20 via the Graph $batch API,
        populating $script:UserCache for each. Reduces hundreds of sequential
        HTTP calls to a handful of batch requests.

    .DESCRIPTION
        Two-phase approach:
        Phase 1: Batch all UPNs against /users (active directory)
        Phase 2: Collect UPNs that returned 404/empty, batch against /directory/deletedItems

    .PARAMETER UserPrincipalNames
        Array of UPN strings to resolve.

    .PARAMETER MaxRetries
        Maximum retries on throttle/transient errors per batch call (default: 3).
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$UserPrincipalNames,

        [Parameter(Mandatory = $false)]
        [int]$MaxRetries = 3
    )

    if ($UserPrincipalNames.Count -eq 0) { return }

    $batchSize = 20
    $totalUsers = $UserPrincipalNames.Count
    $totalBatches = [math]::Ceiling($totalUsers / $batchSize)
    $resolvedCount = 0

    # Phase 1: Look up active users
    $notFoundUpns = [System.Collections.ArrayList]::new()

    for ($batchIndex = 0; $batchIndex -lt $totalBatches; $batchIndex++) {
        $start = $batchIndex * $batchSize
        $end = [math]::Min($start + $batchSize, $totalUsers) - 1
        $batchUpns = $UserPrincipalNames[$start..$end]

        # Build batch request body
        $requests = [System.Collections.ArrayList]::new()
        for ($i = 0; $i -lt $batchUpns.Count; $i++) {
            $escapedUpn = [Uri]::EscapeDataString($batchUpns[$i])
            [void]$requests.Add(@{
                id     = "$i"
                method = "GET"
                url    = "/users?`$filter=userPrincipalName eq '$escapedUpn'&`$select=id,userPrincipalName,accountEnabled,signInActivity"
            })
        }

        $batchBody = @{ requests = @($requests) } | ConvertTo-Json -Depth 4

        # Execute batch with retry logic
        $response = $null
        $retryCount = 0
        $success = $false

        while (-not $success -and $retryCount -le $MaxRetries) {
            try {
                $response = Invoke-MgGraphRequest -Method POST `
                    -Uri 'https://graph.microsoft.com/v1.0/$batch' `
                    -Body $batchBody -ContentType 'application/json' -ErrorAction Stop
                $success = $true
            }
            catch {
                $errorMessage = $_.Exception.Message
                if ($errorMessage -match '429|throttl|Too Many Requests|Service Unavailable|503|504') {
                    $retryCount++
                    if ($retryCount -le $MaxRetries) {
                        $waitSeconds = 60 * $retryCount
                        Write-Warn "Rate limit hit on batch (attempt $retryCount/$MaxRetries). Waiting $waitSeconds seconds..."
                        Start-Sleep -Seconds $waitSeconds
                    }
                    else {
                        Write-Error "Max retries exceeded on batch call. Last error: $errorMessage"
                        throw
                    }
                }
                else {
                    Write-Error "Graph batch API error: $errorMessage"
                    throw
                }
            }
        }

        # Process each sub-response
        foreach ($subResponse in $response.responses) {
            $idx = [int]$subResponse.id
            $upn = $batchUpns[$idx]

            if ($subResponse.status -eq 200 -and $null -ne $subResponse.body.value -and $subResponse.body.value.Count -gt 0) {
                # User found in active directory
                $user = $subResponse.body.value[0]
                $lastSignIn = $null
                $daysSinceSignIn = $null
                if ($null -ne $user.signInActivity -and $null -ne $user.signInActivity.lastSignInDateTime) {
                    $lastSignIn = $user.signInActivity.lastSignInDateTime
                    $daysSinceSignIn = [math]::Round(((Get-Date -AsUTC) - [DateTime]$lastSignIn).TotalDays, 0)
                }
                $script:UserCache[$upn] = @{
                    Status          = if ($user.accountEnabled) { "Enabled" } else { "Disabled" }
                    IsDeleted       = $false
                    IsDisabled      = -not $user.accountEnabled
                    LastSignIn      = $lastSignIn
                    DaysSinceSignIn = $daysSinceSignIn
                }
                $resolvedCount++
            }
            elseif ($subResponse.status -eq 200 -or $subResponse.status -eq 404) {
                # Empty result or not found — check deleted items in Phase 2
                [void]$notFoundUpns.Add($upn)
            }
            else {
                # Other error — cache as Unknown
                $script:UserCache[$upn] = @{
                    Status          = "Unknown"
                    IsDeleted       = $false
                    IsDisabled      = $false
                    LastSignIn      = $null
                    DaysSinceSignIn = $null
                    Error           = "Batch sub-request returned status $($subResponse.status)"
                }
                $resolvedCount++
            }
        }

        $processed = $end + 1
        Write-Host "    Batch $($batchIndex + 1)/${totalBatches}: $processed of $totalUsers users resolved..." -ForegroundColor DarkGray
    }

    # Phase 2: Check deleted items for UPNs not found in Phase 1
    if ($notFoundUpns.Count -gt 0) {
        Write-Host "    Checking $($notFoundUpns.Count) user(s) in deleted items..." -ForegroundColor DarkGray

        $deletedBatches = [math]::Ceiling($notFoundUpns.Count / $batchSize)

        for ($batchIndex = 0; $batchIndex -lt $deletedBatches; $batchIndex++) {
            $start = $batchIndex * $batchSize
            $end = [math]::Min($start + $batchSize, $notFoundUpns.Count) - 1
            $batchUpns = @($notFoundUpns)[$start..$end]

            $requests = [System.Collections.ArrayList]::new()
            for ($i = 0; $i -lt $batchUpns.Count; $i++) {
                $escapedUpn = [Uri]::EscapeDataString($batchUpns[$i])
                [void]$requests.Add(@{
                    id     = "$i"
                    method = "GET"
                    url    = "/directory/deletedItems/microsoft.graph.user?`$filter=userPrincipalName eq '$escapedUpn'&`$select=id,userPrincipalName,deletedDateTime"
                })
            }

            $batchBody = @{ requests = @($requests) } | ConvertTo-Json -Depth 4

            $response = $null
            $retryCount = 0
            $success = $false

            while (-not $success -and $retryCount -le $MaxRetries) {
                try {
                    $response = Invoke-MgGraphRequest -Method POST `
                        -Uri 'https://graph.microsoft.com/v1.0/$batch' `
                        -Body $batchBody -ContentType 'application/json' -ErrorAction Stop
                    $success = $true
                }
                catch {
                    $errorMessage = $_.Exception.Message
                    if ($errorMessage -match '429|throttl|Too Many Requests|Service Unavailable|503|504') {
                        $retryCount++
                        if ($retryCount -le $MaxRetries) {
                            $waitSeconds = 60 * $retryCount
                            Write-Warn "Rate limit hit on deleted-items batch (attempt $retryCount/$MaxRetries). Waiting $waitSeconds seconds..."
                            Start-Sleep -Seconds $waitSeconds
                        }
                        else {
                            Write-Error "Max retries exceeded on deleted-items batch. Last error: $errorMessage"
                            throw
                        }
                    }
                    else {
                        Write-Error "Graph batch API error (deleted items): $errorMessage"
                        throw
                    }
                }
            }

            foreach ($subResponse in $response.responses) {
                $idx = [int]$subResponse.id
                $upn = $batchUpns[$idx]

                if ($subResponse.status -eq 200 -and $null -ne $subResponse.body.value -and $subResponse.body.value.Count -gt 0) {
                    $script:UserCache[$upn] = @{
                        Status          = "Deleted"
                        IsDeleted       = $true
                        IsDisabled      = $false
                        LastSignIn      = $null
                        DaysSinceSignIn = $null
                        DeletedDateTime = $subResponse.body.value[0].deletedDateTime
                    }
                }
                else {
                    # User not found anywhere — permanently deleted or never existed
                    $script:UserCache[$upn] = @{
                        Status          = "Deleted"
                        IsDeleted       = $true
                        IsDisabled      = $false
                        LastSignIn      = $null
                        DaysSinceSignIn = $null
                    }
                }
                $resolvedCount++
            }
        }
    }

    Write-Step "Resolved $resolvedCount user(s) via batch API ($totalBatches batch call(s))"
}

function Get-UserStatus {
    <#
    .SYNOPSIS
        Get user account status by UPN from the pre-populated cache.
        Call Invoke-UserStatusBatch first to populate the cache in bulk.
        Falls back to returning $null if the UPN is not cached.
    #>
    param(
        [string]$UserPrincipalName
    )

    if ([string]::IsNullOrEmpty($UserPrincipalName)) {
        return $null
    }

    if ($script:UserCache.ContainsKey($UserPrincipalName)) {
        return $script:UserCache[$UserPrincipalName]
    }

    return $null
}
#endregion

#region --- Graph Connection ---
function Connect-ToGraph {
    Write-Header "Connecting to Microsoft Graph"

    if ($SkipConnect) {
        Write-Info "Skipping connection (using existing session)"
        return
    }

    $requiredScopes = @(
        "Device.Read.All",
        "DeviceManagementManagedDevices.Read.All"
    )
    if (-not $SkipUserLookup) {
        $requiredScopes += "User.Read.All"
    }

    try {
        $context = Get-MgContext -ErrorAction SilentlyContinue
        if ($null -ne $context) {
            Write-Info "Existing Graph session found for: $($context.Account)"
            $missingScopes = $requiredScopes | Where-Object { $_ -notin $context.Scopes }
            if ($missingScopes.Count -eq 0) {
                Write-Step "All required scopes present"
                return
            }
            Write-Warn "Missing scopes: $($missingScopes -join ', '). Reconnecting..."
        }

        Connect-MgGraph -Scopes $requiredScopes -NoWelcome
        Write-Step "Connected to Microsoft Graph"
    }
    catch {
        Write-Error "Failed to connect to Graph: $_"
        exit 1
    }
}
#endregion

#region --- Data Collection Functions ---
function Get-IntuneMacDevice {
    <#
    .SYNOPSIS
        Retrieve ALL macOS managed devices from Intune via beta API.
        Uses Invoke-MgGraphPaginatedRequest for automatic pagination, rate limiting,
        and throttle detection to handle large tenants reliably.
    #>
    Write-Header "Collecting Intune Managed Mac Devices"
    Write-Info "Querying Intune beta API for all macOS managed devices..."
    if ($ThrottleDelayMs -gt 0) {
        Write-Info "  Throttle delay: ${ThrottleDelayMs}ms between requests"
    }

    $uri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices?" +
           "`$filter=operatingSystem eq 'macOS'" +
           "&`$select=id,deviceName,deviceType,operatingSystem,osVersion," +
           "enrolledDateTime,lastSyncDateTime,complianceState," +
           "azureADDeviceId,serialNumber,managementAgent," +
           "deviceEnrollmentType,azureADRegistered,userPrincipalName," +
           "managedDeviceOwnerType,enrollmentProfileName,isSupervised"

    try {
        $allDevices = Invoke-MgGraphPaginatedRequest -Uri $uri -DelayMs $ThrottleDelayMs
        Write-Step "Total Intune Mac devices: $($allDevices.Count)"
        return $allDevices
    }
    catch {
        Write-Error "Failed to query Intune managed devices: $_"
        return @()
    }
}

function Get-EntraMacDevice {
    <#
    .SYNOPSIS
        Retrieve ALL Entra device records with operatingSystem containing "mac".
        Uses Invoke-MgGraphPaginatedRequest for automatic pagination, rate limiting,
        and throttle detection to handle large tenants reliably.
        This catches both "MacMDM" and "macOS" type records.
    #>
    Write-Header "Collecting Entra ID Mac Device Records"
    Write-Info "Querying Entra ID for all Mac-related device records..."
    if ($ThrottleDelayMs -gt 0) {
        Write-Info "  Throttle delay: ${ThrottleDelayMs}ms between requests"
    }

    $properties = "id,deviceId,displayName,operatingSystem," +
                  "operatingSystemVersion,trustType,mdmAppId," +
                  "isCompliant,registrationDateTime," +
                  "approximateLastSignInDateTime,accountEnabled," +
                  "enrollmentProfileName"

    try {
        # Get "MacMDM" records via raw API for consistent throttle handling
        Write-Info "  Fetching 'MacMDM' records..."
        $macMdmUri = "https://graph.microsoft.com/v1.0/devices?" +
                     "`$filter=operatingSystem eq 'MacMDM'" +
                     "&`$select=$properties"
        $macMdmDevices = Invoke-MgGraphPaginatedRequest -Uri $macMdmUri -DelayMs $ThrottleDelayMs
        Write-Info "    Found $($macMdmDevices.Count) MacMDM records"

        # Get "macOS" records (PSSO/Entra registered)
        Write-Info "  Fetching 'macOS' records..."
        $macOsUri = "https://graph.microsoft.com/v1.0/devices?" +
                    "`$filter=operatingSystem eq 'macOS'" +
                    "&`$select=$properties"
        $macOsDevices = Invoke-MgGraphPaginatedRequest -Uri $macOsUri -DelayMs $ThrottleDelayMs
        Write-Info "    Found $($macOsDevices.Count) macOS records"

        # Combine and deduplicate by object ID
        $allDevices = [System.Collections.ArrayList]::new()
        $seenIds = [System.Collections.Generic.HashSet[string]]::new()

        foreach ($device in @($macMdmDevices) + @($macOsDevices)) {
            if ($null -ne $device -and $seenIds.Add($device.id)) {
                [void]$allDevices.Add($device)
            }
        }

        Write-Step "Total Entra Mac device records: $($allDevices.Count)"
        return $allDevices
    }
    catch {
        Write-Error "Failed to query Entra devices: $_"
        return @()
    }
}
#endregion

#region --- Analysis Functions ---
function Build-DeviceCorrelationMap {
    <#
    .SYNOPSIS
        Build a correlation map linking physical devices (by serial number)
        to their Intune and Entra records.

        The key insight: serial number is the ONLY stable physical device
        identifier. displayName can change, deviceId is unique per registration.

        Strategy:
        1. Group Intune records by serial number (= physical devices)
        2. For each Intune record, resolve to Entra via azureADDeviceId
        3. Find Entra records NOT linked to any Intune record (detached orphans)
    #>
    param(
        [array]$IntuneDevices,
        [array]$EntraDevices
    )

    Write-Header "Building Device Correlation Map"

    # Index Entra devices by deviceId for O(1) lookup
    # Note: Raw API returns camelCase properties (deviceId, not DeviceId)
    $entraByDeviceId = @{}
    foreach ($entra in $EntraDevices) {
        if ($null -ne $entra.deviceId) {
            $entraByDeviceId[$entra.deviceId] = $entra
        }
    }

    # Index Entra devices by displayName for O(1) lookup (handles duplicates)
    $entraByDisplayName = @{}
    foreach ($entra in $EntraDevices) {
        if (-not [string]::IsNullOrEmpty($entra.displayName)) {
            if (-not $entraByDisplayName.ContainsKey($entra.displayName)) {
                $entraByDisplayName[$entra.displayName] = [System.Collections.ArrayList]::new()
            }
            [void]$entraByDisplayName[$entra.displayName].Add($entra)
        }
    }

    # Track which Entra records we've matched to an Intune record
    $matchedEntraObjectIds = [System.Collections.Generic.HashSet[string]]::new()

    # Group Intune devices by serial number
    $serialGroups = $IntuneDevices | Where-Object {
        -not [string]::IsNullOrEmpty($_.serialNumber)
    } | Group-Object -Property serialNumber

    Write-Info "Found $($serialGroups.Count) unique serial numbers"

    $correlationMap = [System.Collections.ArrayList]::new()

    foreach ($group in $serialGroups) {
        $serial = $group.Name
        $intuneRecords = $group.Group

        # Resolve each Intune record to its Entra counterpart
        $linkedEntraRecords = [System.Collections.ArrayList]::new()

        foreach ($intuneRec in $intuneRecords) {
            $aadDeviceId = $intuneRec.azureADDeviceId

            if (-not [string]::IsNullOrEmpty($aadDeviceId) -and $entraByDeviceId.ContainsKey($aadDeviceId)) {
                $entraRec = $entraByDeviceId[$aadDeviceId]
                [void]$linkedEntraRecords.Add($entraRec)
                [void]$matchedEntraObjectIds.Add($entraRec.id)
            }
        }

        # Also search Entra by display name for records not linked via azureADDeviceId.
        # This catches orphaned PSSO records that share the device name but have
        # no Intune backing. Uses O(1) hashtable lookup instead of nested loop.
        $deviceNames = $intuneRecords | Select-Object -ExpandProperty deviceName -Unique
        foreach ($name in $deviceNames) {
            # Skip null/empty device names to avoid false matches
            if ([string]::IsNullOrEmpty($name)) { continue }

            if ($entraByDisplayName.ContainsKey($name)) {
                foreach ($entra in $entraByDisplayName[$name]) {
                    if (-not $matchedEntraObjectIds.Contains($entra.id) -and
                        ($linkedEntraRecords | Where-Object { $_.id -eq $entra.id }).Count -eq 0) {
                        [void]$linkedEntraRecords.Add($entra)
                        [void]$matchedEntraObjectIds.Add($entra.id)
                    }
                }
            }
        }

        [void]$correlationMap.Add([PSCustomObject]@{
            SerialNumber      = $serial
            DeviceNames       = ($deviceNames -join "; ")
            IntuneRecords     = $intuneRecords
            EntraRecords      = $linkedEntraRecords
            IntuneCount       = $intuneRecords.Count
            EntraCount        = $linkedEntraRecords.Count
            HasDuplicates          = ($linkedEntraRecords.Count -gt 1)
            HasIntuneDuplicates    = ($intuneRecords.Count -gt 1)
        })
    }

    # Find detached Entra records (no Intune backing at all)
    $detachedEntra = $EntraDevices | Where-Object {
        -not $matchedEntraObjectIds.Contains($_.id)
    }

    Write-Step "Correlation complete: $($correlationMap.Count) physical devices mapped"
    if ($detachedEntra.Count -gt 0) {
        Write-Warn "Found $($detachedEntra.Count) Entra records with NO Intune backing (detached orphans)"
    }

    return @{
        CorrelationMap = $correlationMap
        DetachedEntra  = $detachedEntra
    }
}

function Get-DeviceRecordAnalysis {
    <#
    .SYNOPSIS
        Analyze a single Entra device record and determine its status
        relative to other records for the same physical device.
    #>
    param(
        $EntraDevice,
        $IntuneRecords,
        $AllEntraForDevice,
        [string]$SerialNumber
    )

    $now = Get-Date -AsUTC

    # MDM binding check
    # Note: Raw API returns camelCase properties (mdmAppId, not MdmAppId)
    $hasMdm = -not [string]::IsNullOrEmpty($EntraDevice.mdmAppId)
    $mdmLabel = if ($hasMdm) {
        switch ($EntraDevice.mdmAppId) {
            "0000000a-0000-0000-c000-000000000000" { "Microsoft Intune" }
            default { "Other MDM ($($EntraDevice.mdmAppId))" }
        }
    } else { "None" }

    # Stale check
    $lastSignIn = $EntraDevice.approximateLastSignInDateTime
    $isStale = $false
    $daysSinceSignIn = $null
    if ($null -ne $lastSignIn) {
        $daysSinceSignIn = [math]::Round(($now - [DateTime]$lastSignIn).TotalDays, 0)
        $isStale = $daysSinceSignIn -gt $StaleThresholdDays
    }
    else {
        # No sign-in ever recorded = definitely stale
        $isStale = $true
        $daysSinceSignIn = "Never"
    }

    # OS version format analysis
    # MacMDM records: "15.7 (24G222)" (full build string)
    # macOS records:  "15.7.0" (simplified semver)
    $osVersion = $EntraDevice.operatingSystemVersion
    $versionFormat = if ($osVersion -match '\(\w+\)') { "FullBuild" }
                     elseif ($osVersion -match '^\d+\.\d+\.\d+$') { "Simplified" }
                     else { "Unknown" }

    # Find matching Intune record
    $matchingIntune = $IntuneRecords | Where-Object {
        $_.azureADDeviceId -eq $EntraDevice.deviceId
    } | Select-Object -First 1

    $intuneDeviceType = if ($matchingIntune) { $matchingIntune.deviceType } else { "N/A" }

    # Ownership classification using tiered scoring
    $ownership = Get-OwnershipClassification -IntuneRecord $matchingIntune -EntraTrustType $EntraDevice.trustType
    $isBYOD = $ownership.IsBYOD

    # Get primary user from matching Intune record
    $primaryUserUPN = if ($matchingIntune) { $matchingIntune.userPrincipalName } else { $null }
    $userStatus = $null
    $userStatusLabel = "N/A"
    $userLastSignIn = $null
    $userDaysSinceSignIn = $null
    $userIsStale = $false

    if (-not $SkipUserLookup -and -not [string]::IsNullOrEmpty($primaryUserUPN)) {
        $userStatus = Get-UserStatus -UserPrincipalName $primaryUserUPN
        if ($null -ne $userStatus) {
            $userStatusLabel = $userStatus.Status
            $userLastSignIn = $userStatus.LastSignIn
            $userDaysSinceSignIn = $userStatus.DaysSinceSignIn
            # User is stale if they haven't signed in within the threshold
            if ($null -ne $userDaysSinceSignIn) {
                $userIsStale = $userDaysSinceSignIn -gt $StaleThresholdDays
            }
        }
    }

    # Build the analysis record
    [PSCustomObject]@{
        # Identification
        SerialNumber       = $SerialNumber
        DisplayName        = $EntraDevice.displayName
        EntraObjectId      = $EntraDevice.id
        EntraDeviceId      = $EntraDevice.deviceId

        # Classification
        OperatingSystem    = $EntraDevice.operatingSystem
        OSVersion          = $osVersion
        OSVersionFormat    = $versionFormat
        IntuneDeviceType   = $intuneDeviceType
        TrustType          = $EntraDevice.trustType

        # Status
        MDM                = $mdmLabel
        HasMDM             = $hasMdm
        IsCompliant        = $EntraDevice.isCompliant
        AccountEnabled     = $EntraDevice.accountEnabled
        RegisteredAt       = $EntraDevice.registrationDateTime
        LastSignIn         = $lastSignIn
        DaysSinceSignIn    = $daysSinceSignIn
        IsStale            = $isStale
        EnrollmentProfile  = $EntraDevice.enrollmentProfileName

        # Duplicate context
        TotalEntraRecords  = $AllEntraForDevice.Count
        IsDuplicate        = ($AllEntraForDevice.Count -gt 1)

        # Ownership classification (tiered scoring)
        IsBYOD                  = $isBYOD
        OwnershipScore          = $ownership.Score
        OwnershipClassification = $ownership.Classification
        OwnershipSignals        = $ownership.Signals

        # Intune enrollment details (for ownership context)
        DeviceEnrollmentType    = if ($matchingIntune) { $matchingIntune.deviceEnrollmentType } else { "N/A" }
        ManagedDeviceOwnerType  = if ($matchingIntune) { $matchingIntune.managedDeviceOwnerType } else { "N/A" }
        IntuneEnrollmentProfile = if ($matchingIntune) { $matchingIntune.enrollmentProfileName } else { "N/A" }
        IsSupervised            = if ($matchingIntune) { $matchingIntune.isSupervised } else { "N/A" }

        # Primary user info
        PrimaryUser             = $primaryUserUPN
        PrimaryUserStatus       = $userStatusLabel
        PrimaryUserLastSignIn   = $userLastSignIn
        PrimaryUserDaysSinceSignIn = $userDaysSinceSignIn
        PrimaryUserIsStale      = $userIsStale

        # Placeholder (filled in next step)
        IsOrphan           = $false
        Recommendation     = ""
        RecommendReason    = ""
    }
}

function Get-CleanupRecommendation {
    <#
    .SYNOPSIS
        For each physical device with duplicates, determine which record(s)
        are orphans and what action to take.

    .DESCRIPTION
        Orphan scoring heuristics (higher = more likely orphan):
          +3  No MDM binding (mdmAppId is null)
          +3  Primary user account deleted          (skipped with -SkipUserLookup)
          +2  Stale device (no sign-in within threshold)
          +2  Account disabled
          +2  Primary user account disabled          (skipped with -SkipUserLookup)
          +1  Both user AND device are stale         (skipped with -SkipUserLookup)
          +1  operatingSystem = "macOS" when a "MacMDM" record exists
          +1  Simplified OS version format ("15.7.0" vs "15.7 (24G222)")
          +1  Not compliant (when another record IS compliant)
          +1  No matching Intune managed device record

        The record with the LOWEST score per serial is considered "primary".
        All others get flagged with recommendations.
    #>
    param([array]$AnalysisRecords)

    Write-Header "Determining Cleanup Recommendations"

    # Group by serial number
    $groups = $AnalysisRecords | Group-Object -Property SerialNumber

    $results = [System.Collections.ArrayList]::new()

    foreach ($group in $groups) {
        $records = @($group.Group)

        if ($records.Count -eq 1) {
            # Single record = no duplicates, just pass through
            $record = $records[0]
            if ($record.IsBYOD) {
                $record.Recommendation = "OK (BYOD)"
                $record.RecommendReason = "BYOD device (Entra ID registered) - not flagged for deletion"
                $script:Stats.BYODDevices++
            }
            else {
                $record.Recommendation = "OK"
                $record.RecommendReason = "Single record for this device"
            }
            [void]$results.Add($record)
            continue
        }

        # Score each record (lower = healthier = more likely the primary)
        $scored = foreach ($record in $records) {
            $score = 0
            $reasons = [System.Collections.ArrayList]::new()

            if (-not $record.HasMDM) {
                $score += 3
                [void]$reasons.Add("No MDM binding")
            }
            # User deleted = strong orphan signal (only when user lookup enabled)
            if (-not $SkipUserLookup -and $record.PrimaryUserStatus -eq "Deleted") {
                $score += 3
                [void]$reasons.Add("Primary user deleted")
            }
            if ($record.IsStale) {
                $score += 2
                [void]$reasons.Add("Stale device (last sign-in: $($record.DaysSinceSignIn) days)")
            }
            if ($record.AccountEnabled -eq $false) {
                $score += 2
                [void]$reasons.Add("Device account disabled")
            }
            # User disabled = likely orphan (only when user lookup enabled)
            if (-not $SkipUserLookup -and $record.PrimaryUserStatus -eq "Disabled") {
                $score += 2
                [void]$reasons.Add("Primary user disabled")
            }
            # Both user and device stale = reinforced staleness (only when user lookup enabled)
            if (-not $SkipUserLookup -and $record.IsStale -and $record.PrimaryUserIsStale) {
                $score += 1
                [void]$reasons.Add("Both user and device are stale")
            }
            if ($record.OperatingSystem -eq "macOS" -and ($records | Where-Object { $_.OperatingSystem -eq "MacMDM" })) {
                $score += 1
                [void]$reasons.Add("PSSO 'macOS' record alongside 'MacMDM'")
            }
            if ($record.OSVersionFormat -eq "Simplified") {
                $score += 1
                [void]$reasons.Add("Simplified OS version format (PSSO origin)")
            }
            if ($record.IsCompliant -ne $true -and ($records | Where-Object { $_.IsCompliant -eq $true })) {
                $score += 1
                [void]$reasons.Add("Not compliant (other record is compliant)")
            }
            if ($record.IntuneDeviceType -eq "N/A") {
                $score += 1
                [void]$reasons.Add("No matching Intune managed device")
            }

            [PSCustomObject]@{
                Record  = $record
                Score   = $score
                Reasons = $reasons
            }
        }

        # Sort by score ascending. Lowest score = primary record.
        $sorted = $scored | Sort-Object -Property Score

        $primaryAssigned = $false
        foreach ($item in $sorted) {
            $record = $item.Record

            # BYOD devices are NEVER flagged for deletion, regardless of score
            if ($record.IsBYOD) {
                $record.IsOrphan = $false
                $record.Recommendation = "OK (BYOD)"
                $record.RecommendReason = "BYOD device (Entra ID registered) - not flagged for deletion"
                $script:Stats.BYODDevices++
                [void]$results.Add($record)
                continue
            }

            if (-not $primaryAssigned) {
                # This is the healthiest record
                $record.IsOrphan = $false
                $record.Recommendation = "KEEP (Primary)"
                $record.RecommendReason = "Healthiest record (score: $($item.Score))"
                $primaryAssigned = $true
            }
            else {
                $record.IsOrphan = $true
                $script:Stats.OrphanRecords++

                if ($item.Score -ge 5) {
                    $record.Recommendation = "REMOVE (High confidence)"
                    $script:Stats.RecommendedForCleanup++
                }
                elseif ($item.Score -ge 3) {
                    $record.Recommendation = "REVIEW (Likely orphan)"
                    $script:Stats.RecommendedForCleanup++
                }
                else {
                    $record.Recommendation = "REVIEW (Low confidence)"
                }

                $record.RecommendReason = ($item.Reasons -join "; ")
            }

            # Track stale records by serial to avoid double-counting duplicates
            if ($record.IsStale -and $script:StaleSerials.Add($record.SerialNumber)) {
                $script:Stats.StaleRecords++
            }
            [void]$results.Add($record)
        }
    }

    return $results
}

function Get-DetachedRecordAnalysis {
    <#
    .SYNOPSIS
        Analyze Entra device records that have no Intune backing at all.
        These are records that exist in Entra but cannot be linked to any
        Intune managed device via azureADDeviceId or displayName.
    #>
    param([array]$DetachedDevices)

    if ($DetachedDevices.Count -eq 0) { return @() }

    Write-Info "Analyzing $($DetachedDevices.Count) detached Entra records..."

    # Note: Raw API returns camelCase properties
    $results = foreach ($device in $DetachedDevices) {
        $now = Get-Date -AsUTC
        $lastSignIn = $device.approximateLastSignInDateTime
        $daysSinceSignIn = $null
        $isStale = $false

        if ($null -ne $lastSignIn) {
            $daysSinceSignIn = [math]::Round(($now - [DateTime]$lastSignIn).TotalDays, 0)
            $isStale = $daysSinceSignIn -gt $StaleThresholdDays
        }
        else {
            $isStale = $true
            $daysSinceSignIn = "Never"
        }

        $hasMdm = -not [string]::IsNullOrEmpty($device.mdmAppId)
        $mdmLabel = if ($hasMdm) {
            switch ($device.mdmAppId) {
                "0000000a-0000-0000-c000-000000000000" { "Microsoft Intune" }
                default { "Other MDM" }
            }
        } else { "None" }

        # Ownership classification using tiered scoring (no Intune record for detached)
        $ownership = Get-OwnershipClassification -EntraTrustType $device.trustType
        $isBYOD = $ownership.IsBYOD

        # Determine recommendation - BYOD devices are NEVER flagged for deletion
        $recommendation = ""
        $recommendReason = ""

        if ($isBYOD) {
            $recommendation = "OK (BYOD)"
            $recommendReason = "BYOD device (Entra ID registered) - not flagged for deletion"
            $script:Stats.BYODDevices++
        }
        elseif ($isStale -and -not $hasMdm) {
            $recommendation = "REMOVE (High confidence)"
            $recommendReason = "No Intune managed device backing this Entra record"
            $script:Stats.RecommendedForCleanup++
        }
        elseif ($isStale -or -not $hasMdm) {
            $recommendation = "REVIEW (Likely orphan)"
            $recommendReason = "No Intune managed device backing this Entra record"
            $script:Stats.RecommendedForCleanup++
        }
        else {
            $recommendation = "REVIEW (Has MDM but no Intune match)"
            $recommendReason = "No Intune managed device backing this Entra record"
        }

        # Track stale detached records by Object ID (they don't have real serials)
        if ($isStale -and $script:StaleSerials.Add("detached:$($device.id)")) {
            $script:Stats.StaleRecords++
        }
        $script:Stats.DetachedEntraRecords++

        [PSCustomObject]@{
            SerialNumber       = "UNKNOWN (Detached)"
            DisplayName        = $device.displayName
            EntraObjectId      = $device.id
            EntraDeviceId      = $device.deviceId
            OperatingSystem    = $device.operatingSystem
            OSVersion          = $device.operatingSystemVersion
            OSVersionFormat    = if ($device.operatingSystemVersion -match '\(\w+\)') { "FullBuild" }
                                 elseif ($device.operatingSystemVersion -match '^\d+\.\d+\.\d+$') { "Simplified" }
                                 else { "Unknown" }
            IntuneDeviceType   = "N/A"
            TrustType          = $device.trustType
            MDM                = $mdmLabel
            HasMDM             = $hasMdm
            IsCompliant        = $device.isCompliant
            AccountEnabled     = $device.accountEnabled
            RegisteredAt       = $device.registrationDateTime
            LastSignIn         = $lastSignIn
            DaysSinceSignIn    = $daysSinceSignIn
            IsStale            = $isStale
            EnrollmentProfile  = $device.enrollmentProfileName
            TotalEntraRecords  = 1
            IsDuplicate        = $false
            # Ownership classification (tiered scoring)
            IsBYOD                  = $isBYOD
            OwnershipScore          = $ownership.Score
            OwnershipClassification = $ownership.Classification
            OwnershipSignals        = $ownership.Signals
            # Intune enrollment details (N/A for detached records)
            DeviceEnrollmentType    = "N/A"
            ManagedDeviceOwnerType  = "N/A"
            IntuneEnrollmentProfile = "N/A"
            IsSupervised            = "N/A"
            # Detached records have no Intune backing, so no primary user
            PrimaryUser             = $null
            PrimaryUserStatus       = "N/A"
            PrimaryUserLastSignIn   = $null
            PrimaryUserDaysSinceSignIn = $null
            PrimaryUserIsStale      = $false
            IsOrphan           = -not $isBYOD  # BYOD devices are not orphans
            Recommendation     = $recommendation
            RecommendReason    = $recommendReason
        }
    }

    return $results
}

function Get-IntuneRecordAnalysis {
    <#
    .SYNOPSIS
        Analyze a single Intune managed device record for Intune-side duplicate
        detection. Returns an Intune-centric object with status, ownership,
        and user fields for scoring.
    #>
    param(
        $IntuneRecord,
        [array]$AllIntuneForSerial,
        [string]$SerialNumber,
        [hashtable]$EntraByDeviceId
    )

    $now = Get-Date -AsUTC

    # Stale check based on lastSyncDateTime
    $lastSync = $IntuneRecord.lastSyncDateTime
    $isStale = $false
    $daysSinceSync = $null
    if ($null -ne $lastSync) {
        $daysSinceSync = [math]::Round(($now - [DateTime]$lastSync).TotalDays, 0)
        $isStale = $daysSinceSync -gt $StaleThresholdDays
    }
    else {
        $isStale = $true
        $daysSinceSync = "Never"
    }

    # Check if this Intune record has a corresponding Entra record
    $aadDeviceId = $IntuneRecord.azureADDeviceId
    $hasEntraMatch = (-not [string]::IsNullOrEmpty($aadDeviceId) -and
                      $null -ne $EntraByDeviceId -and
                      $EntraByDeviceId.ContainsKey($aadDeviceId))

    # Ownership classification
    $enraTrustType = $null
    if ($hasEntraMatch) {
        $enraTrustType = $EntraByDeviceId[$aadDeviceId].trustType
    }
    $ownership = Get-OwnershipClassification -IntuneRecord $IntuneRecord -EntraTrustType $enraTrustType
    $isBYOD = $ownership.IsBYOD

    # Primary user info
    $primaryUserUPN = $IntuneRecord.userPrincipalName
    $userStatusLabel = "N/A"
    $userLastSignIn = $null
    $userDaysSinceSignIn = $null

    if (-not $SkipUserLookup -and -not [string]::IsNullOrEmpty($primaryUserUPN)) {
        $userStatus = Get-UserStatus -UserPrincipalName $primaryUserUPN
        if ($null -ne $userStatus) {
            $userStatusLabel = $userStatus.Status
            $userLastSignIn = $userStatus.LastSignIn
            $userDaysSinceSignIn = $userStatus.DaysSinceSignIn
        }
    }

    [PSCustomObject]@{
        # Identification
        SerialNumber       = $SerialNumber
        DeviceName         = $IntuneRecord.deviceName
        IntuneDeviceId     = $IntuneRecord.id
        AzureADDeviceId    = $aadDeviceId

        # Status
        ComplianceState    = $IntuneRecord.complianceState
        LastSyncDateTime   = $lastSync
        DaysSinceSync      = $daysSinceSync
        IsStale            = $isStale
        EnrolledDateTime   = $IntuneRecord.enrolledDateTime
        HasEntraMatch      = $hasEntraMatch

        # Ownership
        IsBYOD                  = $isBYOD
        OwnershipClassification = $ownership.Classification
        OwnershipScore          = $ownership.Score
        OwnershipSignals        = $ownership.Signals
        DeviceEnrollmentType    = $IntuneRecord.deviceEnrollmentType
        ManagedDeviceOwnerType  = $IntuneRecord.managedDeviceOwnerType

        # User
        PrimaryUser             = $primaryUserUPN
        PrimaryUserStatus       = $userStatusLabel
        PrimaryUserLastSignIn   = $userLastSignIn
        PrimaryUserDaysSinceSignIn = $userDaysSinceSignIn

        # Duplicate context
        TotalIntuneRecords = $AllIntuneForSerial.Count

        # Placeholders (filled in by Get-IntuneCleanupRecommendation)
        IsOrphan           = $false
        OrphanScore        = 0
        Recommendation     = ""
        RecommendReason    = ""
    }
}

function Get-IntuneCleanupRecommendation {
    <#
    .SYNOPSIS
        For each serial number with multiple Intune records, score each record
        to determine which are orphans and what action to take.

    .DESCRIPTION
        Intune orphan scoring heuristics (higher = more likely orphan):
          +3  Stale sync (lastSyncDateTime > threshold)
          +3  Primary user account deleted          (skipped with -SkipUserLookup)
          +2  No Entra match (azureADDeviceId not found in Entra)
          +2  Primary user account disabled          (skipped with -SkipUserLookup)
          +1  Non-compliant (complianceState = "noncompliant")
          +1  Older enrollment (not the newest enrolledDateTime for this serial)

        The record with the LOWEST score per serial is considered "primary".
        Thresholds: >= 5 REMOVE (High confidence), >= 3 REVIEW (Likely orphan),
        else REVIEW (Low confidence). BYOD never flagged.
    #>
    param([array]$AnalysisRecords)

    Write-Header "Determining Intune Cleanup Recommendations"

    $groups = $AnalysisRecords | Group-Object -Property SerialNumber
    $results = [System.Collections.ArrayList]::new()

    foreach ($group in $groups) {
        $records = @($group.Group)

        if ($records.Count -le 1) {
            # Should not happen (only called for serials with >1 record), but safety
            foreach ($record in $records) {
                $record.Recommendation = "OK"
                $record.RecommendReason = "Single Intune record for this device"
                [void]$results.Add($record)
            }
            continue
        }

        # Find the newest enrollment date for this serial
        $newestEnrolled = $records |
            Where-Object { $null -ne $_.EnrolledDateTime } |
            Sort-Object -Property { [DateTime]$_.EnrolledDateTime } -Descending |
            Select-Object -First 1

        # Score each record
        $scored = foreach ($record in $records) {
            $score = 0
            $reasons = [System.Collections.ArrayList]::new()

            if ($record.IsStale) {
                $score += 3
                [void]$reasons.Add("Stale sync ($($record.DaysSinceSync) days)")
            }
            if (-not $SkipUserLookup -and $record.PrimaryUserStatus -eq "Deleted") {
                $score += 3
                [void]$reasons.Add("Primary user deleted")
            }
            if (-not $record.HasEntraMatch) {
                $score += 2
                [void]$reasons.Add("No matching Entra device record")
            }
            if (-not $SkipUserLookup -and $record.PrimaryUserStatus -eq "Disabled") {
                $score += 2
                [void]$reasons.Add("Primary user disabled")
            }
            if ($record.ComplianceState -eq "noncompliant") {
                $score += 1
                [void]$reasons.Add("Non-compliant")
            }
            if ($null -ne $newestEnrolled -and
                $null -ne $record.EnrolledDateTime -and
                $record.IntuneDeviceId -ne $newestEnrolled.IntuneDeviceId) {
                $score += 1
                [void]$reasons.Add("Older enrollment (not newest)")
            }

            [PSCustomObject]@{
                Record  = $record
                Score   = $score
                Reasons = $reasons
            }
        }

        # Sort by score ascending. Lowest score = primary record.
        $sorted = $scored | Sort-Object -Property Score

        $primaryAssigned = $false
        foreach ($item in $sorted) {
            $record = $item.Record
            $record.OrphanScore = $item.Score

            # BYOD devices are NEVER flagged for deletion
            if ($record.IsBYOD) {
                $record.IsOrphan = $false
                $record.Recommendation = "OK (BYOD)"
                $record.RecommendReason = "BYOD device - not flagged for deletion"
                [void]$results.Add($record)
                continue
            }

            if (-not $primaryAssigned) {
                $record.IsOrphan = $false
                $record.Recommendation = "KEEP (Primary)"
                $record.RecommendReason = "Healthiest Intune record (score: $($item.Score))"
                $primaryAssigned = $true
            }
            else {
                $record.IsOrphan = $true
                $script:Stats.IntuneOrphanRecords++

                if ($item.Score -ge 5) {
                    $record.Recommendation = "REMOVE (High confidence)"
                    $script:Stats.IntuneRecommendedCleanup++
                }
                elseif ($item.Score -ge 3) {
                    $record.Recommendation = "REVIEW (Likely orphan)"
                    $script:Stats.IntuneRecommendedCleanup++
                }
                else {
                    $record.Recommendation = "REVIEW (Low confidence)"
                }

                $record.RecommendReason = ($item.Reasons -join "; ")
            }

            [void]$results.Add($record)
        }
    }

    return $results
}
#endregion

#region --- Output Functions ---
function Write-ConsoleSummary {
    param(
        [array]$AllResults,
        [array]$DuplicatesOnly,
        [array]$IntuneDuplicates
    )

    Write-Header "SCAN RESULTS SUMMARY"

    Write-Host "  Intune Mac devices scanned:      " -NoNewline
    Write-Host "$($script:Stats.TotalIntuneMacs)" -ForegroundColor White
    Write-Host "  Entra Mac device records found:   " -NoNewline
    Write-Host "$($script:Stats.TotalEntraRecords)" -ForegroundColor White
    Write-Host "  Unique serial numbers:            " -NoNewline
    Write-Host "$($script:Stats.UniqueSerialNumbers)" -ForegroundColor White
    Write-Host ""
    Write-Host "  Devices with duplicate records:   " -NoNewline
    Write-Host "$($script:Stats.DevicesWithDuplicates)" -ForegroundColor $(if ($script:Stats.DevicesWithDuplicates -gt 0) { "Yellow" } else { "Green" })
    Write-Host "  Orphan records identified:        " -NoNewline
    Write-Host "$($script:Stats.OrphanRecords)" -ForegroundColor $(if ($script:Stats.OrphanRecords -gt 0) { "Yellow" } else { "Green" })
    Write-Host "  Detached Entra records (no Intune):" -NoNewline
    Write-Host " $($script:Stats.DetachedEntraRecords)" -ForegroundColor $(if ($script:Stats.DetachedEntraRecords -gt 0) { "Red" } else { "Green" })
    Write-Host "  Stale records (>$StaleThresholdDays days):      " -NoNewline
    Write-Host "$($script:Stats.StaleRecords)" -ForegroundColor $(if ($script:Stats.StaleRecords -gt 0) { "Yellow" } else { "Green" })
    Write-Host "  Recommended for cleanup:          " -NoNewline
    Write-Host "$($script:Stats.RecommendedForCleanup)" -ForegroundColor $(if ($script:Stats.RecommendedForCleanup -gt 0) { "Red" } else { "Green" })
    Write-Host "  BYOD devices (excluded):          " -NoNewline
    Write-Host "$($script:Stats.BYODDevices)" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Intune duplicate serials:         " -NoNewline
    Write-Host "$($script:Stats.IntuneDuplicateSerials)" -ForegroundColor $(if ($script:Stats.IntuneDuplicateSerials -gt 0) { "Yellow" } else { "Green" })
    Write-Host "  Intune orphan records:            " -NoNewline
    Write-Host "$($script:Stats.IntuneOrphanRecords)" -ForegroundColor $(if ($script:Stats.IntuneOrphanRecords -gt 0) { "Yellow" } else { "Green" })
    Write-Host "  Intune recommended for cleanup:   " -NoNewline
    Write-Host "$($script:Stats.IntuneRecommendedCleanup)" -ForegroundColor $(if ($script:Stats.IntuneRecommendedCleanup -gt 0) { "Red" } else { "Green" })

    # Show duplicate details
    if ($DuplicatesOnly.Count -gt 0) {
        Write-Header "DUPLICATE DEVICE DETAILS"

        $dupGroups = $DuplicatesOnly | Group-Object -Property SerialNumber
        $shownCount = 0

        foreach ($group in $dupGroups) {
            if ($shownCount -ge $MaxDisplayItems) {
                Write-Host ""
                Write-Warn "Showing $MaxDisplayItems of $($dupGroups.Count) serial numbers with Entra duplicates. Check duplicate_and_orphan_records.csv for full details."
                break
            }

            Write-Host ""
            Write-Host "  Serial: " -NoNewline -ForegroundColor Cyan
            Write-Host "$($group.Name)" -ForegroundColor White
            Write-Host "  Device: " -NoNewline -ForegroundColor Cyan
            Write-Host "$($group.Group[0].DisplayName)" -ForegroundColor White
            Write-Host "  Records: $($group.Group.Count)" -ForegroundColor Cyan
            Write-Host ""

            foreach ($record in ($group.Group | Sort-Object -Property Recommendation)) {
                $color = switch -Wildcard ($record.Recommendation) {
                    "KEEP*"               { "Green" }
                    "REMOVE*"             { "Red" }
                    "REVIEW (Likely*"     { "Yellow" }
                    default               { "Gray" }
                }

                Write-Host "    [$($record.Recommendation)]" -ForegroundColor $color -NoNewline
                Write-Host " $($record.OperatingSystem) | " -NoNewline
                Write-Host "OS: $($record.OSVersion) | " -NoNewline
                Write-Host "Trust: $($record.TrustType) | " -NoNewline
                Write-Host "MDM: $($record.MDM) | " -NoNewline
                Write-Host "Device sign-in: $($record.DaysSinceSignIn) days"

                # Show user info if available
                if ($record.PrimaryUser) {
                    $userColor = switch ($record.PrimaryUserStatus) {
                        "Deleted"  { "Red" }
                        "Disabled" { "Yellow" }
                        "Enabled"  { "Green" }
                        default    { "Gray" }
                    }
                    Write-Host "      User: $($record.PrimaryUser) " -NoNewline -ForegroundColor DarkGray
                    Write-Host "[$($record.PrimaryUserStatus)]" -ForegroundColor $userColor -NoNewline
                    if ($record.PrimaryUserDaysSinceSignIn) {
                        Write-Host " | User sign-in: $($record.PrimaryUserDaysSinceSignIn) days" -ForegroundColor DarkGray
                    } else {
                        Write-Host "" # newline
                    }
                }

                if ($record.RecommendReason) {
                    Write-Host "      Reason: $($record.RecommendReason)" -ForegroundColor DarkGray
                }
                Write-Host "      Entra Object ID: $($record.EntraObjectId)" -ForegroundColor DarkGray
            }

            $shownCount++
        }
    }

    # Show detached orphans (excluding BYOD)
    $detached = @($AllResults | Where-Object { $_.SerialNumber -eq "UNKNOWN (Detached)" -and -not $_.IsBYOD })
    if ($detached.Count -gt 0) {
        Write-Header "DETACHED ENTRA RECORDS (No Intune Backing)"
        Write-Warn "These records exist in Entra ID but have no corresponding Intune managed device."
        Write-Warn "Common cause: failed PSSO registration, manual Company Portal install, or deleted Intune record."
        Write-Host ""

        $shownCount = 0
        foreach ($record in $detached) {
            if ($shownCount -ge $MaxDisplayItems) {
                Write-Host ""
                Write-Warn "Showing $MaxDisplayItems of $($detached.Count) detached Entra records. Check duplicate_and_orphan_records.csv for full details."
                break
            }

            $color = switch -Wildcard ($record.Recommendation) {
                "REMOVE*"  { "Red" }
                "REVIEW*"  { "Yellow" }
                default    { "Gray" }
            }

            Write-Host "    [$($record.Recommendation)]" -ForegroundColor $color -NoNewline
            Write-Host " $($record.DisplayName) | " -NoNewline
            Write-Host "$($record.OperatingSystem) $($record.OSVersion) | " -NoNewline
            Write-Host "Trust: $($record.TrustType) | " -NoNewline
            Write-Host "MDM: $($record.MDM) | " -NoNewline
            Write-Host "Last sign-in: $($record.DaysSinceSignIn) days"
            Write-Host "      Entra Object ID: $($record.EntraObjectId)" -ForegroundColor DarkGray

            $shownCount++
        }
    }

    # Show Intune duplicate details
    if ($IntuneDuplicates.Count -gt 0) {
        Write-Header "INTUNE DUPLICATE DEVICE DETAILS"
        Write-Warn "Multiple Intune managed device records found for the same serial number."
        Write-Warn "Common cause: re-enrollment without cleaning up the old Intune record."
        Write-Host ""

        $intuneGroups = $IntuneDuplicates | Group-Object -Property SerialNumber
        $shownCount = 0

        foreach ($group in $intuneGroups) {
            if ($shownCount -ge $MaxDisplayItems) {
                Write-Host ""
                Write-Warn "Showing $MaxDisplayItems of $($intuneGroups.Count) serial numbers with Intune duplicates. Check intune_duplicate_records.csv for full details."
                break
            }

            Write-Host ""
            Write-Host "  Serial: " -NoNewline -ForegroundColor Cyan
            Write-Host "$($group.Name)" -ForegroundColor White
            Write-Host "  Records: $($group.Group.Count)" -ForegroundColor Cyan
            Write-Host ""

            foreach ($record in ($group.Group | Sort-Object -Property Recommendation)) {
                $color = switch -Wildcard ($record.Recommendation) {
                    "KEEP*"               { "Green" }
                    "REMOVE*"             { "Red" }
                    "REVIEW (Likely*"     { "Yellow" }
                    default               { "Gray" }
                }

                Write-Host "    [$($record.Recommendation)]" -ForegroundColor $color -NoNewline
                Write-Host " $($record.DeviceName) | " -NoNewline
                Write-Host "Compliance: $($record.ComplianceState) | " -NoNewline
                Write-Host "Last sync: $($record.DaysSinceSync) days | " -NoNewline
                Write-Host "Enrolled: $($record.EnrolledDateTime) | " -NoNewline
                Write-Host "Entra match: $($record.HasEntraMatch)"

                # Show user info if available
                if ($record.PrimaryUser) {
                    $userColor = switch ($record.PrimaryUserStatus) {
                        "Deleted"  { "Red" }
                        "Disabled" { "Yellow" }
                        "Enabled"  { "Green" }
                        default    { "Gray" }
                    }
                    Write-Host "      User: $($record.PrimaryUser) " -NoNewline -ForegroundColor DarkGray
                    Write-Host "[$($record.PrimaryUserStatus)]" -ForegroundColor $userColor
                }

                if ($record.RecommendReason) {
                    Write-Host "      Reason: $($record.RecommendReason)" -ForegroundColor DarkGray
                }
                Write-Host "      Intune Device ID: $($record.IntuneDeviceId)" -ForegroundColor DarkGray
            }

            $shownCount++
        }
    }

    # Show BYOD devices (informational only - these are excluded from cleanup)
    $byodDevices = @($AllResults | Where-Object { $_.IsBYOD })
    if ($byodDevices.Count -gt 0) {
        Write-Header "BYOD DEVICES (Excluded from Cleanup)"
        Write-Info "Classified via tiered ownership scoring (Intune enrollment signals + Entra TrustType)."
        Write-Info "BYOD devices are included in reports but NEVER flagged for deletion."
        Write-Host ""

        $shownCount = 0
        foreach ($record in $byodDevices) {
            if ($shownCount -ge $MaxDisplayItems) {
                Write-Host ""
                Write-Warn "Showing $MaxDisplayItems of $($byodDevices.Count) BYOD devices. Check all_mac_device_records.csv for full details."
                break
            }

            Write-Host "    [OK (BYOD)]" -ForegroundColor Cyan -NoNewline
            Write-Host " $($record.DisplayName) | " -NoNewline
            Write-Host "$($record.OperatingSystem) $($record.OSVersion) | " -NoNewline
            Write-Host "Trust: $($record.TrustType) | " -NoNewline
            Write-Host "Score: $($record.OwnershipScore) ($($record.OwnershipClassification)) | " -NoNewline
            Write-Host "Last sign-in: $($record.DaysSinceSignIn) days"
            Write-Host "      Signals: $($record.OwnershipSignals)" -ForegroundColor DarkGray
            Write-Host "      Entra Object ID: $($record.EntraObjectId)" -ForegroundColor DarkGray

            $shownCount++
        }
    }
}

function Export-ScanResult {
    param(
        [array]$AllResults,
        [array]$IntuneDuplicates
    )

    # Ensure output directory exists (may already exist from transcript setup)
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }

    # Format DateTime fields to ISO 8601 to avoid Unicode mojibake from .NET 7+ ICU
    $formattedResults = $AllResults | ForEach-Object {
        $record = $_
        if ($null -ne $record.RegisteredAt -and $record.RegisteredAt -ne "") {
            $record.RegisteredAt = ([DateTime]$record.RegisteredAt).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        }
        if ($null -ne $record.LastSignIn -and $record.LastSignIn -ne "") {
            $record.LastSignIn = ([DateTime]$record.LastSignIn).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        }
        if ($null -ne $record.PrimaryUserLastSignIn -and $record.PrimaryUserLastSignIn -ne "") {
            $record.PrimaryUserLastSignIn = ([DateTime]$record.PrimaryUserLastSignIn).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        }
        $record
    }

    # All records (full detail)
    $allPath = Join-Path $OutputPath "all_mac_device_records.csv"
    $formattedResults | Export-Csv -Path $allPath -NoTypeInformation
    Write-Step "Exported all records: $allPath"

    # Duplicates only
    $duplicates = $formattedResults | Where-Object { $_.IsDuplicate -or $_.SerialNumber -eq "UNKNOWN (Detached)" }
    if ($duplicates.Count -gt 0) {
        $dupPath = Join-Path $OutputPath "duplicate_and_orphan_records.csv"
        $duplicates | Export-Csv -Path $dupPath -NoTypeInformation
        Write-Step "Exported duplicates/orphans: $dupPath"
    }

    # Cleanup candidates (actionable) - BYOD devices are explicitly excluded
    $cleanup = $formattedResults | Where-Object { $_.Recommendation -match "REMOVE|REVIEW" -and -not $_.IsBYOD }
    if ($cleanup.Count -gt 0) {
        $cleanPath = Join-Path $OutputPath "recommended_cleanup.csv"
        $cleanup | Select-Object SerialNumber, DisplayName, EntraObjectId, EntraDeviceId,
            OperatingSystem, OSVersion, TrustType, MDM, LastSignIn, DaysSinceSignIn,
            OwnershipClassification, OwnershipScore, OwnershipSignals,
            PrimaryUser, PrimaryUserStatus, PrimaryUserLastSignIn, PrimaryUserDaysSinceSignIn,
            IsBYOD, Recommendation, RecommendReason |
            Export-Csv -Path $cleanPath -NoTypeInformation
        Write-Step "Exported cleanup recommendations: $cleanPath"
    }

    # Intune duplicate CSV exports (only when Intune duplicates exist)
    if ($IntuneDuplicates.Count -gt 0) {
        # Format DateTime fields for Intune records
        $formattedIntune = $IntuneDuplicates | ForEach-Object {
            $record = $_
            if ($null -ne $record.LastSyncDateTime -and $record.LastSyncDateTime -ne "") {
                $record.LastSyncDateTime = ([DateTime]$record.LastSyncDateTime).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
            }
            if ($null -ne $record.EnrolledDateTime -and $record.EnrolledDateTime -ne "") {
                $record.EnrolledDateTime = ([DateTime]$record.EnrolledDateTime).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
            }
            if ($null -ne $record.PrimaryUserLastSignIn -and $record.PrimaryUserLastSignIn -ne "") {
                $record.PrimaryUserLastSignIn = ([DateTime]$record.PrimaryUserLastSignIn).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
            }
            $record
        }

        $intuneDupPath = Join-Path $OutputPath "intune_duplicate_records.csv"
        $formattedIntune | Export-Csv -Path $intuneDupPath -NoTypeInformation
        Write-Step "Exported Intune duplicate records: $intuneDupPath"

        # Intune cleanup candidates (REMOVE/REVIEW, BYOD excluded)
        $intuneCleanup = $formattedIntune | Where-Object { $_.Recommendation -match "REMOVE|REVIEW" -and -not $_.IsBYOD }
        if ($intuneCleanup.Count -gt 0) {
            $intuneCleanPath = Join-Path $OutputPath "recommended_intune_cleanup.csv"
            $intuneCleanup | Select-Object SerialNumber, DeviceName, IntuneDeviceId, AzureADDeviceId,
                ComplianceState, LastSyncDateTime, DaysSinceSync, IsStale, EnrolledDateTime, HasEntraMatch,
                OwnershipClassification, OwnershipScore, OwnershipSignals,
                PrimaryUser, PrimaryUserStatus, PrimaryUserLastSignIn, PrimaryUserDaysSinceSignIn,
                IsBYOD, OrphanScore, Recommendation, RecommendReason |
                Export-Csv -Path $intuneCleanPath -NoTypeInformation
            Write-Step "Exported Intune cleanup recommendations: $intuneCleanPath"
        }
    }

    # Generate a quick removal helper script (informational only, does NOT auto-execute)
    # BYOD devices are explicitly excluded - they should NEVER be in this script
    $removeTargets = $AllResults | Where-Object { $_.Recommendation -match "REMOVE" -and -not $_.IsBYOD }
    $intuneRemoveTargets = @($IntuneDuplicates | Where-Object { $_.Recommendation -match "REMOVE" -and -not $_.IsBYOD })
    $totalRemoveCount = $removeTargets.Count + $intuneRemoveTargets.Count
    if ($totalRemoveCount -gt 0) {
        $helperPath = Join-Path $OutputPath "cleanup_helper.ps1"
        $entraCount = $removeTargets.Count
        $intuneCount = $intuneRemoveTargets.Count

        # Build requirements line based on which sections are present
        $requiresModules = [System.Collections.ArrayList]::new()
        if ($entraCount -gt 0) {
            [void]$requiresModules.Add("Microsoft.Graph.Identity.DirectoryManagement")
        }
        if ($intuneCount -gt 0) {
            [void]$requiresModules.Add("Microsoft.Graph.DeviceManagement")
        }
        $requiresLine = "#Requires -Modules $($requiresModules -join ', ')"

        # Build permissions line
        $permissions = [System.Collections.ArrayList]::new()
        if ($entraCount -gt 0) { [void]$permissions.Add("Device.ReadWrite.All") }
        if ($intuneCount -gt 0) { [void]$permissions.Add("DeviceManagementManagedDevices.ReadWrite.All") }
        $permissionsLine = $permissions -join ", "

        $helperContent = @"
###############################################################################
# cleanup_helper.ps1
#
# AUTO-GENERATED helper script for removing orphaned device records.
# Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
# Total devices flagged for removal: $totalRemoveCount (Entra: $entraCount, Intune: $intuneCount)
#
# HOW TO USE:
#   Option A (Selective deletion - RECOMMENDED):
#     1. Review the device list below - each entry shows device details and reason
#     2. For each device you want to delete, change -DeleteDevice `$false to `$true
#     3. Run this script: .\cleanup_helper.ps1
#     4. Review the summary at the end
#
#   Option B (Delete ALL flagged devices):
#     1. Review the device list below to confirm ALL devices should be deleted
#     2. Run: .\cleanup_helper.ps1 -DeleteAll
#
#   Option C (Preview with -WhatIf):
#     Run: .\cleanup_helper.ps1 -WhatIf         (preview selective)
#     Run: .\cleanup_helper.ps1 -DeleteAll -WhatIf  (preview all)
#
# WARNING: -DeleteAll will delete ALL $totalRemoveCount flagged devices without
#          prompting for each one. This action is IRREVERSIBLE. Only use this
#          after carefully reviewing the recommended_cleanup.csv and
#          recommended_intune_cleanup.csv files, confirming every flagged
#          device is safe to remove.
#
# NOTES:
#   - Remove-MgDevice -DeviceId expects the Entra Object ID (the GUID that
#     identifies the device object in Entra), NOT the deviceId property.
#   - Remove-MgDeviceManagementManagedDevice -ManagedDeviceId expects the
#     Intune managed device ID.
#
# REQUIREMENTS: $permissionsLine
#
# CODE QUALITY:
#   This script passes PSScriptAnalyzer static analysis.
#   Intentional suppressions:
#   - PSAvoidUsingWriteHost: Interactive script requires colored console output
###############################################################################

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = `$false, HelpMessage = "Delete ALL flagged devices without individual confirmation")]
    [switch]`$DeleteAll
)

$requiresLine

# Connect with write permissions (uncomment if not already connected)
# Connect-MgGraph -Scopes "$permissionsLine" -NoWelcome

# Entra orphan counters
`$script:entraSuccessCount = 0
`$script:entraFailedCount = 0
`$script:entraSkippedCount = 0
`$script:entraFailedDevices = @()

# Intune orphan counters
`$script:intuneSuccessCount = 0
`$script:intuneFailedCount = 0
`$script:intuneSkippedCount = 0
`$script:intuneFailedDevices = @()

"@

        # Add Remove-OrphanDevice function if there are Entra targets
        if ($entraCount -gt 0) {
            $helperContent += @"
function Remove-OrphanDevice {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]`$ObjectId,
        [string]`$DisplayName,
        [bool]`$DeleteDevice = `$false
    )

    # If -DeleteAll switch is set, override individual DeleteDevice flags
    if (`$script:DeleteAllDevices) {
        `$DeleteDevice = `$true
    }

    if (-not `$DeleteDevice) {
        Write-Host -Object "  [SKIP] `$DisplayName - not enabled for deletion" -ForegroundColor Gray
        `$script:entraSkippedCount++
        return
    }

    if (`$PSCmdlet.ShouldProcess(`$DisplayName, "Remove device from Entra ID")) {
        Write-Host -Object "  [DELETE] `$DisplayName (Object ID: `$ObjectId)..." -ForegroundColor Yellow -NoNewline
        try {
            Remove-MgDevice -DeviceId `$ObjectId -ErrorAction Stop
            Write-Host -Object " OK" -ForegroundColor Green
            `$script:entraSuccessCount++
        }
        catch {
            Write-Host -Object " FAILED" -ForegroundColor Red
            Write-Host -Object "    Error: `$(`$_.Exception.Message)" -ForegroundColor Red
            `$script:entraFailedCount++
            `$script:entraFailedDevices += [PSCustomObject]@{
                DisplayName = `$DisplayName
                ObjectId    = `$ObjectId
                Error       = `$_.Exception.Message
            }
        }
    }
    else {
        Write-Host -Object "  [WHATIF] Would delete `$DisplayName (Object ID: `$ObjectId)" -ForegroundColor Cyan
        `$script:entraSkippedCount++
    }
}

"@
        }

        # Add Remove-IntuneOrphanDevice function if there are Intune targets
        if ($intuneCount -gt 0) {
            $helperContent += @"
function Remove-IntuneOrphanDevice {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]`$ManagedDeviceId,
        [string]`$DisplayName,
        [bool]`$DeleteDevice = `$false
    )

    # If -DeleteAll switch is set, override individual DeleteDevice flags
    if (`$script:DeleteAllDevices) {
        `$DeleteDevice = `$true
    }

    if (-not `$DeleteDevice) {
        Write-Host -Object "  [SKIP] `$DisplayName - not enabled for deletion" -ForegroundColor Gray
        `$script:intuneSkippedCount++
        return
    }

    if (`$PSCmdlet.ShouldProcess(`$DisplayName, "Remove managed device from Intune")) {
        Write-Host -Object "  [DELETE] `$DisplayName (Intune ID: `$ManagedDeviceId)..." -ForegroundColor Yellow -NoNewline
        try {
            Remove-MgDeviceManagementManagedDevice -ManagedDeviceId `$ManagedDeviceId -ErrorAction Stop
            Write-Host -Object " OK" -ForegroundColor Green
            `$script:intuneSuccessCount++
        }
        catch {
            Write-Host -Object " FAILED" -ForegroundColor Red
            Write-Host -Object "    Error: `$(`$_.Exception.Message)" -ForegroundColor Red
            `$script:intuneFailedCount++
            `$script:intuneFailedDevices += [PSCustomObject]@{
                DisplayName     = `$DisplayName
                ManagedDeviceId = `$ManagedDeviceId
                Error           = `$_.Exception.Message
            }
        }
    }
    else {
        Write-Host -Object "  [WHATIF] Would delete `$DisplayName (Intune ID: `$ManagedDeviceId)" -ForegroundColor Cyan
        `$script:intuneSkippedCount++
    }
}

"@
        }

        # DeleteAll handling
        $helperContent += @"
# Handle -DeleteAll switch with confirmation (skip confirmation in WhatIf mode)
`$script:DeleteAllDevices = `$false
if (`$DeleteAll) {
    if (`$WhatIfPreference) {
        # WhatIf mode - skip confirmation, just enable DeleteAll for preview
        Write-Host -Object ""
        Write-Host -Object ("=" * 70) -ForegroundColor Cyan
        Write-Host -Object "  WHATIF: -DeleteAll MODE (Preview Only)" -ForegroundColor Cyan
        Write-Host -Object ("=" * 70) -ForegroundColor Cyan
        Write-Host -Object ""
        `$script:DeleteAllDevices = `$true
    }
    else {
        # Real deletion - require confirmation
        Write-Host -Object ""
        Write-Host -Object ("=" * 70) -ForegroundColor Red
        Write-Host -Object "  WARNING: -DeleteAll MODE" -ForegroundColor Red
        Write-Host -Object ("=" * 70) -ForegroundColor Red
        Write-Host -Object ""
        Write-Host -Object "  You are about to delete ALL $totalRemoveCount flagged devices." -ForegroundColor Red
        Write-Host -Object "  This action is IRREVERSIBLE." -ForegroundColor Red
        Write-Host -Object ""
        `$confirm = Read-Host -Prompt "  Type 'DELETE ALL' to confirm"
        if (`$confirm -ne 'DELETE ALL') {
            Write-Host -Object ""
            Write-Host -Object "  Aborted. No devices were deleted." -ForegroundColor Yellow
            Write-Host -Object ""
            exit 0
        }
        `$script:DeleteAllDevices = `$true
        Write-Host -Object ""
    }
}

"@

        # Entra orphan section
        if ($entraCount -gt 0) {
            $helperContent += @"
# ==============================================================================
# ENTRA ORPHAN CLEANUP ($entraCount device(s))
# ==============================================================================
Write-Host -Object ""
Write-Host -Object ("=" * 70) -ForegroundColor Cyan
Write-Host -Object "  Entra Orphan Device Cleanup" -ForegroundColor Green
Write-Host -Object ("=" * 70) -ForegroundColor Cyan
Write-Host -Object ""
if (`$script:DeleteAllDevices) {
    Write-Host -Object "Processing $entraCount Entra device(s) (DELETE ALL mode)..." -ForegroundColor Red
} else {
    Write-Host -Object "Processing $entraCount Entra device(s)..." -ForegroundColor Cyan
}
Write-Host -Object ""

"@
            foreach ($target in $removeTargets) {
                $displayName = $target.DisplayName -replace "'", "''" -replace '([\u2018-\u201B])', '$1$1'
                $userInfoLine = if ($target.PrimaryUser) {
                    $userSignIn = if ($target.PrimaryUserDaysSinceSignIn) { "$($target.PrimaryUserDaysSinceSignIn) days ago" } else { "N/A" }
                    "# User: $($target.PrimaryUser) ($($target.PrimaryUserStatus)) | User last sign-in: $userSignIn"
                } else {
                    "# User: N/A (no Intune record)"
                }

                $helperContent += @"
# ------------------------------------------------------------------------------
# Device: $($target.DisplayName)
# OS: $($target.OperatingSystem) $($target.OSVersion) | Trust: $($target.TrustType) | MDM: $($target.MDM)
# Serial: $($target.SerialNumber)
# Device last sign-in: $($target.DaysSinceSignIn) days ago
$userInfoLine
# Reason: $($target.RecommendReason)
# ------------------------------------------------------------------------------
Remove-OrphanDevice ``
    -ObjectId '$($target.EntraObjectId)' ``
    -DisplayName '$displayName' ``
    -DeleteDevice `$false  # <-- Change to `$true to enable deletion

"@
            }
        }

        # Intune orphan section
        if ($intuneCount -gt 0) {
            $helperContent += @"
# ==============================================================================
# INTUNE ORPHAN CLEANUP ($intuneCount device(s))
# ==============================================================================
Write-Host -Object ""
Write-Host -Object ("=" * 70) -ForegroundColor Cyan
Write-Host -Object "  Intune Orphan Device Cleanup" -ForegroundColor Green
Write-Host -Object ("=" * 70) -ForegroundColor Cyan
Write-Host -Object ""
if (`$script:DeleteAllDevices) {
    Write-Host -Object "Processing $intuneCount Intune device(s) (DELETE ALL mode)..." -ForegroundColor Red
} else {
    Write-Host -Object "Processing $intuneCount Intune device(s)..." -ForegroundColor Cyan
}
Write-Host -Object ""

"@
            foreach ($target in $intuneRemoveTargets) {
                $displayName = $target.DeviceName -replace "'", "''" -replace '([\u2018-\u201B])', '$1$1'
                $userInfoLine = if ($target.PrimaryUser) {
                    $userSignIn = if ($target.PrimaryUserDaysSinceSignIn) { "$($target.PrimaryUserDaysSinceSignIn) days ago" } else { "N/A" }
                    "# User: $($target.PrimaryUser) ($($target.PrimaryUserStatus)) | User last sign-in: $userSignIn"
                } else {
                    "# User: N/A"
                }

                $helperContent += @"
# ------------------------------------------------------------------------------
# Device: $($target.DeviceName)
# Serial: $($target.SerialNumber) | Compliance: $($target.ComplianceState) | Entra match: $($target.HasEntraMatch)
# Last sync: $($target.DaysSinceSync) days ago | Enrolled: $($target.EnrolledDateTime)
$userInfoLine
# Reason: $($target.RecommendReason)
# ------------------------------------------------------------------------------
Remove-IntuneOrphanDevice ``
    -ManagedDeviceId '$($target.IntuneDeviceId)' ``
    -DisplayName '$displayName' ``
    -DeleteDevice `$false  # <-- Change to `$true to enable deletion

"@
            }
        }

        # Summary section
        $helperContent += @"

# ==============================================================================
# SUMMARY
# ==============================================================================
Write-Host -Object ""
Write-Host -Object ("=" * 70) -ForegroundColor Cyan
Write-Host -Object "  CLEANUP SUMMARY" -ForegroundColor Green
Write-Host -Object ("=" * 70) -ForegroundColor Cyan
Write-Host -Object ""
"@

        if ($entraCount -gt 0) {
            $helperContent += @"

Write-Host -Object "  ENTRA DEVICES:" -ForegroundColor White
Write-Host -Object "    Processed:          $entraCount" -ForegroundColor White
Write-Host -Object "    Successfully deleted: " -NoNewline; Write-Host -Object `$script:entraSuccessCount -ForegroundColor Green
Write-Host -Object "    Failed to delete:     " -NoNewline; Write-Host -Object `$script:entraFailedCount -ForegroundColor `$(if (`$script:entraFailedCount -gt 0) { "Red" } else { "Green" })
Write-Host -Object "    Skipped (not enabled):" -NoNewline; Write-Host -Object " `$script:entraSkippedCount" -ForegroundColor Yellow
Write-Host -Object ""
"@
        }

        if ($intuneCount -gt 0) {
            $helperContent += @"

Write-Host -Object "  INTUNE DEVICES:" -ForegroundColor White
Write-Host -Object "    Processed:          $intuneCount" -ForegroundColor White
Write-Host -Object "    Successfully deleted: " -NoNewline; Write-Host -Object `$script:intuneSuccessCount -ForegroundColor Green
Write-Host -Object "    Failed to delete:     " -NoNewline; Write-Host -Object `$script:intuneFailedCount -ForegroundColor `$(if (`$script:intuneFailedCount -gt 0) { "Red" } else { "Green" })
Write-Host -Object "    Skipped (not enabled):" -NoNewline; Write-Host -Object " `$script:intuneSkippedCount" -ForegroundColor Yellow
Write-Host -Object ""
"@
        }

        $helperContent += @"

if (`$script:entraFailedDevices.Count -gt 0) {
    Write-Host -Object "  FAILED ENTRA DEVICES:" -ForegroundColor Red
    foreach (`$device in `$script:entraFailedDevices) {
        Write-Host -Object "    - `$(`$device.DisplayName): `$(`$device.Error)" -ForegroundColor Red
    }
    Write-Host -Object ""
}

if (`$script:intuneFailedDevices.Count -gt 0) {
    Write-Host -Object "  FAILED INTUNE DEVICES:" -ForegroundColor Red
    foreach (`$device in `$script:intuneFailedDevices) {
        Write-Host -Object "    - `$(`$device.DisplayName): `$(`$device.Error)" -ForegroundColor Red
    }
    Write-Host -Object ""
}

`$totalSuccess = `$script:entraSuccessCount + `$script:intuneSuccessCount
if (`$totalSuccess -gt 0) {
    Write-Host -Object "  TIP: Run Find-DuplicateMacDevices.ps1 again to verify cleanup." -ForegroundColor Cyan
}
Write-Host -Object ""
"@

        $helperContent | Out-File -FilePath $helperPath -Encoding utf8
        Write-Step "Generated cleanup helper: $helperPath"
        Write-Warn "Review each device and set -DeleteDevice `$true for records you want to remove."
    }
}
#endregion

#region --- Main Execution ---

# Pre-flight check: ensure Microsoft.Graph module is installed
$requiredModule = "Microsoft.Graph.Authentication"
if (-not (Get-Module -ListAvailable -Name $requiredModule)) {
    Write-Host ""
    Write-Host "[FAIL] Required module '$requiredModule' is not installed." -ForegroundColor Red
    Write-Host ""
    Write-Host "  Install it by running:" -ForegroundColor Yellow
    Write-Host "    Install-Module Microsoft.Graph -Scope CurrentUser" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Then re-run this script." -ForegroundColor Yellow
    Write-Host ""
    exit 1
}
Import-Module $requiredModule -ErrorAction Stop

# Check if output folder already exists (warn before overwriting)
if (Test-Path $OutputPath) {
    Write-Host ""
    Write-Host "[!!] Output folder already exists: $OutputPath" -ForegroundColor Yellow
    Write-Host "     Existing files will be overwritten." -ForegroundColor Yellow
    Write-Host ""
    $response = Read-Host "     Continue? [Y/n]"
    if ($response -match '^[Nn]') {
        Write-Host ""
        Write-Host "Aborted. Use -OutputPath to specify a different location." -ForegroundColor Cyan
        exit 0
    }
    Write-Host ""
}
else {
    # Create output directory early for transcript
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

# Start transcript for audit trail
$transcriptPath = Join-Path $OutputPath "scan_transcript.log"
Start-Transcript -Path $transcriptPath -Append | Out-Null

# Initialize results variables at script scope for Ctrl+C handling
$script:allResults = @()
$script:scanCompleted = $false

try {
    Write-Header "macOS Duplicate Device Registration Scanner"
    Write-Host "  Stale threshold:  $StaleThresholdDays days" -ForegroundColor Cyan
    Write-Host "  Output path:      $OutputPath" -ForegroundColor Cyan
    Write-Host "  Platform:         $($platformInfo.Platform)" -ForegroundColor Cyan
    Write-Host "  Throttle delay:   ${ThrottleDelayMs}ms" -ForegroundColor Cyan
    Write-Host "  User lookup:      $(if ($SkipUserLookup) { 'Disabled' } else { 'Enabled' })" -ForegroundColor Cyan
    Write-Host "  Console display:  $MaxDisplayItems items per section" -ForegroundColor Cyan
    Write-Host "  Transcript:       $transcriptPath" -ForegroundColor Cyan
    Write-Host ""

    # Step 1: Connect
    Connect-ToGraph

    # Step 2: Check tenant compliance validity period
    $script:TenantCompliancePeriod = Get-TenantComplianceValidityPeriod
    if ($script:TenantCompliancePeriod -ne $StaleThresholdDays) {
        Write-Host ""
        Write-Warn "Tenant compliance validity period ($($script:TenantCompliancePeriod) days) differs from -StaleThresholdDays ($StaleThresholdDays days)."
        if ($StaleThresholdDays -gt $script:TenantCompliancePeriod) {
            Write-Warn "  Devices may be marked non-compliant by Intune before this script flags them as stale."
        } else {
            Write-Warn "  This script will flag devices as stale before Intune marks them non-compliant."
        }
        Write-Info "  Consider using -StaleThresholdDays $($script:TenantCompliancePeriod) to match tenant settings."
        Write-Host ""
    }

    # Step 3: Collect data from both sources
    $intuneDevices = Get-IntuneMacDevice
    $entraDevices = Get-EntraMacDevice

    $script:Stats.TotalIntuneMacs = $intuneDevices.Count
    $script:Stats.TotalEntraRecords = $entraDevices.Count

    if ($intuneDevices.Count -eq 0 -and $entraDevices.Count -eq 0) {
        Write-Warn "No macOS devices found in either Intune or Entra. Nothing to analyze."
        $script:scanCompleted = $true
        return
    }

    # Step 4: Build correlation map
    $correlation = Build-DeviceCorrelationMap -IntuneDevices $intuneDevices -EntraDevices $entraDevices
    $correlationMap = $correlation.CorrelationMap
    $detachedEntra = $correlation.DetachedEntra

    $script:Stats.UniqueSerialNumbers = $correlationMap.Count
    $script:Stats.DevicesWithDuplicates = ($correlationMap | Where-Object { $_.HasDuplicates }).Count

    # Step 4b: Count Intune-side duplicates
    $script:Stats.IntuneDuplicateSerials = ($correlationMap | Where-Object { $_.HasIntuneDuplicates }).Count

    # Step 5a: Collect unique UPNs and batch-resolve user status
    Write-Header "Analyzing Device Records"

    if ($SkipUserLookup) {
        Write-Info "User status lookups skipped (-SkipUserLookup)"
    }
    else {
        $uniqueUPNs = [System.Collections.Generic.HashSet[string]]::new(
            [StringComparer]::OrdinalIgnoreCase
        )
        foreach ($entry in $correlationMap) {
            foreach ($intuneRecord in $entry.IntuneRecords) {
                if (-not [string]::IsNullOrEmpty($intuneRecord.userPrincipalName)) {
                    [void]$uniqueUPNs.Add($intuneRecord.userPrincipalName)
                }
            }
        }

        if ($uniqueUPNs.Count -gt 0) {
            Write-Info "Resolving $($uniqueUPNs.Count) unique user(s) via batch API..."
            Invoke-UserStatusBatch -UserPrincipalNames @($uniqueUPNs)
        }
        else {
            Write-Info "No user principal names to resolve"
        }
    }

    # Step 5b: Analyze each record (user lookups now hit cache, or skipped)
    Write-Info "Analyzing device records..."
    $analysisRecords = [System.Collections.ArrayList]::new()

    foreach ($entry in $correlationMap) {
        foreach ($entraDevice in $entry.EntraRecords) {
            $record = Get-DeviceRecordAnalysis `
                -EntraDevice $entraDevice `
                -IntuneRecords $entry.IntuneRecords `
                -AllEntraForDevice $entry.EntraRecords `
                -SerialNumber $entry.SerialNumber

            [void]$analysisRecords.Add($record)
        }
    }

    Write-Step "Analyzed $($analysisRecords.Count) Entra records across $($correlationMap.Count) physical devices"
    if (-not $SkipUserLookup) {
        Write-Step "Cached $($script:UserCache.Count) unique user lookups"
    }

    # Step 6: Determine recommendations for duplicates
    $script:allResults = @(Get-CleanupRecommendation -AnalysisRecords $analysisRecords)

    # Step 7: Analyze detached records
    $detachedResults = @(Get-DetachedRecordAnalysis -DetachedDevices $detachedEntra)
    $script:allResults = $script:allResults + $detachedResults

    # Step 7b: Analyze Intune-side duplicates
    $intuneDuplicateEntries = $correlationMap | Where-Object { $_.HasIntuneDuplicates }
    if ($intuneDuplicateEntries.Count -gt 0) {
        Write-Info "Analyzing $($script:Stats.IntuneDuplicateSerials) serial(s) with Intune duplicates..."

        # Build Entra index for HasEntraMatch checks
        $entraByDeviceId = @{}
        foreach ($entra in $entraDevices) {
            if ($null -ne $entra.deviceId) {
                $entraByDeviceId[$entra.deviceId] = $entra
            }
        }

        # Step 5c: Analyze each Intune duplicate record
        $intuneAnalysisRecords = [System.Collections.ArrayList]::new()
        foreach ($entry in $intuneDuplicateEntries) {
            foreach ($intuneRecord in $entry.IntuneRecords) {
                $record = Get-IntuneRecordAnalysis `
                    -IntuneRecord $intuneRecord `
                    -AllIntuneForSerial $entry.IntuneRecords `
                    -SerialNumber $entry.SerialNumber `
                    -EntraByDeviceId $entraByDeviceId
                [void]$intuneAnalysisRecords.Add($record)
            }
        }

        # Step 5d: Determine Intune cleanup recommendations
        $script:intuneDuplicateResults = @(Get-IntuneCleanupRecommendation -AnalysisRecords $intuneAnalysisRecords)
        Write-Step "Analyzed $($script:intuneDuplicateResults.Count) Intune records across $($script:Stats.IntuneDuplicateSerials) duplicate serial(s)"
    }

    # Step 8: Output
    $duplicatesOnly = $script:allResults | Where-Object { $_.IsDuplicate -eq $true }
    Write-ConsoleSummary -AllResults $script:allResults -DuplicatesOnly $duplicatesOnly -IntuneDuplicates $script:intuneDuplicateResults
    Export-ScanResult -AllResults $script:allResults -IntuneDuplicates $script:intuneDuplicateResults

    Write-Header "Scan Complete"
    Write-Host "  Results saved to: " -NoNewline
    Write-Host "$OutputPath" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Next steps:" -ForegroundColor Cyan
    Write-Host "    1. Review 'recommended_cleanup.csv' for flagged Entra records" -ForegroundColor White
    if ($script:Stats.IntuneDuplicateSerials -gt 0) {
        Write-Host "    2. Review 'recommended_intune_cleanup.csv' for flagged Intune records" -ForegroundColor White
        Write-Host "    3. Cross-reference with audit logs if needed" -ForegroundColor White
        Write-Host "    4. Use 'cleanup_helper.ps1' after manual verification" -ForegroundColor White
    }
    else {
        Write-Host "    2. Cross-reference with audit logs if needed" -ForegroundColor White
        Write-Host "    3. Use 'cleanup_helper.ps1' after manual verification" -ForegroundColor White
    }
    Write-Host ""

    $script:scanCompleted = $true
}
finally {
    # Export partial results if interrupted
    if (-not $script:scanCompleted -and $script:allResults.Count -gt 0) {
        Write-Host ""
        Write-Warn "Scan interrupted - exporting partial results..."
        Export-ScanResult -AllResults $script:allResults -IntuneDuplicates $script:intuneDuplicateResults
    }

    Stop-Transcript | Out-Null
}
#endregion
