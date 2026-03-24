# DISCLAIMER:
# This script is provided "as is" without warranties or guarantees of any kind. While it has been created to fulfill specific functions
# and has worked effectively for my personal requirements, its performance may vary in different environments or use-cases.
# Users are advised to employ this script at their own discretion and risk.
# No responsibility will be assumed for any direct, indirect, incidental, or consequential damages that may arise from its use.
# ALWAYS TEST it in a controlled environment before deploying it in your production environment!
#
# -------------------------------------------------------------------------------------------------------------------------------
# AUTHOR: Oktay Sari
# https://allthingscloud.blog
# https://github.com/oktay-sari/
#
# CONTRIBUTORS:
# - Enhanced with AI assistance for comprehensive security checks
# - Community feedback and testing
#
# CODE QUALITY:
#   This script passes PSScriptAnalyzer static analysis.
#   Run: Invoke-ScriptAnalyzer -Path Get-macOSServiceReport.ps1
<#
.SYNOPSIS
    Generates a multi-category macOS service impact report from Intune custom attributes.

.DESCRIPTION
    Connects to Microsoft Graph API, retrieves device run states for up to 7 macOS
    custom attribute scripts deployed via Intune, and generates a consolidated
    CSV and HTML report with category-based navigation.

    Supported categories:
      - iCloud Services: Desktop & Documents Sync, Document Sync, Keychain Sync
      - Sharing Services: AirDrop, AirPlay Receiver
      - AI & Assistant: Apple Intelligence, Siri

    The HTML report embeds a JSON data blob and uses JavaScript to render the
    active category's summary cards, table, and data — enabling category switching
    in the browser without page reloads or external dependencies.

    Requires the Microsoft.Graph.Authentication PowerShell module.
    Install with: Install-Module Microsoft.Graph.Authentication -Scope CurrentUser

.PARAMETER OutputPath
    Directory to save the CSV and HTML reports. Defaults to service_reports/.

.PARAMETER Categories
    Which service categories to query. Accepts: all, icloud, sharing, ai.
    Default: all (queries all categories).

.PARAMETER DesktopDocsSyncName
    Display name of the Desktop & Documents Sync custom attribute in Intune.

.PARAMETER DocumentSyncName
    Display name of the Document Sync custom attribute in Intune.

.PARAMETER KeychainSyncName
    Display name of the Keychain Sync custom attribute in Intune.

.PARAMETER AirDropName
    Display name of the AirDrop Status custom attribute in Intune.

.PARAMETER AirPlayReceiverName
    Display name of the AirPlay Receiver Status custom attribute in Intune.

.PARAMETER AppleIntelligenceName
    Display name of the Apple Intelligence Status custom attribute in Intune.

.PARAMETER SiriName
    Display name of the Siri Status custom attribute in Intune.

.PARAMETER ThrottleDelayMs
    Delay in milliseconds between Graph API page requests (0-5000).
    Default: 100.

.PARAMETER NoBanner
    Omit the #DutchCowboy animated GIF banner from the HTML report.

.PARAMETER Force
    Run non-interactively: skip confirmation prompts and the console banner.

.EXAMPLE
    .\Get-macOSServiceReport.ps1

.EXAMPLE
    .\Get-macOSServiceReport.ps1 -Categories icloud

.EXAMPLE
    .\Get-macOSServiceReport.ps1 -Categories icloud,sharing -OutputPath "C:\Reports"

.EXAMPLE
    .\Get-macOSServiceReport.ps1 -Force -NoBanner
#>

# PSScriptAnalyzer suppression: Interactive script needs colored console output
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '',
    Justification = 'Interactive script needs colored console output')]
[CmdletBinding()]
param(
    [string]$OutputPath = "service_reports",
    [ValidateSet('all', 'icloud', 'sharing', 'ai')]
    [string[]]$Categories = @('all'),
    [string]$DesktopDocsSyncName = "macOS - iCloud Desktop Documents Sync",
    [string]$DocumentSyncName = "macOS - iCloud Document Sync",
    [string]$KeychainSyncName = "macOS - iCloud Keychain Sync",
    [string]$AirDropName = "macOS - AirDrop Status",
    [string]$AirPlayReceiverName = "macOS - AirPlay Receiver Status",
    [string]$AppleIntelligenceName = "macOS - Apple Intelligence Status",
    [string]$SiriName = "macOS - Siri Status",
    [ValidateRange(0, 5000)]
    [int]$ThrottleDelayMs = 100,
    [switch]$NoBanner,
    [switch]$Force
)

# ============================================================================
# Script Registry — defines all 7 scripts, their categories, columns, and
# summary card config. The fetch loop and JSON builder iterate this registry.
# ============================================================================

$ScriptRegistry = [ordered]@{
    desktopDocs = [ordered]@{
        displayName = $DesktopDocsSyncName
        category    = 'icloud'
        label       = 'Desktop & Documents Sync'
        shortLabel  = 'DD'
        columns     = @(
            [ordered]@{ key = 'Status'; label = 'Status'; isStatus = $true }
            [ordered]@{ key = 'Desktop'; label = 'Desktop' }
            [ordered]@{ key = 'Documents'; label = 'Documents' }
            [ordered]@{ key = 'Optimize Storage'; label = 'Opt Storage' }
            [ordered]@{ key = 'Setting Managed'; label = 'Managed' }
        )
        summaryCards = @(
            [ordered]@{ label = 'Enabled (will be impacted)'; statuses = @('Enabled'); dot = 'impact' }
            [ordered]@{ label = 'Blocked by Profile'; statuses = @('BlockedByProfile'); dot = 'managed' }
            [ordered]@{ label = 'Disabled (no impact)'; statuses = @('Disabled'); dot = 'safe' }
        )
        footnote = $null
    }
    documentSync = [ordered]@{
        displayName = $DocumentSyncName
        category    = 'icloud'
        label       = 'Document Sync (iCloud Drive)'
        shortLabel  = 'DS'
        columns     = @(
            [ordered]@{ key = 'Status'; label = 'Status'; isStatus = $true }
            [ordered]@{ key = 'Size'; label = 'Size' }
            [ordered]@{ key = 'Optimize Storage'; label = 'Opt Storage' }
            [ordered]@{ key = 'Setting Managed'; label = 'Managed' }
        )
        summaryCards = @(
            [ordered]@{ label = 'Active (will be impacted)'; statuses = @('Active'); dot = 'impact' }
            [ordered]@{ label = 'Blocked by Profile'; statuses = @('BlockedByProfile'); dot = 'managed' }
            [ordered]@{ label = 'Inactive (no impact)'; statuses = @('Inactive', 'Configured', 'Disabled'); dot = 'safe' }
        )
        footnote = $null
    }
    keychain = [ordered]@{
        displayName = $KeychainSyncName
        category    = 'icloud'
        label       = 'Keychain Sync'
        shortLabel  = 'KC'
        columns     = @(
            [ordered]@{ key = 'Status'; label = 'Status'; isStatus = $true }
            [ordered]@{ key = 'iCloud Account'; label = 'iCloud Account' }
            [ordered]@{ key = 'Setting Managed'; label = 'Managed' }
        )
        summaryCards = @(
            [ordered]@{ label = 'Likely Enabled (will be impacted)'; statuses = @('LikelyEnabled'); dot = 'impact' }
            [ordered]@{ label = 'Blocked by Profile'; statuses = @('BlockedByProfile'); dot = 'managed' }
            [ordered]@{ label = 'No iCloud Account'; statuses = @('NoiCloudAccount'); dot = 'safe' }
        )
        footnote = 'macOS does not expose a reliable API to directly confirm iCloud Keychain status. "LikelyEnabled" means an iCloud account is signed in and no managed profile blocks Keychain Sync. Since iCloud Keychain is enabled by default (opt-out, not opt-in), this is a high-confidence indicator.'
    }
    airdrop = [ordered]@{
        displayName = $AirDropName
        category    = 'sharing'
        label       = 'AirDrop'
        shortLabel  = 'AD'
        columns     = @(
            [ordered]@{ key = 'Status'; label = 'Status'; isStatus = $true }
            [ordered]@{ key = 'Discovery'; label = 'Discovery' }
            [ordered]@{ key = 'Setting Managed'; label = 'Managed' }
        )
        summaryCards = @(
            [ordered]@{ label = 'Enabled (will be impacted)'; statuses = @('Enabled'); dot = 'impact' }
            [ordered]@{ label = 'Blocked by Profile'; statuses = @('BlockedByProfile'); dot = 'managed' }
            [ordered]@{ label = 'Disabled (no impact)'; statuses = @('Disabled'); dot = 'safe' }
        )
        footnote = $null
    }
    airplayReceiver = [ordered]@{
        displayName = $AirPlayReceiverName
        category    = 'sharing'
        label       = 'AirPlay Receiver'
        shortLabel  = 'AR'
        columns     = @(
            [ordered]@{ key = 'Status'; label = 'Status'; isStatus = $true }
            [ordered]@{ key = 'Setting Managed'; label = 'Managed' }
        )
        summaryCards = @(
            [ordered]@{ label = 'Enabled (will be impacted)'; statuses = @('Enabled'); dot = 'impact' }
            [ordered]@{ label = 'Blocked by Profile'; statuses = @('BlockedByProfile'); dot = 'managed' }
            [ordered]@{ label = 'Disabled by User'; statuses = @('DisabledByUser'); dot = 'safe' }
        )
        footnote = $null
    }
    appleIntelligence = [ordered]@{
        displayName = $AppleIntelligenceName
        category    = 'ai'
        label       = 'Apple Intelligence'
        shortLabel  = 'AI'
        columns     = @(
            [ordered]@{ key = 'Status'; label = 'Status'; isStatus = $true }
            [ordered]@{ key = 'WT'; label = 'Writing Tools' }
            [ordered]@{ key = 'Mail'; label = 'Mail Summary' }
            [ordered]@{ key = 'Notes'; label = 'Notes Summary' }
            [ordered]@{ key = 'ExtAI'; label = 'External AI' }
            [ordered]@{ key = 'Setting Managed'; label = 'Managed' }
        )
        summaryCards = @(
            [ordered]@{ label = 'Available (will be impacted)'; statuses = @('Available'); dot = 'impact' }
            [ordered]@{ label = 'Partially Managed'; statuses = @('PartiallyManaged'); dot = 'warning' }
            [ordered]@{ label = 'All Blocked by Profile'; statuses = @('AllBlocked'); dot = 'managed' }
        )
        footnote = $null
    }
    siri = [ordered]@{
        displayName = $SiriName
        category    = 'ai'
        label       = 'Siri'
        shortLabel  = 'SI'
        columns     = @(
            [ordered]@{ key = 'Status'; label = 'Status'; isStatus = $true }
            [ordered]@{ key = 'ListenFor'; label = 'Listen for Siri' }
            [ordered]@{ key = 'Setting Managed'; label = 'Managed' }
        )
        summaryCards = @(
            [ordered]@{ label = 'Enabled (will be impacted)'; statuses = @('Enabled'); dot = 'impact' }
            [ordered]@{ label = 'Blocked by Profile'; statuses = @('BlockedByProfile'); dot = 'managed' }
            [ordered]@{ label = 'Disabled by User'; statuses = @('DisabledByUser'); dot = 'safe' }
        )
        footnote = $null
    }
}

# ============================================================================
# Category Definitions
# ============================================================================

$CategoryDefinitions = [ordered]@{
    icloud = [ordered]@{
        label    = 'iCloud Services'
        subtitle = 'Pre-enforcement impact analysis for BIO 7.1 / 7.2 / 7.3 and CIS 2.1.1.1 / 2.1.1.3'
        scripts  = @('desktopDocs', 'documentSync', 'keychain')
    }
    sharing = [ordered]@{
        label    = 'Sharing Services'
        subtitle = 'Pre-enforcement impact analysis for CIS 2.3.1.1 / 2.3.1.2'
        scripts  = @('airdrop', 'airplayReceiver')
    }
    ai = [ordered]@{
        label    = 'AI & Assistant'
        subtitle = 'Pre-enforcement impact analysis for CIS 2.5.1.x / 2.5.2.x'
        scripts  = @('appleIntelligence', 'siri')
    }
}

# ============================================================================
# Helper functions
# ============================================================================

function Get-AllGraphResult {
    <#
    .SYNOPSIS
        Fetches all pages from a Microsoft Graph API endpoint with throttle retry.
    #>
    param(
        [string]$Uri,
        [int]$DelayMs = 100,
        [int]$MaxRetries = 3
    )

    $allResults = [System.Collections.Generic.List[object]]::new()
    $currentUri = $Uri
    $pageCount = 0
    $retryDelays = @(60, 120, 180)

    while ($currentUri) {
        $attempt = 0
        $success = $false

        while (-not $success -and $attempt -le $MaxRetries) {
            try {
                if ($pageCount -gt 0 -and $DelayMs -gt 0) {
                    Start-Sleep -Milliseconds $DelayMs
                }
                $response = Invoke-MgGraphRequest -Method GET -Uri $currentUri -OutputType PSObject
                $success = $true
            }
            catch {
                $statusCode = 0
                if ($_.Exception.Response) {
                    $statusCode = [int]$_.Exception.Response.StatusCode
                }
                $errorMsg = $_.Exception.Message
                if ($statusCode -in @(429, 503, 504) -or $errorMsg -match '429|throttl|Too Many Requests|Service Unavailable') {
                    $attempt++
                    if ($attempt -gt $MaxRetries) {
                        Write-Host "    Max retries ($MaxRetries) exceeded. Aborting." -ForegroundColor Red
                        throw
                    }
                    $delay = $retryDelays[[Math]::Min($attempt - 1, $retryDelays.Count - 1)]
                    $retryAfter = $null
                    if ($_.Exception.Response.Headers) {
                        $retryAfter = $_.Exception.Response.Headers |
                            Where-Object { $_.Key -eq 'Retry-After' } |
                            Select-Object -ExpandProperty Value -First 1
                    }
                    if ($retryAfter) {
                        $delay = [Math]::Max($delay, [int]$retryAfter)
                    }
                    Write-Host "    HTTP $statusCode — retrying in ${delay}s (attempt $attempt/$MaxRetries)..." -ForegroundColor Yellow
                    Start-Sleep -Seconds $delay
                }
                else {
                    throw
                }
            }
        }

        if ($response.value) {
            foreach ($item in $response.value) {
                $allResults.Add($item)
            }
        }
        $pageCount++
        Write-Host "    Fetched $($allResults.Count) results ($pageCount pages)..." -ForegroundColor Gray
        $currentUri = $response.'@odata.nextLink'
    }

    return $allResults
}

function ConvertFrom-CustomAttributeResult {
    <#
    .SYNOPSIS
        Parses a pipe-delimited custom attribute result string into an ordered hashtable.
    #>
    param([string]$ResultMessage)

    $parsed = [ordered]@{ Status = 'NoData' }

    if ([string]::IsNullOrWhiteSpace($ResultMessage)) {
        return $parsed
    }

    $message = $ResultMessage.Trim()
    $parts = $message -split '\|'
    $parsed['Status'] = $parts[0]

    for ($i = 1; $i -lt $parts.Count; $i++) {
        $colonIndex = $parts[$i].IndexOf(':')
        if ($colonIndex -gt 0) {
            $key = $parts[$i].Substring(0, $colonIndex).Trim()
            $val = $parts[$i].Substring($colonIndex + 1).Trim()
            $parsed[$key] = $val
        }
    }

    return $parsed
}

function ConvertTo-SafeHtml {
    <#
    .SYNOPSIS
        Escapes a string for safe HTML output.
    #>
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    return $Text.Replace('&', '&amp;').Replace('<', '&lt;').Replace('>', '&gt;').Replace('"', '&quot;')
}

function Show-DutchCowboyBanner {
    <#
    .SYNOPSIS
        Displays the #DutchCowboy ASCII art cowboy hat banner.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '',
        Justification = 'Interactive banner requires colored console output')]
    param(
        [Parameter(Mandatory = $false)]
        [string]$Subtitle
    )

    $delay = 40

    $art = @(
        '$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$'
        '$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$'
        '$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$XXX$$$$$$$$$$$$$X++X$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$'
        '$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$;::::;x$$$$$$$X+::::::X$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$'
        '$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$;::::::::::::.........::x$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$'
        '$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$X:::::::::................:+$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$'
        '$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$X:::..:.::...................;$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$'
        '$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$+:.:::::.:.....................:X$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$'
        '$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$x::.::..:::......................::;$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$'
        '$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$;:....:............................:::x$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$'
        '$$$$$$$$$$$$$$$$$$$$$$$$$$$$$X::..:..::....:......................::::;$$$$$$$$$$$$$$$$$$$$$$$$$$$$$'
        '$$$$$$$$$$$$$$$$$$$$$$$$$$$$X:::........:..........................::::+$$$$$$$$$$$$$$$$$$$$$$$$$$$$'
        '$$$$$$$$$$$$$$$$$$$$$$$$$$$$+::.....................................:::;$$$$$$$$$$$$$$$$$$$$$$$$$$$$'
        '$$$$$$$$$$$$$$$$$$$$$$$$$$$$+:............................... .......:::$$$$$$$$$$$$$$$$$$+:::;X$$$$'
        '$$$$x:::::X$$$$$$$$$$$$$$$$$;...............................   ......:::X$$$$$$$$$$$$$$$$x::::::x$$$'
        '$$$$X:::::::;X$$$$$$$$$$$$$$::................................ .......:::$$$$$$$$$$$$$$+:::::::+$$$$'
        '$$$$$+:::::::::X$$$$$$$$$$$$:..............................  . ........::X$$$$$$$$$$$+::::::::+$$$$$'
        '$$$$$$;::::::::::+$$$$$$$$$x:...............................  . ........:x$$$$$$$$$x:::::::::+$$$$$$'
        '$$$$$$X;:::::::::::x$$$$$$$;:.......................... .       .........:;$$$$$$X::::::::::x$$$$$$$'
        '$$$$$$$$+::::::::::::X$$$$+...........................  .  ... ....  ..  .;xX$$X::::::::::+X$$$$$$$$'
        '$$$$$$$$$$x;:::::::::::Xx;::......    .             .  ............:::::::::::.:::::::;x$$$$$$$$$$$$'
        '$$$$$$$$$$$$$$x::::::::::::::::....:..............::..::..::.:...::..:.::.....:::::x$$$$$$$$$$$$$$$$'
        '$$$$$$$$$$$$$$$$$$x::::::::::::::....:...:....:::..:.:.........:..:.........::::x$$$$$$$$$$$$$$$$$$$'
        '$$$$$$$$$$$$$$$$$$$$$X;:::::..:::..::.:::::::::..::........................::x$$$$$$$$$$$$$$$$$$$$$$'
        '$$$$$$$$$$$$$$$$$$$$$$$$X+:::::::::::::.::.:.:::..:::..::................:+XX$$X$$$$$$$$$$$$$$$$$$$$'
        '$$$$$$$$$$$$$$$$$$$$$$$XXXXX+::::::::::.::.::.::::.:::....:.......:...:+XXXXXXXXXX$$$$$$$$$$$$$$$$$$'
        '$$$$$$$$$$$$$$XXXXXXXXXXXXXXXXXx;::::::::::::::.::..:.::::::::::::;+XXXXXXXXXXXXXXXXXX$$$$$$$$$$$$$$'
        '$$$$$$$$$$$$$XXXXXXXXXXxxxxxxxxxxx+++++++++++++xxxxxxxxxxxxxxXXXXXXXXXXXXXXXXXXXXXXXXXXXX$$$$$$$$$$$'
        '$$$$$$$$$$$$XXXXXxxx++++++++++++;;;;;;;;;;;;;;;+++++++++++++++++++++++xxxxxxxxXXXXXXXXXXXXX$$$$$$$$$'
    )

    Write-Host ""
    Write-Host ("=" * 100) -ForegroundColor Cyan
    Start-Sleep -Milliseconds $delay

    foreach ($artLine in $art) {
        Write-Host $artLine -ForegroundColor Cyan
        Start-Sleep -Milliseconds $delay
    }

    Write-Host ""

    $brandText = '                                          #DutchCowboy'
    $cursorUp = "`e[1A`e[2K"

    for ($blink = 0; $blink -lt 4; $blink++) {
        Write-Host $brandText -ForegroundColor Green
        if ($Subtitle) {
            Write-Host "                                    $Subtitle" -ForegroundColor Green
        }
        Start-Sleep -Milliseconds 300
        if ($Subtitle) {
            Write-Host "$cursorUp$cursorUp" -NoNewline
        }
        else {
            Write-Host $cursorUp -NoNewline
        }
        Start-Sleep -Milliseconds 200
    }

    Write-Host $brandText -ForegroundColor Green
    if ($Subtitle) {
        Write-Host "                                    $Subtitle" -ForegroundColor Green
    }

    Write-Host ("=" * 100) -ForegroundColor Cyan
    Write-Host ""
}

# ============================================================================
# HTML Report Template (non-interpolating here-string — JS renders from JSON)
# Placeholders: __REPORT_JSON_DATA__, __REPORT_BANNER__, __REPORT_EXAMPLE_BADGE__
# ============================================================================

$HtmlTemplate = @'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>macOS Service Impact Report</title>
<style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        background: #f1f5f9; color: #1e293b; padding: 24px;
    }
    .header { text-align: center; margin-bottom: 32px; position: relative; }
    .header h1 { font-size: 24px; font-weight: 700; margin-bottom: 4px; }
    .header .subtitle { color: #64748b; font-size: 14px; min-height: 20px; }
    .header .meta { color: #94a3b8; font-size: 12px; margin-top: 4px; }
    .header .example-badge {
        display: inline-block; margin-top: 8px; padding: 4px 12px;
        background: #fef3c7; color: #92400e; border-radius: 12px;
        font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px;
    }
    .category-select-wrapper { position: absolute; top: 0; right: 0; }
    .category-select {
        padding: 8px 12px; border: 1px solid #e2e8f0; border-radius: 8px;
        font-size: 13px; background: white; color: #1e293b;
        cursor: pointer; outline: none; min-width: 180px;
    }
    .category-select:focus { border-color: #94a3b8; }
    .category-select:hover { border-color: #cbd5e1; }

    .summary { display: flex; gap: 16px; margin-bottom: 32px; justify-content: center; flex-wrap: wrap; }
    .card {
        background: white; border-radius: 10px; padding: 20px 24px;
        box-shadow: 0 1px 3px rgba(0,0,0,0.08), 0 1px 2px rgba(0,0,0,0.06);
        min-width: 220px; flex: 1; max-width: 340px;
    }
    .card h3 { font-size: 14px; font-weight: 600; margin-bottom: 12px; color: #475569; }
    .card .stat-row {
        display: flex; justify-content: space-between; align-items: center;
        padding: 6px 8px; margin: 2px 0; border-radius: 6px;
        border-left: 3px solid transparent; cursor: pointer;
        transition: background 0.15s, border-color 0.15s;
    }
    .card .stat-row:hover { background: #f8fafc; }
    .card .stat-row.card-filter-active {
        background: #f0f9ff; border-left-color: #3b82f6;
    }
    .card .stat-row.no-click { cursor: default; }
    .card .stat-label { font-size: 13px; }
    .card .stat-count { font-weight: 700; font-size: 15px; min-width: 32px; text-align: right; }
    .clear-x { color: #94a3b8; font-size: 14px; margin-left: 4px; }

    .dot { display: inline-block; width: 10px; height: 10px; border-radius: 50%; margin-right: 8px; vertical-align: middle; }
    .dot-impact { background: #f59e0b; }
    .dot-warning { background: #fbbf24; border: 1px dashed #d97706; }
    .dot-managed { background: #22c55e; }
    .dot-safe { background: #94a3b8; }
    .dot-other { background: #e2e8f0; }

    .total-bar { text-align: center; margin-bottom: 16px; font-size: 14px; color: #64748b; }
    .total-bar strong { font-size: 28px; color: #1e293b; display: block; }
    .usage-hint {
        text-align: center; margin-bottom: 32px; font-size: 12px; color: #94a3b8;
        line-height: 1.6;
    }

    .table-container {
        background: white; border-radius: 10px; overflow-x: auto;
        box-shadow: 0 1px 3px rgba(0,0,0,0.08), 0 1px 2px rgba(0,0,0,0.06);
    }
    table { width: 100%; border-collapse: collapse; }
    .group-header th {
        background: #0f172a; color: #e2e8f0; padding: 10px 12px;
        font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px;
        border-right: 2px solid #1e293b;
    }
    .group-header th:last-child { border-right: none; }
    .col-header th {
        background: #1e293b; color: #cbd5e1; padding: 8px 12px;
        font-size: 11px; font-weight: 500; text-transform: uppercase; letter-spacing: 0.3px;
        border-right: 1px solid #334155;
    }
    .col-header th:last-child { border-right: none; }
    td {
        padding: 8px 12px; border-bottom: 1px solid #f1f5f9;
        font-size: 13px; white-space: nowrap;
    }
    tr:hover td { background: #f8fafc; }
    .device-name { font-weight: 600; color: #334155; }
    .last-sync { color: #94a3b8; font-size: 12px; }

    .status-impact { color: #d97706; font-weight: 600; }
    .status-warning { color: #d97706; font-weight: 500; font-style: italic; }
    .status-managed { color: #16a34a; font-weight: 600; }
    .status-safe { color: #64748b; }
    .status-error { color: #dc2626; font-weight: 600; }
    .status-na { color: #cbd5e1; }

    .toolbar {
        display: flex; gap: 12px; align-items: center; justify-content: space-between;
        margin-bottom: 12px; flex-wrap: wrap;
    }
    .toolbar .search-box {
        padding: 6px 12px; border: 1px solid #e2e8f0; border-radius: 6px;
        font-size: 13px; width: 260px; outline: none;
    }
    .toolbar .search-box:focus { border-color: #94a3b8; }
    .toolbar .page-size-select {
        padding: 6px 8px; border: 1px solid #e2e8f0; border-radius: 6px;
        font-size: 13px; background: white; outline: none;
    }
    .toolbar .result-count { font-size: 12px; color: #94a3b8; }
    .export-btn {
        padding: 6px 14px; border: 1px solid #e2e8f0; border-radius: 6px;
        font-size: 13px; background: white; cursor: pointer; color: #475569;
        transition: background 0.15s;
    }
    .export-btn:hover { background: #f1f5f9; }

    .pagination {
        display: flex; gap: 4px; align-items: center; justify-content: center;
        margin-top: 16px; flex-wrap: wrap;
    }
    .pagination button {
        padding: 4px 10px; border: 1px solid #e2e8f0; border-radius: 4px;
        background: white; font-size: 12px; cursor: pointer; color: #475569;
    }
    .pagination button:hover { background: #f1f5f9; }
    .pagination button.active { background: #1e293b; color: white; border-color: #1e293b; }
    .pagination button:disabled { opacity: 0.4; cursor: default; }
    .pagination .page-info { font-size: 12px; color: #94a3b8; margin: 0 8px; }

    th.sortable { cursor: pointer; user-select: none; }
    .col-header th.sortable:hover { background: #334155; }
    .group-header th.sortable:hover { background: #1e293b; }
    th.sort-asc::after { content: ' \25B2'; font-size: 9px; }
    th.sort-desc::after { content: ' \25BC'; font-size: 9px; }

    .legend { margin-top: 24px; text-align: center; font-size: 12px; color: #94a3b8; }
    .legend span { margin: 0 12px; }

    .footnote {
        max-width: 800px; margin: 16px auto 0; padding: 12px 16px;
        background: #f8fafc; border-left: 3px solid #94a3b8; border-radius: 4px;
        font-size: 12px; color: #64748b; line-height: 1.5;
    }
    .footnote strong { color: #475569; }

    @media print {
        body { background: white; padding: 0; }
        .card, .table-container { box-shadow: none; border: 1px solid #e5e7eb; }
        .toolbar, .pagination, .category-select-wrapper, .export-btn { display: none !important; }
        tbody tr { display: table-row !important; }
        .example-badge { display: none; }
    }
</style>
</head>
<body>

<div class="header">
    <div class="category-select-wrapper" id="categoryWrapper">
        <select id="categorySelect" class="category-select"></select>
    </div>
    <h1>macOS Service Impact Report</h1>
    <div id="subtitle" class="subtitle"></div>
    <div class="meta">Generated: <span id="generatedDate"></span></div>
    __REPORT_EXAMPLE_BADGE__
</div>

__REPORT_BANNER__

<div class="total-bar">
    <strong id="deviceCount">0</strong>
    devices reporting
</div>

<div id="usageHint" class="usage-hint"></div>

<div id="summaryCards" class="summary"></div>

<div class="toolbar">
    <div style="display:flex;gap:12px;align-items:center">
        <input type="text" class="search-box" id="searchBox" placeholder="Search devices...">
        <span class="result-count" id="resultCount"></span>
    </div>
    <div style="display:flex;gap:8px;align-items:center">
        <button class="export-btn" id="exportBtn">Export 0 rows</button>
        <label style="font-size:12px;color:#64748b">Rows per page:</label>
        <select class="page-size-select" id="pageSize">
            <option value="50">50</option>
            <option value="100">100</option>
            <option value="250" selected>250</option>
            <option value="500">500</option>
        </select>
    </div>
</div>

<div id="tableContainer" class="table-container"></div>

<div class="legend">
    <span><span class="dot dot-impact"></span> Will be impacted by enforcement</span>
    <span><span class="dot dot-managed"></span> Already managed by profile</span>
    <span><span class="dot dot-safe"></span> No impact expected</span>
</div>

<div class="pagination" id="pagination"></div>

<div id="footnotes"></div>

<script>var DATA = __REPORT_JSON_DATA__;</script>
<script>
(function() {
    var data = DATA;
    var activeCategory = null, searchQuery = '', activeCardFilters = [];
    var sortCol = -1, sortDir = 'asc', currentPage = 1, currentColumns = [], blobUrl = null;

    var categorySelect = document.getElementById('categorySelect');
    var categoryWrapper = document.getElementById('categoryWrapper');
    var searchBox = document.getElementById('searchBox');
    var summaryContainer = document.getElementById('summaryCards');
    var tableContainer = document.getElementById('tableContainer');
    var paginationContainer = document.getElementById('pagination');
    var resultCountEl = document.getElementById('resultCount');
    var exportBtn = document.getElementById('exportBtn');
    var subtitleEl = document.getElementById('subtitle');
    var footnotesEl = document.getElementById('footnotes');
    var pageSizeEl = document.getElementById('pageSize');

    function esc(s) {
        if (!s) return '';
        return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
    }

    function statusCls(st) {
        if (!st) return 'status-na';
        if (String(st).indexOf('Error:') === 0) return 'status-error';
        switch (st) {
            case 'Enabled': case 'Active': case 'LikelyEnabled': case 'Available':
                return 'status-impact';
            case 'PartiallyManaged': return 'status-warning';
            case 'BlockedByProfile': case 'AllBlocked': return 'status-managed';
            case 'Disabled': case 'Inactive': case 'Configured': case 'DisabledByUser':
            case 'NoiCloudAccount': case 'NotSupported': return 'status-safe';
            case 'N/A': case 'NoData': case 'Unknown': case 'NoUserLoggedIn':
                return 'status-na';
            default: return 'status-error';
        }
    }

    function getScripts() {
        if (activeCategory === 'all') {
            var s = [];
            data.meta.availableCategories.forEach(function(ck) {
                data.categories[ck].scripts.forEach(function(sk) {
                    if (s.indexOf(sk) === -1) s.push(sk);
                });
            });
            return s;
        }
        return data.categories[activeCategory].scripts.slice();
    }

    function buildCols() {
        var scripts = getScripts(), isAll = activeCategory === 'all', cols = [];
        cols.push({ key: '_name', label: 'Device Name', sk: null, isSt: false,
            gv: function(d) { return d.name || ''; } });

        if (isAll) {
            scripts.forEach(function(sk) {
                var def = data.scripts[sk];
                (function(k, df) {
                    cols.push({ key: k + '_s', label: df.label, sk: k, isSt: true,
                        gv: function(d) { var r = d.results[k]; return r ? (r.Status || 'N/A') : 'N/A'; } });
                })(sk, def);
            });
        } else {
            scripts.forEach(function(sk) {
                var def = data.scripts[sk];
                def.columns.forEach(function(col) {
                    (function(k, c) {
                        cols.push({ key: k + '_' + c.key, label: c.label, sk: k, isSt: !!c.isStatus,
                            group: data.scripts[k].label,
                            gv: function(d) {
                                var r = d.results[k];
                                if (!r) return c.isStatus ? 'N/A' : '';
                                var v = r[c.key];
                                return (v !== undefined && v !== null && v !== '') ? v : (c.isStatus ? 'N/A' : '');
                            } });
                    })(sk, col);
                });
            });
        }

        cols.push({ key: '_ls', label: 'Last Sync', sk: null, isSt: false,
            gv: function(d) { return d.lastSync || ''; } });
        return cols;
    }

    function renderSubtitle() {
        if (activeCategory === 'all') subtitleEl.textContent = 'All deployed services — consolidated overview';
        else if (data.categories[activeCategory]) subtitleEl.textContent = data.categories[activeCategory].subtitle;
        else subtitleEl.textContent = '';
    }

    function renderCards() {
        summaryContainer.innerHTML = '';
        var scripts = getScripts();
        scripts.forEach(function(scriptKey) {
            var def = data.scripts[scriptKey];
            if (!def) return;
            var card = document.createElement('div');
            card.className = 'card';
            var h3 = document.createElement('h3');
            h3.textContent = def.label;
            card.appendChild(h3);

            def.summaryCards.forEach(function(sc) {
                var count = 0;
                data.devices.forEach(function(dv) {
                    var r = dv.results[scriptKey];
                    if (r && sc.statuses.indexOf(r.Status) !== -1) count++;
                });
                var isAct = activeCardFilters.some(function(f) {
                    return f.sk === scriptKey && f.sts.join(',') === sc.statuses.join(',');
                });
                var row = document.createElement('div');
                row.className = 'stat-row' + (isAct ? ' card-filter-active' : '');
                (function(sk2, sts2) {
                    row.onclick = function() { toggleCard(sk2, sts2); };
                })(scriptKey, sc.statuses);
                row.innerHTML = '<span class="stat-label"><span class="dot dot-' + sc.dot + '"></span>' +
                    esc(sc.label) + '</span><span class="stat-count">' + count +
                    (isAct ? ' <span class="clear-x">&times;</span>' : '') + '</span>';
                card.appendChild(row);
            });

            var defined = [];
            def.summaryCards.forEach(function(sc) {
                sc.statuses.forEach(function(s) { if (defined.indexOf(s) === -1) defined.push(s); });
            });
            var oc = 0;
            data.devices.forEach(function(dv) {
                var r = dv.results[scriptKey];
                var st = r ? r.Status : 'N/A';
                if (defined.indexOf(st) === -1) oc++;
            });
            if (oc > 0) {
                var or2 = document.createElement('div');
                or2.className = 'stat-row no-click';
                or2.innerHTML = '<span class="stat-label"><span class="dot dot-other"></span>Other / No Data</span>' +
                    '<span class="stat-count">' + oc + '</span>';
                card.appendChild(or2);
            }
            summaryContainer.appendChild(card);
        });
    }

    function toggleCard(sk, sts) {
        var key = sk + ':' + sts.join(',');
        var idx = -1;
        for (var i = 0; i < activeCardFilters.length; i++) {
            if (activeCardFilters[i].sk === sk && activeCardFilters[i].sts.join(',') === sts.join(',')) { idx = i; break; }
        }
        if (idx >= 0) activeCardFilters.splice(idx, 1);
        else activeCardFilters.push({ sk: sk, sts: sts });
        currentPage = 1;
        render();
    }

    function renderTable(devices) {
        currentColumns = buildCols();
        var isAll = activeCategory === 'all', scripts = getScripts();
        var ps = parseInt(pageSizeEl.value, 10);
        var tp = Math.max(1, Math.ceil(devices.length / ps));
        if (currentPage > tp) currentPage = tp;
        var start = (currentPage - 1) * ps;
        var page = devices.slice(start, start + ps);

        var h = '<table id="reportTable"><thead>';
        if (!isAll) {
            h += '<tr class="group-header">';
            h += '<th rowspan="2" class="sortable" data-col="0">Device Name</th>';
            var ci = 1;
            scripts.forEach(function(sk) {
                var def = data.scripts[sk];
                h += '<th colspan="' + def.columns.length + '">' + esc(def.label) + '</th>';
                ci += def.columns.length;
            });
            h += '<th rowspan="2" class="sortable" data-col="' + ci + '">Last Sync</th></tr>';
            h += '<tr class="col-header">';
            ci = 1;
            scripts.forEach(function(sk) {
                data.scripts[sk].columns.forEach(function(c) {
                    h += '<th class="sortable" data-col="' + ci + '">' + esc(c.label) + '</th>';
                    ci++;
                });
            });
            h += '</tr>';
        } else {
            h += '<tr class="col-header">';
            currentColumns.forEach(function(c, i) {
                h += '<th class="sortable" data-col="' + i + '">' + esc(c.label) + '</th>';
            });
            h += '</tr>';
        }
        h += '</thead><tbody>';
        page.forEach(function(dv) {
            h += '<tr>';
            currentColumns.forEach(function(c) {
                var v = c.gv(dv), cls = '';
                if (c.key === '_name') cls = 'device-name';
                else if (c.key === '_ls') cls = 'last-sync';
                else if (c.isSt) cls = statusCls(v);
                h += '<td class="' + cls + '">' + esc(v) + '</td>';
            });
            h += '</tr>';
        });
        h += '</tbody></table>';
        tableContainer.innerHTML = h;
        resultCountEl.textContent = devices.length + ' of ' + data.devices.length + ' devices';

        var ths = tableContainer.querySelectorAll('th.sortable');
        for (var i = 0; i < ths.length; i++) {
            (function(th) {
                var ci2 = parseInt(th.getAttribute('data-col'), 10);
                th.onclick = function() {
                    if (sortCol === ci2) sortDir = sortDir === 'asc' ? 'desc' : 'asc';
                    else { sortCol = ci2; sortDir = 'asc'; }
                    currentPage = 1;
                    render();
                };
                if (ci2 === sortCol) th.classList.add(sortDir === 'asc' ? 'sort-asc' : 'sort-desc');
            })(ths[i]);
        }
        renderPag(tp);
    }

    function renderPag(tp) {
        paginationContainer.innerHTML = '';
        if (tp <= 1) return;
        function mk(txt, pg, dis) {
            var b = document.createElement('button');
            b.textContent = txt;
            b.disabled = !!dis;
            if (pg === currentPage && typeof txt === 'number') b.className = 'active';
            b.onclick = function() { currentPage = pg; render(); };
            return b;
        }
        paginationContainer.appendChild(mk('Previous', currentPage - 1, currentPage === 1));
        var mx = 7, sp = Math.max(1, currentPage - 3), ep = Math.min(tp, sp + mx - 1);
        if (ep - sp < mx - 1) sp = Math.max(1, ep - mx + 1);
        if (sp > 1) {
            paginationContainer.appendChild(mk(1, 1));
            if (sp > 2) { var d = document.createElement('span'); d.className = 'page-info'; d.textContent = '...'; paginationContainer.appendChild(d); }
        }
        for (var i = sp; i <= ep; i++) paginationContainer.appendChild(mk(i, i));
        if (ep < tp) {
            if (ep < tp - 1) { var d2 = document.createElement('span'); d2.className = 'page-info'; d2.textContent = '...'; paginationContainer.appendChild(d2); }
            paginationContainer.appendChild(mk(tp, tp));
        }
        var info = document.createElement('span');
        info.className = 'page-info';
        info.textContent = 'Page ' + currentPage + ' of ' + tp;
        paginationContainer.appendChild(info);
        paginationContainer.appendChild(mk('Next', currentPage + 1, currentPage === tp));
    }

    function renderFootnotes() {
        footnotesEl.innerHTML = '';
        getScripts().forEach(function(sk) {
            var def = data.scripts[sk];
            if (def && def.footnote) {
                var div = document.createElement('div');
                div.className = 'footnote';
                div.innerHTML = '<strong>' + esc(def.label) + ':</strong> ' + esc(def.footnote);
                footnotesEl.appendChild(div);
            }
        });
    }

    function buildExportFilename() {
        var parts = ['macOS_Service_Report'];
        if (activeCategory === 'all') parts.push('All_Services');
        else if (data.categories[activeCategory]) parts.push(data.categories[activeCategory].label.replace(/[^a-zA-Z0-9]+/g, '_'));
        activeCardFilters.forEach(function(f) {
            var def = data.scripts[f.sk];
            if (def) parts.push(def.shortLabel + '_' + f.sts.join('-'));
        });
        return parts.join('_') + '.csv';
    }

    function exportCsv(devices) {
        var cols = currentColumns, lines = [];
        lines.push(cols.map(function(c) {
            var lbl = c.label;
            if (c.sk && data.scripts[c.sk]) lbl = data.scripts[c.sk].label + ' - ' + c.label;
            return '"' + lbl.replace(/"/g, '""') + '"';
        }).join(','));
        devices.forEach(function(dv) {
            lines.push(cols.map(function(c) {
                return '"' + String(c.gv(dv)).replace(/"/g, '""') + '"';
            }).join(','));
        });
        var csv = '\ufeff' + lines.join('\n');
        if (blobUrl) URL.revokeObjectURL(blobUrl);
        var blob = new Blob([csv], { type: 'text/csv;charset=utf-8' });
        blobUrl = URL.createObjectURL(blob);
        var a = document.createElement('a');
        a.href = blobUrl;
        a.download = buildExportFilename();
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
    }

    function render() {
        renderSubtitle();
        renderCards();
        var devices = data.devices.slice();

        if (activeCardFilters.length > 0) {
            // Group filters by script key: OR within same script, AND across scripts
            var byScript = {};
            activeCardFilters.forEach(function(f) {
                if (!byScript[f.sk]) byScript[f.sk] = [];
                f.sts.forEach(function(s) { if (byScript[f.sk].indexOf(s) === -1) byScript[f.sk].push(s); });
            });
            var scriptKeys = Object.keys(byScript);
            devices = devices.filter(function(dv) {
                for (var i = 0; i < scriptKeys.length; i++) {
                    var r = dv.results[scriptKeys[i]];
                    var st = r ? r.Status : 'N/A';
                    if (byScript[scriptKeys[i]].indexOf(st) === -1) return false;
                }
                return true;
            });
        }

        if (searchQuery) {
            var q = searchQuery.toLowerCase(), scripts = getScripts();
            devices = devices.filter(function(dv) {
                if (dv.name.toLowerCase().indexOf(q) !== -1) return true;
                for (var i = 0; i < scripts.length; i++) {
                    var r = dv.results[scripts[i]];
                    if (r) { var ks = Object.keys(r); for (var j = 0; j < ks.length; j++) {
                        if (String(r[ks[j]]).toLowerCase().indexOf(q) !== -1) return true;
                    }}
                }
                return dv.lastSync && dv.lastSync.toLowerCase().indexOf(q) !== -1;
            });
        }

        if (sortCol >= 0) {
            var cols = buildCols();
            devices.sort(function(a, b) {
                var av = cols[sortCol] ? cols[sortCol].gv(a) : '';
                var bv = cols[sortCol] ? cols[sortCol].gv(b) : '';
                var an = parseFloat(av), bn = parseFloat(bv);
                var c = (!isNaN(an) && !isNaN(bn)) ? an - bn : String(av).localeCompare(String(bv));
                return sortDir === 'asc' ? c : -c;
            });
        }

        renderTable(devices);
        var fc = devices.length;
        exportBtn.textContent = 'Export ' + fc + ' rows';
        exportBtn.onclick = function() { exportCsv(devices); };
        renderFootnotes();
    }

    // --- Init ---
    document.getElementById('deviceCount').textContent = data.devices.length;
    document.getElementById('generatedDate').textContent = data.meta.generated;

    var cats = data.meta.availableCategories;
    if (!cats || cats.length === 0) return;

    if (cats.length <= 1) {
        categoryWrapper.style.display = 'none';
        activeCategory = cats[0];
    } else {
        cats.forEach(function(ck) {
            var opt = document.createElement('option');
            opt.value = ck;
            opt.textContent = data.categories[ck].label;
            categorySelect.appendChild(opt);
        });
        var allOpt = document.createElement('option');
        allOpt.value = 'all';
        allOpt.textContent = 'All Services';
        categorySelect.appendChild(allOpt);
        activeCategory = cats[0];
        categorySelect.value = activeCategory;
        categorySelect.onchange = function() {
            activeCategory = this.value;
            activeCardFilters = [];
            searchQuery = '';
            searchBox.value = '';
            sortCol = -1; sortDir = 'asc'; currentPage = 1;
            render();
        };
    }

    searchBox.oninput = function() { searchQuery = this.value; currentPage = 1; render(); };
    pageSizeEl.onchange = function() { currentPage = 1; render(); };

    var hints = [];
    if (cats.length > 1) hints.push('Switch categories using the dropdown in the top-right corner.');
    hints.push('Click a summary card count to filter the table. Click the same card again to clear the filter.');
    hints.push('Click any column header to sort.');
    document.getElementById('usageHint').textContent = hints.join(' ');

    render();
})();
</script>
</body>
</html>
'@

# ============================================================================
# Main execution
# ============================================================================

if (-not $Force) {
    Show-DutchCowboyBanner -Subtitle "macOS Service Impact Report"
}

# --- Determine which categories/scripts to query ---
$categoriesToQuery = if ('all' -in $Categories) {
    @($CategoryDefinitions.Keys)
} else {
    $Categories | Where-Object { $CategoryDefinitions.ContainsKey($_) }
}

$scriptKeysToQuery = [System.Collections.Generic.List[string]]::new()
foreach ($cat in $categoriesToQuery) {
    foreach ($sk in $CategoryDefinitions[$cat].scripts) {
        if ($sk -notin $scriptKeysToQuery) {
            $scriptKeysToQuery.Add($sk)
        }
    }
}

# --- Check for required module ---
$moduleName = "Microsoft.Graph.Authentication"
if (-not (Get-Module -ListAvailable -Name $moduleName)) {
    Write-Host "Required module '$moduleName' not found." -ForegroundColor Red
    Write-Host "Install it with: Install-Module $moduleName -Scope CurrentUser" -ForegroundColor Yellow
    exit 1
}
Import-Module $moduleName -ErrorAction Stop

# --- Ensure output directory exists ---
if (-not (Test-Path -Path $OutputPath)) {
    New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
}

# --- Connect to Microsoft Graph ---
$scopes = @(
    "DeviceManagementConfiguration.Read.All",
    "DeviceManagementManagedDevices.Read.All"
)
try {

Write-Host ""
Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan
Connect-MgGraph -Scopes $scopes -ErrorAction Stop
Write-Host "Connected successfully." -ForegroundColor Green

# --- Confirm script names before querying ---
if (-not $Force) {
    Write-Host ""
    Write-Host "The report will look for these custom attribute scripts in Intune:" -ForegroundColor Cyan
    $scriptIdx = 1
    foreach ($sk in $scriptKeysToQuery) {
        Write-Host "  $scriptIdx. $($ScriptRegistry[$sk].displayName)" -ForegroundColor White
        $scriptIdx++
    }
    Write-Host ""
    Write-Host "If you renamed them in Intune, re-run with the appropriate -Name parameter." -ForegroundColor Gray
    $confirm = Read-Host "Do the names match your Intune setup? (Y/n)"
    if ($confirm -and $confirm.Trim().ToLower() -eq 'n') {
        Write-Host "Exiting. Re-run with the correct script names." -ForegroundColor Yellow
        exit 0
    }
}

# --- Fetch custom attribute shell scripts ---
Write-Host ""
Write-Host "Fetching custom attribute scripts from Intune..." -ForegroundColor Cyan
$scriptsUri = "https://graph.microsoft.com/beta/deviceManagement/deviceCustomAttributeShellScripts"
$allScripts = Get-AllGraphResult -Uri $scriptsUri -DelayMs $ThrottleDelayMs
Write-Host "  Found $($allScripts.Count) custom attribute script(s) in Intune." -ForegroundColor Gray

# --- Match scripts by display name ---
$scriptMap = @{}  # key: registry key, value: Graph API script object

foreach ($graphScript in $allScripts) {
    foreach ($sk in $scriptKeysToQuery) {
        if ($graphScript.displayName -eq $ScriptRegistry[$sk].displayName) {
            $scriptMap[$sk] = $graphScript
        }
    }
}

# --- Report what was found ---
$foundScriptKeys = @($scriptKeysToQuery | Where-Object { $scriptMap.ContainsKey($_) })

Write-Host ""
Write-Host "Queried categories: $($categoriesToQuery -join ', ')" -ForegroundColor Cyan
Write-Host "Found scripts:      $($foundScriptKeys.Count) of $($scriptKeysToQuery.Count)" -ForegroundColor Cyan

foreach ($sk in $scriptKeysToQuery) {
    if ($sk -in $foundScriptKeys) {
        Write-Host "  [OK] $($ScriptRegistry[$sk].displayName)" -ForegroundColor Green
    } else {
        Write-Host "  [--] $($ScriptRegistry[$sk].displayName) (not found)" -ForegroundColor Yellow
    }
}

if ($foundScriptKeys.Count -eq 0) {
    Write-Host ""
    Write-Host "No matching scripts found. Exiting." -ForegroundColor Red
    Write-Host ""
    Write-Host "Available scripts in your tenant:" -ForegroundColor Gray
    foreach ($s in $allScripts) {
        Write-Host "  - $($s.displayName)" -ForegroundColor Gray
    }
    exit 1
}

# Determine which categories have at least one found script
$foundCategories = [System.Collections.Generic.List[string]]::new()
foreach ($catKey in $CategoryDefinitions.Keys) {
    $catScripts = $CategoryDefinitions[$catKey].scripts | Where-Object { $_ -in $foundScriptKeys }
    if ($catScripts) {
        $foundCategories.Add($catKey)
    }
}

$skippedCategories = @($categoriesToQuery | Where-Object { $_ -notin $foundCategories })

Write-Host ""
$foundCatLabels = @($foundCategories | ForEach-Object { $CategoryDefinitions[$_].label })
Write-Host "Report will include: $($foundCatLabels -join ', ')" -ForegroundColor Green
if ($skippedCategories.Count -gt 0) {
    $skippedLabels = @($skippedCategories | ForEach-Object { $CategoryDefinitions[$_].label })
    Write-Host "Skipped (no scripts found): $($skippedLabels -join ', ')" -ForegroundColor Yellow
}

# --- Fetch device run states for each found script ---
Write-Host ""
$deviceData = @{}  # Key: deviceName (lowercase), Value: hashtable

foreach ($scriptKey in $foundScriptKeys) {
    $scriptObj = $scriptMap[$scriptKey]

    Write-Host "Fetching device results for '$($scriptObj.displayName)'..." -ForegroundColor Cyan
    $runStatesUri = "https://graph.microsoft.com/beta/deviceManagement/deviceCustomAttributeShellScripts/$($scriptObj.id)/deviceRunStates?`$expand=managedDevice(`$select=deviceName,id)"
    $runStates = Get-AllGraphResult -Uri $runStatesUri -DelayMs $ThrottleDelayMs
    Write-Host "  Retrieved $($runStates.Count) device result(s)." -ForegroundColor Gray

    foreach ($state in $runStates) {
        $devName = $state.managedDevice.deviceName
        if ([string]::IsNullOrWhiteSpace($devName)) {
            $devName = $state.managedDevice.id
        }
        if ([string]::IsNullOrWhiteSpace($devName)) { continue }

        $devKey = $devName.ToLower()
        if (-not $deviceData.ContainsKey($devKey)) {
            $deviceData[$devKey] = @{
                DeviceName = $devName
                LastSync   = $null
            }
        }

        # Use error code if present
        $resultMessage = $state.resultMessage
        if ($state.errorCode -and $state.errorCode -ne 0) {
            $resultMessage = "Error:Code$($state.errorCode)"
        }

        $parsed = ConvertFrom-CustomAttributeResult -ResultMessage $resultMessage
        $deviceData[$devKey][$scriptKey] = $parsed

        # Track most recent sync time
        if ($state.lastStateUpdateDateTime) {
            try {
                $syncTime = [datetime]$state.lastStateUpdateDateTime
                $currentLast = $deviceData[$devKey]['LastSync']
                if (-not $currentLast -or $syncTime -gt $currentLast) {
                    $deviceData[$devKey]['LastSync'] = $syncTime
                }
            }
            catch {
                Write-Verbose "Could not parse date for device '$devName': $_"
            }
        }
    }
}

if ($deviceData.Count -eq 0) {
    Write-Host ""
    Write-Host "No device results found. The scripts may not have run yet." -ForegroundColor Yellow
    exit 0
}

# ============================================================================
# Build JSON data blob
# ============================================================================

Write-Host ""
Write-Host "Building report for $($deviceData.Count) device(s)..." -ForegroundColor Cyan

# Build the JSON structure
$jsonData = [ordered]@{
    meta = [ordered]@{
        generated           = (Get-Date -Format 'yyyy-MM-dd HH:mm')
        deviceCount         = $deviceData.Count
        availableCategories = @($foundCategories)
    }
    categories = [ordered]@{}
    scripts    = [ordered]@{}
    devices    = @()
}

# Categories (only those with found scripts)
foreach ($catKey in $foundCategories) {
    $catScripts = @($CategoryDefinitions[$catKey].scripts | Where-Object { $_ -in $foundScriptKeys })
    $jsonData.categories[$catKey] = [ordered]@{
        label    = $CategoryDefinitions[$catKey].label
        subtitle = $CategoryDefinitions[$catKey].subtitle
        scripts  = $catScripts
    }
}

# Script definitions (only found scripts)
foreach ($sk in $foundScriptKeys) {
    $reg = $ScriptRegistry[$sk]
    $jsonData.scripts[$sk] = [ordered]@{
        label        = $reg.label
        shortLabel   = $reg.shortLabel
        columns      = $reg.columns
        summaryCards = $reg.summaryCards
        footnote     = $reg.footnote
    }
}

# Device data
$deviceList = [System.Collections.Generic.List[object]]::new()
foreach ($devKey in ($deviceData.Keys | Sort-Object)) {
    $dev = $deviceData[$devKey]
    $results = [ordered]@{}
    foreach ($sk in $foundScriptKeys) {
        if ($dev[$sk]) {
            $results[$sk] = $dev[$sk]
        }
    }
    $lastSyncStr = ''
    if ($dev['LastSync']) {
        $lastSyncStr = $dev['LastSync'].ToString('yyyy-MM-dd HH:mm')
    }
    $deviceList.Add([ordered]@{
        name     = $dev['DeviceName']
        lastSync = $lastSyncStr
        results  = $results
    })
}
$jsonData.devices = @($deviceList)

$jsonBlob = $jsonData | ConvertTo-Json -Depth 10 -Compress
# Prevent </script> injection in JSON values
$safeJson = $jsonBlob.Replace('</', '<\/')

# ============================================================================
# Export CSV
# ============================================================================

$timestamp = Get-Date -Format 'yyyy-MM-dd_HHmm'
$csvPath = Join-Path $OutputPath "macOS_Service_Report_$timestamp.csv"

# Condensed CSV if multiple categories, full detail if single category
$isCondensedCsv = $foundCategories.Count -gt 1

$csvRows = foreach ($devKey in ($deviceData.Keys | Sort-Object)) {
    $dev = $deviceData[$devKey]
    $row = [ordered]@{ 'Device Name' = $dev['DeviceName'] }

    foreach ($sk in $foundScriptKeys) {
        $reg = $ScriptRegistry[$sk]
        $parsed = if ($dev[$sk]) { $dev[$sk] } else { [ordered]@{ Status = 'N/A' } }

        if ($isCondensedCsv) {
            $row["$($reg.shortLabel) Status"] = $parsed['Status']
        } else {
            foreach ($col in $reg.columns) {
                $colName = "$($reg.shortLabel) $($col.label)"
                $val = $parsed[$col.key]
                if ([string]::IsNullOrEmpty($val)) {
                    $val = if ($col.isStatus) { 'N/A' } else { '' }
                }
                $row[$colName] = $val
            }
        }
    }

    $row['Last Sync'] = if ($dev['LastSync']) { $dev['LastSync'].ToString('yyyy-MM-dd HH:mm') } else { '' }
    [PSCustomObject]$row
}

$csvRows | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
Write-Host ""
Write-Host "CSV report saved: $csvPath" -ForegroundColor Green

# ============================================================================
# Generate HTML report
# ============================================================================

$htmlPath = Join-Path $OutputPath "macOS_Service_Report_$timestamp.html"

# Banner
$bannerHtml = ''
if (-not $NoBanner) {
    $bannerGifPath = Join-Path $PSScriptRoot "dutchcowboy_matrix_450w_oncerun.gif"
    if (Test-Path $bannerGifPath) {
        $gifBytes = [System.IO.File]::ReadAllBytes($bannerGifPath)
        $gifBase64 = [System.Convert]::ToBase64String($gifBytes)
        $bannerHtml = "<div style=`"text-align:center;margin-bottom:24px`"><img src=`"data:image/gif;base64,$gifBase64`" width=`"340`" alt=`"#DutchCowboy`"></div>"
    }
    else {
        Write-Host "  Banner GIF not found at: $bannerGifPath — skipping." -ForegroundColor Yellow
    }
}

# Assemble HTML from template
$htmlContent = $HtmlTemplate.Replace('__REPORT_JSON_DATA__', $safeJson).Replace('__REPORT_BANNER__', $bannerHtml).Replace('__REPORT_EXAMPLE_BADGE__', '')

$htmlContent | Out-File -FilePath $htmlPath -Encoding UTF8
Write-Host "HTML report saved: $htmlPath" -ForegroundColor Green

# ============================================================================
# Console summary
# ============================================================================

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host " Report Summary" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Total devices:  $($deviceData.Count)"

foreach ($sk in $foundScriptKeys) {
    $reg = $ScriptRegistry[$sk]
    Write-Host ""
    Write-Host "  $($reg.label):" -ForegroundColor White

    foreach ($sc in $reg.summaryCards) {
        $count = 0
        foreach ($devKey in $deviceData.Keys) {
            $parsed = $deviceData[$devKey][$sk]
            if ($parsed -and $sc.statuses -contains $parsed['Status']) {
                $count++
            }
        }
        $color = switch ($sc.dot) {
            'impact'  { 'Yellow' }
            'warning' { 'Yellow' }
            'managed' { 'Green' }
            'safe'    { 'Gray' }
            default   { 'DarkGray' }
        }
        $padLabel = $sc.label.PadRight(32)
        Write-Host "    ${padLabel}: $count" -ForegroundColor $color
    }

    # Count "other"
    $definedStatuses = @()
    foreach ($sc in $reg.summaryCards) {
        $definedStatuses += $sc.statuses
    }
    $otherCount = 0
    foreach ($devKey in $deviceData.Keys) {
        $parsed = $deviceData[$devKey][$sk]
        $status = if ($parsed) { $parsed['Status'] } else { 'N/A' }
        if ($status -notin $definedStatuses) { $otherCount++ }
    }
    if ($otherCount -gt 0) {
        $padOther = "Other / No Data".PadRight(32)
        Write-Host "    ${padOther}: $otherCount" -ForegroundColor DarkGray
    }
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  CSV:  $csvPath" -ForegroundColor White
Write-Host "  HTML: $htmlPath" -ForegroundColor White
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

} # end try
finally {
    Disconnect-MgGraph | Out-Null
}

# --- Open HTML report ---
if (Test-Path $htmlPath) {
    Invoke-Item $htmlPath
}
