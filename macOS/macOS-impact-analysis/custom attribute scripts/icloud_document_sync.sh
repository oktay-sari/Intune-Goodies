#!/bin/bash
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
#   This script passes shellcheck static analysis.
#   Run: shellcheck icloud_document_sync.sh
# =============================================================================
# Intune Custom Attribute: iCloud Document Sync (iCloud Drive)
# NOTE: 
# Intune display name: "macOS - iCloud Document Sync"
#   (Get-iCloudServiceReport.ps1 looks for this name to pull results)
#
# Purpose: Detect if iCloud Drive is active and report total data size,
#          Optimize Storage status, and whether a managed profile already
#          restricts the feature.
#          Covers general document sync including app-specific containers
#          (Pages, Numbers, Keynote, third-party apps).
#          Used for impact analysis before implementing BIO 7.1.
#
# Managed preference key:
#   com.apple.applicationaccess -> allowCloudDocumentSync
#
# Output format: Status|Size:X.XXgb|Optimize Storage:X|Setting Managed:X
# Max output length: kept compact by design (Intune limit is 20KB)
# Anonymized: No user info, device-level only.
# =============================================================================

# --- Helper: format size (MB -> GB when >= 1024) ---
format_size() {
    local mb="$1"
    if [[ "$mb" -ge 1024 ]]; then
        local hundredths=$(( mb * 100 / 1024 ))
        local whole=$(( hundredths / 100 ))
        local frac=$(( hundredths % 100 ))
        printf '%d.%02dgb' "$whole" "$frac"
    else
        printf '%dmb' "$mb"
    fi
}

# Get the currently logged-in user
currentUser=$(stat -f "%Su" /dev/console)
if [[ "$currentUser" == "loginwindow" || -z "$currentUser" ]]; then
    echo "NoUserLoggedIn"
    exit 0
fi

# --- Check managed profile restriction (system-wide, no home dir needed) ---
# Key: allowCloudDocumentSync (com.apple.applicationaccess)
# Source: mSCP icloud_drive_disable rule / BIO 7.1
managedValue=$(/usr/bin/osascript -l JavaScript -e \
    '$.NSUserDefaults.alloc.initWithSuiteName("com.apple.applicationaccess").objectForKey("allowCloudDocumentSync").js' 2>/dev/null)
if [[ "$managedValue" == "false" ]]; then
    echo "BlockedByProfile|Size:N/A|Optimize Storage:N/A|Setting Managed:Yes"
    exit 0
fi

# --- Get home directory (retry once for login race condition) ---
userHome=$(dscl . -read /Users/"$currentUser" NFSHomeDirectory 2>/dev/null | awk '{print $2}')
if [[ -z "$userHome" || ! -d "$userHome" ]]; then
    sleep 5
    userHome=$(dscl . -read /Users/"$currentUser" NFSHomeDirectory 2>/dev/null | awk '{print $2}')
fi
if [[ -z "$userHome" || ! -d "$userHome" ]]; then
    echo "Unknown|Size:Unknown|Optimize Storage:Unknown|Setting Managed:No"
    exit 0
fi

mobileDocsPath="$userHome/Library/Mobile Documents"

# Check if Mobile Documents folder exists
if [[ ! -d "$mobileDocsPath" ]]; then
    echo "Disabled|Size:0mb|Optimize Storage:Unknown|Setting Managed:No"
    exit 0
fi

# --- Check Optimize Mac Storage ---
optimizedStorage="Unknown"
birdPlist="$userHome/Library/Preferences/com.apple.bird.plist"
if [[ -f "$birdPlist" ]]; then
    optValue=$(/usr/bin/defaults read "$birdPlist" optimize-storage 2>/dev/null)
    if [[ "$optValue" == "1" || "$optValue" == "true" ]]; then
        optimizedStorage="Yes"
    elif [[ "$optValue" == "0" || "$optValue" == "false" ]]; then
        optimizedStorage="No"
    fi
fi

# Calculate total size excluding Desktop & Documents (reported separately by BIO 7.3 script)
# du -smL follows symlinks (macOS creates symlinks for Desktop & Documents sync)
cloudDocsDesktop="$mobileDocsPath/com~apple~CloudDocs/Desktop"
cloudDocsDocuments="$mobileDocsPath/com~apple~CloudDocs/Documents"

totalSizeMB=$(du -smL "$mobileDocsPath" 2>/dev/null | awk '{print $1}')
[[ -z "$totalSizeMB" ]] && totalSizeMB=0

ddSizeMB=0
if [[ -e "$cloudDocsDesktop" ]]; then
    desktopSize=$(du -smL "$cloudDocsDesktop" 2>/dev/null | awk '{print $1}')
    ddSizeMB=$((ddSizeMB + ${desktopSize:-0}))
fi
if [[ -e "$cloudDocsDocuments" ]]; then
    docsSize=$(du -smL "$cloudDocsDocuments" 2>/dev/null | awk '{print $1}')
    ddSizeMB=$((ddSizeMB + ${docsSize:-0}))
fi

netSizeMB=$((totalSizeMB - ddSizeMB))
[[ $netSizeMB -lt 0 ]] && netSizeMB=0

# Check if any app containers exist (directories in Mobile Documents)
containerCount=$(find "$mobileDocsPath" -maxdepth 1 -type d 2>/dev/null | grep -cv "^${mobileDocsPath}$")

# Format size for human readability
netSize=$(format_size "$netSizeMB")

if [[ $containerCount -gt 0 && $totalSizeMB -gt 0 ]]; then
    echo "Active|Size:${netSize}|Optimize Storage:${optimizedStorage}|Setting Managed:No"
elif [[ $containerCount -gt 0 ]]; then
    echo "Configured|Size:0mb|Optimize Storage:${optimizedStorage}|Setting Managed:No"
else
    echo "Inactive|Size:0mb|Optimize Storage:${optimizedStorage}|Setting Managed:No"
fi

exit 0
