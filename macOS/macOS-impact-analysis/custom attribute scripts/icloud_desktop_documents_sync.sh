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
#   Run: shellcheck icloud_desktop_documents_sync.sh
# =============================================================================
# Intune Custom Attribute: iCloud Desktop & Documents Sync
# NOTE: 
# Intune display name: "macOS - iCloud Desktop Documents Sync"
#   (Get-iCloudServiceReport.ps1 looks for this name to pull results)
#
# Purpose: Detect if iCloud Desktop & Documents sync is enabled and report
#          data size, Optimize Storage status, and whether a managed profile
#          already restricts the feature.
#          Used for impact analysis before implementing BIO 7.3 / CIS 2.1.1.3.
#
# Managed preference key:
#   com.apple.applicationaccess -> allowCloudDesktopAndDocuments
#
# Output format: Status|Desktop:X.XXgb|Documents:X.XXgb|Optimize Storage:X|Setting Managed:X
# Max output length: kept compact by design (Intune limit is 20KB)
# Anonymized: No user info, device-level only.
#
# Notes:
#   - macOS creates symlinks (not copies) for Desktop & Documents sync:
#     ~/Library/Mobile Documents/com~apple~CloudDocs/Desktop -> ~/Desktop
#     du -smL (follow symlinks) is required to measure actual data size.
#   - Sizes shown in GB (>= 1024mb) or mb (< 1024mb) for readability.
# =============================================================================

# --- Helper: format size (MB -> GB when >= 1024) ---
format_size() {
    local mb="$1"
    if [[ "$mb" -ge 1024 ]]; then
        # Integer division to two decimal places: mb * 100 / 1024, then insert dot
        local hundredths=$(( mb * 100 / 1024 ))
        local whole=$(( hundredths / 100 ))
        local frac=$(( hundredths % 100 ))
        printf '%d.%02dgb' "$whole" "$frac"
    else
        printf '%dmb' "$mb"
    fi
}

# Get the currently logged-in user (skip if loginwindow)
currentUser=$(stat -f "%Su" /dev/console)
if [[ "$currentUser" == "loginwindow" || -z "$currentUser" ]]; then
    echo "NoUserLoggedIn"
    exit 0
fi

# --- Check managed profile restriction (system-wide, no home dir needed) ---
# Key: allowCloudDesktopAndDocuments (com.apple.applicationaccess)
# Source: mSCP icloud_sync_disable rule / CIS 2.1.1.3 / BIO 7.3
managedValue=$(/usr/bin/osascript -l JavaScript -e \
    '$.NSUserDefaults.alloc.initWithSuiteName("com.apple.applicationaccess").objectForKey("allowCloudDesktopAndDocuments").js' 2>/dev/null)
if [[ "$managedValue" == "false" ]]; then
    echo "BlockedByProfile|Desktop:N/A|Documents:N/A|Optimize Storage:N/A|Setting Managed:Yes"
    exit 0
fi

# --- Get home directory (retry once for login race condition) ---
userHome=$(dscl . -read /Users/"$currentUser" NFSHomeDirectory 2>/dev/null | awk '{print $2}')
if [[ -z "$userHome" || ! -d "$userHome" ]]; then
    sleep 5
    userHome=$(dscl . -read /Users/"$currentUser" NFSHomeDirectory 2>/dev/null | awk '{print $2}')
fi
if [[ -z "$userHome" || ! -d "$userHome" ]]; then
    echo "Unknown|Desktop:Unknown|Documents:Unknown|Optimize Storage:Unknown|Setting Managed:No"
    exit 0
fi

# Paths to iCloud Desktop & Documents sync folders
iCloudBase="$userHome/Library/Mobile Documents/com~apple~CloudDocs"
iCloudDesktop="$iCloudBase/Desktop"
iCloudDocuments="$iCloudBase/Documents"

# Check if the iCloud CloudDocs base folder exists at all
if [[ ! -d "$iCloudBase" ]]; then
    echo "Disabled|iCloudDriveNotActive|Setting Managed:No"
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

# --- Check Desktop sync ---
# du -smL follows symlinks (macOS creates symlinks for Desktop & Documents sync)
desktopEnabled="No"
desktopSizeMB=0
if [[ -e "$iCloudDesktop" ]]; then
    desktopEnabled="Yes"
    desktopSizeMB=$(du -smL "$iCloudDesktop" 2>/dev/null | awk '{print $1}')
    [[ -z "$desktopSizeMB" ]] && desktopSizeMB=0
fi

# --- Check Documents sync ---
documentsEnabled="No"
documentsSizeMB=0
if [[ -e "$iCloudDocuments" ]]; then
    documentsEnabled="Yes"
    documentsSizeMB=$(du -smL "$iCloudDocuments" 2>/dev/null | awk '{print $1}')
    [[ -z "$documentsSizeMB" ]] && documentsSizeMB=0
fi

# Format sizes for human readability
desktopSize=$(format_size "$desktopSizeMB")
documentsSize=$(format_size "$documentsSizeMB")

# Determine overall status
if [[ "$desktopEnabled" == "Yes" || "$documentsEnabled" == "Yes" ]]; then
    echo "Enabled|Desktop:${desktopSize}|Documents:${documentsSize}|Optimize Storage:${optimizedStorage}|Setting Managed:No"
else
    echo "Disabled|Desktop:0mb|Documents:0mb|Optimize Storage:${optimizedStorage}|Setting Managed:No"
fi

exit 0
