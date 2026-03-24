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
#   Run: shellcheck icloud_keychain_sync.sh
# =============================================================================
# Intune Custom Attribute: iCloud Keychain Sync
# NOTE: 
# Intune display name: "macOS - iCloud Keychain Sync"
#   (Get-iCloudServiceReport.ps1 looks for this name to pull results)
#
# Purpose: Detect if iCloud Keychain sync is enabled on the device.
#          Used for impact analysis before implementing BIO 7.2 /
#          CIS 2.1.1.1 (Level 2 audit).
#
# Managed preference key:
#   com.apple.applicationaccess -> allowCloudKeychainSync
#
# Detection approach:
#   iCloud Keychain is enabled by default when signing into iCloud.
#   Rather than relying on file artifacts that change across macOS versions
#   (cloudkeychainproxy3.plist, keychain-2.db-wal), this script uses:
#   1. Managed preference check (definitive when profile blocks it)
#   2. ~/Library/Mobile Documents existence (proves iCloud is signed in)
#   3. MobileMeAccounts.plist as internal fallback (fresh sign-in edge case)
#   If iCloud is active and no profile blocks keychain sync, it is almost
#   certainly enabled (opt-out, not opt-in).
#
# Output format: Status|iCloud Account:X|Setting Managed:X
# Max output length: kept compact by design (Intune limit is 20KB)
# Anonymized: No user info, device-level only.
# =============================================================================

# Get the currently logged-in user
currentUser=$(stat -f "%Su" /dev/console)
if [[ "$currentUser" == "loginwindow" || -z "$currentUser" ]]; then
    echo "NoUserLoggedIn"
    exit 0
fi

# --- Check 1: Managed profile restriction (system-wide, no home dir needed) ---
# Key: allowCloudKeychainSync (com.apple.applicationaccess)
# Source: mSCP icloud_keychain_disable rule / BIO 7.2 / CIS 2.1.1.1
managedValue=$(/usr/bin/osascript -l JavaScript -e \
    '$.NSUserDefaults.alloc.initWithSuiteName("com.apple.applicationaccess").objectForKey("allowCloudKeychainSync").js' 2>/dev/null)
if [[ "$managedValue" == "false" ]]; then
    echo "BlockedByProfile|iCloud Account:N/A|Setting Managed:Yes"
    exit 0
fi

# --- Get home directory (retry once for login race condition) ---
userHome=$(dscl . -read /Users/"$currentUser" NFSHomeDirectory 2>/dev/null | awk '{print $2}')
if [[ -z "$userHome" || ! -d "$userHome" ]]; then
    sleep 5
    userHome=$(dscl . -read /Users/"$currentUser" NFSHomeDirectory 2>/dev/null | awk '{print $2}')
fi
if [[ -z "$userHome" || ! -d "$userHome" ]]; then
    echo "Unknown|iCloud Account:Unknown|Setting Managed:No"
    exit 0
fi

# --- Check 2: iCloud account presence ---
# Primary: ~/Library/Mobile Documents exists when iCloud is signed in
# Fallback: MobileMeAccounts.plist for fresh sign-in edge case
iCloudActive="No"
mobileDocsPath="$userHome/Library/Mobile Documents"

if [[ -d "$mobileDocsPath" ]]; then
    iCloudActive="Yes"
fi

# Fallback: if Mobile Documents doesn't exist yet but MobileMe shows an account
if [[ "$iCloudActive" == "No" ]]; then
    mobileMePlist="$userHome/Library/Preferences/MobileMeAccounts.plist"
    if [[ -f "$mobileMePlist" ]]; then
        accountCount=$(/usr/bin/defaults read "$mobileMePlist" Accounts 2>/dev/null | grep -c "AccountID")
        if [[ $accountCount -gt 0 ]]; then
            iCloudActive="Yes"
        fi
    fi
fi

# --- Determine status ---
# iCloud Keychain is enabled by default when iCloud is signed in.
# If no managed profile blocks it, it is almost certainly active.
if [[ "$iCloudActive" == "Yes" ]]; then
    status="LikelyEnabled"
else
    status="NoiCloudAccount"
fi

echo "${status}|iCloud Account:${iCloudActive}|Setting Managed:No"

exit 0
