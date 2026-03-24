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
#   Run: shellcheck airdrop_status.sh
# =============================================================================
# Intune Custom Attribute: AirDrop Status
# NOTE:
# Intune display name: "macOS - AirDrop Status"
#
# Purpose: Detect if AirDrop is enabled and report discoverability setting
#          and whether a managed profile already restricts the feature.
#          Used for impact analysis before implementing CIS 2.3.1.1 (Level 1).
#
# Managed preference key:
#   com.apple.applicationaccess -> allowAirDrop
#
# Detection approach:
#   1. Managed preference check (definitive when profile blocks it)
#   2. AirDrop discoverability setting per user
#      (Off / Contacts Only / Everyone)
#
# Output format: Status|Discovery:X|Setting Managed:X
# Max output length: kept compact by design (Intune limit is 20KB)
# Anonymized: No user info, device-level only.
# =============================================================================

# Get the currently logged-in user (skip if loginwindow)
currentUser=$(stat -f "%Su" /dev/console)
if [[ "$currentUser" == "loginwindow" || -z "$currentUser" ]]; then
    echo "NoUserLoggedIn"
    exit 0
fi

# --- Check managed profile restriction (system-wide, no home dir needed) ---
# Key: allowAirDrop (com.apple.applicationaccess)
# Source: mSCP os_airdrop_disable rule / CIS 2.3.1.1
managedValue=$(/usr/bin/osascript -l JavaScript -e \
    '$.NSUserDefaults.alloc.initWithSuiteName("com.apple.applicationaccess").objectForKey("allowAirDrop").js' 2>/dev/null)
if [[ "$managedValue" == "false" ]]; then
    echo "BlockedByProfile|Discovery:N/A|Setting Managed:Yes"
    exit 0
fi

# --- Get home directory (retry once for login race condition) ---
userHome=$(dscl . -read /Users/"$currentUser" NFSHomeDirectory 2>/dev/null | awk '{print $2}')
if [[ -z "$userHome" || ! -d "$userHome" ]]; then
    sleep 5
    userHome=$(dscl . -read /Users/"$currentUser" NFSHomeDirectory 2>/dev/null | awk '{print $2}')
fi
if [[ -z "$userHome" || ! -d "$userHome" ]]; then
    echo "Unknown|Discovery:Unknown|Setting Managed:No"
    exit 0
fi

# --- Check AirDrop discoverability setting ---
# The DiscoverableMode key in com.apple.sharingd controls AirDrop:
#   "Off"            = AirDrop disabled by user
#   "Contacts Only"  = Only contacts can see this device
#   "Everyone"       = Anyone nearby can see this device
#   (empty/missing)  = Default (Contacts Only on modern macOS)
airdropPlist="$userHome/Library/Preferences/com.apple.sharingd.plist"
discovery="Unknown"

if [[ -f "$airdropPlist" ]]; then
    discoverableMode=$(/usr/bin/defaults read "$airdropPlist" DiscoverableMode 2>/dev/null)
    case "$discoverableMode" in
        "Off")            discovery="Off" ;;
        "Contacts Only")  discovery="ContactsOnly" ;;
        "Everyone")       discovery="Everyone" ;;
        *)                discovery="Default" ;;
    esac
else
    discovery="Default"
fi

# --- Determine overall status ---
if [[ "$discovery" == "Off" ]]; then
    echo "Disabled|Discovery:Off|Setting Managed:No"
else
    echo "Enabled|Discovery:${discovery}|Setting Managed:No"
fi

exit 0
