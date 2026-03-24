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
#   Run: shellcheck airplay_receiver_status.sh
# =============================================================================
# Intune Custom Attribute: AirPlay Receiver Status
# NOTE:
# Intune display name: "macOS - AirPlay Receiver Status"
#
# Purpose: Detect if AirPlay Receiver is enabled and whether a managed profile
#          already restricts the feature.
#          Used for impact analysis before implementing CIS 2.3.1.2 (Level 1).
#
# Managed preference key:
#   com.apple.applicationaccess -> allowAirPlayIncomingRequests
#
# Detection approach:
#   1. Managed preference check (definitive when profile blocks it)
#   2. User-level AirPlay Receiver setting
#      (com.apple.controlcenter -> AirplayRecieverEnabled — note Apple's typo)
#
# AirPlay Receiver was introduced in macOS Monterey (12.0). It allows other
# Apple devices to share content to the Mac's screen. Enabled by default.
# The CIS benchmark recommends disabling it to reduce attack surface from
# frequent connection requests and information leakage.
#
# Output format: Status|Setting Managed:X
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
# Key: allowAirPlayIncomingRequests (com.apple.applicationaccess)
# Source: mSCP system_settings_airplay_receiver_disable rule / CIS 2.3.1.2
managedValue=$(/usr/bin/osascript -l JavaScript -e \
    '$.NSUserDefaults.alloc.initWithSuiteName("com.apple.applicationaccess").objectForKey("allowAirPlayIncomingRequests").js' 2>/dev/null)
if [[ "$managedValue" == "false" ]]; then
    echo "BlockedByProfile|Setting Managed:Yes"
    exit 0
fi

# --- Get home directory (retry once for login race condition) ---
userHome=$(dscl . -read /Users/"$currentUser" NFSHomeDirectory 2>/dev/null | awk '{print $2}')
if [[ -z "$userHome" || ! -d "$userHome" ]]; then
    sleep 5
    userHome=$(dscl . -read /Users/"$currentUser" NFSHomeDirectory 2>/dev/null | awk '{print $2}')
fi
if [[ -z "$userHome" || ! -d "$userHome" ]]; then
    echo "Unknown|Setting Managed:No"
    exit 0
fi

# --- Check user-level AirPlay Receiver setting ---
# com.apple.controlcenter -> AirplayRecieverEnabled (yes, Apple misspelled "Receiver")
# 1 or true = enabled, 0 or false = disabled by user
airplayEnabled="Unknown"
controlCenterPlist="$userHome/Library/Preferences/com.apple.controlcenter.plist"
if [[ -f "$controlCenterPlist" ]]; then
    airplayVal=$(/usr/bin/defaults read "$controlCenterPlist" AirplayRecieverEnabled 2>/dev/null)
    if [[ "$airplayVal" == "1" || "$airplayVal" == "true" ]]; then
        airplayEnabled="Yes"
    elif [[ "$airplayVal" == "0" || "$airplayVal" == "false" ]]; then
        airplayEnabled="No"
    fi
fi

# Default: AirPlay Receiver is enabled by default on macOS Monterey+
# If the key is missing, it's still on (Apple's default behavior)
if [[ "$airplayEnabled" == "Unknown" ]]; then
    airplayEnabled="Yes"
fi

# --- Determine overall status ---
if [[ "$airplayEnabled" == "Yes" ]]; then
    echo "Enabled|Setting Managed:No"
elif [[ "$airplayEnabled" == "No" ]]; then
    echo "DisabledByUser|Setting Managed:No"
else
    echo "Unknown|Setting Managed:No"
fi

exit 0
