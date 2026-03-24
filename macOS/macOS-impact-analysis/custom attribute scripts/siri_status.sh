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
#   Run: shellcheck siri_status.sh
# =============================================================================
# Intune Custom Attribute: Siri Status
# NOTE:
# Intune display name: "macOS - Siri Status"
#
# Purpose: Detect if Siri is enabled and whether "Listen for Siri" (always-on
#          microphone) is active. Reports managed profile restriction status.
#          Used for impact analysis before implementing CIS 2.5.2.1 (Level 1)
#          and CIS 2.5.2.2 (Level 1, manual).
#
# Managed preference keys:
#   com.apple.applicationaccess -> allowAssistant
#   com.apple.Siri -> VoiceTriggerUserEnabled (per-user, not profile-manageable)
#
# Detection approach:
#   1. Managed preference check for allowAssistant (profile blocks Siri)
#   2. User-level Siri enabled status (com.apple.assistant.support -> Assistant Enabled)
#   3. "Listen for Siri" / "Hey Siri" status (VoiceTriggerUserEnabled)
#   Note: "Listen for" cannot currently be disabled via profile or plist.
#   CIS recommends disabling Siri entirely because of this limitation.
#
# Output format: Status|ListenFor:X|Setting Managed:X
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
# Key: allowAssistant (com.apple.applicationaccess)
# Source: mSCP system_settings_siri_disable rule / CIS 2.5.2.1
managedValue=$(/usr/bin/osascript -l JavaScript -e \
    '$.NSUserDefaults.alloc.initWithSuiteName("com.apple.applicationaccess").objectForKey("allowAssistant").js' 2>/dev/null)
if [[ "$managedValue" == "false" ]]; then
    echo "BlockedByProfile|ListenFor:N/A|Setting Managed:Yes"
    exit 0
fi

# --- Get home directory (retry once for login race condition) ---
userHome=$(dscl . -read /Users/"$currentUser" NFSHomeDirectory 2>/dev/null | awk '{print $2}')
if [[ -z "$userHome" || ! -d "$userHome" ]]; then
    sleep 5
    userHome=$(dscl . -read /Users/"$currentUser" NFSHomeDirectory 2>/dev/null | awk '{print $2}')
fi
if [[ -z "$userHome" || ! -d "$userHome" ]]; then
    echo "Unknown|ListenFor:Unknown|Setting Managed:No"
    exit 0
fi

# --- Check if Siri is enabled at the user level ---
# com.apple.assistant.support -> "Assistant Enabled" (boolean)
siriEnabled="Unknown"
siriPlist="$userHome/Library/Preferences/com.apple.assistant.support.plist"
if [[ -f "$siriPlist" ]]; then
    assistantEnabled=$(/usr/bin/defaults read "$siriPlist" "Assistant Enabled" 2>/dev/null)
    if [[ "$assistantEnabled" == "1" || "$assistantEnabled" == "true" ]]; then
        siriEnabled="Yes"
    elif [[ "$assistantEnabled" == "0" || "$assistantEnabled" == "false" ]]; then
        siriEnabled="No"
    fi
fi

# --- Check "Listen for Siri" / "Hey Siri" ---
# com.apple.Siri -> VoiceTriggerUserEnabled (per-user setting)
# Note: This key is NOT manageable via profile (CIS 2.5.2.2 is Manual for this reason)
listenFor="Unknown"
siriVoicePlist="$userHome/Library/Preferences/com.apple.Siri.plist"
if [[ -f "$siriVoicePlist" ]]; then
    voiceTrigger=$(/usr/bin/defaults read "$siriVoicePlist" VoiceTriggerUserEnabled 2>/dev/null)
    if [[ "$voiceTrigger" == "1" || "$voiceTrigger" == "true" ]]; then
        listenFor="Yes"
    elif [[ "$voiceTrigger" == "0" || "$voiceTrigger" == "false" ]]; then
        listenFor="No"
    fi
fi

# --- Determine overall status ---
if [[ "$siriEnabled" == "Yes" ]]; then
    echo "Enabled|ListenFor:${listenFor}|Setting Managed:No"
elif [[ "$siriEnabled" == "No" ]]; then
    echo "DisabledByUser|ListenFor:${listenFor}|Setting Managed:No"
else
    echo "Unknown|ListenFor:${listenFor}|Setting Managed:No"
fi

exit 0
