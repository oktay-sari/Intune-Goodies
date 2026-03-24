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
#   Run: shellcheck apple_intelligence_status.sh
# =============================================================================
# Intune Custom Attribute: Apple Intelligence & Writing Tools Status
# NOTE:
# Intune display name: "macOS - Apple Intelligence Status"
#
# Purpose: Detect which Apple Intelligence features are active and whether
#          managed profiles already restrict them.
#          Used for impact analysis before implementing CIS 2.5.1.1 / 2.5.1.2
#          / 2.5.1.3 / 2.5.1.4 (all Level 1).
#
# Managed preference keys (all under com.apple.applicationaccess):
#   allowExternalIntelligenceIntegrations       -> External AI (ChatGPT etc.)
#   allowExternalIntelligenceIntegrationsSignIn  -> Sign-in to external AI
#   allowWritingTools                           -> Writing Tools (rewrite/proofread)
#   allowMailSummary                            -> Mail Summarization
#   allowNotesTranscriptionSummary              -> Notes Summarization
#
# Detection approach:
#   Each key returns "false" when a profile blocks it, empty/undefined when
#   no profile is deployed (feature available to user). We check all five
#   keys and report a consolidated status.
#
# Output format: Status|WT:X|Mail:X|Notes:X|ExtAI:X|Setting Managed:X
#   WT = Writing Tools, Mail = Mail Summary, Notes = Notes Summary,
#   ExtAI = External Intelligence (ChatGPT etc.)
# Max output length: kept compact by design (Intune limit is 20KB)
# Anonymized: No user info, device-level only.
# =============================================================================

# --- Helper: read a managed preference and return Yes/No/Unmanaged ---
# "false" means a profile explicitly blocks it.
# Empty/undefined means no profile is deployed (feature is available).
# "true" means a profile explicitly allows it.
read_managed_pref() {
    local key="$1"
    local val
    val=$(/usr/bin/osascript -l JavaScript -e \
        "$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess').objectForKey('${key}').js" 2>/dev/null)
    if [[ "$val" == "false" ]]; then
        echo "Blocked"
    elif [[ "$val" == "true" ]]; then
        echo "Allowed"
    else
        echo "Unmanaged"
    fi
}

# --- Check each Apple Intelligence feature ---
writingTools=$(read_managed_pref "allowWritingTools")
mailSummary=$(read_managed_pref "allowMailSummary")
notesSummary=$(read_managed_pref "allowNotesTranscriptionSummary")
externalAI=$(read_managed_pref "allowExternalIntelligenceIntegrations")
externalAISignIn=$(read_managed_pref "allowExternalIntelligenceIntegrationsSignIn")

# --- Determine if any feature is managed ---
anyManaged="No"
if [[ "$writingTools" == "Blocked" || "$mailSummary" == "Blocked" || \
      "$notesSummary" == "Blocked" || "$externalAI" == "Blocked" || \
      "$externalAISignIn" == "Blocked" ]]; then
    anyManaged="Partial"
fi

# Check if ALL are blocked
if [[ "$writingTools" == "Blocked" && "$mailSummary" == "Blocked" && \
      "$notesSummary" == "Blocked" && "$externalAI" == "Blocked" && \
      "$externalAISignIn" == "Blocked" ]]; then
    anyManaged="Yes"
fi

# --- Translate to short labels for output ---
# Blocked = profile disables it, Available = no profile (user can use it)
wt_short="Yes"
[[ "$writingTools" == "Blocked" ]] && wt_short="No"

mail_short="Yes"
[[ "$mailSummary" == "Blocked" ]] && mail_short="No"

notes_short="Yes"
[[ "$notesSummary" == "Blocked" ]] && notes_short="No"

# External AI: both keys must be unblocked for it to be available
extai_short="Yes"
if [[ "$externalAI" == "Blocked" || "$externalAISignIn" == "Blocked" ]]; then
    extai_short="No"
fi

# --- Determine overall status ---
if [[ "$anyManaged" == "Yes" ]]; then
    echo "AllBlocked|WT:${wt_short}|Mail:${mail_short}|Notes:${notes_short}|ExtAI:${extai_short}|Setting Managed:Yes"
elif [[ "$anyManaged" == "Partial" ]]; then
    echo "PartiallyManaged|WT:${wt_short}|Mail:${mail_short}|Notes:${notes_short}|ExtAI:${extai_short}|Setting Managed:Partial"
else
    echo "Available|WT:${wt_short}|Mail:${mail_short}|Notes:${notes_short}|ExtAI:${extai_short}|Setting Managed:No"
fi

exit 0
