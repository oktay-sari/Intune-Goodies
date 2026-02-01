# Homebrew Security Check for Intune v3.0.2 🍺🔒

**Enterprise Homebrew security auditing for Microsoft Intune managed Macs**

Let's be real: Homebrew is amazing, but in an enterprise environment it can also be a security nightmare waiting to happen. World-writable binaries? Third-party taps from who-knows-where? Supply chain attacks through git remote hijacking? Yeah, this script checks for all of that.

## Blog

For the full story behind this script and more macOS security content for Intune, check out [allthingscloud.blog](https://allthingscloud.blog/auditing-homebrew-security-intune-mac-fleet).

## What's New in v3.0.2

This release continues the focus on **reliability and maintainability**. We've refined log management and separated the changelog for cleaner code.

### The Highlights

| Change | What It Means |
|--------|---------------|
| **Smarter log rotation** | 500KB max log size with 3 backup files (~16 days of history) |
| **Dedicated changelog** | Version history moved to `Changelog - Homebrew Security Audit Script.txt` |
| **Cleaner codebase** | No more changelog comments cluttering the script |

### Recent Fixes (v3.0.1)

| Fix | Impact |
|-----|--------|
| **TAPS_OFFICIAL double-zero bug** | Fixed invalid JSON when grep -c returned 0 with exit code 1 |

### v3.0.0 Refactor Highlights

| Change | What It Means |
|--------|---------------|
| **21% less code** | From 1203 lines to ~950. Less code = fewer bugs. |
| **DEBUG_MODE toggle** | Flip one variable for verbose troubleshooting. Production stays quiet. |
| **Security-only checks** | Removed hygiene checks (cleanup, auto-update, analytics, doctor). This is a security scanner, not a housekeeping tool. |
| **100% clean stdout** | Every line is `key=value`. No more rogue diagnostics breaking Intune parsing. |
| **Modular user context** | Consolidated user detection into clean functions. No more scattered global variables. |

### What Got Removed in v3.0.0 (and Why)

These checks were interesting but not security-relevant:

- `check_cleanup_needed` → Hygiene, not security
- `check_auto_update` → Hygiene, not security  
- `check_auto_update_disabled` → Hygiene, not security
- `check_analytics` → Privacy, not security
- `check_doctor` → Diagnostics, not security

The result? A leaner script that does one thing well: **find security issues in Homebrew installations**.

## Quick Start

### Deploy to Intune

1. Upload `homebrew_security_check_intune_v3_0_2.sh` to Intune
2. **Run as:** System (NOT signed-in user)
3. **Schedule:** Daily
4. **Hide notifications:** Yes

### Create Custom Attributes

You have two options:

**Option A: Minimal Core (Recommended)**
Deploy just 8 attributes that cover 90% of security use cases. Less admin overhead, same security signal.

**Option B: Extended Set**
Deploy all 24 attributes for granular compliance reporting and automated remediation workflows.

👉 **See the [Deployment Guide](deployment_guide_homebrew_audit.md) for complete setup instructions and attribute scripts.**

### Check the Logs

```bash
# View recent scan activity
sudo tail -50 /Library/Logs/Microsoft/IntuneScripts/HomebrewSecurity/scan.log

# Validate state.json
sudo python3 -m json.tool /Library/Logs/Microsoft/IntuneScripts/HomebrewSecurity/state.json

# Check for missing keys
sudo python3 - <<'PY'
import json
p="/Library/Logs/Microsoft/IntuneScripts/HomebrewSecurity/state.json"
required = ["installed", "security_score", "status", "summary", "last_scan", "script_version"]
d=json.load(open(p))
missing=[k for k in required if k not in d]
print("Missing:", missing if missing else "None")
PY
```

### Common Issues

| Symptom | Cause | Fix |
|---------|-------|-----|
| All attributes show 0 or Unknown | state.json missing | Wait for script to run, check logs |
| Score is INCOMPLETE | No console user at scan time | Normal at loginwindow; re-scan when user logs in |
| Attributes not updating | Intune check-in delay | Wait up to 24 hours |

## Files in This Package

| File | Description |
|------|-------------|
| `homebrew_security_check_intune_v3_0_2.sh` | **Main script** → Deploy to Intune |
| `homebrew_security_check_v3_0_2_DEPLOYMENT.md` | **Deployment guide** → Testing, attribute scripts, rollout |
| `Changelog - Homebrew Security Audit Script.txt` | **Version history** → All changes documented |
| `README.md` | This file |

## Version History

| Version | Key Changes |
|---------|-------------|
| **3.0.2** | Log rotation: 500KB max, 3 backups (~16 days history). Changelog moved to dedicated file. |
| **3.0.1** | Fixed TAPS_OFFICIAL double-zero bug causing invalid JSON |
| **3.0.0** | Code refactor (21% reduction), DEBUG_MODE, removed non-security checks, modular user context |
| 2.9.5 | Fixed set -e in wrapper, exec_git_origin path quoting |
| 2.9.4 | main() returns instead of exits, wrapper actually works |
| 2.9.2 | Git remote robustness, edge case handling |
| 2.9.1 | Git remote validation, TapRisk attribute |
| 2.9.0 | Policy-driven tap checking, supply chain detection |
| 2.8.4 | CONSOLE_USER fix, INCOMPLETE score |

For complete changelog details, see `Changelog - Homebrew Security Audit Script.txt`.

## Requirements

- macOS 13+ (Ventura, Sonoma, Sequoia)
- Microsoft Intune
- Homebrew (script handles "not installed" gracefully)

## Design Principles

These are non-negotiable:

1. **Never run `brew` as root** → Corrupts file ownership
2. **Always output key=value** → Clean Intune parsing
3. **Always exit 0** → Script success ≠ security status
4. **Diagnostics to stderr/log** → Never pollute stdout
5. **Fail safe** → Output something useful even on catastrophic failure

## Resources

- [Intune Shell Scripts Documentation](https://learn.microsoft.com/en-us/mem/intune/apps/macos-shell-scripts)
- [Intune Custom Attributes](https://learn.microsoft.com/en-us/mem/intune/apps/macos-custom-attributes)
- [Homebrew Security Best Practices](https://docs.brew.sh/Security)

---

**Version:** 3.0.2  
**Author:** Oktay Sari  
