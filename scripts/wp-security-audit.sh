#!/usr/bin/env bash
# ==============================================================================
# WordPress Security Audit Script
# Author: Mark Anthony Garcia (GEENXT)
# Repository: https://github.com/markans/wordpress-security-hardening-playbook
# Reference Guide: https://www.geenxt.com/blog/how-to-harden-wordpress-security/
# Description: Automated security checklist inspector for WordPress installations.
# ==============================================================================

set -uo pipefail

COLOR_RESET="\033[0m"
COLOR_RED="\033[1;31m"
COLOR_GREEN="\033[1;32m"
COLOR_YELLOW="\033[1;33m"
COLOR_BLUE="\033[1;34m"

print_header() {
    echo -e "${COLOR_BLUE}================================================================${COLOR_RESET}"
    echo -e "${COLOR_BLUE}  WordPress Security Audit & Hardening Inspector${COLOR_RESET}"
    echo -e "${COLOR_BLUE}  Developer Playbook by Mark Anthony Garcia (GEENXT)${COLOR_RESET}"
    echo -e "${COLOR_BLUE}================================================================${COLOR_RESET}"
    echo ""
}

log_pass() {
    echo -e " [${COLOR_GREEN}PASS${COLOR_RESET}] $1"
}

log_warn() {
    echo -e " [${COLOR_YELLOW}WARN${COLOR_RESET}] $1"
}

log_fail() {
    echo -e " [${COLOR_RED}FAIL${COLOR_RESET}] $1"
}

WP_PATH="${1:-.}"

if [ ! -f "$WP_PATH/wp-config.php" ] && [ ! -f "$WP_PATH/../wp-config.php" ]; then
    echo -e "${COLOR_RED}Error: wp-config.php not found in '$WP_PATH' or parent directory.${COLOR_RESET}"
    echo "Usage: ./wp-security-audit.sh /path/to/wordpress"
    exit 1
fi

WP_CONFIG="$WP_PATH/wp-config.php"
if [ ! -f "$WP_CONFIG" ]; then
    WP_CONFIG="$WP_PATH/../wp-config.php"
fi

print_header
echo "Target WordPress Root: $WP_PATH"
echo "Target Configuration File: $WP_CONFIG"
echo ""

echo "--- 1. Filesystem Permissions Audit ---"

# Check wp-config permissions
CONFIG_PERM=$(stat -c "%a" "$WP_CONFIG" 2>/dev/null || stat -f "%Op" "$WP_CONFIG" 2>/dev/null | tail -c 4)
if [[ "$CONFIG_PERM" =~ ^(400|440|600|640)$ ]]; then
    log_pass "wp-config.php permissions are restrictive ($CONFIG_PERM)."
else
    log_warn "wp-config.php permissions are $CONFIG_PERM. Recommended: 400 or 440."
fi

# Check for world-writable directories
WRITABLE_DIRS=$(find "$WP_PATH" -maxdepth 3 -type d -perm -002 2>/dev/null | wc -l)
if [ "$WRITABLE_DIRS" -eq 0 ]; then
    log_pass "No world-writable directories detected in core folders."
else
    log_fail "Found $WRITABLE_DIRS world-writable directories (permission 777). Restrict to 755."
fi

echo ""
echo "--- 2. Malicious Code & Uploads Inspection ---"

# Check for PHP files inside uploads directory
UPLOADS_DIR="$WP_PATH/wp-content/uploads"
if [ -d "$UPLOADS_DIR" ]; then
    PHP_IN_UPLOADS=$(find "$UPLOADS_DIR" -type f -name "*.php" 2>/dev/null)
    if [ -z "$PHP_IN_UPLOADS" ]; then
        log_pass "Zero PHP executable scripts found in wp-content/uploads/."
    else
        log_fail "PHP files detected inside uploads directory! Inspect immediately:"
        echo "$PHP_IN_UPLOADS" | head -n 10
    fi
else
    log_warn "wp-content/uploads directory not found at $UPLOADS_DIR."
fi

echo ""
echo "--- 3. wp-config.php Security Constants Audit ---"

# Check DISALLOW_FILE_EDIT
if grep -q "DISALLOW_FILE_EDIT" "$WP_CONFIG"; then
    if grep -E "define\s*\(\s*['\"]DISALLOW_FILE_EDIT['\"]\s*,\s*true\s*\)" "$WP_CONFIG" >/dev/null; then
        log_pass "DISALLOW_FILE_EDIT is set to true (Admin file editing disabled)."
    else
        log_warn "DISALLOW_FILE_EDIT exists but may not be set to true."
    fi
else
    log_warn "DISALLOW_FILE_EDIT constant is missing. Add: define('DISALLOW_FILE_EDIT', true);"
fi

# Check table prefix
if grep -E "\\\$table_prefix\s*=\s*['\"]wp_['\"];" "$WP_CONFIG" >/dev/null; then
    log_warn "Default table prefix 'wp_' in use. Consider migrating to a unique prefix."
else
    log_pass "Custom database table prefix is configured."
fi

# Check debug mode
if grep -E "define\s*\(\s*['\"]WP_DEBUG['\"]\s*,\s*true\s*\)" "$WP_CONFIG" >/dev/null; then
    if grep -E "define\s*\(\s*['\"]WP_DEBUG_DISPLAY['\"]\s*,\s*false\s*\)" "$WP_CONFIG" >/dev/null; then
        log_pass "WP_DEBUG is enabled but WP_DEBUG_DISPLAY is disabled (errors logged, not printed)."
    else
        log_warn "WP_DEBUG is true and WP_DEBUG_DISPLAY may be active. Sensitive paths may leak."
    fi
else
    log_pass "WP_DEBUG is disabled on production."
fi

echo ""
echo "--- 4. WP-CLI Core & Plugin Integrity Verification ---"

if command -v wp &>/dev/null; then
    echo "Running WP-CLI core checksum verification..."
    if wp core verify-checksums --path="$WP_PATH" &>/dev/null; then
        log_pass "WordPress core files match official WordPress.org checksums."
    else
        log_fail "WordPress core checksum verification failed! Modified files detected."
    fi
else
    log_warn "WP-CLI is not installed or not in PATH. Skipping automated checksum check."
fi

echo ""
echo -e "${COLOR_BLUE}Audit completed. Read the full hardening guide at:${COLOR_RESET}"
echo -e "https://www.geenxt.com/blog/how-to-harden-wordpress-security/"
echo ""
