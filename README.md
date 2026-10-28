# WordPress Security Hardening Playbook & Developer Cheatsheet

[![WordPress](https://img.shields.io/badge/WordPress-Security%20Hardening-21759b?logo=wordpress&logoColor=white)](https://www.geenxt.com/blog/how-to-harden-wordpress-security/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Production%20Tested-success)](https://github.com/markans/wordpress-security-hardening-playbook)
[![Author](https://img.shields.io/badge/Author-Mark%20Anthony%20Garcia-108548)](https://github.com/markans)
[![Documentation](https://img.shields.io/badge/Guide-GEENXT-ff6600)](https://www.geenxt.com/blog/how-to-harden-wordpress-security/)

A practical, production-tested WordPress security hardening playbook, configuration repository, and audit cheatsheet for system administrators, DevOps engineers, and WordPress developers.

> **Official Companion Guide:**  
> For the complete architectural analysis, risk matrix, and long-term maintenance workflows, read the full [WordPress security hardening playbook](https://www.geenxt.com/blog/how-to-harden-wordpress-security/) on [GEENXT](https://www.geenxt.com/).

---

## The Core Philosophy: Why Plugins Alone Do Not Secure WordPress

Many site owners install four or five security plugins hoping for safety. In practice, stacking heavy security plugins introduces severe drawbacks:

1. **Database Overhead & Resource Contention:** Heavy plugins write hundreds of thousands of firewall and access log entries into the MySQL `wp_options` or custom database tables. This inflates database backups and consumes PHP worker memory during traffic spikes.
2. **False Sense of Security:** Application-level PHP firewalls run after PHP and MySQL have already initialized. An edge-level bot attack still consumes server resources before a plugin can block it.
3. **Operational Fragility:** Automated plugin IP blocking can inadvertently lock out legitimate administrators, REST API webhooks, payment callbacks, or third-party CRM integrations.

True WordPress hardening happens at the **server, filesystem, edge firewall, and authentication layers**.

---

## The 5 Pillars of WordPress Hardening

```
+--------------------------------------------------------------------------+
|                     1. SERVER & FILESYSTEM LOCKDOWN                      |
|  Strict file permissions, wp-config isolation, disable file editing      |
+--------------------------------------------------------------------------+
                                    |
+--------------------------------------------------------------------------+
|                   2. AUTHENTICATION & ACCESS CONTROL                     |
|  Disable XML-RPC, rate-limit wp-login, block REST user enumeration, 2FA  |
+--------------------------------------------------------------------------+
                                    |
+--------------------------------------------------------------------------+
|                   3. DATABASE HYGIENE & PREFIX ISOLATION                 |
|  Unique table prefix, least-privilege DB grants, off-site cloud backups  |
+--------------------------------------------------------------------------+
                                    |
+--------------------------------------------------------------------------+
|                   4. ATTACK SURFACE REDUCTION & INTEGRITY                |
|  WP-CLI core checksums, remove inactive themes/plugins, automated audits |
+--------------------------------------------------------------------------+
                                    |
+--------------------------------------------------------------------------+
|                  5. EDGE FIREWALL & DEFENSIVE HTTP HEADERS               |
|  Cloudflare WAF, HSTS, X-Frame-Options, X-Content-Type-Options, CSP      |
+--------------------------------------------------------------------------+
```

### 1. Server Infrastructure and Filesystem Lockdown
- **Permissions:** Directories must be set to `755` (or `750`), and regular files to `644` (or `640`).
- **Configuration File:** Set `wp-config.php` to `400` or `440` read-only permissions:
  ```bash
  chmod 440 /var/www/html/wp-config.php
  ```
- **Disallow In-Dashboard File Editing:** Add to `wp-config.php` before the `/* That's all, stop editing! */` line:
  ```php
  define('DISALLOW_FILE_EDIT', true);
  ```
- **Block Script Execution in Uploads:** Prevent attackers from running web shells inside `/wp-content/uploads/` via server rules. Ready-to-use snippets are available in `configs/nginx-security.conf` and `configs/.htaccess`.

### 2. Authentication, Session Security, and Access Control
- **Disable XML-RPC (`xmlrpc.php`):** XML-RPC is obsolete for modern WordPress sites and serves as a primary vector for brute-force credential stuffing and amplification DDoS attacks.
- **Block REST API User Enumeration:** Scanners scrape usernames through `/wp-json/wp/v2/users` or `/?author=1`. Restrict this endpoint to authenticated users only.
- **Enforce Two-Factor Authentication (2FA):** Mandatory 2FA for Administrator and Editor roles eliminates more than 99% of automated account takeover attempts.

### 3. Database Hygiene and Prefix Isolation
- **Custom Prefix:** Avoid the predictable `wp_` prefix. Use a random alphanumeric prefix (for example, `gx72_`) upon installation.
- **Least-Privilege Database Grants:** The database user should possess only `SELECT`, `INSERT`, `UPDATE`, `DELETE`, `CREATE`, `DROP`, `ALTER`, and `INDEX` permissions. Revoke administrative privileges such as `GRANT OPTION`, `SUPER`, and `FILE`.
- **Encrypted Daily Backups:** Retain encrypted off-site cloud snapshots (Wasabi, AWS S3, or Backblaze) independent of the web hosting provider.

### 4. Attack Surface Reduction and Core Integrity Verification
- **Audit Core Files Against Official Checksums:**
  ```bash
  wp core verify-checksums
  ```
- **Audit Plugin Checksums:**
  ```bash
  wp plugin verify-checksums --all
  ```
- **Prune Inactive Code:** Delete all unused plugins and themes. Inactive themes can still be accessed directly if vulnerable PHP files exist on disk.

### 5. Edge Firewall Filtering and Defensive HTTP Headers
Deploy modern HTTP security headers to prevent clickjacking, MIME-type confusion, and cross-site scripting:
- `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`
- `X-Frame-Options: SAMEORIGIN`
- `X-Content-Type-Options: nosniff`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Permissions-Policy: camera=(), microphone=(), geolocation=(), browsing-topics=()`

---

## Repository Contents

| File | Description |
|:---|:---|
| [`configs/nginx-security.conf`](configs/nginx-security.conf) | Production Nginx rules for blocking PHP in uploads, protecting config files, disabling XML-RPC, and adding HTTP headers. |
| [`configs/.htaccess`](configs/.htaccess) | Production Apache / LiteSpeed directives for file protection, disabling directory indexes, and security headers. |
| [`scripts/wp-security-audit.sh`](scripts/wp-security-audit.sh) | Executable bash script that inspects permissions, uploads folders, wp-config constants, and WP-CLI checksums. |
| [`LICENSE`](LICENSE) | Open-source MIT License. |

---

## Quick Start: Running the Audit Script

Clone the repository and run the audit script against your WordPress root:

```bash
git clone https://github.com/markans/wordpress-security-hardening-playbook.git
cd wordpress-security-hardening-playbook
chmod +x scripts/wp-security-audit.sh

# Run audit against the local directory or specific path
./scripts/wp-security-audit.sh /var/www/html
```

---

## WP-CLI Hardening Cheatsheet

```bash
# 1. Verify core files integrity
wp core verify-checksums

# 2. Check plugin integrity
wp plugin verify-checksums --all

# 3. List vulnerable or outdated plugins
wp plugin list --update=available

# 4. List all administrators to audit access
wp user list --role=administrator

# 5. Reset all user authentication salts in wp-config.php
wp config shuffle-salts

# 6. Delete all inactive plugins
wp plugin delete $(wp plugin list --status=inactive --field=name)
```

---

## Emergency Incident Response Checklist

If your WordPress website has been breached or compromised:

1. **Take Immediate Snapshots:** Create a raw filesystem and database archive before making modifications. Keep web server access logs intact for forensic analysis.
2. **Switch Site to Maintenance Mode:** Prevent visitors from receiving malware downloads and stop automated bots from triggering active payloads.
3. **Reinstall Clean WordPress Core:**
   ```bash
   wp core download --force --skip-content
   ```
4. **Reinstall Plugins from WordPress.org:** Delete suspect plugin directories and install fresh copies directly from official repositories.
5. **Inspect the Uploads Directory:** Search for executable scripts:
   ```bash
   find /path/to/wp-content/uploads/ -type f -name "*.php"
   ```
6. **Rotate All Credentials:**
   - Change MySQL database user password.
   - Rotate WordPress authentication salts (`wp config shuffle-salts`).
   - Reset all administrator passwords.
   - Update SFTP, SSH, and hosting control panel passwords.

---

## Professional Support & Maintenance Services

Need direct assistance implementing this security playbook, fixing a hacked website, or keeping your production environment monitored around the clock?

- **Dedicated Hardening:** Explore our specialized [WordPress security hardening services](https://www.geenxt.com/wordpress-security-hardening/).
- **Monthly Maintenance Plans:** Review comprehensive [WordPress maintenance plans](https://www.geenxt.com/wordpress-support/) on [GEENXT](https://www.geenxt.com/).
  - **Care ($49/mo):** Cloud backups, weekly updates, uptime monitoring, security scans.
  - **Professional ($99/mo):** Core Web Vitals optimization, staging updates, technical SEO support, priority bug fixes.
  - **Premium ($499/mo):** Full dedicated support, proactive code audits, custom WooCommerce assistance.
- **Turnaround:** Fast turnaround under 24 hours, month-to-month contracts, cancel anytime, with a 7-day money-back guarantee.

---

## About the Author

This repository is maintained by **Mark Anthony Garcia**, founder and lead developer at [GEENXT](https://www.geenxt.com/).

- **Background:** Philippines-based AI Engineer and WordPress Developer with over 10 years of hands-on experience in web development, performance engineering, technical SEO, and security.
- **Track Record:** Upwork Top Rated developer, 100% Job Success Score, and over 10,600 billed client hours.
- **Connect:**
  - Website: [https://www.geenxt.com/](https://www.geenxt.com/)
  - Author Profile: [Mark Anthony Garcia on GEENXT](https://www.geenxt.com/mark-anthony-garcia/)
  - GitHub: [@markans](https://github.com/markans)
  - LinkedIn: [Mark Anthony Garcia](https://www.linkedin.com/in/mark-anthony-garcia1023)

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
