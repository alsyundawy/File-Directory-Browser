# File & Directory Browser

[![Latest Version](https://img.shields.io/github/v/release/alsyundawy/File-Directory-Browser)](https://github.com/alsyundawy/File-Directory-Browser/releases)
[![Maintenance Status](https://img.shields.io/maintenance/yes/9999)](https://github.com/alsyundawy/File-Directory-Browser/)
[![License](https://img.shields.io/github/license/alsyundawy/File-Directory-Browser)](https://github.com/alsyundawy/File-Directory-Browser/blob/master/LICENSE)
[![GitHub Issues](https://img.shields.io/github/issues/alsyundawy/File-Directory-Browser)](https://github.com/alsyundawy/File-Directory-Browser/issues)
[![GitHub Pull Requests](https://img.shields.io/github/issues-pr/alsyundawy/File-Directory-Browser)](https://github.com/alsyundawy/File-Directory-Browser/pulls)
[![Donate with PayPal](https://img.shields.io/badge/PayPal-donate-orange)](https://www.paypal.me/alsyundawy)
[![Sponsor with GitHub](https://img.shields.io/badge/GitHub-sponsor-orange)](https://github.com/sponsors/alsyundawy)
[![GitHub Stars](https://img.shields.io/github/stars/alsyundawy/File-Directory-Browser?style=social)](https://github.com/alsyundawy/File-Directory-Browser/stargazers)
[![GitHub Forks](https://img.shields.io/github/forks/alsyundawy/File-Directory-Browser?style=social)](https://github.com/alsyundawy/File-Directory-Browser/network/members)
[![GitHub Contributors](https://img.shields.io/github/contributors/alsyundawy/File-Directory-Browser?style=social)](https://github.com/alsyundawy/File-Directory-Browser/graphs/contributors)

---

## About The Project

**File & Directory Browser** is a security-hardened, lightweight, and responsive single-file PHP directory browser and indexer. Built as a modern, drop-in replacement for standard web server directory indexing (such as Apache `mod_autoindex` or Nginx `autoindex`), it provides a rich user experience without requiring database servers, heavy runtimes, or external package dependencies.

Everything runs from a single `index.php` file, delivering instant client-side search, deterministic multi-attribute sorting, on-demand file checksum computation (CRC32, MD5, SHA-1) backed by an atomic local caching system, bcrypt-authenticated folder password protection, enterprise-grade defense-in-depth security headers, and an elegant Glassmorphic UI adhering to WCAG 2.2 AAA accessibility standards.

---

## User Interface

### Modern Glassmorphic Dark UI

![Modern Glassmorphic Dark UI](https://github.com/user-attachments/assets/ec10a8d2-662d-4aac-a1a1-14a6178b86bb)

### Classic Ambient Dark UI

![Classic Ambient Dark UI](https://github.com/user-attachments/assets/fdebf249-6bf7-4d49-806b-6399432c9d9d)

---

## Key Features

- 🔒 **Enterprise-Grade Security & Privacy:**
  - **Path Traversal Defense:** Rigorous path segment normalization and canonical filesystem path verification (`realpath`) preventing traversal exploits.
  - **Symlink Containment Guards:** External symlinks outside the base directory are strictly disabled by default; every file entry is validated against symlink escape guards before enumeration.
  - **Strict Security Headers:** Full suite of protective HTTP headers including dynamic nonce-based Content-Security-Policy (CSP), `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: strict-origin-when-cross-origin`, and `Permissions-Policy`.
  - **Search Privacy & Anti-Indexing:** Integrated `X-Robots-Tag: noindex, nofollow, noarchive` headers and `<meta name="robots" content="noindex,nofollow">` tags to prevent search engines from crawling or indexing file lists.
  - **Hardened Session Cookies:** Session cookies configured with `HttpOnly`, `SameSite=Strict`, and `Secure` attributes with session fixation defenses (`session_regenerate_id(true)`).
  - **Defense-in-Depth Cache Directory Protection:** Automatic `.cache/` folder hardening generating both `.htaccess` (Apache) and an empty `index.html` (Nginx, Caddy, Lighttpd) to prevent unauthorized cache indexing.
  - **Bcrypt Password-Protected Folders:** Restrict access to designated folders using secure bcrypt hashes (`password_hash` / `password_verify`) with zero plaintext storage.
  - **CSRF Token Protection & Rate Limiting:** Password entry forms utilize cryptographically secure `bin2hex(random_bytes(32))` CSRF tokens with post-login regeneration, plus configurable brute-force lockout rules (`$loginMaxAttempts` and `$loginLockSeconds`) with live countdown timers.
  - **Sensitive File Exclusion:** Critical system files (`.env`, `.php`, `.git`, `.htaccess`, `.sql`, etc.) are hidden from directory listings and checksum checks by default.
- ⚡ **Smart Hash Caching & Deterministic Sorting:**
  - **On-Demand File Checksums:** Computes CRC32, MD5, and SHA-1 checksums on demand with interactive one-click clipboard copying.
  - **High-Performance Local Cache:** Checksum results are stored locally, keyed by file size, modification time (`mtime`), and schema version to eliminate redundant I/O operations.
  - **Deterministic Natural Sorting:** Implements `strnatcasecmp` tie-breaker in directory sorting to guarantee consistent row order when timestamps or file sizes are identical.
  - **Optimized Minified Assets:** All internal CSS stylesheets and JavaScript blocks are minified to deliver ultra-fast page rendering and small network footprints.
- 🔍 **Real-Time Search & Keyboard Navigation:**
  - **Instant Client-Side Filtering:** Fast, zero-reload browser filtering by filename using client-side JavaScript that preserves table layout integrity.
  - **Interactive Keyboard Shortcuts:** Press `/` or `Ctrl+K` (`Cmd+K` on macOS) to instantly focus the search bar; press `Escape` to clear search filters and dismiss.
  - **Interactive Breadcrumb Navigation:** Path breadcrumbs with dynamic folder icons (`fa-folder-open`) and clean URL structure (`/?berkas=folder/subfolder`).
  - **Floating Home FAB & Back-to-Top:** Smooth floating buttons for instant return to root and smooth top-scrolling.
- 🎨 **Modern Glassmorphic UI & Full Accessibility (WCAG 2.2 AA/AAA):**
  - **Glassmorphic Aesthetic:** Sleek backdrop filters, dark/light theme switching, and dynamically color-coded file icons based on file type extensions.
  - **High-Contrast Accessibility (WCAG AAA):** Footer text color achieves > 7.5:1 contrast ratio, fully passing WCAG AAA standards.
  - **Accessible Table & Navigation:** Native `scope="col"` and dynamic `aria-sort` attributes on table headers, active breadcrumbs marked with `aria-current="page"`, high-visibility `:focus-visible` keyboard rings, and semantic `<output class="empty-state">` live regions for assistive technologies.
  - **Motion Sensitivity Support:** Fully respects `@media (prefers-reduced-motion: reduce)` system preferences.
- 🛠️ **Code Quality & Static Analysis Compliance:**
  - **100% PSR-12 Standard:** 0 errors on PHP CodeSniffer (`phpcs --standard=PSR12`).
  - **PHPStan Level Max (Level 9):** 0 errors and 0 warnings with strict typing and complete generic PHPDoc annotations.
  - **Psalm Level 3:** 0 errors and 0 warnings.
  - **SonarQube Clean Architecture:** Minimized cognitive complexity, isolated single-return functions, and eliminated nested ternary operators.

---

## Requirements

| Requirement | Minimum Version | Notes |
| :--- | :--- | :--- |
| **PHP** | `8.0` or newer | Fully tested and compatible up to PHP 8.4+ (PHP 8.2+ recommended for production) |
| **PHP Extensions** | `session`, `hash`, `json`, `pcre`, `spl` | Standard built-in PHP extensions |
| **Web Server** | Any standard web server | Apache (recommended), Nginx, Lighttpd, Caddy, or PHP Built-in CLI Server |
| **HTTPS / SSL** | Highly Recommended | Required for full security of session cookies and sensitive token transmission |

---

## Quick Start

1. **Download:** Grab the latest `index.php` from the [Releases](https://github.com/alsyundawy/File-Directory-Browser/releases) page or clone the repository:

   ```bash
   git clone https://github.com/alsyundawy/File-Directory-Browser.git
   ```

2. **Deploy:** Copy `index.php` into the directory on your web server that you want to browse and share.
3. **Configure:** Open `index.php` in a text editor to customize optional settings (such as page title, password-protected folders, or date formatting).
4. **Browse:** Open your web browser and navigate to your folder URL (e.g. `http://localhost/files/` or `https://yourdomain.com/`).

---

## Installation Guide (Ubuntu / Debian)

Below are complete, production-grade installation guides for **Ubuntu** (20.04 / 22.04 / 24.04 LTS) and **Debian** (11 / 12) using either **Apache** or **Nginx + PHP-FPM**.

### Step 1: System Preparation & File Deployment

Update your system package repositories and deploy the project files to your target web directory:

```bash
# Update package repositories
sudo apt update && sudo apt upgrade -y

# Install Git and unzip utilities
sudo apt install -y git unzip curl

# Create target web root directory
sudo mkdir -p /var/www/file-browser

# Clone repository into web directory
sudo git clone https://github.com/alsyundawy/File-Directory-Browser.git /var/www/file-browser

# Set ownership to the web server user (www-data)
sudo chown -R www-data:www-data /var/www/file-browser
sudo chmod -R 755 /var/www/file-browser

# Grant write permissions for the .cache directory (required for hash caching)
sudo chmod -R 775 /var/www/file-browser
```

---

### Step 2 (Option A): Apache Web Server Setup

If you are using the Apache HTTP Server:

#### 1. Install Apache & PHP Modules

```bash
# Install Apache and PHP runtime with required extensions
sudo apt install -y apache2 php php-cli libapache2-mod-php php-json php-mbstring

# Enable required Apache modules (rewrite & headers)
sudo a2enmod rewrite headers
```

#### 2. Configure Apache Virtual Host

Create a new Virtual Host configuration:

```bash
sudo nano /etc/apache2/sites-available/file-browser.conf
```

Add the following configuration (replace `files.example.com` with your domain or server IP):

```apache
<VirtualHost *:80>
    ServerName files.example.com
    ServerAdmin webmaster@example.com
    DocumentRoot /var/www/file-browser

    <Directory /var/www/file-browser>
        Options -Indexes +FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>

    # Block access to hidden files and directories (.env, .git, etc.)
    <FilesMatch "^\.">
        Require all denied
    </FilesMatch>

    # Logging
    ErrorLog ${APACHE_LOG_DIR}/file-browser_error.log
    CustomLog ${APACHE_LOG_DIR}/file-browser_access.log combined
</VirtualHost>
```

#### 3. Enable Site & Restart Apache

```bash
# Enable the Virtual Host
sudo a2ensite file-browser.conf

# Optional: Disable the default Apache welcome page
sudo a2dissite 000-default.conf

# Verify Apache configuration syntax
sudo apache2ctl configtest

# Restart Apache service
sudo systemctl restart apache2
```

---

### Step 2 (Option B): Nginx + PHP-FPM Setup

If you are using Nginx for lightweight, high-performance web delivery:

#### 1. Install Nginx & PHP-FPM

```bash
# Install Nginx and PHP-FPM with essential extensions
sudo apt install -y nginx php-fpm php-cli php-json php-mbstring
```

> [!NOTE]
> Check your installed PHP-FPM socket version (e.g. `/run/php/php8.3-fpm.sock` or `/run/php/php8.2-fpm.sock`) by running: `ls -la /run/php/php*-fpm.sock`.

#### 2. Configure Nginx Server Block

Create a new Nginx server configuration:

```bash
sudo nano /etc/nginx/sites-available/file-browser
```

Add the following configuration (adjust `server_name` and the `fastcgi_pass` socket path to match your environment):

```nginx
server {
    listen 80;
    listen [::]:80;
    server_name files.example.com;

    root /var/www/file-browser;
    index index.php;

    charset utf-8;
    client_max_body_size 100M;

    # Primary routing: route through index.php if not a direct static file
    location / {
        try_files $uri $uri/ /index.php?$args;
    }

    # Pass PHP scripts to FastCGI server (PHP-FPM)
    location ~ \.php$ {
        include snippets/fastcgi-php.conf;

        # Adjust PHP-FPM socket path to match your installed PHP version:
        fastcgi_pass unix:/run/php/php8.3-fpm.sock;
        # For PHP 8.2 use: fastcgi_pass unix:/run/php/php8.2-fpm.sock;

        fastcgi_param SCRIPT_FILENAME $realpath_root$fastcgi_script_name;
        include fastcgi_params;
    }

    # Deny direct access to .cache directory and hidden dotfiles
    location ~ /\. {
        deny all;
        access_log off;
        log_not_found off;
    }

    # Deny direct access to sensitive file extensions
    location ~* \.(env|git|sql|htaccess|htpasswd)$ {
        deny all;
        return 404;
    }

    # Logging
    error_log  /var/log/nginx/file-browser_error.log;
    access_log /var/log/nginx/file-browser_access.log;
}
```

#### 3. Enable Site & Restart Nginx

```bash
# Create symbolic link to enable site
sudo ln -s /etc/nginx/sites-available/file-browser /etc/nginx/sites-enabled/

# Optional: Remove default Nginx welcome site
sudo rm -f /etc/nginx/sites-enabled/default

# Verify Nginx configuration syntax
sudo nginx -t

# Restart Nginx and PHP-FPM services
sudo systemctl restart nginx
sudo systemctl restart php*-fpm
```

---

### Step 3: SSL / HTTPS Encryption with Let's Encrypt (Recommended)

To protect session cookies and CSRF tokens in transit, secure your installation with free automated SSL certificates via Certbot:

```bash
# For Apache:
sudo apt install -y certbot python3-certbot-apache
sudo certbot --apache -d files.example.com

# For Nginx:
sudo apt install -y certbot python3-certbot-nginx
sudo certbot --nginx -d files.example.com
```

Certbot will automatically install the certificate, configure HTTPS redirects, and establish an automated background renewal timer.

---

## Configuration

Open `index.php` in any text editor to adjust the configuration parameters located at the top of the file:

```php
// =================== GENERAL SETTINGS ===================
$browseDirectories       = true;                  // Allow browsing sub-directories
$title                   = 'Index of {{path}}';   // Page title format ({{path}} is dynamic)
$subtitle                = '{{files}} files, {{size}} total'; // Subtitle format
$showParent              = true;                  // Show parent directory link (..)
$showDirectories         = true;                  // Display directories in file table
$showDirectoriesFirst    = true;                  // Group directories at the top of listing
$showHiddenFiles         = false;                 // Hide/show dotfiles (.example)
$alignment               = 'left';                // Text alignment ('left' or 'center')
$showIcons               = true;                  // Display Font Awesome file/folder icons
$dateFormat              = 'd-M-Y H:i';           // Date format for file modified time
$sizeDecimals            = 1;                     // Decimal places for file sizes
$browseDefault           = '';                    // Default folder path on initial load
$allowExternalSymlinks   = false;                 // Allow symlinks outside base directory
$enableHashCache         = true;                  // Enable local cache for file checksums
$hashCacheVersion        = '2026-07-08-v2';       // Internal cache schema version
$timezone                = 'Asia/Jakarta';        // Default application timezone
```

### Folder Password Protection

To password-protect specific folders, generate a bcrypt hash first and map folder names to their hashes in `$protectedFolders`:

```bash
# Generate a bcrypt hash via your terminal:
php -r "echo password_hash('your_secret_password', PASSWORD_BCRYPT);"
```

Then configure the array in `index.php`:

```php
// =================== FOLDER PASSWORD PROTECTION ===================
$protectedFolders = [
    'secret-docs' => '$2y$12$YourGeneratedBcryptHashHere...',
    'private'     => '$2y$12$AnotherGeneratedBcryptHashHere...',
];

$passwordSessionLifetime = 2400; // Login session validity in seconds (default: 40 minutes)
$loginMaxAttempts        = 5;    // Max failed login attempts before lockout
$loginLockSeconds        = 300;  // Lockout duration in seconds (5 minutes)
```

> [!IMPORTANT]
> **Never store plaintext passwords.** Always use a bcrypt hash produced by `password_hash($password, PASSWORD_BCRYPT)`.

---

## Keyboard Shortcuts

| Shortcut | Action | Description |
| :--- | :--- | :--- |
| `/` or `Ctrl + K` (`Cmd + K` on macOS) | **Focus Search** | Instantly highlights and focuses the search input bar from anywhere on the page |
| `Escape` | **Clear & Dismiss** | Clears active search filters, restores the full listing, and removes focus |

---

## Changelog

### Version 3.9 (August 3, 2026) — Full Security Audit, Accessibility WCAG 2.2, Strict PHPStan Max & Performance Polish

- **🔒 SECURITY HARDENING:**
  - **Symlink Escape Containment:** Added symlink containment check for file entries in the directory listing loop, guaranteeing symlinked files outside `$baseDir` cannot be enumerated when `$allowExternalSymlinks` is false.
  - **Cache Protection Defense-in-Depth:** Added auto-generated `index.html` in `.cache/` directory alongside `.htaccess` to prevent directory listing on non-Apache web servers (Nginx, Caddy, Lighttpd, PHP CLI server).
  - **Robots Anti-Indexing & Privacy:** Added `X-Robots-Tag: noindex, nofollow, noarchive` in `sendSecurityHeaders()` and `<meta name="robots" content="noindex,nofollow">` on password & hash check pages for unified search privacy.
- **🐛 BUG FIXES:**
  - **PHP 8 Request URI Runtime Warning:** Added array check on `parse_url()` return value before accessing `$parsedUrl['path']`, preventing PHP 8 "Trying to access array offset on false" warning on malformed request URIs.
  - **CRLF Injection Prevention on Redirect:** Sanitized redirect URL against `\r` and `\n` in the URL normalizer redirector to prevent potential CRLF header injection.
  - **Search Filter Zero Results DOM Visibility:** Fixed critical DOM bug where `#noResultRow` remained invisible when 0 files matched due to inline style conflict with `.hidden-row` stylesheet rule; switched to `classList.toggle('hidden-row')`.
  - **Search Filter Empty Folder State Handling:** Handled empty folder state (`#emptyRow`) gracefully during active search filtering.
  - **Parent Directory Link Relative Path Encoding:** Added missing `encodeRelativePath()` to parent directory link in table body.
- **♿ ACCESSIBILITY & UI/UX (WCAG 2.2 AA/AAA Compliance):**
  - **Footer Text Contrast Ratio:** Fixed contrast ratio on footer text (`.footer` color `#94a3b8`), achieving a contrast ratio of > 7.5:1 and passing WCAG AAA compliance.
  - **Table Column Headers & `aria-sort`:** Added table column `scope="col"` and dynamic `aria-sort` attributes (`ascending`/`descending`/`none`) to header `<th>` elements via a dedicated helper function.
  - **Breadcrumb Navigation Location Indicator:** Added `aria-current="page"` to the active breadcrumb path segment for improved screen reader navigation.
  - **High-Visibility Keyboard Focus Outline:** Added high-visibility `:focus-visible` outlines for links, buttons, and form inputs for seamless keyboard navigation.
  - **Semantic Live Region `<output>`:** Replaced `role="status"` on `<tr>` with semantic `<output class="empty-state">` for universal assistive device support.
  - **Reduced Motion Preference Support:** Added `@media (prefers-reduced-motion: reduce)` CSS rules to honor user motion preferences.
  - **Keyboard Shortcuts for Quick Search:** Added `/` and `Ctrl+K` (`Cmd+K` on macOS) search shortcut to instantly focus the input, and `Escape` to clear search criteria and blur.
  - **Hash Check Table & Back Navigation:** Styled `.hash-table th` elements and added fallback `window.location.href` to the back button on the hash verification page when browser history is empty.
- **⚡ PERFORMANCE & DETERMINISTIC SORTING:**
  - **Deterministic Natural Sort Tie-Breaker:** Added filename natural sort tie-breaker (`strnatcasecmp`) in `usort()` for deterministic ordering when date or size attributes match.
- **🛠️ CODE QUALITY & STATIC ANALYSIS (PHPStan Max, Psalm, Sonar & PSR-12):**
  - **SonarQube Cognitive Complexity Reduction:** Extracted nested ternary operations into dedicated `getSortAriaAttribute()` helper function.
  - **PHPStan Level Max (Level 9) & Psalm Level 3 Clean Pass:** Achieved 100% clean passes on PHPStan Level Max (Level 9) and Psalm Level 3 with 0 errors and 0 warnings, resolving all mixed casts and docblock type redundancies.
  - **PSR-12 HTML/PHP Code Alignment:** Formatted and aligned all inline PHP code blocks within HTML context, achieving 100% PSR-12 compliance with 0 errors and 0 warnings via `phpcs --standard=PSR12`.
  - **Centralized Version Constant:** Defined centralized `APP_VERSION = '3.9.0'` constant displayed seamlessly in the application footer.

---

### Version 3.8 (July 29–30, 2026) — Security Hardening, DevSkim, CSP Compliance & Code Quality

- **🔒 SECURITY [CSP & DevSkim] — DevSkim Security Scan & CSP Compliance:**
  - Standardized CSRF token generation using cryptographically secure `bin2hex(random_bytes(32))` instead of non-cryptographic time-based hashing (`uniqid` + `microtime`). Added explicit DevSkim ignore annotations (`DS197836`, `DS126858`) for intentional file checksum features (`md5`, `sha1`), query string parameters, and filesystem cache keys.
  - Removed `javascript:history.back()` URI from hash page back-link; replaced with a proper `<button id="backBtn">` handled via nonce script block to fully comply with strict CSP `script-src` policy.
  - Removed inline `style="display:none"` from `#noResultRow` element; moved to CSS class `.hidden-row` to comply with strict CSP `style-src` policy.
  - Added `nonce` attribute to `<noscript><style>` blocks on all pages for consistent CSP compliance across all rendering paths.
  - Port number in `getSafeHost()` is now validated to be within valid TCP range (1–65535) to prevent malformed Host header injection via out-of-range port values.
- **🐛 BUG FIXES:**
  - Fixed column misalignment in table body — directory rows had 5 `<td>` elements (date-primary and date-secondary as separate columns) while file rows had 4. Unified date display so both dir and file rows use a single `<td class="date-cell">` containing both primary and secondary spans inside, matching thead column count of 4.
  - `sanitizePath()` `preg_replace` with `/u` modifier now has explicit fallback if the regex fails due to invalid UTF-8 input, preventing silent null return.
  - `ensureCacheDir()` now checks `mkdir()` return value and logs error on failure instead of silently continuing, preventing obscure cache-write errors downstream.
  - `calculateHashes()` now calls `error_log()` when `fopen()` fails, improving production debuggability.
  - `writeHashCache()` now verifies return value of `rename()` and logs on failure, ensuring temp file cleanup even on rename failure.
- **✨ IMPROVEMENTS:**
  - `humanizeFilesize()` now uses `number_format()` instead of `round()` to ensure consistent decimal display (e.g., "1.0 MB" not "1 MB").
  - `humanizeFilesize()` caches `count($units)` before the loop to avoid repeated function calls on every iteration.
  - `$unlockedSessions` reference at directory browsing section replaced with explicit null-safe array initialization to prevent potential reference warnings.
  - Added `$_GET['sort'] ?? 'name'` and `$_GET['order'] ?? 'asc'` with explicit null coalescing before allowlist check for strict_types safety.
- **🛠️ CODE QUALITY & LINTER COMPLIANCE (PHPCS & Sonar):**
  - **PHP CodeSniffer (PHPCS):** Executed `phpcbf` and manual formatting fixes across all PHP files to resolve all syntax, indentation, and spacing errors (0 PHPCS errors remaining).
  - **Multiple Returns Reduction:** Refactored `getMediaIconClass()`, `createHashCacheDir()`, `readHashCache()`, and `listDirectory()` to reduce multiple return statements (max 1 per function).
  - **Cognitive Complexity:** Extracted `isValidHashData()`, `processDirectoryItem()`, and `getScandirFiles()` helper functions, reducing cognitive complexity in `readHashCache()` (from 22 to 2) and `listDirectory()` (from 24 to 3).
  - **Nested Ternaries & Parameter Limits:** Replaced nested ternary operations in `buildDirectoryEntry()` and sort button icons (`$nameIcon`, `$dateIcon`, `$sizeIcon`) with clear `if` statements. Reduced parameter count of `processDirectoryItem()` from 9 to 5.

---

### Version 3.7 (July 18, 2026) — Bug Fixes, Security Hardening & Code Quality

- **🐛 Bug Fix [CRITICAL] — Extension Guard:**
  - Fixed unreachable code in the extension guard — `foreach($requiredExtensions)` was placed inside the `version_compare()` if-block after `exit()`, causing all extension checks to never execute due to a misplaced closing brace.
- **🔒 Bug Fix [SECURITY] — Reflected XSS on Password Page:**
  - Added `e()` escaping on `$lockedFolder` in the `renderPasswordPage()` hidden input and all HTML attributes to prevent Reflected XSS via folder name.
- **🔒 Bug Fix [SECURITY] — CSRF Token Fixation:**
  - Added CSRF token regeneration after successful folder login to prevent CSRF token fixation and reuse attacks.
- **🐛 Bug Fix — `queryUrl()` Empty String:**
  - `queryUrl()` now returns `''` (empty string) instead of `'?'` when params are empty, preventing malformed URLs in sort links and breadcrumbs.
- **🐛 Bug Fix — `calculateHashes()` fread Error:**
  - `calculateHashes()` now correctly short-circuits on `fread() === false` before calling `hash_update()`, preventing hash computation on failed reads.
- **🔒 Security — `isValidHashData()` Hex Length Validation:**
  - `isValidHashData()` now strictly validates hex string length per algorithm (crc32=8, md5=32, sha1=40) to reject corrupt or spoofed cache entries.
- **🔒 Security — `ensureCacheDir()` Path Sanitization:**
  - `ensureCacheDir()` now sanitizes `$hashCacheVersion` before using it as a filesystem path component to prevent path injection.
- **🔒 Security — Removed Error Suppression Operator:**
  - Removed excessive `@` error suppression on file I/O functions (`file_put_contents`, `rename`, `unlink`, `chmod`, `fopen`) and replaced with explicit return-value checks.
- **✨ Improvement — Session Cleanup on `getFirstLockedFolder()`:**
  - Added cleanup of expired `unlocked_folders` session entries inside `getFirstLockedFolder()` to prevent unbounded session bloat over time.
- **✨ Improvement — Explicit `Content-Type` Header:**
  - Added an explicit `Content-Type: text/html; charset=UTF-8` header in `sendSecurityHeaders()` to remove reliance on browser charset sniffing.
- **✨ Improvement — Integer Cast on Lock Timer:**
  - Added explicit `(int)` cast on `$lockTimeRemaining` output in HTML for `strict_types` safety and clean integer rendering.
- **🛠️ Code Quality:**
  - Minor PSR-12 alignment and comment consistency improvements.

---

### Version 3.6 (July 18, 2026) — Security Hardening, CSP Compliance & Performance Optimization

- **🔒 Security — CSP Inline Style Fix:**
  - Fixed inline `style` attribute on the hash page container that violated the strict CSP policy.
- **🔒 Security — CSP Script-src Compliance:**
  - Removed inline `onsubmit` handler from the search form to achieve full `CSP script-src` compliance without `'unsafe-inline'`.
- **🔒 Security — Session Fixation Prevention:**
  - Added `session_regenerate_id(true)` after successful folder password verification to prevent session fixation.
- **🔒 Security — `X-XSS-Protection: 0` Header:**
  - Added `X-XSS-Protection: 0` header to disable the legacy browser XSS auditor and prevent false positives.
- **⚡ Performance — `isHiddenName()` Static Cache:**
  - Cached `strtolower` mapping in `isHiddenName()` using a `static` variable to avoid repeated `array_map` calls.
- **⚡ Performance — `humanizeFilesize()` Loop Optimization:**
  - Pre-computed unit count outside the loop boundary in `humanizeFilesize()`.
- **⚡ Performance — `ob_end_flush()` Safety Check:**
  - Improved the `ob_end_flush` shutdown handler with an `ob_get_level()` safety check.
- **🐛 Bug Fix — Lock Time Display:**
  - Used `intdiv()` for lock time display to prevent float output in user-facing messages.

---

### Version 3.5 (July 14, 2026) — Premium Glassmorphic Dark Theme & Style Customization

- **🎨 UI/UX — Premium Glassmorphic Dark Theme:**
  - Implemented a modern Premium Glassmorphic Dark Theme featuring a beautiful fixed radial-gradient background.
- **🎨 UI/UX — Custom Link & Icon Styling:**
  - Custom-styled folder/file links and icons in both Light and Dark modes to match design specifications.
- **🎨 UI/UX — Breadcrumb Open Folder Icon:**
  - Integrated the open folder icon (`fa-folder-open`) in breadcrumb navigation while retaining standard closed folder icons in the file list view for visual consistency.
- **📱 UI/UX — Mobile Responsiveness:**
  - Optimized mobile media queries to scale down all text, paddings, and header elements for a highly compact and responsive layout across all device resolutions.
- **🐛 Bug Fix — Infinite 301 Redirect Loop:**
  - Resolved an infinite 301 redirect loop on nested folder parameters containing URL-encoded slashes (`%2F`) which previously caused the spinner loader to get stuck indefinitely.

---

### Version 3.4 (July 14, 2026) — URL Sanitizer, Rate-Limit, Quality Audits & UI Enhancement

- **🔒 Security, Quality Audits & Rate-Limiting:**
  - Added brute-force/rate-limit protection to folder passwords using login attempt limits (`$loginMaxAttempts = 5`) and temporary lockout timers (`$loginLockSeconds = 300`) with real-time countdown display.
  - Merged nested conditional `if` statements to resolve code analyzer warnings.
  - Relocated `ob_end_flush()` to a centralized `register_shutdown_function()` to ensure proper output buffer cleaning upon termination.
- **⚡ Performance Optimization:**
  - Minified all internal JavaScript blocks (Theme Switchers, Lock Countdown, Search and lists controller) to minimize payload size and improve execution speed.
- **🎨 UI/UX & Dark Mode Contrast Fix:**
  - Resolved blurry text styling in dark mode on the Hash Check page by setting `h2` heading color via `var(--text-primary)` and updating `.text-muted`/`.text-secondary` rules to use crisp high-contrast colors.
- **🔗 Clean URL Routing:**
  - Swapped directory browsing query parameter from `folder` to `berkas`.
  - Stripped `index.php` path segment from URLs and implemented automatic redirects (HTTP 301) from `/index.php?folder=XXX` to `/?berkas=XXX` for cleaner SEO routing.
  - Decoded `%2F` in query parameters back to slashes to display clean folder paths (e.g. `?berkas=folder1/subfolder1`), redirecting requests containing URL-encoded `%2F` to clean slash representations.
- **✨ Modern Hash Check UI & Clipboard Support:**
  - Modernized the Hash Check overlay with a narrower card layout, elegant shield badge styling, and CSP-compliant, one-click clipboard copying buttons with visual success feedback.
- **Footer Encoding Fix:**
  - Replaced copyright character symbols in the footer with robust HTML entities to prevent font encoding glitches.
- **✨ Sorting Interactive Improvement:**
  - Removed default highlighted/active selection state from sorting buttons. Active highlight only appears upon explicit query sort requests; otherwise, buttons display standard interactive hover effects.
- **🛠️ Font Awesome Maintenance:**
  - Consolidated and simplified Font Awesome mappings into a single static array in `getFileIconClass()`, removing six helper subfunctions to maximize readability and ease of maintenance.

---

### Version 3.3 (July 13, 2026) — Strict CSP Compliance, Readability Overhaul & Clean Layout

- **🔒 Security & CSP Hardening:**
  - Removed all remaining inline `style="..."` attributes on HTML tags (`#search-form-container`, `#fileTable`, and `<col>` elements) to achieve 100% CSP compliance without relying on `'unsafe-inline'`.
  - Added dynamic CSP nonce value to the style tag within the `<noscript>` block.
  - Rewrote JavaScript `.cssText` manipulation to use individual style property settings instead, avoiding CSP style-src blocks.
- **🎨 UI/UX & Light Mode Contrast Enhancement:**
  - Optimized Light Mode contrast to match clean design aesthetics — featuring high readability, crisp text, and zero eye-strain.
  - Hardened text and color contrast in Dark Mode to ensure high legibility and eliminate blurry fonts.
  - Aligned the Back-to-Top and Home FAB button coordinates on the bottom-right for clean, non-overlapping floating layouts.
- **🐛 Bug Fix:**
  - Fixed the back-to-listing button on the file hash verification page to function correctly under strict CSP headers.

---

### Version 3.2 (July 13, 2026) — Password Protection, Security Hardening & UI Enhancement

- **🔒 Security & Authentication:**
  - Migrated folder protection from plaintext passwords to secure `password_hash(PASSWORD_BCRYPT)` and `password_verify()`.
  - Replaced plaintext comparison (`===`) with `password_verify()` to eliminate timing attacks.
  - Added case-insensitive folder protection checking across nested subfolders and files.
- **🐛 Bug Fixes:**
  - Fixed non-functional "Back to Listing" button on Hash Check page caused by CSP blocking inline `onclick` handlers by moving logic to a nonce-tagged script block.
  - Fixed breadcrumb path accumulation using `array_values()` after `array_filter()` to prevent off-by-one errors on deeply nested folders.
- **✨ Features & UI/UX:**
  - Introduced floating **Home FAB button** (indigo house icon) positioned above the Back-to-Top button that appears after scrolling 300px, enabling instant one-click return to the root folder.
  - Built a glassmorphic password prompt interface matching application themes.
  - Added lock icons next to protected directories in the file table.
  - Fixed dark mode table colors by properly defining the `--h` variable in dark settings.
- **⚡ Performance:**
  - Minified all inline CSS stylesheets with a regex-based minifier, saving ~16.7 KB (15.3% file size reduction).
  - Moved `array_change_key_case($protectedFolders)` outside the listing loop, improving lookup efficiency from O(n) to O(1).
- **♿ Accessibility & Code Quality:**
  - Directed post-login redirects specifically to the freshly unlocked folder instead of the generic canonical URL.
  - Added descriptive `aria-label` attributes on hash fingerprint links and `aria-hidden="true"` on decorative icons.
  - Extracted `findOriginalFolderKey()` helper to reduce cognitive complexity in `getFirstLockedFolder()`.

---

### Version 3.1 (July 13, 2026) — Refactoring, Clean Code & Subresource Integrity

- **Refactoring & Clean Code:**
  - Reduced cognitive complexity across primary functions (`listDirectory`, `processDirectoryItem`, `readHashCache`) by decomposing into modular helper functions with single return paths.
  - Reduced parameter counts on directory listing functions to comply with clean code standards.
  - Converted inline HTML elements in README to standard Markdown for Markdownlint compliance.
- **Security & Standards Hardening:**
  - Integrated SHA-384 Subresource Integrity (SRI) hashes and `crossorigin` attributes across external dependencies (Bootstrap and Font Awesome CSS/JS).
  - Centralized session cookie handling with explicit `secure` flags.
- **Accessibility & CSS Enhancements:**
  - Added standard `background-clip` property alongside `-webkit-background-clip` for cross-browser visual fidelity.
  - Converted Back-to-Top buttons from non-standard tags to native `<button>` elements for proper keyboard accessibility.

---

### Version 3.0 (July 8, 2026) — Aesthetic Overhaul & Performance Optimization

- **Performance Optimizations:**
  - Optimized directory iteration by eliminating redundant `realpath` calls on symlinks.
  - Introduced `isDisplayableFolder` validation to prevent hidden directories from leaking.
- **Aesthetic Overhaul:**
  - Completely redesigned UI with a modern Glassmorphic Dark Theme featuring ambient radial gradients, subtle micro-animations, and dynamically color-coded file icons.
  - Implemented `<noscript>` fallback styling to gracefully handle loading screen transitions when JavaScript is disabled.

---

## Documentation Notes

> [!IMPORTANT]
>
> 1. **Cache Folder Permissions:** Ensure that the directory containing the script has write permissions so it can create the `.cache` folder automatically. If write permissions are unavailable, file checksum caching will be safely bypassed to guarantee uninterrupted runtime.
> 2. **HTTPS/SSL Deployment:** It is strongly recommended to host this script under an SSL/HTTPS domain to guarantee encryption of CSRF session cookies and authentication tokens in transit.
> 3. **Exclusion of Sensitive Files:** By default, critical file formats including `.php`, `.bat`, `.env`, `.sql`, `.htaccess`, and others are blocked from being listed, viewed, or hashed to prevent unauthorized code execution and credential leaks.
> 4. **Folder Passwords (Must Be Hashed):** Folder protection passwords **must not** be stored in plaintext. Always use the output of `password_hash('your_password', PASSWORD_BCRYPT)`. Generate a hash with:
>    `php -r "echo password_hash('your_password', PASSWORD_BCRYPT);"`
> 5. **CSP & Inline Event Handlers:** This script enforces a strict nonce-based Content-Security-Policy. Inline `onclick=""` HTML attributes will be blocked by CSP — all event listeners must be registered inside `<script nonce="...">` blocks.
> 6. **Multi-Webserver Cache Protection:** The `.cache/` folder automatically generates both `.htaccess` (Apache) and an empty `index.html` file to prevent unauthorized directory listing across Apache, Nginx, Caddy, Lighttpd, and the PHP CLI built-in server.
> 7. **Search Keyboard Shortcuts:** Press `/` or `Ctrl+K` (`Cmd+K` on macOS) anywhere on the page to immediately focus the search input, and press `Escape` to clear search criteria and dismiss the input field.
> 8. **Accessibility Compliance (WCAG 2.2 AA/AAA):** The interface strictly adheres to modern accessibility standards featuring high contrast ratios (WCAG AAA), keyboard navigation with `:focus-visible`, breadcrumb `aria-current="page"`, table column header `aria-sort`, semantic `<output class="empty-state">` screen reader live regions, and `prefers-reduced-motion` support.

---

## Donation

You are free to use, modify, and distribute this script for personal and commercial purposes under the MIT License.

If you find this project helpful and would like to support ongoing maintenance and new features, please consider donating:

- **PayPal:** [paypal.me/alsyundawy](https://www.paypal.me/alsyundawy)
- **GitHub Sponsors:** [github.com/sponsors/alsyundawy](https://github.com/sponsors/alsyundawy)

For Indonesian local bank transfers or e-wallet payments via QRIS, you can scan the barcode below:

![QRIS Donation](https://github.com/user-attachments/assets/a0126f28-6dde-43da-ba14-d7c9a27de0df)

---

## License

This project is licensed under the [MIT License](LICENSE) — Copyright © 2026 **HARRY DS ALSYUNDAWY** — ALSYUNDAWY IT SOLUTION.

> **Note:** Please retain attribution credit to the original author (**HARRY DS ALSYUNDAWY — ALSYUNDAWY IT SOLUTION**) if you use or distribute this script. Attribution is appreciated though not legally mandated under the MIT License.

---

![Repobeats analytics](https://repobeats.axiom.co/api/embed/78ddb5f1a231029b742cc467a74bcce400941d0f.svg "Repobeats analytics image")
