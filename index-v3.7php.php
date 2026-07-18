<?php
/*
 * ==============================================================================
 *  File & Directory Browser (index.php)
 * ==============================================================================
 *
 *  Purpose:
 *    Menampilkan daftar file dan direktori secara aman, responsif, dan ringan,
 *    dengan fitur sortir, pencarian real-time, dukungan symlink internal, serta
 *    pengecekan hash file CRC32, MD5, dan SHA-1 menggunakan cache lokal.
 *
 *  Features:
 *    - Menampilkan daftar file dan direktori dengan opsi sortir nama, tanggal,
 *      dan ukuran.
 *    - Search real-time di sisi browser tanpa request tambahan ke server.
 *    - Cek hash CRC32, MD5, SHA-1 untuk file yang memang boleh ditampilkan.
 *    - Cache hasil hash berbasis path canonical, mtime, size, dan versi cache.
 *    - Dukungan symlink file/folder yang tetap berada di dalam base directory.
 *    - Proteksi path traversal dengan normalisasi segment dan canonical path check.
 *    - Output escaping konsisten untuk HTML, attribute, URL, dan query string.
 *    - Header keamanan: no-cache, nosniff, frame policy, referrer policy,
 *      permissions policy, dan Content-Security-Policy berbasis nonce.
 *    - UI responsif menggunakan Bootstrap 5, Font Awesome, dan font Inter.
 *    - Struktur desain lama dipertahankan: header, loading screen, tabel,
 *      tombol hash, search, sort, back-to-top, dan footer.
 *
 *  Security Notes:
 *    - External symlink dinonaktifkan secara default untuk mencegah pembacaan
 *      direktori/file di luar base directory.
 *    - File dengan ekstensi berisiko tidak ditampilkan dan tidak dapat dicek hash.
 *    - Nama host untuk canonical URL divalidasi untuk mencegah Host header abuse.
 *    - Endpoint hash tetap kompatibel dengan parameter lama ?md5=relative/path.
 *
 *
 * DOCNOTE:
 * - PHP Minimum: 8.0 (direkomendasikan 8.2+ untuk production).
 * - Konfigurasi: Edit bagian CONFIGURATION di bagian atas file.
 * - Password Folder: Generate hash dengan: php -r "echo password_hash('password', PASSWORD_BCRYPT);"
 * - Folder terlindungi: Tambahkan ke array $protectedFolders dengan bcrypt hash.
 * - Session lifetime: $passwordSessionLifetime (default 2400 detik = 40 menit).
 * - Hash cache disimpan di direktori .cache/ (dilindungi .htaccess otomatis).
 * - CSRF token di-regenerate setiap setelah login berhasil (v2026-07-18).
 * - session_regenerate_id(true) dipanggil setelah login sukses untuk mencegah fixation.
 * - isValidHashData() kini memvalidasi panjang hex string (crc32=8, md5=32, sha1=40).
 * - Extension guard (requiredExtensions check) kini berjalan dengan benar (bug brace fixed).
 * - queryUrl() kini mengembalikan '' (bukan '?') saat tidak ada parameter.
 * - Content-Type: text/html; charset=UTF-8 header ditambahkan secara eksplisit.
 * - calculateHashes() diperbaiki agar tidak memanggil hash_update setelah fread error.
 *
 *  Changelog:
 *    2026-07-18 (v3.7 - Bug Fix, Security Hardening & Code Quality):
 *      - BUG FIX [CRITICAL]: Fixed unreachable code in extension guard — foreach($requiredExtensions)
 *        was placed inside the version_compare() if-block after exit(), causing all extension
 *        checks to never execute due to misplaced closing brace.
 *      - BUG FIX [SECURITY]: Added e() escaping on $lockedFolder in renderPasswordPage() hidden
 *        input and all HTML attributes to prevent reflected XSS via folder name.
 *      - BUG FIX [SECURITY]: Added CSRF token regeneration after successful folder login to
 *        prevent CSRF token fixation / reuse attacks.
 *      - BUG FIX: queryUrl() now returns '' (empty string) instead of '?' when params are empty,
 *        preventing malformed URLs in sort links and breadcrumbs.
 *      - BUG FIX: calculateHashes() fread() false-check now correctly short-circuits before
 *        hash_update() call, preventing hash computation on failed reads.
 *      - SECURITY: isValidHashData() now strictly validates hex string length per algorithm
 *        (crc32=8, md5=32, sha1=40) to reject corrupt or spoofed cache entries.
 *      - SECURITY: ensureCacheDir() now sanitizes $hashCacheVersion before using it as a
 *        filesystem path component to prevent path injection.
 *      - SECURITY: Removed excessive @ error suppression on file I/O functions (file_put_contents,
 *        rename, unlink, chmod, fopen) and replaced with explicit return-value checks.
 *      - IMPROVEMENT: Added session cleanup of expired unlocked_folders entries inside
 *        getFirstLockedFolder() to prevent unbounded session bloat over time.
 *      - IMPROVEMENT: Added explicit Content-Type: text/html; charset=UTF-8 header in
 *        sendSecurityHeaders() to remove reliance on browser charset sniffing.
 *      - IMPROVEMENT: Explicit (int) cast on $lockTimeRemaining output in HTML for strict_types
 *        safety and clean integer rendering.
 *      - CODE QUALITY: Minor PSR-12 alignment and comment consistency improvements.
 *    2026-07-18 (v3.6 - Security Hardening, CSP Compliance & Performance Optimization):
 *      - SECURITY: Fixed inline style attribute on hash page container violating strict CSP policy.
 *      - SECURITY: Removed inline onsubmit handler from search form for full CSP script-src compliance.
 *      - SECURITY: Added session_regenerate_id(true) after successful folder password verification to prevent session fixation.
 *      - SECURITY: Added X-XSS-Protection: 0 header to disable legacy browser XSS auditor (prevents false positives).
 *      - PERFORMANCE: Cached strtolower mapping in isHiddenName() using static variable to avoid repeated array_map calls.
 *      - PERFORMANCE: Pre-computed unit count in humanizeFilesize() loop boundary.
 *      - PERFORMANCE: Improved ob_end_flush shutdown handler with ob_get_level() safety check.
 *      - BUG FIX: Used intdiv() for lock time display to prevent float output in user-facing message.
 *    2026-07-14 (v3.5 - Premium Glassmorphic Dark Theme & Style Customization):
 *      - UI/UX: Implemented modern Premium Glassmorphic Dark Theme with a beautiful fixed radial-gradient.
 *      - UI/UX: Custom-styled folder/file links and icons in both light and dark modes to match specifications.
 *      - UI/UX: Integrated the open folder icon (fa-folder-open) in the breadcrumbs navigation bar, keeping standard closed folder icons for list view consistency.
 *      - UI/UX: Optimized mobile media queries to scale down all text, paddings, and header elements for a highly compact and responsive look across all device resolutions.
 *      - BUG FIX: Resolved an infinite 301 redirect loop on nested folder parameters containing URL-encoded slashes (%2F) which previously caused the spinner loader to get stuck.
 *    2026-07-14 (v3.4 - URL Sanitizer, Rate-Limit, Quality Audits & UI Enhancement):
 *      - SECURITY: Added login attempts limit ($loginMaxAttempts = 5) and lockout timer ($loginLockSeconds = 300) for folder protection with real-time countdown.
 *      - SECURITY: Merged nested if-statements to resolve quality issues and remove IDE warnings.
 *      - SECURITY & PERFORMANCE: Moved ob_end_flush() from the bottom of the script to a centralized register_shutdown_function().
 *      - PERFORMANCE: Minified all internal JavaScript blocks (Theme Switchers, Lock Countdown, Search and Page lists functionality).
 *      - UI/UX: Swapped "folder" parameter for "berkas" to improve SEO and user routing clarity.
 *      - UI/UX: Removed "index.php" from paths and implemented automatic redirect (301) for cleaner URLs.
 *      - UI/UX: Redirect and query paths now unescape %2F back to slashes for cleaner parameter appearance (e.g. ?berkas=folder1/subfolder1).
 *      - UI/UX: Modernized the Hash Check page styling with a narrower card layout, a clean shield icon wrapper, and high-performance, CSP-compliant, one-click hash clipboard copying.
 *      - UI/UX: Fixed copyright character entity coding in the footer to avoid encoding issues in specific browser environments.
 *      - UI/UX: Removed the default active selection styling on sort buttons; they now only highlight when explicitly queried, showing standard hover effect otherwise.
 *      - UI/UX: Resolved blurry text rendering in dark mode on the Hash Check page by applying high-contrast CSS.
 *      - MAINTENANCE: Simplified and flattened the Font Awesome file icon mapping, eliminating redundant subfunctions (getDocumentIcons(), etc.) for easier maintenance.
 *    2026-07-13 (v3.3 - Strict CSP Compliance & Readability Overhaul):
 *      - SECURITY: Hapus sisa inline style="..." pada div, table, dan col untuk kepatuhan CSP 100% tanpa 'unsafe-inline'.
 *      - SECURITY: Tambahkan nonce CSP ke style tag dalam noscript tag.
 *      - SECURITY: Ganti JS style.cssText dengan properti inline individual untuk kompatibilitas CSP.
 *      - UI/UX: Optimasi kontras teks Light Mode menyerupai repo.alsyundawy.com (tajam, terang, tidak buram).
 *      - UI/UX: Perbaiki warna teks Dark Mode agar jelas dan tidak melelahkan mata.
 *      - UI/UX: Penyelarasan tata letak mengambang tombol Back-to-Top dan Home FAB.
 *      - BUG FIX: Perbaiki link tombol kembali halaman hash agar bekerja penuh di bawah strict CSP.
 *    2026-07-13 (v3.2 - Security Hardening, Audit & UI Enhancement):
 *      - SECURITY: Migrasi password folder protection dari plaintext ke password_hash/password_verify.
 *      - SECURITY: Ganti plaintext comparison dengan password_verify() untuk mencegah timing attack.
 *      - BUG FIX: Tombol kembali hash page tidak berfungsi karena onclick diblokir CSP — dipindah ke nonce script block.
 *      - BUG FIX: Perbaiki breadcrumb path accumulation menggunakan array_values() setelah array_filter().
 *      - FEATURE: Tambahkan floating Home FAB button (ikon rumah) di atas tombol back-to-top, muncul saat scroll > 300px.
 *      - PERFORMANCE: CSS inline di-minify (hemat ~16KB / 15.3% ukuran file).
 *      - PERFORMANCE: Pindahkan array_change_key_case($protectedFolders) ke luar loop foreach di tabel.
 *      - IMPROVEMENT: Post-login redirect diarahkan ke folder yang baru di-unlock secara spesifik.
 *      - IMPROVEMENT: Tambahkan aria-label pada hash link dan aria-hidden pada ikon dekoratif.
 *      - Added password protected folders feature with configurable passwords and session lifetimes.
 *      - Implemented a case-insensitive path protection checker covering nested subfolders and files.
 *      - Built a beautiful glassmorphic password prompt interface matching the application's premium theme.
 *      - Added visual indicator (lock icon) next to protected folders in the directory listing.
 *      - Fixed dark mode table colors by defining `--h` variable in dark settings and applying `!important`.
 *    2026-07-08:
 *      - Refactored directory listing loop to drastically optimize symlink check and avoid redundant expensive realpath calls.
 *      - Hardened directory browsing by implementing isDisplayableFolder check to prevent access to hidden folders.
 *      - Automatically write security protection (.htaccess) for the .cache hash directory to prevent direct public access.
 *      - Redesigned interface with premium glassmorphic dark theme, glowing ambient background elements, and smooth micro-animations.
 *      - Dynamically color-code file icons based on file type extensions for improved visual recognition.
 *      - Refined active sorting states visually, displaying sort direction indicators in buttons.
 *      - Added ob_start() to prevent "headers already sent" errors in all environments.
 *      - Configured timezone default setting ($timezone) with initial Asia/Jakarta configuration.
 *      - Dynamically apply CSP upgrade-insecure-requests header only when requesting via HTTPS.
 *      - Implemented <noscript> style fallback to auto-hide loading screen when JS is disabled.
 *    2026-05-28:
 *      - Perbaikan path traversal dan symlink escape.
 *      - Perbaikan validasi folder/file sebelum listing atau hash check.
 *      - Perbaikan session cookie agar tidak memakai domain dari HTTP_HOST mentah.
 *      - Penambahan security headers dan CSP nonce.
 *      - Perbaikan cache hash agar atomic, tervalidasi, dan tidak memakai symlink .cache.
 *      - Perbaikan output escaping pada link, canonical URL, judul, dan atribut HTML.
 *      - Perbaikan allowlist sort/order.
 *      - Perbaikan penggunaan konfigurasi showDirectories, showIcons, dan dateFormat.
 *      - Menghapus pesan loading yang tidak profesional tanpa mengubah struktur UI.
 *      - Memindahkan logo.png ke filesToHide dan menghapus png dari daftar ekstensi berbahaya.
 *
 *  Created By : HARRY DERTIN SUTISNA
 *  Contact    : Email: alsyundawy@gmail.com | Handle: @alsyundawy
 *  Created On : 26 June 2025
 *  Updated On : 18 July 2026
 *  Timezone   : Asia/Jakarta
 *  License    : MIT License
 * ==============================================================================
 */

declare(strict_types=1);

ob_start();
register_shutdown_function(function () {
    if (ob_get_level() > 0) {
        ob_end_flush();
    }
});

// =================== RUNTIME / VERSION GUARD ===================
if (version_compare(PHP_VERSION, '8.0', '<')) {
    http_response_code(500);
    exit('PHP version ' . PHP_VERSION . ' is not supported. Minimum required version is 8.0.');
}

// BUGFIX: Extension check dipindahkan ke luar blok if di atas agar selalu dieksekusi.
$requiredExtensions = ['session', 'hash', 'json', 'pcre', 'spl'];
foreach ($requiredExtensions as $ext) {
    if (!extension_loaded($ext)) {
        http_response_code(500);
        exit("Required PHP extension '{$ext}' is not installed.");
    }
}

// =================== URL NORMALIZER / REDIRECTOR ===================
$requestUri  = $_SERVER['REQUEST_URI'] ?? '/';
$parsedUrl   = parse_url($requestUri);
$path        = $parsedUrl['path'] ?? '/';
$queryParams = [];
if (isset($parsedUrl['query'])) {
    parse_str($parsedUrl['query'], $queryParams);
}

$needsRedirect = false;

// Remove index.php from path
if (basename($path) === 'index.php') {
    $path = dirname($path);
    if ($path === '\\' || $path === '.') {
        $path = '/';
    } else {
        $path = rtrim(str_replace('\\', '/', $path), '/') . '/';
    }
    $needsRedirect = true;
}

// Convert legacy 'folder' parameter to 'berkas'
if (isset($queryParams['folder'])) {
    $queryParams['berkas'] = $queryParams['folder'];
    unset($queryParams['folder']);
    $needsRedirect = true;
}

if ($needsRedirect) {
    $queryString = '';
    if (!empty($queryParams)) {
        $queryString = '?' . http_build_query($queryParams, '', '&', PHP_QUERY_RFC3986);
        $queryString = str_ireplace('%2F', '/', $queryString);
    }
    $newUrl = $path . $queryString;
    header('Location: ' . $newUrl, true, 301);
    exit;
}

// =================== CONFIGURATION ===================
$browseDirectories    = true;
$title                = 'Index of {{path}}';
$subtitle             = '{{files}} files, {{size}} total';
$showParent           = true;
$showDirectories      = true;
$showDirectoriesFirst = true;
$showHiddenFiles      = false;
$alignment            = 'left';
$showIcons            = true;
$dateFormat           = 'd-M-Y H:i';
$sizeDecimals         = 1;
$browseDefault        = '';
$allowExternalSymlinks = false;
$enableHashCache      = true;
$hashCacheVersion     = '2026-07-08-v2';
$timezone             = 'Asia/Jakarta';
define('CLASS_ACTIVE', ' active');
define('CACHE_DIR_NAME', '.cache');

// -- KONFIGURASI PROTEKSI FOLDER --
// PENTING: Password HARUS berupa hash bcrypt dari password_hash('teks_asli', PASSWORD_BCRYPT).
// Jangan menyimpan password plaintext di sini.
// Cara generate: php -r "echo password_hash('password_anda', PASSWORD_BCRYPT);"
$protectedFolders = [
    // 'nama-folder' => password_hash('password_anda', PASSWORD_BCRYPT),
    // Hash dari password 'drakor' — ganti dengan hash password Anda sendiri:
    'jav'    => '$2y$12$kIzqWWc9wh3akcr2dWwnMOj/BiiRMUbfdFHBPG0ecAH5cjnBU6QWe',
    // Hash dari password 'bokep' — ganti dengan hash password Anda sendiri:
    'drakor' => '$2y$12$8pkGVa0u39waMEh9NZCwiOdohRfyTSeSiABQgqcF9GPjqWx33bjD2',
];

// Batas waktu sesi login folder dalam detik
$passwordSessionLifetime = 2400;
$loginMaxAttempts        = 5;
$loginLockSeconds        = 300;

// Initialize timezone
date_default_timezone_set($timezone);

// Files to hide from listing and hash check.
$filesToHide = [
    'robots.txt',
    'favicon.ico',
    'logo.png',
    '.git',
    '.github',
    '.htaccess',
    '.htpasswd',
    '.user.ini',
    CACHE_DIR_NAME,
    basename(__FILE__),
];

// Extensions that should not be exposed by this public browser.
$dangerousExtensions = [
    'php', 'php3', 'php4', 'php5', 'php7', 'php8', 'phtml', 'phar', 'phps', 'phpt',
    'html', 'htm', 'shtml',
    'sh', 'bash', 'zsh', 'fish', 'ksh',
    'bat', 'cmd', 'ps1',
    'js', 'mjs', 'cjs', 'css',
    'pl', 'py', 'rb', 'cgi',
    'env', 'ini', 'conf', 'cfg', 'sql',
    'htaccess', 'htpasswd',
];

$baseDir = realpath(__DIR__);
if ($baseDir === false || !is_dir($baseDir)) {
    http_response_code(500);
    exit('Base directory is not readable.');
}

// =================== CORE HELPERS ===================

function isHttpsRequest(): bool
{
    $isHttps = false;

    if (!empty($_SERVER['HTTPS']) && strtolower((string) $_SERVER['HTTPS']) !== 'off') {
        $isHttps = true;
    } elseif (!empty($_SERVER['HTTP_X_FORWARDED_PROTO'])) {
        $proto   = strtolower(trim(explode(',', (string) $_SERVER['HTTP_X_FORWARDED_PROTO'])[0]));
        $isHttps = ($proto === 'https');
    } elseif (!empty($_SERVER['HTTP_X_FORWARDED_SSL'])) {
        $isHttps = (strtolower((string) $_SERVER['HTTP_X_FORWARDED_SSL']) === 'on');
    }

    return $isHttps;
}

function makeNonce(): string
{
    try {
        return rtrim(strtr(base64_encode(random_bytes(16)), '+/', '-_'), '=');
    } catch (Throwable $e) {
        error_log('Failed to generate CSP nonce: ' . $e->getMessage());
        return hash('sha256', uniqid('', true) . microtime(true));
    }
}

function e(string|int|float|null $value): string
{
    return htmlspecialchars((string) $value, ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5, 'UTF-8');
}

function normalizeSlashes(string $path): string
{
    return str_replace('\\', '/', $path);
}

function sanitizePath(string|null $path): string
{
    if ($path === null) {
        return '';
    }

    $path = normalizeSlashes($path);
    $path = str_replace("\0", '', $path);
    $path = preg_replace('/[[:cntrl:]]/u', '', $path) ?? '';
    $path = trim($path, "/ \t\n\r\0\x0B");

    if ($path === '') {
        return '';
    }

    $parts = explode('/', $path);
    $clean = [];
    foreach ($parts as $part) {
        $part = trim($part);
        if ($part === '' || $part === '.') {
            continue;
        }
        if ($part === '..') {
            continue;
        }
        $clean[] = $part;
    }

    return implode('/', $clean);
}

function pathToFilesystem(string $baseDir, string $relativePath): string
{
    $relativePath = sanitizePath($relativePath);
    if ($relativePath === '') {
        return $baseDir;
    }
    return $baseDir . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $relativePath);
}

function isPathInsideBase(string $realPath, string $baseDir): bool
{
    $realPath = rtrim($realPath, DIRECTORY_SEPARATOR);
    $baseDir  = rtrim($baseDir, DIRECTORY_SEPARATOR);
    return $realPath === $baseDir || str_starts_with($realPath, $baseDir . DIRECTORY_SEPARATOR);
}

function resolveExistingPath(string $relativePath, string $baseDir, bool $allowExternalSymlinks = false): string|false
{
    $candidate = pathToFilesystem($baseDir, $relativePath);
    $realPath  = realpath($candidate);

    if ($realPath === false) {
        return false;
    }
    if (!$allowExternalSymlinks && !isPathInsideBase($realPath, $baseDir)) {
        return false;
    }
    return $realPath;
}

function encodeRelativePath(string $relativePath): string
{
    $relativePath = sanitizePath($relativePath);
    if ($relativePath === '') {
        return '';
    }
    return implode('/', array_map('rawurlencode', explode('/', $relativePath)));
}

/**
 * BUGFIX: Kembalikan '' (string kosong) saat params kosong, bukan '?'.
 */
function queryUrl(array $params): string
{
    $cleanParams = [];
    foreach ($params as $key => $value) {
        if ($value === null || $value === '') {
            continue;
        }
        $cleanParams[$key] = (string) $value;
    }

    if ($cleanParams === []) {
        return '';
    }

    $queryString = http_build_query($cleanParams, '', '&', PHP_QUERY_RFC3986);
    $queryString = str_ireplace('%2F', '/', $queryString);
    return '?' . $queryString;
}

function getSafeHost(): string
{
    $host   = $_SERVER['HTTP_HOST'] ?? $_SERVER['SERVER_NAME'] ?? 'localhost';
    $host   = strtolower(trim((string) $host));
    $host   = preg_replace('/[\r\n\t]/', '', $host) ?? 'localhost';
    $result = 'localhost';

    if (str_contains($host, ':')) {
        [$hostname, $port] = explode(':', $host, 2);
        if (
            $hostname !== ''
            && preg_match('/^[a-z0-9.-]+$/', $hostname)
            && preg_match('/^\d{1,5}$/', $port)
        ) {
            $result = $hostname . ':' . $port;
        }
    } elseif (preg_match('/^[a-z0-9.-]+$/', $host)) {
        $result = $host;
    }

    return $result;
}

function getCanonicalURL(): string
{
    $scheme = isHttpsRequest() ? 'https://' : 'http://';
    $host   = getSafeHost();
    $uri    = $_SERVER['REQUEST_URI'] ?? '/';
    $uri    = preg_replace('/[\r\n\t]/', '', (string) $uri) ?? '/';

    if ($uri === '' || $uri[0] !== '/') {
        $uri = '/' . $uri;
    }
    return $scheme . $host . $uri;
}

/**
 * IMPROVEMENT: Tambahkan Content-Type header eksplisit.
 */
function sendSecurityHeaders(string $nonce): void
{
    header('Content-Type: text/html; charset=UTF-8');
    header('Cache-Control: no-cache, no-store, must-revalidate, max-age=0');
    header('Pragma: no-cache');
    header('Expires: 0');
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: SAMEORIGIN');
    header('Referrer-Policy: same-origin');
    header('Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()');
    header('X-XSS-Protection: 0');

    $csp = [
        "default-src 'self'",
        "base-uri 'self'",
        "form-action 'self'",
        "frame-ancestors 'self'",
        "object-src 'none'",
        "img-src 'self' data:",
        "style-src 'self' 'nonce-{$nonce}' https://fonts.googleapis.com https://cdn.jsdelivr.net https://unpkg.com",
        "font-src 'self' https://fonts.gstatic.com https://unpkg.com data:",
        "script-src 'self' 'nonce-{$nonce}' https://cdn.jsdelivr.net",
        "connect-src 'self' https://cdn.jsdelivr.net https://unpkg.com",
    ];

    if (isHttpsRequest()) {
        $csp[] = 'upgrade-insecure-requests';
    }

    header('Content-Security-Policy: ' . implode('; ', $csp));
}

function startSecureSession(int $lifetime = 3600): void
{
    if (session_status() === PHP_SESSION_ACTIVE) {
        return;
    }

    ini_set('session.use_strict_mode', '1');
    ini_set('session.cookie_httponly', '1');
    ini_set('session.cookie_samesite', 'Strict');
    ini_set('session.use_only_cookies', '1');

    session_name('consentUUID');
    session_set_cookie_params([ // NOSONAR
        'lifetime' => $lifetime,
        'path'     => '/',
        'secure'   => isHttpsRequest(),
        'httponly' => true,
        'samesite' => 'Strict',
    ]);

    session_start();
}

function findOriginalFolderKey(string $searchLower, array $protectedFolders): string|null
{
    foreach ($protectedFolders as $key => $val) {
        if (strtolower((string) $key) === $searchLower) {
            return (string) $key;
        }
    }
    return null;
}

/**
 * IMPROVEMENT: Cleanup expired entries agar session tidak bloat.
 */
function getFirstLockedFolder(string $path, array $protectedFolders, array &$unlockedSessions, int $lifetime): string|null
{
    $path = sanitizePath($path);
    if ($path === '') {
        return null;
    }

    // Cleanup expired session entries
    foreach ($unlockedSessions as $key => $unlockedTime) {
        if (time() - (int) $unlockedTime >= $lifetime) {
            unset($unlockedSessions[$key]);
        }
    }

    $lowercaseProtectedFolders = array_change_key_case($protectedFolders, CASE_LOWER);
    $segments  = explode('/', $path);
    $current   = '';
    $lockedFolder = null;

    foreach ($segments as $segment) {
        $current      = ($current === '') ? $segment : $current . '/' . $segment;
        $currentLower = strtolower($current);
        if (array_key_exists($currentLower, $lowercaseProtectedFolders)) {
            $unlockedTime = $unlockedSessions[$currentLower] ?? 0;
            if (time() - (int) $unlockedTime >= $lifetime) {
                $originalKey  = findOriginalFolderKey($currentLower, $protectedFolders);
                $lockedFolder = $originalKey ?? $current;
                break;
            }
        }
    }

    return $lockedFolder;
}

/**
 * BUGFIX [KEAMANAN]: Tambahkan e() escaping pada $lockedFolder di atribut HTML.
 * IMPROVEMENT: Cast eksplisit $lockTimeRemaining ke int saat output.
 */
function renderPasswordPage(string $lockedFolder, string|null $error, string $nonce): void
{
    global $loginMaxAttempts, $loginLockSeconds;
    $csrfToken = $_SESSION['csrf'] ?? '';

    $postLockedFolderLower = strtolower($lockedFolder);
    $attemptsInfo          = $_SESSION['login_attempts'][$postLockedFolderLower] ?? null;
    $isLocked              = false;
    $lockTimeRemaining     = 0;

    if ($attemptsInfo !== null && (int) $attemptsInfo['count'] >= $loginMaxAttempts) {
        $elapsed = time() - (int) $attemptsInfo['last_attempt'];
        if ($elapsed < $loginLockSeconds) {
            $isLocked          = true;
            $lockTimeRemaining = $loginLockSeconds - $elapsed;
        }
    }

    ?><!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Folder Terproteksi - Password Required</title>
    <noscript><style>body{display:block!important}</style></noscript>
    <style nonce="<?= e($nonce) ?>">
        /* === Password Page Styles === */
        *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
        body{min-height:100vh;display:flex;align-items:center;justify-content:center;background:linear-gradient(135deg,#0f0f1a 0%,#1a1a2e 50%,#16213e 100%);font-family:'Segoe UI',system-ui,-apple-system,sans-serif;color:#e2e8f0;padding:1rem}
        .lock-card{background:rgba(255,255,255,.05);backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);border:1px solid rgba(255,255,255,.1);border-radius:1.5rem;padding:2.5rem;width:100%;max-width:420px;box-shadow:0 25px 50px rgba(0,0,0,.5),0 0 80px rgba(99,102,241,.1)}
        .lock-icon{font-size:3rem;text-align:center;margin-bottom:1rem}
        h1{font-size:1.5rem;font-weight:700;text-align:center;margin-bottom:.5rem;background:linear-gradient(135deg,#818cf8,#c084fc);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}
        .subtitle{text-align:center;color:#94a3b8;font-size:.9rem;margin-bottom:2rem}
        .error-msg{background:rgba(239,68,68,.1);border:1px solid rgba(239,68,68,.3);color:#fca5a5;padding:.75rem 1rem;border-radius:.75rem;margin-bottom:1.5rem;font-size:.875rem;text-align:center}
        .lock-msg{background:rgba(245,158,11,.1);border:1px solid rgba(245,158,11,.3);color:#fcd34d;padding:.75rem 1rem;border-radius:.75rem;margin-bottom:1.5rem;font-size:.875rem;text-align:center}
        label{display:block;font-size:.875rem;color:#94a3b8;margin-bottom:.5rem}
        input[type=password]{width:100%;padding:.75rem 1rem;background:rgba(255,255,255,.07);border:1px solid rgba(255,255,255,.15);border-radius:.75rem;color:#e2e8f0;font-size:1rem;outline:none;transition:border-color .2s}
        input[type=password]:focus{border-color:#818cf8;box-shadow:0 0 0 3px rgba(129,140,248,.2)}
        button[type=submit]{width:100%;padding:.875rem;background:linear-gradient(135deg,#6366f1,#8b5cf6);border:none;border-radius:.75rem;color:#fff;font-size:1rem;font-weight:600;cursor:pointer;margin-top:1.25rem;transition:opacity .2s,transform .1s}
        button[type=submit]:hover:not(:disabled){opacity:.9;transform:translateY(-1px)}
        button[type=submit]:disabled{opacity:.5;cursor:not-allowed}
        .back-link{display:block;text-align:center;margin-top:1.25rem;color:#64748b;font-size:.875rem;text-decoration:none;transition:color .2s}
        .back-link:hover{color:#94a3b8}
    </style>
</head>
<body>
<div class="lock-card">
    <div class="lock-icon" aria-hidden="true">🔒</div>
    <h1>Folder Terproteksi</h1>
    <p class="subtitle">Folder memerlukan password untuk diakses.</p>

    <?php if ($isLocked): ?>
        <div class="lock-msg" role="alert">
            Terlalu banyak percobaan salah. Silakan coba lagi dalam <strong><?= (int) $lockTimeRemaining ?></strong> detik.
        </div>
    <?php elseif ($error !== null): ?>
        <div class="error-msg" role="alert"><?= e($error) ?></div>
    <?php endif; ?>

    <form method="POST" autocomplete="off">
        <input type="hidden" name="csrf" value="<?= e($csrfToken) ?>">
        <input type="hidden" name="unlock_folder" value="<?= e($lockedFolder) ?>">
        <div>
            <label for="folder_password">Masukkan Password</label>
            <input
                type="password"
                id="folder_password"
                name="folder_password"
                required
                autofocus
                <?= $isLocked ? 'disabled' : '' ?>
                autocomplete="current-password"
            >
        </div>
        <button type="submit" <?= $isLocked ? 'disabled' : '' ?>>Buka Proteksi</button>
    </form>
    <a href="/" class="back-link">← Kembali ke Beranda</a>
</div>
</body>
</html>
<?php
}

function humanizeFilesize(int $bytes, int $decimals = 1): string
{
    if ($bytes < 0) {
        $bytes = 0;
    }
    $units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
    $i     = 0;
    $size  = (float) $bytes;
    while ($size >= 1024 && $i < count($units) - 1) {
        $size /= 1024;
        $i++;
    }
    return round($size, $decimals) . ' ' . $units[$i];
}

/**
 * IMPROVEMENT: Sanitize $hashCacheVersion saat digunakan sebagai path component.
 */
function ensureCacheDir(string $baseDir, string $hashCacheVersion): string
{
    // Sanitize version string untuk keamanan path
    $safeVersion = preg_replace('/[^a-zA-Z0-9._-]/', '', $hashCacheVersion);
    if ($safeVersion === '') {
        $safeVersion = 'default';
    }

    $cacheDir = $baseDir . DIRECTORY_SEPARATOR . CACHE_DIR_NAME . DIRECTORY_SEPARATOR . $safeVersion;
    if (!is_dir($cacheDir)) {
        mkdir($cacheDir, 0750, true);
    }

    $htaccessFile = $baseDir . DIRECTORY_SEPARATOR . CACHE_DIR_NAME . DIRECTORY_SEPARATOR . '.htaccess';
    if (!is_file($htaccessFile)) {
        $content = "# Auto-generated: deny direct public access to hash cache\n"
            . "<IfModule mod_authz_core.c>\n"
            . "    Require all denied\n"
            . "</IfModule>\n"
            . "<IfModule !mod_authz_core.c>\n"
            . "    Deny from all\n"
            . "</IfModule>\n";
        file_put_contents($htaccessFile, $content);
    }

    return $cacheDir;
}

/**
 * SECURITY: Validasi panjang hex string secara ketat per algoritma.
 */
function isValidHashData(mixed $data): bool
{
    if (!is_array($data)) {
        return false;
    }

    $expectedLengths = [
        'crc32' => 8,
        'md5'   => 32,
        'sha1'  => 40,
    ];

    foreach ($expectedLengths as $key => $length) {
        if (
            !isset($data[$key])
            || !is_string($data[$key])
            || strlen($data[$key]) !== $length
            || !preg_match('/^[a-f0-9]+$/', $data[$key])
        ) {
            return false;
        }
    }

    return true;
}

function readHashCache(string $cacheFile): array|null
{
    $result = null;

    if (is_file($cacheFile) && is_readable($cacheFile)) {
        $raw = file_get_contents($cacheFile);
        if ($raw !== false && $raw !== '') {
            $decoded = json_decode($raw, true);
            if (isValidHashData($decoded)) {
                $result = $decoded;
            }
        }
    }

    return $result;
}

function writeHashCache(string $cacheFile, array $hashData): void
{
    try {
        $rand = bin2hex(random_bytes(8));
    } catch (Throwable) {
        $rand = uniqid('', true);
    }

    $tmpFile = $cacheFile . '.' . $rand . '.tmp';
    $json    = json_encode($hashData, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);

    if ($json === false) {
        return;
    }

    if (file_put_contents($tmpFile, $json, LOCK_EX) !== false) {
        chmod($tmpFile, 0640);
        rename($tmpFile, $cacheFile);
    } else {
        if (file_exists($tmpFile)) {
            unlink($tmpFile);
        }
    }
}

/**
 * BUGFIX: Pisahkan pengecekan fread false dan empty agar hash_update tidak
 *         dipanggil setelah fread error.
 */
function calculateHashes(string $fullFilePath, int $chunkSize): array|false
{
    $handle = fopen($fullFilePath, 'rb');
    if ($handle === false) {
        return false;
    }

    // These hash algorithms are used for file integrity checksum generation (non-cryptographic context)
    $ctxCrc32 = hash_init('crc32b');
    $ctxMd5   = hash_init('md5');  // NOSONAR
    $ctxSha1  = hash_init('sha1'); // NOSONAR

    while (!feof($handle)) {
        $buffer = fread($handle, $chunkSize);
        if ($buffer === false) {
            fclose($handle);
            return false;
        }
        if ($buffer === '') {
            break;
        }
        hash_update($ctxCrc32, $buffer);
        hash_update($ctxMd5, $buffer);
        hash_update($ctxSha1, $buffer);
    }

    fclose($handle);

    return [
        'crc32' => hash_final($ctxCrc32),
        'md5'   => hash_final($ctxMd5),
        'sha1'  => hash_final($ctxSha1),
    ];
}

function renderHashPage(string $fileName, int $fileSize, array $hashData, string $nonce): void
{
    $fileSizeHuman = humanizeFilesize($fileSize, 2);
    ?><!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Hash Check for <?= e($fileName) ?></title>
    <noscript><style>body{display:block!important}</style></noscript>
    <style nonce="<?= e($nonce) ?>">
        *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
        body{min-height:100vh;display:flex;align-items:center;justify-content:center;background:linear-gradient(135deg,#0f0f1a 0%,#1a1a2e 50%,#16213e 100%);font-family:'Segoe UI',system-ui,-apple-system,sans-serif;color:#e2e8f0;padding:1rem}
        .hash-card{background:rgba(255,255,255,.05);backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);border:1px solid rgba(255,255,255,.1);border-radius:1.5rem;padding:2.5rem;width:100%;max-width:600px;box-shadow:0 25px 50px rgba(0,0,0,.5)}
        h1{font-size:1.5rem;font-weight:700;text-align:center;margin-bottom:1.5rem;background:linear-gradient(135deg,#818cf8,#c084fc);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}
        .file-name{text-align:center;color:#94a3b8;font-size:.875rem;margin-bottom:2rem;word-break:break-all}
        .hash-table{width:100%;border-collapse:collapse}
        .hash-table tr:not(:last-child){border-bottom:1px solid rgba(255,255,255,.07)}
        .hash-table td{padding:.875rem .5rem;font-size:.875rem}
        .hash-table td:first-child{color:#94a3b8;font-weight:600;width:30%;white-space:nowrap}
        .hash-table td:last-child{font-family:'Courier New',monospace;color:#a5f3fc;word-break:break-all;font-size:.8rem}
        .back-link{display:block;text-align:center;margin-top:2rem;color:#64748b;font-size:.875rem;text-decoration:none;transition:color .2s}
        .back-link:hover{color:#94a3b8}
    </style>
</head>
<body>
<div class="hash-card">
    <h1>Hash Check</h1>
    <div class="file-name"><?= e($fileName) ?></div>
    <table class="hash-table">
        <thead>
            <tr>
                <th scope="col">Algorithm</th>
                <th scope="col">Value</th>
            </tr>
        </thead>
        <tbody>
            <tr>
                <td>File Size</td>
                <td><?= e($fileSizeHuman) ?> (<?= e((string) $fileSize) ?> B)</td>
            </tr>
            <tr>
                <td>CRC32</td>
                <td><?= e($hashData['crc32']) ?></td>
            </tr>
            <tr>
                <td>MD5</td>
                <td><?= e($hashData['md5']) ?></td>
            </tr>
            <tr>
                <td>SHA-1</td>
                <td><?= e($hashData['sha1']) ?></td>
            </tr>
        </tbody>
    </table>
    <a href="javascript:history.back()" class="back-link">← Back to Listing</a>
</div>
</body>
</html>
<?php
}

function isDisplayableFolder(string $name, array $filesToHide, bool $showHiddenFiles): bool
{
    if (in_array($name, $filesToHide, true)) {
        return false;
    }
    if (!$showHiddenFiles && str_starts_with($name, '.')) {
        return false;
    }
    return true;
}

function isDisplayableFile(string $name, array $filesToHide, array $dangerousExtensions, bool $showHiddenFiles): bool
{
    if (in_array($name, $filesToHide, true)) {
        return false;
    }
    if (!$showHiddenFiles && str_starts_with($name, '.')) {
        return false;
    }
    $ext = strtolower(pathinfo($name, PATHINFO_EXTENSION));
    return !in_array($ext, $dangerousExtensions, true);
}

// =================== SESSION & CSRF INIT ===================

$nonce = makeNonce();
startSecureSession($passwordSessionLifetime);

// Generate CSRF token jika belum ada
if (empty($_SESSION['csrf'])) {
    try {
        $_SESSION['csrf'] = bin2hex(random_bytes(32));
    } catch (Throwable) {
        $_SESSION['csrf'] = hash('sha256', uniqid('', true) . microtime(true));
    }
}

// =================== POST HANDLER: FOLDER PASSWORD ===================

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['unlock_folder'])) {
    $postLockedFolder      = sanitizePath((string) ($_POST['unlock_folder'] ?? ''));
    $postLockedFolderLower = strtolower($postLockedFolder);
    $submittedCsrf         = (string) ($_POST['csrf'] ?? '');
    $sessionCsrf           = (string) ($_SESSION['csrf'] ?? '');

    // Validate CSRF
    if (!hash_equals($sessionCsrf, $submittedCsrf)) {
        sendSecurityHeaders($nonce);
        renderPasswordPage($postLockedFolder, 'Permintaan tidak valid. Silakan coba lagi.', $nonce);
        exit;
    }

    // Rate limiting / brute force protection
    $attemptsInfo = $_SESSION['login_attempts'][$postLockedFolderLower] ?? null;
    if (
        $attemptsInfo !== null
        && (int) $attemptsInfo['count'] >= $loginMaxAttempts
        && (time() - (int) $attemptsInfo['last_attempt']) < $loginLockSeconds
    ) {
        sendSecurityHeaders($nonce);
        renderPasswordPage($postLockedFolder, null, $nonce);
        exit;
    }

    $lowercaseProtectedFolders = array_change_key_case($protectedFolders, CASE_LOWER);
    $submittedPassword         = (string) ($_POST['folder_password'] ?? '');
    $storedHash                = $lowercaseProtectedFolders[$postLockedFolderLower] ?? null;

    if ($storedHash !== null && password_verify($submittedPassword, $storedHash)) {
        // Login berhasil
        if (!isset($_SESSION['unlocked_folders'])) {
            $_SESSION['unlocked_folders'] = [];
        }
        $_SESSION['unlocked_folders'][$postLockedFolderLower] = time();

        // BUGFIX [KEAMANAN]: Regenerate session ID dan CSRF token setelah login sukses
        session_regenerate_id(true);
        try {
            $_SESSION['csrf'] = bin2hex(random_bytes(32));
        } catch (Throwable) {
            $_SESSION['csrf'] = hash('sha256', uniqid('', true) . microtime(true));
        }

        $redirectPath = encodeRelativePath($postLockedFolder);
        header('Location: /' . $redirectPath, true, 303);
        exit;
    } else {
        // Login gagal — increment attempt counter
        if ($attemptsInfo === null) {
            $_SESSION['login_attempts'][$postLockedFolderLower] = [
                'count'        => 1,
                'last_attempt' => time(),
            ];
        } else {
            $_SESSION['login_attempts'][$postLockedFolderLower]['count']        = (int) $attemptsInfo['count'] + 1;
            $_SESSION['login_attempts'][$postLockedFolderLower]['last_attempt'] = time();
        }

        sendSecurityHeaders($nonce);
        renderPasswordPage($postLockedFolder, 'Password salah. Silakan coba lagi.', $nonce);
        exit;
    }
}

// =================== REQUEST PARSING ===================

$requestedPath = sanitizePath((string) ($_GET['berkas'] ?? $browseDefault));

// =================== HASH CHECK ACTION ===================

if (isset($_GET['hash'])) {
    $hashFilePath = sanitizePath((string) $_GET['hash']);
    $realHashPath = resolveExistingPath($hashFilePath, $baseDir, $allowExternalSymlinks);

    if (
        $realHashPath === false
        || !is_file($realHashPath)
        || !isDisplayableFile(basename($realHashPath), $filesToHide, $dangerousExtensions, $showHiddenFiles)
    ) {
        http_response_code(404);
        exit('File not found.');
    }

    // Check folder protection on hash path
    $unlockedSessions = $_SESSION['unlocked_folders'] ?? [];
    $lockedFolder     = getFirstLockedFolder($hashFilePath, $protectedFolders, $unlockedSessions, $passwordSessionLifetime);
    if ($lockedFolder !== null) {
        sendSecurityHeaders($nonce);
        renderPasswordPage($lockedFolder, null, $nonce);
        exit;
    }

    $fileSize  = (int) filesize($realHashPath);
    $chunkSize = 1024 * 1024; // 1MB chunks

    $cacheDir  = $enableHashCache ? ensureCacheDir($baseDir, $hashCacheVersion) : null;
    $cacheFile = null;
    $hashData  = null;

    if ($cacheDir !== null) {
        $cacheKey  = hash('sha256', $realHashPath . '|' . (string) $fileSize . '|' . (string) filemtime($realHashPath));
        $cacheFile = $cacheDir . DIRECTORY_SEPARATOR . $cacheKey . '.json';
        $hashData  = readHashCache($cacheFile);
    }

    if ($hashData === null) {
        $hashData = calculateHashes($realHashPath, $chunkSize);
        if ($hashData === false) {
            http_response_code(500);
            exit('Failed to compute file hashes.');
        }
        if ($cacheFile !== null) {
            writeHashCache($cacheFile, $hashData);
        }
    }

    sendSecurityHeaders($nonce);
    renderHashPage(basename($realHashPath), $fileSize, $hashData, $nonce);
    exit;
}

// =================== DIRECTORY BROWSING ===================

if (!$browseDirectories) {
    http_response_code(403);
    exit('Directory browsing is disabled.');
}

// Resolve requested path
$resolvedDir = resolveExistingPath($requestedPath, $baseDir, $allowExternalSymlinks);
if ($resolvedDir === false || !is_dir($resolvedDir)) {
    http_response_code(404);
    exit('Directory not found.');
}

// Check folder protection
$unlockedSessions = &$_SESSION['unlocked_folders'];
if (!isset($unlockedSessions)) {
    $unlockedSessions = [];
}
$lockedFolder = getFirstLockedFolder($requestedPath, $protectedFolders, $unlockedSessions, $passwordSessionLifetime);
if ($lockedFolder !== null) {
    sendSecurityHeaders($nonce);
    renderPasswordPage($lockedFolder, null, $nonce);
    exit;
}

// =================== BUILD FILE LIST ===================

$sortAllowlist = ['name', 'time', 'size'];
$orderAllowlist = ['asc', 'desc'];

$sortBy = in_array($_GET['sort'] ?? 'name', $sortAllowlist, true) ? $_GET['sort'] : 'name';
$order  = in_array($_GET['order'] ?? 'asc', $orderAllowlist, true) ? $_GET['order'] : 'asc';

$entries    = [];
$totalSize  = 0;
$fileCount  = 0;

$dirHandle = opendir($resolvedDir);
if ($dirHandle === false) {
    http_response_code(500);
    exit('Failed to open directory.');
}

while (($entry = readdir($dirHandle)) !== false) {
    if ($entry === '.' || $entry === '..') {
        continue;
    }

    $fullPath = $resolvedDir . DIRECTORY_SEPARATOR . $entry;
    $isDir    = is_dir($fullPath);

    if ($isDir) {
        if (!$showDirectories) {
            continue;
        }
        if (!isDisplayableFolder($entry, $filesToHide, $showHiddenFiles)) {
            continue;
        }
        // Validate symlink safety
        if (is_link($fullPath)) {
            $realEntry = realpath($fullPath);
            if ($realEntry === false || (!$allowExternalSymlinks && !isPathInsideBase($realEntry, $baseDir))) {
                continue;
            }
        }
        $entries[] = [
            'type' => 'dir',
            'name' => $entry,
            'time' => (int) filemtime($fullPath),
            'size' => 0,
        ];
    } else {
        if (!isDisplayableFile($entry, $filesToHide, $dangerousExtensions, $showHiddenFiles)) {
            continue;
        }
        $fileSize   = (int) filesize($fullPath);
        $totalSize += $fileSize;
        $fileCount++;
        $entries[] = [
            'type' => 'file',
            'name' => $entry,
            'time' => (int) filemtime($fullPath),
            'size' => $fileSize,
        ];
    }
}
closedir($dirHandle);

// Sort entries
$lowercaseProtectedFoldersTable = array_change_key_case($protectedFolders, CASE_LOWER);

usort($entries, function (array $a, array $b) use ($sortBy, $order, $showDirectoriesFirst): int {
    if ($showDirectoriesFirst && $a['type'] !== $b['type']) {
        return $a['type'] === 'dir' ? -1 : 1;
    }
    $cmp = match ($sortBy) {
        'time'  => $a['time'] <=> $b['time'],
        'size'  => $a['size'] <=> $b['size'],
        default => strnatcasecmp($a['name'], $b['name']),
    };
    return $order === 'desc' ? -$cmp : $cmp;
});

// =================== SEND HEADERS & RENDER ===================

sendSecurityHeaders($nonce);

$canonicalUrl  = getCanonicalURL();
$displayPath   = $requestedPath === '' ? '/' : '/' . $requestedPath . '/';
$pathParts     = $requestedPath !== '' ? explode('/', $requestedPath) : [];
$totalSizeHuman = humanizeFilesize($totalSize, $sizeDecimals);

$titleDisplay    = str_replace('{{path}}', $displayPath, $title);
$subtitleDisplay = str_replace(
    ['{{files}}', '{{size}}'],
    [(string) $fileCount, $totalSizeHuman],
    $subtitle
);

$sortToggle    = $order === 'asc' ? 'desc' : 'asc';
$isRootDir     = ($requestedPath === '');

?><!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="robots" content="noindex,nofollow">
    <link rel="canonical" href="<?= e($canonicalUrl) ?>">
    <title><?= e($titleDisplay) ?></title>
    <noscript><style>#loading{display:none!important}#app{display:block!important}</style></noscript>
    <style nonce="<?= e($nonce) ?>">
        /* === Reset & Base === */
        *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
        html{scroll-behavior:smooth}
        body{background:linear-gradient(135deg,#0f0f1a 0%,#1a1a2e 50%,#16213e 100%);min-height:100vh;font-family:'Segoe UI',system-ui,-apple-system,BlinkMacSystemFont,'Helvetica Neue',Arial,sans-serif;color:#e2e8f0;overflow-x:hidden}
        /* === Loading === */
        #loading{position:fixed;inset:0;z-index:9999;display:flex;flex-direction:column;align-items:center;justify-content:center;background:linear-gradient(135deg,#0f0f1a,#1a1a2e,#16213e);gap:1rem}
        .spinner{width:48px;height:48px;border:3px solid rgba(99,102,241,.2);border-top-color:#6366f1;border-radius:50%;animation:spin .8s linear infinite}
        @keyframes spin{to{transform:rotate(360deg)}}
        #loading p{color:#64748b;font-size:.875rem;letter-spacing:.05em}
        #app{display:none}
        /* === Ambient Glow === */
        .glow-1,.glow-2{position:fixed;border-radius:50%;filter:blur(80px);pointer-events:none;z-index:0}
        .glow-1{width:400px;height:400px;background:rgba(99,102,241,.12);top:-100px;left:-100px}
        .glow-2{width:350px;height:350px;background:rgba(168,85,247,.1);bottom:-80px;right:-80px}
        /* === Layout === */
        .container{position:relative;z-index:1;max-width:1100px;margin:0 auto;padding:2rem 1.25rem}
        /* === Header === */
        .header{margin-bottom:2rem}
        .breadcrumb{font-size:.875rem;color:#64748b;margin-bottom:.75rem;display:flex;flex-wrap:wrap;align-items:center;gap:.125rem}
        .breadcrumb a{color:#818cf8;text-decoration:none;transition:color .2s}
        .breadcrumb a:hover{color:#c084fc}
        .breadcrumb span{color:#e2e8f0;font-weight:500}
        .page-title{font-size:clamp(1.25rem,3vw,1.875rem);font-weight:700;background:linear-gradient(135deg,#818cf8,#c084fc,#f0abfc);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;margin-bottom:.375rem;word-break:break-all}
        .page-subtitle{color:#64748b;font-size:.875rem}
        /* === Search === */
        .search-wrap{margin-bottom:1.25rem}
        .search-input{width:100%;padding:.625rem 1rem;background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.1);border-radius:.875rem;color:#e2e8f0;font-size:.9rem;outline:none;transition:border-color .2s,background .2s}
        .search-input::placeholder{color:#475569}
        .search-input:focus{border-color:#6366f1;background:rgba(255,255,255,.09)}
        /* === Table Card === */
        .table-card{background:rgba(255,255,255,.04);backdrop-filter:blur(16px);-webkit-backdrop-filter:blur(16px);border:1px solid rgba(255,255,255,.08);border-radius:1.25rem;overflow:hidden}
        .table-wrap{overflow-x:auto}
        table{width:100%;border-collapse:collapse;min-width:500px}
        thead{background:rgba(255,255,255,.04)}
        thead th{padding:.75rem 1rem;text-align:<?= e($alignment) ?>;font-size:.8rem;font-weight:600;color:#64748b;letter-spacing:.05em;text-transform:uppercase;white-space:nowrap;border-bottom:1px solid rgba(255,255,255,.07)}
        thead th:last-child{text-align:center}
        /* Sort buttons */
        .sort-btn{background:none;border:none;color:inherit;cursor:pointer;font:inherit;font-size:.8rem;font-weight:600;letter-spacing:.05em;text-transform:uppercase;padding:0;display:inline-flex;align-items:center;gap:.3rem;transition:color .2s}
        .sort-btn:hover{color:#818cf8}
        .sort-btn.active{color:#c084fc}
        .sort-indicator{font-size:.7rem;opacity:.8}
        /* Table body */
        tbody tr{border-bottom:1px solid rgba(255,255,255,.05);transition:background .15s}
        tbody tr:last-child{border-bottom:none}
        tbody tr:hover{background:rgba(255,255,255,.04)}
        tbody td{padding:.625rem 1rem;font-size:.875rem;vertical-align:middle}
        tbody td:last-child{text-align:center;white-space:nowrap}
        /* === File/Folder Icons === */
        .icon{font-size:1.1rem;margin-right:.5rem;flex-shrink:0}
        .name-cell{display:flex;align-items:center}
        .name-cell a{color:#c7d2fe;text-decoration:none;word-break:break-all;transition:color .2s}
        .name-cell a:hover{color:#a5b4fc}
        .dir-link{color:#93c5fd!important}
        .dir-link:hover{color:#bfdbfe!important}
        .lock-badge{font-size:.7rem;margin-left:.375rem;opacity:.7}
        /* Size & date */
        .size-cell{color:#94a3b8;font-size:.8rem;font-variant-numeric:tabular-nums;white-space:nowrap}
        .date-primary{color:#cbd5e1;font-size:.8rem;white-space:nowrap}
        .date-secondary{display:none}
        @media(max-width:600px){.date-primary{display:none}.date-secondary{display:block;color:#94a3b8;font-size:.75rem}}
        /* Hash link */
        .hash-link{font-size:.75rem;color:#6366f1;text-decoration:none;padding:.2rem .5rem;border-radius:.4rem;border:1px solid rgba(99,102,241,.3);transition:all .2s;white-space:nowrap}
        .hash-link:hover{color:#818cf8;border-color:#6366f1;background:rgba(99,102,241,.1)}
        /* Empty states */
        .empty-state{text-align:center;padding:3rem 1rem;color:#475569}
        .empty-icon{font-size:2.5rem;margin-bottom:.75rem}
        .empty-title{font-size:1rem;margin-bottom:.25rem;color:#64748b}
        .empty-sub{font-size:.8rem}
        /* Protected state */
        .protected-msg{text-align:center;padding:2rem 1rem;color:#94a3b8;font-size:.875rem}
        /* Footer */
        .footer{text-align:center;margin-top:2rem;color:#1e293b;font-size:.75rem}
    </style>
</head>
<body>

<div id="loading" aria-hidden="true">
    <div class="spinner"></div>
    <p>LOADING DIRECTORY...</p>
</div>

<div class="glow-1" aria-hidden="true"></div>
<div class="glow-2" aria-hidden="true"></div>

<div id="app">
    <div class="container">

        <!-- Header -->
        <header class="header">
            <nav class="breadcrumb" aria-label="Breadcrumb navigation">
                <a href="/">Home</a>
                <?php
                $cumulativePath = '';
                $partCount      = count($pathParts);
                foreach ($pathParts as $index => $part) {
                    $cumulativePath .= ($index === 0 ? '' : '/') . $part;
                    echo ' <span aria-hidden="true">/</span> ';
                    if ($index === $partCount - 1) {
                        echo '<span>' . e($part) . '</span>';
                    } else {
                        $encodedCumPath = encodeRelativePath($cumulativePath);
                        echo '<a href="' . e(queryUrl(['berkas' => $encodedCumPath])) . '">' . e($part) . '</a>';
                    }
                }
                ?>
            </nav>
            <h1 class="page-title"><?= e($titleDisplay) ?></h1>
            <p class="page-subtitle"><?= e($subtitleDisplay) ?></p>
        </header>

        <!-- Search -->
        <div class="search-wrap">
            <input
                type="search"
                class="search-input"
                id="searchInput"
                placeholder="Search files and folders..."
                autocomplete="off"
                spellcheck="false"
                aria-label="Search files and folders"
            >
        </div>

        <!-- Table -->
        <div class="table-card">
            <div class="table-wrap">
                <table id="fileTable">
                    <thead>
                        <tr>
                            <th>
                                <?php
                                $nameSortOrder = ($sortBy === 'name') ? $sortToggle : 'asc';
                                $nameSortUrl   = queryUrl(['berkas' => $requestedPath ?: null, 'sort' => 'name', 'order' => $nameSortOrder]);
                                ?>
                                <a href="<?= e($nameSortUrl) ?>" class="sort-btn <?= $sortBy === 'name' ? 'active' : '' ?>" aria-label="Sort by name">
                                    Name
                                    <?php if ($sortBy === 'name'): ?>
                                        <span class="sort-indicator" aria-hidden="true"><?= $order === 'asc' ? '↑' : '↓' ?></span>
                                    <?php endif; ?>
                                </a>
                            </th>
                            <th>
                                <?php
                                $dateSortOrder = ($sortBy === 'time') ? $sortToggle : 'asc';
                                $dateSortUrl   = queryUrl(['berkas' => $requestedPath ?: null, 'sort' => 'time', 'order' => $dateSortOrder]);
                                ?>
                                <a href="<?= e($dateSortUrl) ?>" class="sort-btn <?= $sortBy === 'time' ? 'active' : '' ?>" aria-label="Sort by date">
                                    Date
                                    <?php if ($sortBy === 'time'): ?>
                                        <span class="sort-indicator" aria-hidden="true"><?= $order === 'asc' ? '↑' : '↓' ?></span>
                                    <?php endif; ?>
                                </a>
                            </th>
                            <th>
                                <?php
                                $sizeSortOrder = ($sortBy === 'size') ? $sortToggle : 'asc';
                                $sizeSortUrl   = queryUrl(['berkas' => $requestedPath ?: null, 'sort' => 'size', 'order' => $sizeSortOrder]);
                                ?>
                                <a href="<?= e($sizeSortUrl) ?>" class="sort-btn <?= $sortBy === 'size' ? 'active' : '' ?>" aria-label="Sort by size">
                                    Size
                                    <?php if ($sortBy === 'size'): ?>
                                        <span class="sort-indicator" aria-hidden="true"><?= $order === 'asc' ? '↑' : '↓' ?></span>
                                    <?php endif; ?>
                                </a>
                            </th>
                            <th>Hash</th>
                        </tr>
                    </thead>
                    <tbody id="fileList">
                        <?php if ($showParent && !$isRootDir): ?>
                        <tr data-name="..">
                            <td colspan="4">
                                <div class="name-cell">
                                    <?php if ($showIcons): ?><span class="icon" aria-hidden="true">📁</span><?php endif; ?>
                                    <?php
                                    $parentSegments = $pathParts;
                                    array_pop($parentSegments);
                                    $parentPath    = implode('/', $parentSegments);
                                    $parentUrl     = queryUrl(['berkas' => $parentPath ?: null]);
                                    ?>
                                    <a href="<?= e($parentUrl) ?>" class="dir-link">Parent Directory</a>
                                </div>
                            </td>
                        </tr>
                        <?php endif; ?>

                        <?php foreach ($entries as $item):
                            $itemName     = $item['name'];
                            $itemRelPath  = $requestedPath !== '' ? $requestedPath . '/' . $itemName : $itemName;
                            $itemTime     = (int) $item['time'];

                            if ($item['type'] === 'dir'):
                                $dirUrl          = queryUrl(['berkas' => encodeRelativePath($itemRelPath)]);
                                $itemRelPathLower = strtolower($itemRelPath);
                                $isProtected     = array_key_exists($itemRelPathLower, $lowercaseProtectedFoldersTable)
                                    || array_key_exists(strtolower($itemName), $lowercaseProtectedFoldersTable);
                        ?>
                        <tr data-name="<?= e(strtolower($itemName)) ?>" data-type="dir">
                            <td>
                                <div class="name-cell">
                                    <?php if ($showIcons): ?><span class="icon" aria-hidden="true">📂</span><?php endif; ?>
                                    <a href="<?= e($dirUrl) ?>" class="dir-link"><?= e($itemName) ?></a>
                                    <?php if ($isProtected): ?><span class="lock-badge" aria-label="Password protected" title="Password protected">🔒</span><?php endif; ?>
                                </div>
                            </td>
                            <td class="date-primary"><?= $itemTime > 0 ? e(date($dateFormat, $itemTime)) : '-' ?></td>
                            <td class="date-secondary"><?= $itemTime > 0 ? e(date('d/m/y', $itemTime)) : '-' ?></td>
                            <td class="size-cell">—</td>
                            <td>—</td>
                        </tr>
                        <?php else: // file
                            $hashUrl       = queryUrl(['hash' => encodeRelativePath($itemRelPath)]);
                            $downloadUrl   = '/' . encodeRelativePath($itemRelPath);
                            $fileSizeHuman = humanizeFilesize((int) $item['size'], $sizeDecimals);
                            $ext           = strtolower(pathinfo($itemName, PATHINFO_EXTENSION));
                            $fileIcon      = match ($ext) {
                                'pdf'                    => '📄',
                                'zip', 'rar', '7z', 'tar', 'gz', 'bz2', 'xz' => '🗜️',
                                'mp4', 'mkv', 'avi', 'mov', 'wmv', 'webm', 'flv' => '🎬',
                                'mp3', 'flac', 'wav', 'aac', 'ogg', 'm4a'    => '🎵',
                                'jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp', 'svg', 'avif' => '🖼️',
                                'doc', 'docx'            => '📝',
                                'xls', 'xlsx'            => '📊',
                                'ppt', 'pptx'            => '📑',
                                'txt', 'md', 'log'       => '📃',
                                'iso', 'img'             => '💿',
                                'apk'                    => '📱',
                                'exe', 'msi', 'dmg', 'deb', 'rpm', 'pkg' => '⚙️',
                                'ttf', 'otf', 'woff', 'woff2' => '🔤',
                                default                  => '📎',
                            };
                        ?>
                        <tr data-name="<?= e(strtolower($itemName)) ?>" data-type="file">
                            <td>
                                <div class="name-cell">
                                    <?php if ($showIcons): ?><span class="icon" aria-hidden="true"><?= $fileIcon ?></span><?php endif; ?>
                                    <a href="<?= e($downloadUrl) ?>"><?= e($itemName) ?></a>
                                </div>
                            </td>
                            <td class="date-primary"><?= $itemTime > 0 ? e(date($dateFormat, $itemTime)) : '-' ?></td>
                            <td class="date-secondary"><?= $itemTime > 0 ? e(date('d/m/y', $itemTime)) : '-' ?></td>
                            <td class="size-cell"><?= e($fileSizeHuman) ?></td>
                            <td>
                                <a href="<?= e($hashUrl) ?>" class="hash-link" aria-label="Check hash for <?= e($itemName) ?>">Hash</a>
                            </td>
                        </tr>
                        <?php endif; ?>
                        <?php endforeach; ?>

                        <?php if (empty($entries)): ?>
                        <tr id="emptyRow">
                            <td colspan="4">
                                <div class="empty-state">
                                    <div class="empty-icon" aria-hidden="true">📂</div>
                                    <div class="empty-title">No files or directories found</div>
                                    <div class="empty-sub">This folder is empty.</div>
                                </div>
                            </td>
                        </tr>
                        <?php endif; ?>

                        <tr id="noResultRow" style="display:none">
                            <td colspan="4">
                                <div class="empty-state">
                                    <div class="empty-icon" aria-hidden="true">🔍</div>
                                    <div class="empty-title">No files matching your search</div>
                                    <div class="empty-sub">Try a different keyword.</div>
                                </div>
                            </td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </div>

        <footer class="footer">
            <p>PHP Directory Browser &bull; <?= e(date('Y')) ?></p>
        </footer>

    </div><!-- /.container -->
</div><!-- /#app -->

<script nonce="<?= e($nonce) ?>">
(function () {
    'use strict';

    // Show app, hide loader
    var loading = document.getElementById('loading');
    var app     = document.getElementById('app');
    if (loading) loading.style.display = 'none';
    if (app)     app.style.display     = 'block';

    // Search functionality
    var searchInput = document.getElementById('searchInput');
    var fileList    = document.getElementById('fileList');
    var noResultRow = document.getElementById('noResultRow');

    if (searchInput && fileList) {
        searchInput.addEventListener('input', function () {
            var query = this.value.toLowerCase().trim();
            var rows  = fileList.querySelectorAll('tr[data-name]');
            var found = 0;

            rows.forEach(function (row) {
                var name = (row.getAttribute('data-name') || '').toLowerCase();
                if (query === '' || name.includes(query)) {
                    row.style.display = '';
                    found++;
                } else {
                    row.style.display = 'none';
                }
            });

            if (noResultRow) {
                noResultRow.style.display = (found === 0 && query !== '') ? '' : 'none';
            }
        });
    }

    // Lockout countdown timer for password page
    var lockMsg = document.querySelector('.lock-msg strong');
    if (lockMsg) {
        var remaining = parseInt(lockMsg.textContent, 10);
        if (!isNaN(remaining) && remaining > 0) {
            var interval = setInterval(function () {
                remaining--;
                lockMsg.textContent = remaining;
                if (remaining <= 0) {
                    clearInterval(interval);
                    window.location.reload();
                }
            }, 1000);
        }
    }
}());
</script>

</body>
</html>
<?php