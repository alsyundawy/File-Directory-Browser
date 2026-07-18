<?php
/**
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
 *  Changelog:
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
 *  Updated On : 14 July 2026
 *  Timezone   : Asia/Jakarta
 *  License    : MIT License
 * ==============================================================================
 */

declare(strict_types=1);

ob_start();
register_shutdown_function('ob_end_flush');

// =================== RUNTIME / VERSION GUARD ===================
if (version_compare(PHP_VERSION, '8.0', '<')) {
    http_response_code(500);
    exit('PHP version ' . PHP_VERSION . ' is not supported. Minimum required version is 8.0.');
}

$requiredExtensions = ['session', 'hash', 'json', 'pcre', 'spl'];
foreach ($requiredExtensions as $extension) {
    if (!extension_loaded($extension)) {
        http_response_code(500);
        exit("Required PHP extension '{$extension}' is not installed.");
    }
}

// =================== URL NORMALIZER / REDIRECTOR ===================
$requestUri = $_SERVER['REQUEST_URI'] ?? '/';
$parsedUrl = parse_url($requestUri);
$path = $parsedUrl['path'] ?? '/';
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

// Convert 'folder' parameter to 'berkas'
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
$browseDirectories      = true;
$title                  = 'Index of {{path}}';
$subtitle               = '{{files}} files, {{size}} total';
$showParent             = true;
$showDirectories        = true;
$showDirectoriesFirst   = true;
$showHiddenFiles        = false;
$alignment              = 'left';
$showIcons              = true;
$dateFormat             = 'd-M-Y H:i';
$sizeDecimals           = 1;
$browseDefault          = '';
$allowExternalSymlinks  = false;
$enableHashCache        = true;
$hashCacheVersion       = '2026-07-08-v2';
$timezone               = 'Asia/Jakarta';
define('CLASS_ACTIVE', ' active');

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
    '.cache',
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
        $proto = strtolower(trim(explode(',', (string) $_SERVER['HTTP_X_FORWARDED_PROTO'])[0]));
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
        return '?';
    }

    $queryString = http_build_query($cleanParams, '', '&', PHP_QUERY_RFC3986);
    $queryString = str_ireplace('%2F', '/', $queryString);
    return '?' . $queryString;
}

function getSafeHost(): string
{
    $host = $_SERVER['HTTP_HOST'] ?? $_SERVER['SERVER_NAME'] ?? 'localhost';
    $host = strtolower(trim((string) $host));
    $host = preg_replace('/[\r\n\t]/', '', $host) ?? 'localhost';

    if (str_contains($host, ':')) {
        [$hostname, $port] = explode(':', $host, 2);
        if ($hostname !== '' && preg_match('/^[a-z0-9.-]+$/', $hostname) && preg_match('/^\\d{1,5}$/', $port)) {
            return $hostname . ':' . $port;
        }
    }

    if (!preg_match('/^[a-z0-9.-]+$/', $host)) {
        return 'localhost';
    }

    return $host;
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

function sendSecurityHeaders(string $nonce): void
{
    header('Cache-Control: no-cache, no-store, must-revalidate, max-age=0');
    header('Pragma: no-cache');
    header('Expires: 0');
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: SAMEORIGIN');
    header('Referrer-Policy: same-origin');
    header('Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()');

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
        $csp[] = "upgrade-insecure-requests";
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
        if (strtolower($key) === $searchLower) {
            return $key;
        }
    }
    return null;
}

function getFirstLockedFolder(string $path, array $protectedFolders, array $unlockedSessions, int $lifetime): string|null
{
    $path = sanitizePath($path);
    if ($path === '') {
        return null;
    }

    $lowercaseProtectedFolders = array_change_key_case($protectedFolders, CASE_LOWER);
    $segments = explode('/', $path);
    $current = '';
    $lockedFolder = null;

    foreach ($segments as $segment) {
        $current = ($current === '') ? $segment : $current . '/' . $segment;
        $currentLower = strtolower($current);
        if (array_key_exists($currentLower, $lowercaseProtectedFolders)) {
            $unlockedTime = $unlockedSessions[$currentLower] ?? 0;
            if (time() - $unlockedTime >= $lifetime) {
                $originalKey = findOriginalFolderKey($currentLower, $protectedFolders);
                $lockedFolder = $originalKey ?? $current;
                break;
            }
        }
    }

    return $lockedFolder;
}

function renderPasswordPage(string $lockedFolder, string|null $error, string $nonce): void
{
    global $loginMaxAttempts, $loginLockSeconds;
    $csrfToken = $_SESSION['csrf'] ?? '';

    $postLockedFolderLower = strtolower($lockedFolder);
    $attemptsInfo = $_SESSION['login_attempts'][$postLockedFolderLower] ?? null;
    $isLocked = false;
    $lockTimeRemaining = 0;

    if ($attemptsInfo !== null && $attemptsInfo['count'] >= $loginMaxAttempts) {
        $elapsed = time() - $attemptsInfo['last_attempt'];
        if ($elapsed < $loginLockSeconds) {
            $isLocked = true;
            $lockTimeRemaining = $loginLockSeconds - $elapsed;
        }
    }
    ?>
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <script nonce="<?php echo e($nonce); ?>">(function(){(localStorage.getItem("theme")||"light")==="dark"&&document.documentElement.classList.add("dark-mode")})();</script>
        <link rel="icon" type="image/x-icon" href="favicon.ico">
        <title>Folder Terproteksi - Password Required</title>
        <meta name="robots" content="noindex,nofollow">
        <link rel="preconnect" href="https://fonts.googleapis.com">
        <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=Lora:ital,wght@0,400..700;1,400..700&display=swap" rel="stylesheet">
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.7/dist/css/bootstrap.min.css" integrity="sha384-LN+7fdVzj6u52u30Kp6M/trliBMCMKTyK833zpbD+pXdCLuTusPj697FH4R/5mcr" crossorigin="anonymous">
        <link rel="stylesheet" href="https://unpkg.com/@fortawesome/fontawesome-free@6.7.2/css/all.min.css" integrity="sha384-nRgPTkuX86pH8yjPJUAFuASXQSSl2/bBUiNV47vSYpKFxHJhbcrGnmlYpYJMeD7a" crossorigin="anonymous">
        <style nonce="<?php echo e($nonce); ?>">:root{--bg-color:#f8fafc;--card-bg:rgba(255,255,255,0.7);--card-border:rgba(0,0,0,0.08);--primary-glow:linear-gradient(135deg,#6366f1 0%,#4f46e5 100%);--text-primary:#0f172a;--text-secondary:#475569;--border-color:rgba(0,0,0,0.06);--glass-blur:blur(16px);--accent-color:#4f46e5;--accent-hover:#3730a3}.dark-mode{--bg-color:#080c14;--card-bg:rgba(15,23,42,0.65);--card-border:rgba(255,255,255,0.08);--primary-glow:linear-gradient(135deg,#4f46e5 0%,#7c3aed 100%);--text-primary:#f8fafc;--text-secondary:#cbd5e1;--border-color:rgba(255,255,255,0.06);--accent-color:#6366f1;--accent-hover:#818cf8}.dark-mode .text-muted{color:#cbd5e1 !important}.dark-mode .text-secondary{color:#cbd5e1 !important}body{font-family:'Inter',sans-serif;background-color:var(--bg-color);background-image:radial-gradient(at 0% 0%,rgba(79,70,229,0.1) 0px,transparent 50%),radial-gradient(at 100% 100%,rgba(124,58,237,0.1) 0px,transparent 50%);background-attachment:fixed;color:var(--text-primary);min-height:100vh;display:flex;align-items:center;justify-content:center;-webkit-font-smoothing:antialiased;-moz-osx-font-smoothing:grayscale}.dark-mode body{background-color:#080c14 !important;background-image:radial-gradient(at 0% 0%,rgba(79,70,229,0.12) 0px,transparent 50%),radial-gradient(at 100% 100%,rgba(124,58,237,0.12) 0px,transparent 50%)}h4{font-family:'Lora',serif;font-weight:600}.card{background:var(--card-bg) !important;backdrop-filter:var(--glass-blur);-webkit-backdrop-filter:var(--glass-blur);border:1px solid var(--card-border);border-radius:12px;padding:2.5rem;box-shadow:0 10px 30px -10px rgba(0,0,0,0.25);width:100%;max-width:450px}.dark-mode .card{box-shadow:0 10px 30px -10px rgba(0,0,0,0.5)}.form-control{background:rgba(255,255,255,0.04);border:1px solid var(--card-border);color:var(--text-primary);border-radius:8px;padding:0.75rem 1rem;transition:all 0.3s ease}.form-control:focus{background:rgba(255,255,255,0.08);border-color:var(--accent-color);box-shadow:0 0 0 3px rgba(99,102,241,0.25);color:var(--text-primary)}.btn-primary{background:var(--primary-glow);border:none;color:white;font-weight:600;padding:0.75rem;border-radius:8px;transition:all 0.2s ease;box-shadow:0 4px 12px rgba(99,102,241,0.3)}.btn-primary:hover{transform:translateY(-1px);box-shadow:0 6px 15px rgba(99,102,241,0.4)}.btn-secondary{background:rgba(0,0,0,0.05);border:1px solid var(--card-border);color:var(--text-primary);padding:0.75rem;border-radius:8px;font-weight:500;transition:all 0.2s ease}.dark-mode .btn-secondary{background:rgba(255,255,255,0.06)}.btn-secondary:hover{background:rgba(0,0,0,0.1);border-color:var(--text-secondary);color:var(--text-primary)}.dark-mode .btn-secondary:hover{background:rgba(255,255,255,0.12);color:white}.alert-danger{background:rgba(239,68,68,0.15);border:1px solid rgba(239,68,68,0.3);color:#fca5a5;border-radius:8px}#theme-toggle-pw.theme-toggle-header{position:fixed;top:20px;right:20px;width:40px;height:40px;border-radius:50%;background:var(--card-bg);border:1px solid var(--card-border);color:var(--text-primary);display:flex;align-items:center;justify-content:center;cursor:pointer;z-index:1000;transition:all 0.3s cubic-bezier(0.4,0,0.2,1);backdrop-filter:var(--glass-blur);-webkit-backdrop-filter:var(--glass-blur);box-shadow:0 4px 6px -1px rgba(0,0,0,0.1)}#theme-toggle-pw.theme-toggle-header:hover{transform:scale(1.1) rotate(15deg);border-color:var(--accent-color);box-shadow:0 0 12px rgba(99,102,241,0.4)}</style>
    </head>
    <body>
        <button class="btn btn-outline-secondary theme-toggle-header" id="theme-toggle-pw" title="Toggle Theme" aria-label="Toggle Theme">
            <i class="fas fa-sun"></i>
        </button>
        <div class="card">
            <div class="text-center mb-4">
                <i class="fas fa-lock fa-3x mb-3 text-warning"></i>
                <h4 class="mb-1">Folder Terproteksi</h4>
                <p class="text-muted small">Folder <code class="text-info"><?php echo e($lockedFolder); ?></code> memerlukan password untuk diakses.</p>
            </div>

            <?php if ($isLocked): ?>
                <div class="alert alert-danger py-2 text-center small mb-3">
                    <i class="fas fa-lock me-1"></i> Terlalu banyak percobaan salah.<br>Silakan coba lagi dalam <span id="lock-countdown"><?php echo $lockTimeRemaining; ?></span> detik.
                </div>
            <?php elseif ($error !== null): ?>
                <div class="alert alert-danger py-2 text-center small mb-3">
                    <i class="fas fa-exclamation-circle me-1"></i> <?php echo e($error); ?>
                </div>
            <?php endif; ?>

            <form method="POST" action="">
                <input type="hidden" name="csrf_token" value="<?php echo e($csrfToken); ?>">
                <input type="hidden" name="locked_folder" value="<?php echo e($lockedFolder); ?>">
                <div class="mb-3">
                    <label for="folder_password" class="form-label small text-muted">Masukkan Password</label>
                    <input type="password" class="form-control" id="folder_password" name="folder_password" placeholder="Password" required autofocus <?php echo $isLocked ? 'disabled' : ''; ?>>
                </div>
                <div class="d-grid gap-2">
                    <button type="submit" class="btn btn-primary" <?php echo $isLocked ? 'disabled' : ''; ?>>
                        <i class="fas fa-unlock me-2"></i> Buka Proteksi
                    </button>
                    <a href="?" class="btn btn-secondary text-center">
                        <i class="fas fa-home me-2"></i> Kembali ke Beranda
                    </a>
                </div>
            </form>
        </div>
        <script nonce="<?php echo e($nonce); ?>">(function(){const e=document.getElementById("theme-toggle-pw");if(e){const n=()=>{const t=document.documentElement.classList.contains("dark-mode"),o=e.querySelector("i");o&&(o.className=t?"fas fa-sun":"fas fa-moon")};n(),e.addEventListener("click",()=>{document.documentElement.classList.toggle("dark-mode");const t=document.documentElement.classList.contains("dark-mode");localStorage.setItem("theme",t?"dark":"light"),n()})}})();</script>
        <?php if ($isLocked): ?>
        <script nonce="<?php echo e($nonce); ?>">(function(){var n=<?php echo (int) $lockTimeRemaining; ?>,t=document.getElementById("lock-countdown"),o=setInterval(function(){n--,t&&(t.textContent=n),n<=0&&(clearInterval(o),window.location.reload())},1e3)})();</script>
        <?php endif; ?>
    </body>
    </html>
    <?php
}

function humanizeFilesize(int|float $bytes, int $decimals = 0): string
{
    $bytes = max(0, (float) $bytes);
    $units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
    $factor = 0;

    while ($bytes >= 1024 && $factor < count($units) - 1) {
        $bytes /= 1024;
        $factor++;
    }

    return sprintf('%.' . max(0, $decimals) . 'f %s', $bytes, $units[$factor]);
}

function getDocAndMiscIcons(): array
{
    return [
        // Documents
        'pdf'        => 'fa-file-pdf',
        'doc'        => 'fa-file-word',
        'docx'       => 'fa-file-word',
        'docm'       => 'fa-file-word',
        'xls'        => 'fa-file-excel',
        'xlsx'       => 'fa-file-excel',
        'xlsm'       => 'fa-file-excel',
        'xlsb'       => 'fa-file-excel',
        'ppt'        => 'fa-file-powerpoint',
        'pptx'       => 'fa-file-powerpoint',
        'pptm'       => 'fa-file-powerpoint',
        'txt'        => 'fa-file-alt',
        'odt'        => 'fa-file-alt',
        'ods'        => 'fa-file-excel',
        'odp'        => 'fa-file-powerpoint',
        'rtf'        => 'fa-file-alt',
        'ps'         => 'fa-file-alt',
        'epub'       => 'fa-file-alt',
        'pages'      => 'fa-file-alt',
        'numbers'    => 'fa-file-excel',
        'key'        => 'fa-file-powerpoint',
        'md'         => 'fa-file-contract',

        // Miscellaneous
        'csv'        => 'fa-file-csv',
        'tsv'        => 'fa-file-csv',
        'parquet'    => 'fa-file-csv',
        'feather'    => 'fa-file-csv',
        'orc'        => 'fa-file-csv',
        'avro'       => 'fa-file-csv',
        'env'        => 'fa-file-cog',
        'conf'       => 'fa-file-cog',
        'cfg'        => 'fa-file-cog',
        'ini'        => 'fa-file-cog',
        'toml'       => 'fa-file-cog',
        'properties' => 'fa-file-cog',
        'mobi'       => 'fa-book',
        'azw3'       => 'fa-book',
        'djvu'       => 'fa-book',
        'exe'        => 'fa-file-code',
        'dll'        => 'fa-cogs',
        'so'         => 'fa-cogs',
        'dylib'      => 'fa-cogs',
        'ttf'        => 'fa-font',
        'otf'        => 'fa-font',
        'woff'       => 'fa-font',
        'woff2'      => 'fa-font',
        'log'        => 'fa-file-alt',
        'db'         => 'fa-database',
        'sqlite'     => 'fa-database',
        'sqlite3'    => 'fa-database',
        'bak'        => 'fa-history',
        'tmp'        => 'fa-history',
        'temp'       => 'fa-history',
        'torrent'    => 'fa-magnet',
        'vcf'        => 'fa-address-card',
        'ics'        => 'fa-calendar',
        'tex'        => 'fa-file-alt',
        'bib'        => 'fa-file-alt',
        'stl'        => 'fa-cube',
        'obj'        => 'fa-cube',
        'fbx'        => 'fa-cube',
        'step'       => 'fa-cube',
        'iges'       => 'fa-cube',
    ];
}

function getMediaAndCodeIcons(): array
{
    return [
        // Images
        'jpg'        => 'fa-file-image',
        'jpeg'       => 'fa-file-image',
        'jfif'       => 'fa-file-image',
        'png'        => 'fa-file-image',
        'gif'        => 'fa-file-image',
        'bmp'        => 'fa-file-image',
        'svg'        => 'fa-file-image',
        'webp'       => 'fa-file-image',
        'tiff'       => 'fa-file-image',
        'tif'        => 'fa-file-image',
        'ico'        => 'fa-file-image',
        'heic'       => 'fa-file-image',
        'heif'       => 'fa-file-image',
        'avif'       => 'fa-file-image',
        'psd'        => 'fa-file-image',
        'ai'         => 'fa-file-image',
        'eps'        => 'fa-file-image',
        'raw'        => 'fa-file-image',
        'cr2'        => 'fa-file-image',
        'nef'        => 'fa-file-image',

        // Audio & Video
        'mp3'        => 'fa-file-audio',
        'wav'        => 'fa-file-audio',
        'ogg'        => 'fa-file-audio',
        'flac'       => 'fa-file-audio',
        'aac'        => 'fa-file-audio',
        'm4a'        => 'fa-file-audio',
        'wma'        => 'fa-file-audio',
        'midi'       => 'fa-file-audio',
        'mid'        => 'fa-file-audio',
        'opus'       => 'fa-file-audio',
        'aiff'       => 'fa-file-audio',
        'amr'        => 'fa-file-audio',
        'mp4'        => 'fa-file-video',
        'avi'        => 'fa-file-video',
        'mov'        => 'fa-file-video',
        'wmv'        => 'fa-file-video',
        'mkv'        => 'fa-file-video',
        'webm'       => 'fa-file-video',
        'flv'        => 'fa-file-video',
        'mpeg'       => 'fa-file-video',
        'mpg'        => 'fa-file-video',
        '3gp'        => 'fa-file-video',
        'm4v'        => 'fa-file-video',
        'ogv'        => 'fa-file-video',
        'vob'        => 'fa-file-video',

        // Archives
        'zip'        => 'fa-file-archive',
        'rar'        => 'fa-file-archive',
        '7z'         => 'fa-file-archive',
        'tar'        => 'fa-file-archive',
        'gz'         => 'fa-file-archive',
        'bz2'        => 'fa-file-archive',
        'xz'         => 'fa-file-archive',
        'zst'        => 'fa-file-archive',
        'lz'         => 'fa-file-archive',
        'lz4'        => 'fa-file-archive',
        'iso'        => 'fa-file-archive',
        'dmg'        => 'fa-file-archive',
        'pkg'        => 'fa-file-archive',
        'deb'        => 'fa-file-archive',
        'rpm'        => 'fa-file-archive',
        'apk'        => 'fa-file-archive',
        'msi'        => 'fa-file-archive',

        // Code
        'js'         => 'fa-file-code',
        'jsx'        => 'fa-file-code',
        'ts'         => 'fa-file-code',
        'tsx'        => 'fa-file-code',
        'css'        => 'fa-file-code',
        'scss'       => 'fa-file-code',
        'sass'       => 'fa-file-code',
        'less'       => 'fa-file-code',
        'html'       => 'fa-file-code',
        'htm'        => 'fa-file-code',
        'php'        => 'fa-file-code',
        'py'         => 'fa-file-code',
        'java'       => 'fa-file-code',
        'class'      => 'fa-file-code',
        'jar'        => 'fa-file-code',
        'cpp'        => 'fa-file-code',
        'c'          => 'fa-file-code',
        'h'          => 'fa-file-code',
        'hpp'        => 'fa-file-code',
        'cs'         => 'fa-file-code',
        'go'         => 'fa-file-code',
        'rb'         => 'fa-file-code',
        'sh'         => 'fa-file-code',
        'bash'       => 'fa-file-code',
        'zsh'        => 'fa-file-code',
        'bat'        => 'fa-file-code',
        'cmd'        => 'fa-file-code',
        'ps1'        => 'fa-file-code',
        'json'       => 'fa-file-code',
        'yaml'       => 'fa-file-code',
        'yml'        => 'fa-file-code',
        'xml'        => 'fa-file-code',
        'sql'        => 'fa-file-code',
        'swift'      => 'fa-file-code',
        'kt'         => 'fa-file-code',
        'kts'        => 'fa-file-code',
        'dart'       => 'fa-file-code',
        'lua'        => 'fa-file-code',
        'pl'         => 'fa-file-code',
        'r'          => 'fa-file-code',
        'rs'         => 'fa-file-code',
        'groovy'     => 'fa-file-code',
        'ipynb'      => 'fa-file-code',
    ];
}

function getFileIconClass(string $filename): string
{
    static $iconMap = null;
    if ($iconMap === null) {
        $iconMap = array_merge(
            getDocAndMiscIcons(),
            getMediaAndCodeIcons()
        );
    }

    $extension = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
    return $iconMap[$extension] ?? 'fa-file';
}

function isHiddenName(string $name, bool $showHiddenFiles, array $filesToHide): bool
{
    $lowerName = strtolower($name);
    $hiddenMap = array_map('strtolower', $filesToHide);

    if (in_array($lowerName, $hiddenMap, true)) {
        return true;
    }

    return !$showHiddenFiles && str_starts_with($name, '.');
}

function isDangerousExtension(string $name, array $dangerousExtensions): bool
{
    $extension = strtolower(pathinfo($name, PATHINFO_EXTENSION));
    return $extension !== '' && in_array($extension, $dangerousExtensions, true);
}

function isDisplayableFile(string $relativePath, bool $showHiddenFiles, array $filesToHide, array $dangerousExtensions): bool
{
    $relativePath = sanitizePath($relativePath);
    if ($relativePath === '') {
        return false;
    }

    $segments = explode('/', $relativePath);
    foreach ($segments as $segment) {
        if (isHiddenName($segment, $showHiddenFiles, $filesToHide)) {
            return false;
        }
    }

    return !isDangerousExtension(basename($relativePath), $dangerousExtensions);
}

function isDisplayableFolder(string $relativePath, bool $showHiddenFiles, array $filesToHide): bool
{
    $relativePath = sanitizePath($relativePath);
    if ($relativePath === '') {
        return true;
    }

    $segments = explode('/', $relativePath);
    foreach ($segments as $segment) {
        if (isHiddenName($segment, $showHiddenFiles, $filesToHide)) {
            return false;
        }
    }

    return true;
}

function createHashCacheDir(string $baseDir): string|false
{
    $cacheDir = $baseDir . DIRECTORY_SEPARATOR . '.cache';
    $success = true;

    if (is_link($cacheDir)) {
        error_log('Hash cache disabled because .cache is a symlink.');
        $success = false;
    } elseif (!is_dir($cacheDir) && !@mkdir($cacheDir, 0750, true) && !is_dir($cacheDir)) {
        error_log('Hash cache disabled because .cache cannot be created.');
        $success = false;
    } elseif (!is_writable($cacheDir)) {
        error_log('Hash cache disabled because .cache is not writable.');
        $success = false;
    }

    if (!$success) {
        return false;
    }

    // Write htaccess to protect cache files from public exposure
    $htaccessFile = $cacheDir . DIRECTORY_SEPARATOR . '.htaccess';
    if (!is_file($htaccessFile)) {
        $content = "<IfModule authz_core_module>\n    Require all denied\n</IfModule>\n<IfModule !authz_core_module>\n    Deny from all\n</IfModule>\n";
        @file_put_contents($htaccessFile, $content);
    }

    return $cacheDir;
}

function isValidHashData(mixed $data): bool
{
    $valid = false;

    if (is_array($data)) {
        $valid = true;
        foreach (['crc32', 'md5', 'sha1'] as $key) {
            if (!isset($data[$key]) || !is_string($data[$key]) || !preg_match('/^[a-f0-9]+$/', $data[$key])) {
                $valid = false;
                break;
            }
        }
    }

    return $valid;
}

function readHashCache(string $cacheFile): array|null
{
    $data = null;

    if (is_file($cacheFile) && is_readable($cacheFile)) {
        $raw = @file_get_contents($cacheFile);
        if ($raw !== false && $raw !== '') {
            $decoded = json_decode($raw, true);
            if (isValidHashData($decoded)) {
                $data = $decoded;
            }
        }
    }

    return $data;
}

function writeHashCache(string $cacheFile, array $hashData): void
{
    try {
        $rand = bin2hex(random_bytes(8));
    } catch (Throwable) {
        $rand = uniqid('', true);
    }
    $tmpFile = $cacheFile . '.' . $rand . '.tmp';
    $json = json_encode($hashData, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);

    if ($json === false) {
        return;
    }

    if (@file_put_contents($tmpFile, $json, LOCK_EX) !== false) {
        @chmod($tmpFile, 0640);
        @rename($tmpFile, $cacheFile);
    } else {
        @unlink($tmpFile);
    }
}

function calculateHashes(string $fullFilePath, int $chunkSize): array|false
{
    $handle = @fopen($fullFilePath, 'rb');
    if ($handle === false) {
        return false;
    }

    // These hash algorithms are used for file integrity checksum generation (non-cryptographic context)
    $ctxCrc32 = hash_init('crc32b');
    $ctxMd5   = hash_init('md5'); // NOSONAR
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
    ?>
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <script nonce="<?php echo e($nonce); ?>">(function(){(localStorage.getItem("theme")||"light")==="dark"&&document.documentElement.classList.add("dark-mode")})();</script>
        <link rel="icon" type="image/x-icon" href="favicon.ico">
        <title>Hash Check for <?php echo e($fileName); ?></title>
        <meta name="description" content="Verify file integrity with CRC32, MD5, and SHA-1 hash algorithms">
        <meta name="robots" content="noindex,nofollow">
        <link rel="canonical" href="<?php echo e(getCanonicalURL()); ?>">
        <link rel="preconnect" href="https://fonts.googleapis.com">
        <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=Lora:ital,wght@0,400..700;1,400..700&display=swap" rel="stylesheet">
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.7/dist/css/bootstrap.min.css" integrity="sha384-LN+7fdVzj6u52u30Kp6M/trliBMCMKTyK833zpbD+pXdCLuTusPj697FH4R/5mcr" crossorigin="anonymous">
        <link rel="stylesheet" href="https://unpkg.com/@fortawesome/fontawesome-free@6.7.2/css/all.min.css" integrity="sha384-nRgPTkuX86pH8yjPJUAFuASXQSSl2/bBUiNV47vSYpKFxHJhbcrGnmlYpYJMeD7a" crossorigin="anonymous">
        <style nonce="<?php echo e($nonce); ?>">:root{--bg-color:#f8fafc;--card-bg:rgba(255,255,255,0.7);--card-border:rgba(0,0,0,0.08);--primary-glow:linear-gradient(135deg,#6366f1 0%,#4f46e5 100%);--text-primary:#0f172a;--text-secondary:#475569;--border-color:rgba(0,0,0,0.06);--glass-blur:blur(16px);--stripe-odd:rgba(0,0,0,0.015);--stripe-even:rgba(0,0,0,0.035);--accent-color:#4f46e5;--accent-hover:#3730a3}.dark-mode{--bg-color:#080c14;--card-bg:rgba(15,23,42,0.65);--card-border:rgba(255,255,255,0.08);--primary-glow:linear-gradient(135deg,#4f46e5 0%,#7c3aed 100%);--text-primary:#f8fafc;--text-secondary:#cbd5e1;--border-color:rgba(255,255,255,0.06);--stripe-odd:rgba(255,255,255,0.015);--stripe-even:rgba(255,255,255,0.035);--accent-color:#6366f1;--accent-hover:#818cf8}.dark-mode .text-muted{color:var(--text-secondary) !important}.dark-mode .text-secondary{color:var(--text-secondary) !important}body{font-family:'Inter',sans-serif;background-color:var(--bg-color);background-image:radial-gradient(at 0% 0%,rgba(79,70,229,0.1) 0px,transparent 50%),radial-gradient(at 100% 100%,rgba(124,58,237,0.1) 0px,transparent 50%);background-attachment:fixed;color:var(--text-primary);min-height:100vh;display:flex;align-items:center;-webkit-font-smoothing:antialiased;-moz-osx-font-smoothing:grayscale}.dark-mode body{background-color:#080c14 !important;background-image:radial-gradient(at 0% 0%,rgba(79,70,229,0.12) 0px,transparent 50%),radial-gradient(at 100% 100%,rgba(124,58,237,0.12) 0px,transparent 50%)}h2{font-family:'Lora',serif;font-weight:600;color:var(--text-primary)}.dark-mode h2{color:var(--text-primary) !important}.card{background:var(--card-bg) !important;backdrop-filter:var(--glass-blur);-webkit-backdrop-filter:var(--glass-blur);border:1px solid var(--card-border);border-radius:16px;padding:2rem;box-shadow:0 10px 40px -10px rgba(0,0,0,0.15);width:100%}.dark-mode .card{box-shadow:0 10px 40px -10px rgba(0,0,0,0.4)}.table{color:var(--text-primary) !important;--bs-table-bg:transparent !important;--bs-table-color:var(--text-primary) !important;margin-bottom:0}.table-striped>tbody>tr{color:var(--text-primary) !important}.table-striped>tbody>tr:nth-of-type(odd)>td,.table-striped>tbody>tr:nth-of-type(odd)>th{background-color:var(--stripe-odd) !important;color:var(--text-primary) !important}.table-striped>tbody>tr:nth-of-type(even)>td,.table-striped>tbody>tr:nth-of-type(even)>th{background-color:var(--stripe-even) !important;color:var(--text-primary) !important}.table td,.table th{border-color:var(--border-color) !important;padding:0.75rem 1rem;vertical-align:middle}.table th{font-weight:600;color:var(--text-secondary);width:120px;font-size:0.8rem;text-transform:uppercase;letter-spacing:0.5px}.hash-value{font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;word-break:break-all;color:var(--accent-color);font-size:0.85rem}.btn-copy-hash{background:none;border:none;padding:2px 6px;color:var(--text-secondary);transition:color 0.2s;cursor:pointer}.btn-copy-hash:hover{color:var(--accent-color)}.hash-icon-wrapper{background:rgba(99,102,241,0.1);color:var(--accent-color);width:56px;height:56px;border-radius:50%;display:inline-flex;align-items:center;justify-content:center}.btn-secondary{background:rgba(0,0,0,0.05);border:1px solid var(--card-border);color:var(--text-primary);transition:all 0.2s cubic-bezier(0.4,0,0.2,1);font-weight:500;padding:0.6rem 1.2rem}.dark-mode .btn-secondary{background:rgba(255,255,255,0.06)}.btn-secondary:hover{background:rgba(0,0,0,0.1);border-color:var(--text-secondary);color:var(--text-primary);transform:translateY(-1px)}.dark-mode .btn-secondary:hover{background:rgba(255,255,255,0.12);color:white}#theme-toggle-hash.theme-toggle-header{position:fixed;top:20px;right:20px;width:40px;height:40px;border-radius:50%;background:var(--card-bg);border:1px solid var(--card-border);color:var(--text-primary);display:flex;align-items:center;justify-content:center;cursor:pointer;z-index:1000;transition:all 0.3s cubic-bezier(0.4,0,0.2,1);backdrop-filter:var(--glass-blur);-webkit-backdrop-filter:var(--glass-blur);box-shadow:0 4px 6px -1px rgba(0,0,0,0.1)}#theme-toggle-hash.theme-toggle-header:hover{transform:scale(1.1) rotate(15deg);border-color:var(--accent-color);box-shadow:0 0 12px rgba(99,102,241,0.4)}</style>
    </head>
    <body>
        <button class="btn btn-outline-secondary theme-toggle-header" id="theme-toggle-hash" title="Toggle Theme" aria-label="Toggle Theme">
            <i class="fas fa-sun"></i>
        </button>
        <div class="container py-5 d-flex justify-content-center align-items-center" style="min-height: 90vh;">
            <div class="col-11 col-sm-10 col-md-8 col-lg-5">
                <div class="card">
                    <div class="text-center mb-4">
                        <div class="hash-icon-wrapper mb-3">
                            <i class="fas fa-shield-halved fa-xl"></i>
                        </div>
                        <h2 class="h4 mb-1">Hash Check</h2>
                        <p class="text-muted small text-truncate px-2 mb-0" title="<?php echo e($fileName); ?>"><?php echo e($fileName); ?></p>
                    </div>
                    <div class="table-responsive rounded border border-secondary border-opacity-25 mb-4">
                        <table class="table table-striped align-middle">
                            <tbody>
                                <tr>
                                    <th>File Size</th>
                                    <td><?php echo e($fileSizeHuman); ?> (<?php echo e(number_format($fileSize)); ?> B)</td>
                                </tr>
                                <tr>
                                    <th>CRC32</th>
                                    <td>
                                        <div class="d-flex align-items-center justify-content-between">
                                            <span class="hash-value"><?php echo e($hashData['crc32']); ?></span>
                                            <button class="btn-copy-hash" data-hash="<?php echo e($hashData['crc32']); ?>" title="Copy CRC32 hash">
                                                <i class="far fa-copy"></i>
                                            </button>
                                        </div>
                                    </td>
                                </tr>
                                <tr>
                                    <th>MD5</th>
                                    <td>
                                        <div class="d-flex align-items-center justify-content-between">
                                            <span class="hash-value"><?php echo e($hashData['md5']); ?></span>
                                            <button class="btn-copy-hash" data-hash="<?php echo e($hashData['md5']); ?>" title="Copy MD5 hash">
                                                <i class="far fa-copy"></i>
                                            </button>
                                        </div>
                                    </td>
                                </tr>
                                <tr>
                                    <th>SHA-1</th>
                                    <td>
                                        <div class="d-flex align-items-center justify-content-between">
                                            <span class="hash-value"><?php echo e($hashData['sha1']); ?></span>
                                            <button class="btn-copy-hash" data-hash="<?php echo e($hashData['sha1']); ?>" title="Copy SHA-1 hash">
                                                <i class="far fa-copy"></i>
                                            </button>
                                        </div>
                                    </td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                    <div class="text-center">
                        <button type="button" class="btn btn-secondary" id="btnBackHash">
                            <i class="fas fa-arrow-left me-2"></i> Back to Listing
                        </button>
                    </div>
                </div>
            </div>
        </div>
        <script nonce="<?php echo e($nonce); ?>" src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.7/dist/js/bootstrap.bundle.min.js" integrity="sha384-ndDqU0Gzau9qJ1lfW4pNLlhNTkCfHzAVBReH9diLvGRem5+R9g2FzA8ZGN954O5Q" crossorigin="anonymous"></script>
        <script nonce="<?php echo e($nonce); ?>">(function(){var n=document.getElementById("btnBackHash");n&&n.addEventListener("click",function(){history.back()});const e=document.getElementById("theme-toggle-hash");if(e){const c=()=>{const t=document.documentElement.classList.contains("dark-mode"),o=e.querySelector("i");o&&(o.className=t?"fas fa-sun":"fas fa-moon")};c(),e.addEventListener("click",()=>{document.documentElement.classList.toggle("dark-mode");const t=document.documentElement.classList.contains("dark-mode");localStorage.setItem("theme",t?"dark":"light"),c()})}document.querySelectorAll(".btn-copy-hash").forEach(t=>{t.addEventListener("click",()=>{const c=t.getAttribute("data-hash");navigator.clipboard.writeText(c).then(()=>{const o=t.querySelector("i");o.className="fas fa-check text-success",setTimeout(()=>{o.className="far fa-copy"},1.5e3)})})})})();</script>
    </body>
    </html>
    <?php
}

function resolveItemRealPath(string $linkPath, bool $isSymlink, bool $allowExternalSymlinks, string $baseDir): string|false
{
    $result = false;

    if (!$isSymlink) {
        $result = $linkPath;
    } else {
        $real = realpath($linkPath);
        if ($real !== false && ($allowExternalSymlinks || isPathInsideBase($real, $baseDir))) {
            $result = $real;
        }
    }

    return $result;
}

function isItemAllowed(string $file, bool $isDir, bool $showFolders, array $dangerousExtensions): bool
{
    $allowed = true;

    if ($isDir) {
        if (!$showFolders) {
            $allowed = false;
        }
    } else {
        if (isDangerousExtension($file, $dangerousExtensions)) {
            $allowed = false;
        }
    }

    return $allowed;
}

function getItemSize(string $itemRealPath, bool $isDir): int
{
    $size = 0;

    if (!$isDir) {
        $fileSizeVal = @filesize($itemRealPath);
        $size = $fileSizeVal !== false ? (int) $fileSizeVal : 0;
    }

    return $size;
}

function getItemCreatedTime(string $itemRealPath, int $itemTime): int
{
    $stat = @stat($itemRealPath);
    $itemCreated = $itemTime;

    if (is_array($stat) && isset($stat['birthtime']) && (int) $stat['birthtime'] > 0) {
        $itemCreated = (int) $stat['birthtime'];
    }

    return $itemCreated;
}

function processDirectoryItem(
    string $file,
    string $fullPath,
    string $path,
    bool $showFolders,
    bool $showHidden
): array|null {
    global $baseDir, $filesToHide, $dangerousExtensions, $allowExternalSymlinks;

    $result = null;

    if ($file !== '.' && $file !== '..' && !isHiddenName($file, $showHidden, $filesToHide)) {
        $linkPath = $fullPath . DIRECTORY_SEPARATOR . $file;
        $isSymlink = is_link($linkPath);
        $itemRealPath = resolveItemRealPath($linkPath, $isSymlink, $allowExternalSymlinks, $baseDir);

        if ($itemRealPath !== false) {
            $isDir = is_dir($itemRealPath);
            if (isItemAllowed($file, $isDir, $showFolders, $dangerousExtensions)) {
                $relativeItemPath = trim($path . '/' . $file, '/');
                $itemSize = getItemSize($itemRealPath, $isDir);
                $itemTime = (int) (@filemtime($itemRealPath) ?: 0);
                $itemCreated = getItemCreatedTime($itemRealPath, $itemTime);

                $result = [
                    'name'      => $file,
                    'relative'  => $relativeItemPath,
                    'isDir'     => $isDir,
                    'size'      => $itemSize,
                    'time'      => $itemTime,
                    'created'   => $itemCreated,
                    'isSymlink' => $isSymlink,
                ];
            }
        }
    }

    return $result;
}

function populateItems(array $files, string $fullPath, string $path, bool $showFolders, bool $showHidden): array
{
    global $totalFiles, $totalSize;
    $items = [];

    foreach ($files as $file) {
        $item = processDirectoryItem($file, $fullPath, $path, $showFolders, $showHidden);
        if ($item !== null) {
            $items[] = $item;
            if (!$item['isDir']) {
                $totalFiles++;
                $totalSize += $item['size'];
            }
        }
    }

    return $items;
}

function listDirectory(string $path, bool $showFolders = true, bool $showHidden = false): array
{
    global $baseDir, $filesToHide, $allowExternalSymlinks;

    $items = [];
    $path = sanitizePath($path);

    if (isDisplayableFolder($path, $showHidden, $filesToHide)) {
        $fullPath = resolveExistingPath($path, $baseDir, $allowExternalSymlinks);
        if ($fullPath !== false && is_dir($fullPath) && is_readable($fullPath)) {
            $files = @scandir($fullPath);
            if ($files !== false) {
                $items = populateItems($files, $fullPath, $path, $showFolders, $showHidden);
            }
        }
    }

    return $items;
}

// =================== INITIALIZATION ===================
$nonce = makeNonce();
sendSecurityHeaders($nonce);
startSecureSession(max(3600, $passwordSessionLifetime));

try {
    if (!isset($_SESSION['csrf'])) {
        $_SESSION['csrf'] = bin2hex(random_bytes(32));
    }
} catch (Throwable $e) {
    error_log('Failed to generate CSRF token: ' . $e->getMessage());
}

// =================== FOLDER PROTECTION CHECK ===================
$accessedDir = '';
if (isset($_GET['md5'])) {
    $requestedFile = sanitizePath((string) $_GET['md5']);
    $accessedDir = sanitizePath(dirname($requestedFile));
} elseif (isset($_GET['berkas'])) {
    $accessedDir = sanitizePath((string) $_GET['berkas']);
} else {
    $accessedDir = sanitizePath($browseDefault);
}

$unlockedSessions = $_SESSION['unlocked_folders'] ?? [];
$lockedFolder = getFirstLockedFolder($accessedDir, $protectedFolders, $unlockedSessions, $passwordSessionLifetime);

if ($lockedFolder !== null) {
    $loginError = null;
    $postLockedFolderLower = strtolower($lockedFolder);

    // Check if locked out
    $attemptsInfo = $_SESSION['login_attempts'][$postLockedFolderLower] ?? null;
    $isLocked = false;
    $lockTimeRemaining = 0;
    if ($attemptsInfo !== null && $attemptsInfo['count'] >= $loginMaxAttempts) {
        $elapsed = time() - $attemptsInfo['last_attempt'];
        if ($elapsed < $loginLockSeconds) {
            $isLocked = true;
            $lockTimeRemaining = $loginLockSeconds - $elapsed;
        } else {
            unset($_SESSION['login_attempts'][$postLockedFolderLower]);
        }
    }

    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['folder_password'], $_POST['locked_folder'], $_POST['csrf_token'])) {
        $csrfSession = $_SESSION['csrf'] ?? '';
        if (!hash_equals($csrfSession, (string) $_POST['csrf_token'])) {
            http_response_code(403);
            exit('Invalid CSRF token.');
        }

        $postLockedFolder = (string) $_POST['locked_folder'];
        $postLockedFolderLower = strtolower($postLockedFolder);
        $passwordInput = (string) $_POST['folder_password'];
        $lowercaseProtectedFolders = array_change_key_case($protectedFolders, CASE_LOWER);

        if ($isLocked) {
            $loginError = 'Terlalu banyak percobaan salah. Login dikunci sementara.';
        } elseif (array_key_exists($postLockedFolderLower, $lowercaseProtectedFolders)) {
            $storedHash = $lowercaseProtectedFolders[$postLockedFolderLower];
            if (password_verify($passwordInput, $storedHash)) {
                // Success: clear attempts and set unlock
                unset($_SESSION['login_attempts'][$postLockedFolderLower]);
                $_SESSION['unlocked_folders'][$postLockedFolderLower] = time();

                // Close session before redirect to persist data
                session_write_close();

                // Redirect back to the folder that was just unlocked
                $redirectTarget = queryUrl(['berkas' => $accessedDir]);
                header('Location: ' . $redirectTarget);
                exit;
            } else {
                // Increment login attempts
                if (!isset($_SESSION['login_attempts'][$postLockedFolderLower])) {
                    $_SESSION['login_attempts'][$postLockedFolderLower] = ['count' => 1, 'last_attempt' => time()];
                } else {
                    $_SESSION['login_attempts'][$postLockedFolderLower]['count']++;
                    $_SESSION['login_attempts'][$postLockedFolderLower]['last_attempt'] = time();
                }

                $remainingAttempts = $loginMaxAttempts - $_SESSION['login_attempts'][$postLockedFolderLower]['count'];
                if ($remainingAttempts <= 0) {
                    $loginError = 'Terlalu banyak percobaan salah. Login dikunci selama ' . ($loginLockSeconds / 60) . ' menit.';
                } else {
                    $loginError = 'Password salah! Sisa percobaan: ' . $remainingAttempts . '.';
                }
            }
        }
    }

    // Render password input page and exit
    renderPasswordPage($lockedFolder, $loginError, $nonce);
    exit;
}

if (session_status() === PHP_SESSION_ACTIVE) {
    session_write_close();
}

// =================== HASH CHECK WITH CACHE ===================
if (isset($_GET['md5'])) {
    $requestedFile = sanitizePath((string) $_GET['md5']);

    if (!isDisplayableFile($requestedFile, $showHiddenFiles, $filesToHide, $dangerousExtensions)) {
        http_response_code(404);
        exit('File not found or invalid.');
    }

    $fullFilePath = resolveExistingPath($requestedFile, $baseDir, $allowExternalSymlinks);

    if ($fullFilePath === false || !is_file($fullFilePath) || !is_readable($fullFilePath)) {
        http_response_code(404);
        exit('File not found or invalid.');
    }

    $fileName = basename($fullFilePath);
    $fileSize = (int) (@filesize($fullFilePath) ?: 0);
    $fileMtime = (int) (@filemtime($fullFilePath) ?: 0);
    $chunkSize = ($fileSize > 1073741824) ? 1048576 : 32768;
    $hashData = null;

    if ($enableHashCache) {
        $cacheDir = createHashCacheDir($baseDir);
        if ($cacheDir !== false) {
            $cacheKey = hash('sha256', implode('|', [
                $hashCacheVersion,
                $fullFilePath,
                (string) $fileSize,
                (string) $fileMtime,
            ]));
            $cacheFile = $cacheDir . DIRECTORY_SEPARATOR . $cacheKey . '.json';
            $hashData = readHashCache($cacheFile);
        }
    }

    if ($hashData === null) {
        $hashData = calculateHashes($fullFilePath, $chunkSize);
        if ($hashData === false) {
            http_response_code(500);
            exit('Failed to calculate file hash.');
        }

        if ($enableHashCache && isset($cacheFile)) {
            writeHashCache($cacheFile, $hashData);
        }
    }

    renderHashPage($fileName, $fileSize, $hashData, $nonce);
    exit;
}

// =================== SET BROWSED DIRECTORY ===================
$totalFiles = 0;
$totalSize  = 0;
$currentDir = sanitizePath($browseDefault);

if ($browseDirectories && isset($_GET['berkas'])) {
    $requested = sanitizePath((string) $_GET['berkas']);
    if (isDisplayableFolder($requested, $showHiddenFiles, $filesToHide)) {
        $realPath = resolveExistingPath($requested, $baseDir, $allowExternalSymlinks);

        if ($realPath !== false && is_dir($realPath) && is_readable($realPath)) {
            $currentDir = $requested;
        }
    }
}

$displayDir = '/' . ltrim($currentDir, '/');

// =================== LIST DIRECTORY ===================
$items = listDirectory($currentDir, $showDirectories, $showHiddenFiles);

// =================== SORTING FILES & DIRECTORIES ===================
$allowedSorts = ['name', 'modified', 'size'];
$isSortExplicit = isset($_GET['sort']) && in_array((string) $_GET['sort'], $allowedSorts, true);
$sort = $isSortExplicit ? (string) $_GET['sort'] : 'name';

$order = isset($_GET['order']) && strtolower((string) $_GET['order']) === 'desc'
    ? 'desc'
    : 'asc';

usort($items, function (array $a, array $b) use ($sort, $order, $showDirectoriesFirst): int {
    if ($showDirectoriesFirst) {
        if ($a['isDir'] && !$b['isDir']) {
            return -1;
        }
        if (!$a['isDir'] && $b['isDir']) {
            return 1;
        }
    }

    $result = match ($sort) {
        'modified' => ($a['time'] <=> $b['time']) ?: strcasecmp((string) $a['name'], (string) $b['name']),
        'size'     => ($a['size'] <=> $b['size']) ?: strcasecmp((string) $a['name'], (string) $b['name']),
        default    => strcasecmp((string) $a['name'], (string) $b['name']),
    };

    return ($order === 'desc') ? -$result : $result;
});

$pageTitle = str_replace('{{path}}', $displayDir, $title);
$alignmentClass = match ($alignment) {
    'center' => 'text-center',
    'right'  => 'text-end',
    default  => 'text-start',
};
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <script nonce="<?php echo e($nonce); ?>">(function(){(localStorage.getItem("theme")||"light")==="dark"&&document.documentElement.classList.add("dark-mode")})();</script>
    <link rel="icon" type="image/x-icon" href="favicon.ico">
    <title><?php echo e($pageTitle); ?></title>
    <meta name="description" content="Securely browse files and folders online. Custom responsive UI with light and dark mode toggling.">
    <meta name="robots" content="noindex,nofollow">
    <link rel="canonical" href="<?php echo e(getCanonicalURL()); ?>">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=Lora:ital,wght@0,400..700;1,400..700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.7/dist/css/bootstrap.min.css" integrity="sha384-LN+7fdVzj6u52u30Kp6M/trliBMCMKTyK833zpbD+pXdCLuTusPj697FH4R/5mcr" crossorigin="anonymous">
    <link rel="stylesheet" href="https://unpkg.com/@fortawesome/fontawesome-free@6.7.2/css/all.min.css" integrity="sha384-nRgPTkuX86pH8yjPJUAFuASXQSSl2/bBUiNV47vSYpKFxHJhbcrGnmlYpYJMeD7a" crossorigin="anonymous">
    <style nonce="<?php echo e($nonce); ?>">:root{--p:#007bff;--s:#475569;--h:#f8f9fa;--b:#dee2e6;--tp:#0f172a;--ts:#334155;--hc:#0f172a;--fi:#007bff;--bl:#fff;--bg-color:var(--bl);--card-bg:#fff;--card-border:var(--b);--text-primary:var(--tp);--text-secondary:var(--ts);--text-muted:var(--s);--border-color:var(--b);--hover-bg:rgba(0,123,255,0.04);--row-bg:#fff;--row-hover:#f1f5f9;--parent-row-bg:#f8fafc;--parent-row-hover:#f1f5f9;--shadow-sm:0 1px 2px 0 rgba(0,0,0,0.05);--shadow-md:0 10px 30px rgba(0,123,255,0.05);--shadow-lg:0 10px 15px -3px rgba(0,0,0,0.1);--accent-color:var(--p);--accent-hover:#0056b3}.dark-mode{--bl:#070c1e;--bg-color:#070c1e;--card-bg:rgba(13,27,56,0.4);--card-border:rgba(255,255,255,0.08);--text-primary:#f8fafc;--text-secondary:#cbd5e1;--text-muted:#94a3b8;--border-color:rgba(255,255,255,0.08);--hover-bg:rgba(59,130,246,0.12);--h:rgba(13,27,56,0.25);--row-bg:rgba(13,27,56,0.2);--row-hover:rgba(13,27,56,0.45);--parent-row-bg:rgba(13,27,56,0.3);--parent-row-hover:rgba(59,130,246,0.15);--shadow-lg:0 8px 32px 0 rgba(0,0,0,0.37);--accent-color:#38bdf8;--accent-hover:#60a5fa}.dark-mode .text-muted{color:var(--text-muted) !important}.dark-mode .text-secondary{color:var(--text-secondary) !important}*{box-sizing:border-box}html,body{background-color:var(--bg-color);transition:background-color 0.3s ease,color 0.3s ease}body{font-family:'Inter',sans-serif;font-weight:400;font-size:1rem;line-height:1.7;color:var(--text-primary);margin:0;overflow-x:hidden}body.dark-mode{background:radial-gradient(circle at top,#0f1c3f 0%,#070c1e 100%) !important;background-attachment:fixed !important}h1,h2,h3,h4,h5,h6{font-family:'Lora',serif;font-weight:600;color:var(--hc);transition:color 0.3s ease}.dark-mode h1,.dark-mode h2,.dark-mode h3,.dark-mode h4,.dark-mode h5,.dark-mode h6{color:var(--text-primary)}a{text-decoration:none;color:var(--p);transition:all 0.2s ease}a:hover{color:#0052a3}.dark-mode a{color:#60a5fa}.dark-mode a:hover{color:#93c5fd}.container{max-width:1400px;padding:0 2rem;margin:0 auto;width:100%}.loading-screen{position:fixed;top:0;left:0;width:100%;height:100%;background:var(--bg-color);display:flex;flex-direction:column;align-items:center;justify-content:center;z-index:9999;transition:opacity 0.3s ease,visibility 0.3s ease}.loading-screen.fade-out{opacity:0;visibility:hidden}.spinner{width:45px;height:45px;border:3.5px solid var(--border-color);border-top-color:var(--p);border-radius:50%;animation:spin 0.8s linear infinite;margin-bottom:1.25rem}.dark-mode .spinner{border-top-color:#60a5fa}.loading-text{font-size:0.8rem;font-weight:700;letter-spacing:0.15em;color:var(--text-secondary)}@keyframes spin{to{transform:rotate(360deg)}}header{padding:2rem 0;background-color:var(--bg-color);border-bottom:1px solid var(--border-color);position:relative;z-index:100;transition:background-color 0.3s ease,border-color 0.3s ease}.dark-mode header{background:rgba(7,12,30,0.45);border-bottom:1px solid rgba(255,255,255,0.08);backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px)}.logo-container img{max-height:80px;width:auto;max-width:100%;transition:transform 0.3s ease,filter 0.3s ease;filter:drop-shadow(0 2px 8px rgba(0,0,0,0.08))}@media(min-width:992px){.logo-container img{max-height:180px}}.logo-container img:hover{transform:scale(1.05) rotate(1deg)}.dark-mode .logo-container img{filter:drop-shadow(0 0 12px rgba(59,130,246,0.45))}header h3{font-size:1.5rem;margin:1rem 0 0.5rem;font-weight:700}header h1.display-5{font-size:clamp(1.25rem,4vw,2rem);word-break:break-all;font-weight:600;margin-top:1rem}.repo-pathbar{display:flex;align-items:center;flex-wrap:wrap;gap:.45rem;width:100%;margin:0 auto 1.5rem;padding:.9rem 1rem;color:#334155;background:#fff;border:1px solid rgba(0,123,255,.1);border-radius:14px;box-shadow:0 10px 30px rgba(0,123,255,.05);font-size:.92rem;line-height:1.45;transition:background-color 0.3s ease,border-color 0.3s ease,box-shadow 0.3s ease}.repo-pathbar-trail{display:inline-flex;align-items:center;flex-wrap:wrap;gap:.35rem;min-width:0}.repo-pathbar a,.repo-pathbar-current{display:inline-flex;align-items:center;gap:.38rem;max-width:100%;word-break:break-all;overflow-wrap:anywhere;font-weight:700}.repo-pathbar-current{color:#64748b}.repo-pathbar-separator{color:#94a3b8;font-weight:800;user-select:none}.dark-mode .repo-pathbar{background:rgba(13,27,56,0.55) !important;border:1px solid rgba(255,255,255,0.08) !important;box-shadow:0 8px 32px 0 rgba(0,0,0,0.3) !important;color:#cbd5e1;backdrop-filter:blur(16px);-webkit-backdrop-filter:blur(16px)}.dark-mode .repo-pathbar-current{color:#cbd5e1}.dark-mode .repo-pathbar-separator{color:rgba(255,255,255,0.4)}.btn-outline-secondary{color:var(--text-secondary);background-color:transparent;border-color:var(--card-border);transition:all 0.2s ease}.btn-outline-secondary:hover,.btn-outline-secondary.active{background-color:var(--hover-bg);border-color:var(--accent-color);color:var(--accent-color)}.table-container{border-radius:12px;overflow:hidden;box-shadow:var(--shadow-md);border:1px solid var(--border-color);background-color:var(--card-bg);margin-bottom:2.5rem;transition:border-color 0.3s ease,background-color 0.3s ease}.dark-mode .table-container{background:rgba(13,27,56,0.4) !important;border:1px solid rgba(255,255,255,0.08) !important;box-shadow:0 8px 32px 0 rgba(0,0,0,0.3) !important;backdrop-filter:blur(16px);-webkit-backdrop-filter:blur(16px)}.table-responsive{margin-bottom:0;border-radius:0;overflow-x:auto}.table{margin-bottom:0;font-size:0.95rem;width:100%;table-layout:fixed;border-collapse:collapse;border-color:var(--border-color)}.table th,.table td{padding:1rem .75rem;vertical-align:middle;border-color:var(--border-color);overflow:hidden;text-overflow:ellipsis}.dark-mode .table,.dark-mode .table th,.dark-mode .table td{border-color:rgba(255,255,255,0.06) !important}.table thead th{background:#212529 !important;color:#ffffff !important;font-weight:700;text-transform:uppercase;letter-spacing:0.05em;font-size:0.75rem;border-color:#212529;transition:background-color 0.3s ease,border-color 0.3s ease}.dark-mode .table thead th{background:rgba(22,38,77,0.7) !important;color:var(--text-primary) !important;border-color:rgba(255,255,255,0.1) !important}.table-col-date{width:200px !important;min-width:200px !important;max-width:200px !important;white-space:nowrap}.table-col-size{width:115px !important;min-width:115px !important;max-width:115px !important;text-align:right}.table-col-hash{width:76px !important;min-width:76px !important;max-width:76px !important;text-align:center}.table-col-date .short-date{display:none}.table-col-date .full-date{display:inline}.table tbody tr:nth-of-type(odd)>td,.table tbody tr:nth-of-type(odd)>th{background-color:var(--card-bg) !important;color:var(--text-primary) !important}.table tbody tr:nth-of-type(even)>td,.table tbody tr:nth-of-type(even)>th{background-color:var(--h) !important;color:var(--text-primary) !important}.dark-mode .table tbody tr:nth-of-type(odd)>td,.dark-mode .table tbody tr:nth-of-type(odd)>th{background-color:rgba(13,27,56,0.2) !important;color:var(--text-primary) !important}.dark-mode .table tbody tr:nth-of-type(even)>td,.dark-mode .table tbody tr:nth-of-type(even)>th{background-color:rgba(13,27,56,0.45) !important;color:var(--text-primary) !important}.table-hover tbody tr{transition:background-color 0.2s ease,box-shadow 0.2s ease}.table-hover tbody tr:hover>td,.table-hover tbody tr:hover>th{background-color:#f1f5f9 !important}.dark-mode .table-hover tbody tr:hover>td,.dark-mode .table-hover tbody tr:hover>th{background-color:rgba(59,130,246,0.12) !important;box-shadow:inset 0 0 0 1px rgba(59,130,246,0.25)}.parent-row>td,.parent-row>th{background-color:var(--parent-row-bg) !important}.parent-row:hover>td,.parent-row:hover>th{background-color:var(--parent-row-hover) !important}.dark-mode .parent-row>td,.dark-mode .parent-row>th{background-color:rgba(13,27,56,0.3) !important}.dark-mode .parent-row:hover>td,.dark-mode .parent-row:hover>th{background-color:rgba(59,130,246,0.15) !important}.folder-link,.file-link{color:var(--accent-color) !important;font-weight:500;transition:color 0.15s ease}.folder-link:hover,.file-link:hover{color:var(--accent-hover) !important;text-decoration:underline}.file-icon{font-size:1.1rem;width:1.5rem;text-align:center;color:var(--accent-color);margin-right:0.5rem}.search-wrapper{padding:0.9rem 0 0.25rem;transition:all 0.3s ease}.search-form{max-width:520px;margin:0 auto}.search-input-group{display:flex;align-items:center;background:#fff;border:1.5px solid rgba(0,123,255,0.15);border-radius:50px;overflow:hidden;box-shadow:0 2px 16px rgba(0,0,0,0.06);transition:border-color .2s ease,box-shadow .2s ease,background-color 0.3s ease}.search-input-group:focus-within{border-color:rgba(0,123,255,0.45);box-shadow:0 4px 20px rgba(0,123,255,0.1),0 0 0 3px rgba(0,123,255,0.07)}.search-icon-left{padding:0 0 0 1.1rem;color:#c0c8d0;font-size:0.78rem;flex-shrink:0;pointer-events:none}.search-input{flex:1;border:0;background:transparent;padding:0.6rem 0.7rem;font-size:0.875rem;color:var(--text-primary);outline:none;min-width:0}.search-input::placeholder{color:#c0c8d0;font-style:italic}.search-btn{border:0;background:linear-gradient(135deg,var(--p) 0%,#0056b3 100%);color:#fff;padding:0 1.1rem;min-height:38px;cursor:pointer;font-size:0.78rem;border-radius:0 50px 50px 0;transition:background .2s;flex-shrink:0}.search-btn:hover{background:linear-gradient(135deg,#0056b3 0%,#003f88 100%)}.search-hint{font-size:0.7rem;color:#c0c8d0;margin:0.45rem 0 0;text-align:center;letter-spacing:0.01em}.dark-mode .search-input-group{background:rgba(13,27,56,0.55) !important;border-color:rgba(255,255,255,0.1) !important;backdrop-filter:blur(8px)}.dark-mode .search-input::placeholder{color:#475569}.dark-mode .search-icon-left{color:#475569}.dark-mode .search-hint{color:#475569}.search-hidden{display:none !important}.fab-home{position:fixed;bottom:8.75rem;right:1.5rem;width:2.25rem;height:2.25rem;background:linear-gradient(135deg,#6366f1 0%,#4f46e5 100%);color:#fff;border-radius:50%;border:none;display:flex;align-items:center;justify-content:center;cursor:pointer;opacity:0;visibility:hidden;z-index:2000;box-shadow:0 4px 14px rgba(99,102,241,.45),0 1px 3px rgba(0,0,0,.15);transition:all .25s cubic-bezier(.175,.885,.32,1.275)}.fab-home.show{opacity:1;visibility:visible}.fab-home:hover{transform:translateY(-4px) scale(1.1);box-shadow:0 8px 22px rgba(99,102,241,.55)}.fab-home i{font-size:.7rem}.dark-mode .fab-home{background:linear-gradient(135deg,#818cf8 0%,#6366f1 100%);box-shadow:0 4px 14px rgba(129,140,248,.35),0 1px 3px rgba(0,0,0,.3)}.dark-mode .fab-home:hover{background:#4f46e5;box-shadow:0 6px 16px rgba(99,102,241,.4)}.back-to-top-control{position:fixed;bottom:5rem;right:1.5rem;width:2.25rem;height:2.25rem;background:linear-gradient(135deg,#0ea5e9 0%,#0284c7 100%);color:#fff;border-radius:50%;border:none;display:flex;align-items:center;justify-content:center;cursor:pointer;opacity:0;visibility:hidden;z-index:2000;box-shadow:0 4px 14px rgba(14,165,233,.45),0 1px 3px rgba(0,0,0,.15);transition:all .25s cubic-bezier(.175,.885,.32,1.275)}.back-to-top-control.show{opacity:1;visibility:visible}.back-to-top-control:hover{transform:translateY(-4px) scale(1.1);box-shadow:0 8px 22px rgba(14,165,233,.55)}.back-to-top-control i{font-size:.7rem}.dark-mode .back-to-top-control{background:linear-gradient(135deg,#38bdf8 0%,#0ea5e9 100%);box-shadow:0 4px 14px rgba(56,189,248,.35),0 1px 3px rgba(0,0,0,.3)}.dark-mode .back-to-top-control:hover{background:#2563eb;box-shadow:0 6px 16px rgba(59,130,246,.4)}#theme-toggle-main.theme-toggle-header{position:absolute !important;top:1.5rem !important;right:1.5rem !important;bottom:auto !important;left:auto !important;z-index:150 !important;width:40px;height:40px;border-radius:50%;display:flex;align-items:center;justify-content:center;cursor:pointer;transition:all 0.3s cubic-bezier(0.4,0,0.2,1);will-change:auto !important;transform:none !important}.dark-mode #theme-toggle-main.theme-toggle-header{background:rgba(255,255,255,0.05) !important;border:1px solid rgba(255,255,255,0.1) !important;color:#cbd5e1 !important}#theme-toggle-main.theme-toggle-header i{pointer-events:none;transform:none !important}#theme-toggle-main.theme-toggle-header:hover{transform:scale(1.1) rotate(15deg) !important}footer{text-align:center;padding:2.5rem 0 1.75rem;color:var(--text-secondary);font-size:0.875rem;transition:color 0.3s ease}.footer-inner{max-width:640px;margin:0 auto;padding:0 1.25rem}.footer-divider{width:56px;height:2px;background:linear-gradient(90deg,transparent,var(--p),transparent);margin:0 auto 1.75rem;border-radius:1px}.dark-mode .footer-divider{background:linear-gradient(90deg,transparent,#38bdf8,transparent)}.social-links{display:flex;justify-content:center;gap:1rem;flex-wrap:wrap;margin-bottom:2rem;padding:0 .5rem}.social-links a{display:flex;align-items:center;justify-content:center;width:2.2rem;height:2.2rem;border-radius:50%;border:1.5px solid rgba(0,0,0,0.12);color:var(--text-secondary);font-size:0.82rem;text-decoration:none;transition:all .22s ease;opacity:0.8}.social-links a:hover{background:var(--p);color:#fff !important;border-color:var(--p);opacity:1;transform:translateY(-2px);box-shadow:0 4px 10px rgba(0,123,255,0.25)}.dark-mode .social-links a{border-color:rgba(255,255,255,0.12);color:#cbd5e1}.dark-mode .social-links a:hover{background:#38bdf8;border-color:#38bdf8;color:#fff !important;box-shadow:0 4px 10px rgba(56,189,248,0.3)}.footer-title{font-size:.74rem;font-weight:700;letter-spacing:.04em;margin-bottom:.35rem;line-height:2;text-align:center;padding:0 .5rem}.footer-title a{color:var(--text-primary);text-decoration:none;transition:color .2s;display:inline-flex;flex-wrap:wrap;justify-content:center;align-items:center;gap:.15rem}.footer-title a:hover{color:var(--p)}.ft-sep{opacity:.35;font-weight:400;letter-spacing:0;flex-shrink:0}.ft-part{white-space:nowrap;display:inline}.footer-copy{font-size:0.7rem;opacity:0.5;margin:0}.no-results{display:none;text-align:center;padding:3rem 1.5rem;color:var(--text-secondary)}.no-results.show{display:block}.symlink-badge{margin-left:0.5rem;font-size:0.8rem;color:var(--text-muted)}@media(max-width:576px){html{font-size:13px !important}body{font-size:0.82rem !important;line-height:1.5 !important}.container{padding:0 0.4rem !important}header{padding:1rem 0 !important}.logo-container img{max-height:48px !important}header h3{font-size:1.1rem !important;margin:0.5rem 0 0.25rem !important}header h1.display-5{font-size:1rem !important;margin-top:0.5rem !important}.repo-pathbar{padding:0.5rem 0.6rem !important;font-size:0.75rem !important;margin-bottom:0.75rem !important;border-radius:8px !important;gap:0.3rem !important}.repo-pathbar-trail{gap:0.25rem !important}.repo-pathbar a,.repo-pathbar-current{gap:0.25rem !important;font-size:0.75rem !important}.repo-pathbar-separator{font-weight:700 !important}.table-container{margin-bottom:1.5rem !important;border-radius:8px !important}.table{font-size:0.7rem !important;table-layout:auto !important;width:100% !important}.table th,.table td{padding:0.4rem 0.25rem !important}colgroup col:nth-child(4){display:none !important}#fileTable col:nth-child(4){display:none !important;width:0 !important;min-width:0 !important;max-width:0 !important}.table th:nth-child(4),.table td:nth-child(4){display:none !important}#fileTable col:nth-child(2),#fileTable col:nth-child(3){width:1% !important;min-width:0 !important;max-width:none !important}.table-col-date{width:1% !important;min-width:0 !important;max-width:none !important;font-size:0.6rem !important;white-space:nowrap !important}.table-col-size{width:1% !important;min-width:0 !important;max-width:none !important;white-space:nowrap !important;text-align:right !important}.table-col-hash{display:none !important;width:0 !important;min-width:0 !important;max-width:0 !important}.table th:nth-child(1),.table td:nth-child(1){width:auto !important;word-break:break-all !important}.table-col-date .full-date{display:none !important}.table-col-date .short-date{display:inline !important}.table-responsive{overflow-x:hidden !important;border-radius:8px !important}#theme-toggle-main.theme-toggle-header{top:0.75rem !important;right:0.75rem !important;width:32px !important;height:32px !important}.search-wrapper{padding:0.5rem 0 !important}.search-input{padding:0.4rem 0.5rem !important;font-size:0.75rem !important}.search-btn{padding:0 0.8rem !important;min-height:30px !important;font-size:0.75rem !important}.search-hint{margin:0.25rem 0 0 !important;font-size:0.65rem !important}.social-links{gap:0.5rem !important;margin-bottom:1.25rem !important}.social-links a{width:1.75rem !important;height:1.75rem !important;font-size:0.7rem !important}.footer-divider{margin-bottom:1.25rem !important}.footer-title{font-size:0.65rem !important;line-height:1.6 !important}.footer-title a{flex-direction:column !important;gap:0.05rem !important}.ft-sep{display:none !important}.ft-part{display:block !important;text-align:center !important;width:100% !important}.back-to-top-control{bottom:3.75rem !important;right:1rem !important;width:1.75rem !important;height:1.75rem !important}.back-to-top-control i{font-size:0.6rem !important}.fab-home{bottom:6.5rem !important;right:1rem !important;width:1.75rem !important;height:1.75rem !important}.fab-home i{font-size:0.6rem !important}}@media(min-width:2560px){.container{max-width:2200px}body{font-size:1.2rem}.logo-container img{max-height:300px}}@media(min-width:3840px){.container{max-width:3200px}body{font-size:1.5rem}.logo-container img{max-height:400px}}@media print{.search-wrapper,.btn-group,#theme-toggle-main,.back-to-top-control{display:none !important}}#search-form-container{display:none;transition:opacity .18s ease,transform .18s ease}</style>
    <noscript>
        <style nonce="<?php echo e($nonce); ?>">.loading-screen{display:none !important}</style>
    </noscript>
</head>
<body>
    <!-- Loading Screen -->
    <div class="loading-screen" id="loadingScreen" aria-live="polite" aria-label="Loading">
        <span class="spinner"></span>
        <div class="loading-text">LOADING DIRECTORY...</div>
    </div>

    <!-- Header -->
    <header class="text-center site-header">
        <button id="theme-toggle-main" class="btn btn-outline-secondary theme-toggle-header" type="button" aria-label="Toggle dark/light mode" title="Toggle dark/light mode">
            <i class="fas fa-moon"></i>
        </button>
        <div class="container">
            <div class="logo-container">
                <a href="?" title="Back to Home"><img src="logo.png" alt="Logo" class="img-fluid" loading="lazy"></a>
            </div>
            <h3 class="mt-3">REPOSITORY FILE &amp; DIRECTORY BROWSER</h3>
            <p class="mb-0 text-muted"><strong>Menampilkan Daftar File Dan Direktori Yang Tersedia</strong></p>
            <div class="mt-3 text-center">
                <h1 class="display-5"><?php echo e($pageTitle); ?></h1>
                <p class="text-muted">
                    <?php echo e(str_replace(
                        ['{{files}}', '{{size}}'],
                        [(string) $totalFiles, humanizeFilesize($totalSize, $sizeDecimals)],
                        $subtitle
                    )); ?>
                </p>
            </div>
            <?php
            $nameIconClass = 'fa-sort-alpha-down';
            if ($sort === 'name') {
                $nameIconClass = ($order === 'asc') ? 'fa-sort-alpha-down' : 'fa-sort-alpha-up';
            }

            $modifiedIconClass = 'fa-calendar-alt';
            if ($sort === 'modified') {
                $modifiedIconClass = ($order === 'asc') ? 'fa-sort-amount-down' : 'fa-sort-amount-up';
            }

            $sizeIconClass = 'fa-weight-hanging';
            if ($sort === 'size') {
                $sizeIconClass = ($order === 'asc') ? 'fa-sort-numeric-down' : 'fa-sort-numeric-up';
            }
            ?>
            <div class="d-flex justify-content-center align-items-center mt-3 flex-wrap gap-2">
                <div class="btn-group" aria-label="Sort Options">
                    <a href="<?php echo e(queryUrl(['berkas' => $currentDir, 'sort' => 'name', 'order' => ($sort === 'name' && $order === 'asc') ? 'desc' : 'asc'])); ?>"
                       class="btn btn-outline-secondary<?php echo ($isSortExplicit && $sort === 'name') ? CLASS_ACTIVE : ''; ?>" aria-label="Sort by name">
                        <i class="fas <?php echo e($nameIconClass); ?>"></i><span class="d-none d-sm-inline ms-1">Name</span>
                    </a>
                    <a href="<?php echo e(queryUrl(['berkas' => $currentDir, 'sort' => 'modified', 'order' => ($sort === 'modified' && $order === 'asc') ? 'desc' : 'asc'])); ?>"
                       class="btn btn-outline-secondary<?php echo ($isSortExplicit && $sort === 'modified') ? CLASS_ACTIVE : ''; ?>" aria-label="Sort by date">
                        <i class="fas <?php echo e($modifiedIconClass); ?>"></i><span class="d-none d-sm-inline ms-1">Date</span>
                    </a>
                    <a href="<?php echo e(queryUrl(['berkas' => $currentDir, 'sort' => 'size', 'order' => ($sort === 'size' && $order === 'asc') ? 'desc' : 'asc'])); ?>"
                       class="btn btn-outline-secondary<?php echo ($isSortExplicit && $sort === 'size') ? CLASS_ACTIVE : ''; ?>" aria-label="Sort by size">
                        <i class="fas <?php echo e($sizeIconClass); ?>"></i><span class="d-none d-sm-inline ms-1">Size</span>
                    </a>
                </div>
                <button type="button" id="search-toggle" class="btn btn-outline-secondary" title="Cari File" aria-label="Toggle search">
                    <i class="fas fa-search"></i>
                </button>
            </div>
            <div class="search-wrapper" id="search-form-container">
                <form method="GET" action="" class="search-form" onsubmit="event.preventDefault();">
                    <div class="search-input-group">
                        <span class="search-icon-left" aria-hidden="true"><i class="fas fa-search"></i></span>
                        <input type="text" id="searchInput" class="search-input" placeholder="Cari nama file..." autocomplete="off" spellcheck="false" aria-label="Cari file">
                        <button class="search-btn" type="button" aria-label="Mulai pencarian"><i class="fas fa-arrow-right"></i></button>
                    </div>
                    <p class="search-hint">Tekan Escape untuk membersihkan pencarian</p>
                </form>
            </div>
        </div>
    </header>

    <!-- Main Content -->
    <main class="container text-start mt-4">
        <nav class="repo-pathbar" aria-label="Lokasi folder">
            <span class="repo-pathbar-trail">
                <?php if ($currentDir === ''): ?>
                    <span class="repo-pathbar-current" aria-current="page">
                        <i class="fas fa-home" aria-hidden="true"></i> Home
                    </span>
                <?php else: ?>
                    <a href="?"><i class="fas fa-home" aria-hidden="true"></i> Home</a>
                    <?php
                    // array_values() ensures 0-based sequential keys after array_filter()
                    $parts = array_values(array_filter(explode('/', $currentDir)));
                    $partCount = count($parts);
                    $cumulativePath = '';
                    foreach ($parts as $index => $part) {
                        $cumulativePath .= ($index === 0 ? '' : '/') . $part;
                        echo '<span class="repo-pathbar-separator">/</span>';
                        if ($index === $partCount - 1) {
                            echo '<span class="repo-pathbar-current" aria-current="page"><i class="fas fa-folder-open" aria-hidden="true"></i> ' . e($part) . '</span>';
                        } else {
                            echo '<a href="' . e(queryUrl(['berkas' => $cumulativePath])) . '"><i class="fas fa-folder-open" aria-hidden="true"></i> ' . e($part) . '</a>';
                        }
                    }
                    ?>
                <?php endif; ?>
            </span>
        </nav>

        <div class="table-container">
            <div class="table-responsive">
                <table class="table table-bordered table-striped table-hover text-start" id="fileTable">
                    <colgroup>
                        <col>
                        <col>
                        <col>
                        <col>
                    </colgroup>
                    <thead>
                        <tr>
                            <th>Name</th>
                            <th class="table-col-date">Date</th>
                            <th class="table-col-size">Size</th>
                            <th class="table-col-hash">Hash</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php if ($showParent && $currentDir !== ''):
                            $parentDir = sanitizePath(dirname($currentDir));
                            if ($parentDir === '.') {
                                $parentDir = '';
                            }
                        ?>
                        <tr class="parent-row">
                            <td class="text-break">
                                <a href="<?php echo e(queryUrl(['berkas' => $parentDir])); ?>" class="folder-link d-flex align-items-center">
                                    <i class="fas fa-arrow-up file-icon me-2"></i>
                                    <span>Parent Directory</span>
                                </a>
                            </td>
                            <td class="table-col-date">-</td>
                            <td class="table-col-size">-</td>
                            <td class="table-col-hash">-</td>
                        </tr>
                        <?php endif; ?>

                        <?php
                        // Pre-compute once outside the loop for performance
                        $protectedFoldersLower = array_change_key_case($protectedFolders, CASE_LOWER);
                        foreach ($items as $item):
                            $itemName = (string) $item['name'];
                            $relativePath = (string) $item['relative'];
                            $iconClass = $item['isDir'] ? 'fa-folder' : getFileIconClass($itemName);
                            $link = $item['isDir']
                                ? queryUrl(['berkas' => $relativePath])
                                : encodeRelativePath($relativePath);
                            $itemTime = (int) $item['time'];
                        ?>
                        <tr data-name="<?php echo e(strtolower($itemName)); ?>">
                            <td class="text-break">
                                <a href="<?php echo e($link); ?>" class="<?php echo $item['isDir'] ? 'folder-link' : 'file-link'; ?> d-flex align-items-center">
                                    <i class="fas <?php echo e($iconClass); ?> file-icon"></i>
                                    <span><?php echo e($itemName); ?></span>
                                    <?php if ($item['isDir'] && array_key_exists(strtolower($relativePath), $protectedFoldersLower)): ?>
                                        <small class="ms-2 text-warning" title="Password Protected">
                                            <i class="fas fa-lock"></i>
                                        </small>
                                    <?php endif; ?>
                                    <?php if ($item['isSymlink']): ?>
                                        <small class="symlink-badge" title="Symbolic Link">
                                            <i class="fas fa-link"></i>
                                        </small>
                                    <?php endif; ?>
                                </a>
                            </td>
                            <td class="table-col-date">
                                <span class="full-date"><?php echo $itemTime > 0 ? e(date($dateFormat, $itemTime)) : '-'; ?></span>
                                <span class="short-date"><?php echo $itemTime > 0 ? e(date('d/m/y', $itemTime)) : '-'; ?></span>
                            </td>
                            <td class="table-col-size"><?php echo $item['isDir'] ? '-' : e(humanizeFilesize((int) $item['size'], $sizeDecimals)); ?></td>
                            <td class="table-col-hash">
                                <?php if (!$item['isDir']): ?>
                                    <a href="<?php echo e(queryUrl(['md5' => $relativePath])); ?>"
                                       title="Check Hash" aria-label="Check hash for <?php echo e($itemName); ?>">
                                        <i class="fas fa-fingerprint" aria-hidden="true"></i>
                                    </a>
                                <?php else: ?>
                                    -
                                <?php endif; ?>
                            </td>
                        </tr>
                        <?php endforeach; ?>

                        <?php if (empty($items)): ?>
                        <tr>
                            <td colspan="4" class="text-center text-muted py-5">
                                <i class="fas fa-folder-open fa-3x mb-3 text-secondary opacity-50"></i>
                                <p class="mb-0">No files or directories found</p>
                            </td>
                        </tr>
                        <?php endif; ?>
                    </tbody>
                </table>
                <div class="no-results" id="noResults">
                    <i class="fas fa-search fa-3x mb-3 text-secondary opacity-50"></i>
                    <p class="mb-0">No files matching your search</p>
                </div>
            </div>
        </div>
    </main>

    <!-- Floating Home Button -->
    <button class="fab-home" id="fabHome" type="button" aria-label="Kembali ke halaman utama" title="Home">
        <i class="fas fa-home" aria-hidden="true"></i>
    </button>

    <!-- Back to Top Button -->
    <button class="back-to-top-control" id="backToTop" type="button" aria-label="Kembali ke atas" title="Kembali ke atas">
        <i class="fas fa-arrow-up"></i>
    </button>

    <!-- Footer -->
    <footer>
        <div class="footer-inner">
            <div class="footer-divider"></div>
            <div class="social-links">
                <a href="https://github.com/alsyundawy" target="_blank" rel="noopener noreferrer" aria-label="GitHub"><i class="fa-brands fa-github"></i></a>
                <a href="https://twitter.com/alsyundawy" target="_blank" rel="noopener noreferrer" aria-label="Twitter / X"><i class="fa-brands fa-x-twitter"></i></a>
                <a href="https://facebook.com/alsyundawy" target="_blank" rel="noopener noreferrer" aria-label="Facebook"><i class="fa-brands fa-facebook-f"></i></a>
                <a href="https://instagram.com/harry.ds.alsyundawy" target="_blank" rel="noopener noreferrer" aria-label="Instagram"><i class="fa-brands fa-instagram"></i></a>
                <a href="https://threads.net/harry.ds.alsyundawy" target="_blank" rel="noopener noreferrer" aria-label="Threads"><i class="fa-brands fa-threads"></i></a>
                <a href="https://t.me/alsyundawy" target="_blank" rel="noopener noreferrer" aria-label="Telegram"><i class="fa-brands fa-telegram"></i></a>
                <a href="https://wa.me/alsyundawy" target="_blank" rel="noopener noreferrer" aria-label="WhatsApp"><i class="fa-brands fa-whatsapp"></i></a>
                <a href="https://tiktok.com/@alsyundawy" target="_blank" rel="noopener noreferrer" aria-label="TikTok"><i class="fa-brands fa-tiktok"></i></a>
            </div>
            <p class="footer-title">
                <a href="https://www.alsyundawy.com/" target="_blank" rel="noopener noreferrer">
                    <span class="ft-part">REPOSITORY FILE &amp; DIRECTORY BROWSER.</span>
                    <span class="ft-part">SUPPORT BY HARRY DS ALSYUNDAWY | ALSYUNDAWY IT SOLUTION.</span>
                </a>
            </p>
            <p class="footer-copy">&copy; 2009&ndash;2026 &middot; All Rights Reserved</p>
        </div>
    </footer>

    <!-- Scripts -->
    <script nonce="<?php echo e($nonce); ?>">(function(){"use strict";const e={loading:document.getElementById("loadingScreen"),backToTop:document.getElementById("backToTop"),searchInput:document.getElementById("searchInput"),fileTable:document.getElementById("fileTable"),noResults:document.getElementById("noResults"),themeToggle:document.getElementById("theme-toggle-main"),searchToggle:document.getElementById("search-toggle"),searchContainer:document.getElementById("search-form-container")},m=sessionStorage.getItem("isNavigating")==="true"?250:400;if(e.loading&&setTimeout(()=>{e.loading.classList.add("fade-out"),setTimeout(()=>{e.loading.style.display="none"},300)},m),document.querySelectorAll("a").forEach(t=>{t.addEventListener("click",function(){this.href&&!this.target&&!this.href.includes("#")&&!this.href.startsWith("javascript:")&&sessionStorage.setItem("isNavigating","true")})}),window.addEventListener("beforeunload",()=>{setTimeout(()=>sessionStorage.removeItem("isNavigating"),100)}),e.themeToggle){const t=()=>{const s=document.documentElement.classList.contains("dark-mode"),o=e.themeToggle.querySelector("i");o&&(o.className=s?"fas fa-sun":"fas fa-moon")};t(),e.themeToggle.addEventListener("click",()=>{document.documentElement.classList.toggle("dark-mode");const s=document.documentElement.classList.contains("dark-mode");localStorage.setItem("theme",s?"dark":"light"),t()})}const a=document.getElementById("fabHome");if(a&&(window.addEventListener("scroll",function(){window.requestAnimationFrame(function(){a.classList.toggle("show",window.scrollY>300)})},{passive:!0}),a.addEventListener("click",function(){window.location.href="?"})),e.backToTop&&(window.addEventListener("scroll",function(){window.requestAnimationFrame(function(){e.backToTop.classList.toggle("show",window.scrollY>300)})},{passive:!0}),e.backToTop.addEventListener("click",function(){window.scrollTo({top:0,behavior:"smooth"})})),e.searchToggle&&e.searchContainer&&e.searchToggle.addEventListener("click",function(t){t.preventDefault(),e.searchContainer.style.display==="block"?(e.searchContainer.style.opacity="0",e.searchContainer.style.transform="translateY(-6px)",setTimeout(function(){e.searchContainer.style.display="none"},180)):(e.searchContainer.style.display="block",e.searchContainer.style.opacity="0",e.searchContainer.style.transform="translateY(-6px)",e.searchContainer.offsetHeight,e.searchContainer.style.opacity="1",e.searchContainer.style.transform="translateY(0)",e.searchInput&&e.searchInput.focus())}),e.searchInput&&e.fileTable&&e.noResults){const t=e.fileTable.querySelector("tbody"),s=Array.from(t.querySelectorAll("tr:not(.parent-row)")),o=t.querySelector(".parent-row");let c;const r=()=>{const n=e.searchInput.value.toLowerCase().trim();let i=0;s.forEach(l=>{const d=l.getAttribute("data-name");if(!d)return;const u=!n||d.includes(n);l.classList.toggle("search-hidden",!u),u&&i++}),o&&o.classList.toggle("search-hidden",n!=="");const g=n===""||i>0;e.fileTable.classList.toggle("d-none",!g),e.noResults.classList.toggle("show",n!==""&&i===0)};e.searchInput.addEventListener("input",()=>{clearTimeout(c),c=setTimeout(r,150)}),e.searchInput.addEventListener("keydown",n=>{n.key==="Escape"&&(e.searchInput.value="",r())})}})();</script>
</body>
</html>
