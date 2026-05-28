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
 *  Updated On : 28 May 2026
 *  Timezone   : Asia/Jakarta
 *  License    : MIT License
 * ==============================================================================
 */

declare(strict_types=1);

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
$hashCacheVersion       = '2026-05-28-v1';

// Files to hide from listing and hash check.
$filesToHide = [
    'robots.txt',
    'favicon.ico',
    'logo.png',
    basename(__FILE__),
];

// Extensions that should not be exposed by this public browser.
$dangerousExtensions = [
    'php', 'php3', 'php4', 'php5', 'phtml', 'phar',
    'html', 'htm', 'shtml',
    'sh', 'bash', 'zsh', 'fish', 'ksh',
    'bat', 'cmd', 'ps1',
    'js', 'mjs', 'cjs', 'css',
    'pl', 'py', 'rb', 'cgi',
    'env', 'ini', 'conf', 'cfg', 'sql',
];

$baseDir = realpath(__DIR__);
if ($baseDir === false || !is_dir($baseDir)) {
    http_response_code(500);
    exit('Base directory is not readable.');
}

// =================== CORE HELPERS ===================
function isHttpsRequest(): bool
{
    if (!empty($_SERVER['HTTPS']) && strtolower((string) $_SERVER['HTTPS']) !== 'off') {
        return true;
    }

    if (!empty($_SERVER['HTTP_X_FORWARDED_PROTO'])) {
        $proto = strtolower(trim(explode(',', (string) $_SERVER['HTTP_X_FORWARDED_PROTO'])[0]));
        return $proto === 'https';
    }

    if (!empty($_SERVER['HTTP_X_FORWARDED_SSL'])) {
        return strtolower((string) $_SERVER['HTTP_X_FORWARDED_SSL']) === 'on';
    }

    return false;
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

    return '?' . http_build_query($cleanParams, '', '&', PHP_QUERY_RFC3986);
}

function getSafeHost(): string
{
    $host = $_SERVER['HTTP_HOST'] ?? $_SERVER['SERVER_NAME'] ?? 'localhost';
    $host = strtolower(trim((string) $host));
    $host = preg_replace('/[\r\n\t]/', '', $host) ?? 'localhost';

    if (str_contains($host, ':')) {
        [$hostname, $port] = explode(':', $host, 2);
        if ($hostname !== '' && preg_match('/^[a-z0-9.-]+$/', $hostname) && preg_match('/^[0-9]{1,5}$/', $port)) {
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
        "connect-src 'self'",
        "upgrade-insecure-requests",
    ];

    header('Content-Security-Policy: ' . implode('; ', $csp));
}

function startSecureSession(): void
{
    if (session_status() === PHP_SESSION_ACTIVE) {
        return;
    }

    ini_set('session.use_strict_mode', '1');
    ini_set('session.cookie_httponly', '1');
    ini_set('session.cookie_samesite', 'Strict');
    ini_set('session.use_only_cookies', '1');

    session_name('consentUUID');
    session_set_cookie_params([
        'lifetime' => 1440,
        'path'     => '/',
        'secure'   => isHttpsRequest(),
        'httponly' => true,
        'samesite' => 'Strict',
    ]);

    session_start();
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

function getFileIconClass(string $filename): string
{
    static $iconMap = [
        // Documents
        'pdf' => 'fa-file-pdf',
        'doc' => 'fa-file-word',
        'docx' => 'fa-file-word',
        'docm' => 'fa-file-word',
        'xls' => 'fa-file-excel',
        'xlsx' => 'fa-file-excel',
        'xlsm' => 'fa-file-excel',
        'xlsb' => 'fa-file-excel',
        'ppt' => 'fa-file-powerpoint',
        'pptx' => 'fa-file-powerpoint',
        'pptm' => 'fa-file-powerpoint',
        'txt' => 'fa-file-alt',
        'odt' => 'fa-file-alt',
        'ods' => 'fa-file-excel',
        'odp' => 'fa-file-powerpoint',
        'rtf' => 'fa-file-alt',
        'ps' => 'fa-file-alt',
        'epub' => 'fa-file-alt',
        'pages' => 'fa-file-alt',
        'numbers' => 'fa-file-excel',
        'key' => 'fa-file-powerpoint',
        'md' => 'fa-file-contract',

        // Images
        'jpg' => 'fa-file-image',
        'jpeg' => 'fa-file-image',
        'jfif' => 'fa-file-image',
        'png' => 'fa-file-image',
        'gif' => 'fa-file-image',
        'bmp' => 'fa-file-image',
        'svg' => 'fa-file-image',
        'webp' => 'fa-file-image',
        'tiff' => 'fa-file-image',
        'tif' => 'fa-file-image',
        'ico' => 'fa-file-image',
        'heic' => 'fa-file-image',
        'heif' => 'fa-file-image',
        'avif' => 'fa-file-image',
        'psd' => 'fa-file-image',
        'ai' => 'fa-file-image',
        'eps' => 'fa-file-image',
        'raw' => 'fa-file-image',
        'cr2' => 'fa-file-image',
        'nef' => 'fa-file-image',

        // Audio
        'mp3' => 'fa-file-audio',
        'wav' => 'fa-file-audio',
        'ogg' => 'fa-file-audio',
        'flac' => 'fa-file-audio',
        'aac' => 'fa-file-audio',
        'm4a' => 'fa-file-audio',
        'wma' => 'fa-file-audio',
        'midi' => 'fa-file-audio',
        'mid' => 'fa-file-audio',
        'opus' => 'fa-file-audio',
        'aiff' => 'fa-file-audio',
        'amr' => 'fa-file-audio',

        // Video
        'mp4' => 'fa-file-video',
        'avi' => 'fa-file-video',
        'mov' => 'fa-file-video',
        'wmv' => 'fa-file-video',
        'mkv' => 'fa-file-video',
        'webm' => 'fa-file-video',
        'flv' => 'fa-file-video',
        'mpeg' => 'fa-file-video',
        'mpg' => 'fa-file-video',
        '3gp' => 'fa-file-video',
        'm4v' => 'fa-file-video',
        'ogv' => 'fa-file-video',
        'vob' => 'fa-file-video',

        // Archives
        'zip' => 'fa-file-archive',
        'rar' => 'fa-file-archive',
        '7z' => 'fa-file-archive',
        'tar' => 'fa-file-archive',
        'gz' => 'fa-file-archive',
        'bz2' => 'fa-file-archive',
        'xz' => 'fa-file-archive',
        'zst' => 'fa-file-archive',
        'lz' => 'fa-file-archive',
        'lz4' => 'fa-file-archive',
        'iso' => 'fa-file-archive',
        'dmg' => 'fa-file-archive',
        'pkg' => 'fa-file-archive',
        'deb' => 'fa-file-archive',
        'rpm' => 'fa-file-archive',
        'apk' => 'fa-file-archive',
        'msi' => 'fa-file-archive',

        // Code & Programming
        'js' => 'fa-file-code',
        'jsx' => 'fa-file-code',
        'ts' => 'fa-file-code',
        'tsx' => 'fa-file-code',
        'css' => 'fa-file-code',
        'scss' => 'fa-file-code',
        'sass' => 'fa-file-code',
        'less' => 'fa-file-code',
        'html' => 'fa-file-code',
        'htm' => 'fa-file-code',
        'php' => 'fa-file-code',
        'py' => 'fa-file-code',
        'java' => 'fa-file-code',
        'class' => 'fa-file-code',
        'jar' => 'fa-file-code',
        'cpp' => 'fa-file-code',
        'c' => 'fa-file-code',
        'h' => 'fa-file-code',
        'hpp' => 'fa-file-code',
        'cs' => 'fa-file-code',
        'go' => 'fa-file-code',
        'rb' => 'fa-file-code',
        'sh' => 'fa-file-code',
        'bash' => 'fa-file-code',
        'zsh' => 'fa-file-code',
        'bat' => 'fa-file-code',
        'cmd' => 'fa-file-code',
        'ps1' => 'fa-file-code',
        'json' => 'fa-file-code',
        'yaml' => 'fa-file-code',
        'yml' => 'fa-file-code',
        'xml' => 'fa-file-code',
        'sql' => 'fa-file-code',
        'swift' => 'fa-file-code',
        'kt' => 'fa-file-code',
        'kts' => 'fa-file-code',
        'dart' => 'fa-file-code',
        'lua' => 'fa-file-code',
        'pl' => 'fa-file-code',
        'r' => 'fa-file-code',
        'rs' => 'fa-file-code',
        'groovy' => 'fa-file-code',
        'ipynb' => 'fa-file-code',

        // Data Formats
        'csv' => 'fa-file-csv',
        'tsv' => 'fa-file-csv',
        'parquet' => 'fa-file-csv',
        'feather' => 'fa-file-csv',
        'orc' => 'fa-file-csv',
        'avro' => 'fa-file-csv',

        // Configurations
        'env' => 'fa-file-cog',
        'conf' => 'fa-file-cog',
        'cfg' => 'fa-file-cog',
        'ini' => 'fa-file-cog',
        'toml' => 'fa-file-cog',
        'properties' => 'fa-file-cog',

        // E-Books
        'mobi' => 'fa-book',
        'azw3' => 'fa-book',
        'djvu' => 'fa-book',

        // Executables
        'exe' => 'fa-cogs',
        'dll' => 'fa-cogs',
        'so' => 'fa-cogs',
        'dylib' => 'fa-cogs',

        // Fonts
        'ttf' => 'fa-font',
        'otf' => 'fa-font',
        'woff' => 'fa-font',
        'woff2' => 'fa-font',

        // Miscellaneous
        'log' => 'fa-file-alt',
        'db' => 'fa-database',
        'sqlite' => 'fa-database',
        'sqlite3' => 'fa-database',
        'bak' => 'fa-history',
        'tmp' => 'fa-history',
        'temp' => 'fa-history',
        'torrent' => 'fa-magnet',
        'vcf' => 'fa-address-card',
        'ics' => 'fa-calendar',
        'tex' => 'fa-file-alt',
        'bib' => 'fa-file-alt',
        'stl' => 'fa-cube',
        'obj' => 'fa-cube',
        'fbx' => 'fa-cube',
        'step' => 'fa-cube',
        'iges' => 'fa-cube',
    ];

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

function createHashCacheDir(string $baseDir): string|false
{
    $cacheDir = $baseDir . DIRECTORY_SEPARATOR . '.cache';

    if (is_link($cacheDir)) {
        error_log('Hash cache disabled because .cache is a symlink.');
        return false;
    }

    if (!is_dir($cacheDir)) {
        if (!@mkdir($cacheDir, 0750, true) && !is_dir($cacheDir)) {
            error_log('Hash cache disabled because .cache cannot be created.');
            return false;
        }
    }

    if (!is_writable($cacheDir)) {
        error_log('Hash cache disabled because .cache is not writable.');
        return false;
    }

    return $cacheDir;
}

function readHashCache(string $cacheFile): array|null
{
    if (!is_file($cacheFile) || !is_readable($cacheFile)) {
        return null;
    }

    $raw = @file_get_contents($cacheFile);
    if ($raw === false || $raw === '') {
        return null;
    }

    $data = json_decode($raw, true);
    if (!is_array($data)) {
        return null;
    }

    foreach (['crc32', 'md5', 'sha1'] as $key) {
        if (!isset($data[$key]) || !is_string($data[$key]) || !preg_match('/^[a-f0-9]+$/', $data[$key])) {
            return null;
        }
    }

    return $data;
}

function writeHashCache(string $cacheFile, array $hashData): void
{
    $tmpFile = $cacheFile . '.' . bin2hex(random_bytes(8)) . '.tmp';
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

    $ctxCrc32 = hash_init('crc32b');
    $ctxMd5   = hash_init('md5');
    $ctxSha1  = hash_init('sha1');

    while (!feof($handle)) {
        $buffer = fread($handle, $chunkSize);
        if ($buffer === false) {
            fclose($handle);
            return false;
        }
        if ($buffer === '') {
            continue;
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
        <link rel="icon" type="image/x-icon" href="favicon.ico">
        <title>Hash Check for <?php echo e($fileName); ?></title>
        <meta name="description" content="Verify file integrity with CRC32, MD5, and SHA-1 hash algorithms">
        <meta name="keywords" content="hash check, file verification, CRC32, MD5, SHA-1">
        <meta name="author" content="ALSYUNDAWY IT SOLUTION">
        <meta name="robots" content="noindex,nofollow">
        <link rel="canonical" href="<?php echo e(getCanonicalURL()); ?>">
        <link rel="preconnect" href="https://fonts.googleapis.com">
        <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.7/dist/css/bootstrap.min.css">
        <link rel="stylesheet" href="https://unpkg.com/@fortawesome/fontawesome-free@6.7.2/css/all.min.css">
        <style nonce="<?php echo e($nonce); ?>">
            body {
                font-family: 'Inter', sans-serif;
                -webkit-font-smoothing: antialiased;
                -moz-osx-font-smoothing: grayscale;
            }
            .table th { width: 150px; }
            .hash-value { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace; word-break: break-all; }
        </style>
    </head>
    <body class="bg-white">
        <div class="container py-5">
            <h2 class="mb-4">Hash Check for <small><?php echo e($fileName); ?></small></h2>
            <div class="table-responsive">
                <table class="table table-bordered table-striped">
                    <tbody>
                        <tr>
                            <th>File Size</th>
                            <td><?php echo e($fileSizeHuman); ?> (<?php echo e(number_format($fileSize)); ?> bytes)</td>
                        </tr>
                        <tr>
                            <th>CRC32</th>
                            <td class="hash-value"><?php echo e($hashData['crc32']); ?></td>
                        </tr>
                        <tr>
                            <th>MD5</th>
                            <td class="hash-value"><?php echo e($hashData['md5']); ?></td>
                        </tr>
                        <tr>
                            <th>SHA-1</th>
                            <td class="hash-value"><?php echo e($hashData['sha1']); ?></td>
                        </tr>
                    </tbody>
                </table>
            </div>
            <a href="javascript:history.back()" class="btn btn-secondary mt-3">
                <i class="fas fa-arrow-left"></i> Back
            </a>
        </div>
        <script nonce="<?php echo e($nonce); ?>" src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.7/dist/js/bootstrap.bundle.min.js"></script>
    </body>
    </html>
    <?php
}

function listDirectory(string $path, bool $showFolders = true, bool $showHidden = false): array
{
    global $totalFiles, $totalSize, $baseDir, $filesToHide, $dangerousExtensions, $allowExternalSymlinks;

    $items = [];
    $path = sanitizePath($path);
    $fullPath = resolveExistingPath($path, $baseDir, $allowExternalSymlinks);

    if ($fullPath === false || !is_dir($fullPath) || !is_readable($fullPath)) {
        return $items;
    }

    $files = @scandir($fullPath);
    if ($files === false) {
        return $items;
    }

    foreach ($files as $file) {
        if ($file === '.' || $file === '..') {
            continue;
        }

        if (isHiddenName($file, $showHidden, $filesToHide)) {
            continue;
        }

        $relativeItemPath = trim($path . '/' . $file, '/');
        $itemRealPath = resolveExistingPath($relativeItemPath, $baseDir, $allowExternalSymlinks);
        if ($itemRealPath === false) {
            continue;
        }

        $isDir = is_dir($itemRealPath);
        if ($isDir && !$showFolders) {
            continue;
        }

        if (!$isDir && isDangerousExtension($file, $dangerousExtensions)) {
            continue;
        }

        $linkPath = pathToFilesystem($baseDir, $relativeItemPath);
        $isSymlink = is_link($linkPath);
        $itemSize = $isDir ? 0 : (int) (@filesize($itemRealPath) ?: 0);
        $itemTime = (int) (@filemtime($itemRealPath) ?: 0);
        $stat = @stat($itemRealPath);
        $itemCreated = (is_array($stat) && isset($stat['birthtime']) && (int) $stat['birthtime'] > 0)
            ? (int) $stat['birthtime']
            : $itemTime;

        $items[] = [
            'name'      => $file,
            'relative'  => $relativeItemPath,
            'isDir'     => $isDir,
            'size'      => $itemSize,
            'time'      => $itemTime,
            'created'   => $itemCreated,
            'isSymlink' => $isSymlink,
        ];

        if (!$isDir) {
            $totalFiles++;
            $totalSize += $itemSize;
        }
    }

    return $items;
}

// =================== INITIALIZATION ===================
$nonce = makeNonce();
sendSecurityHeaders($nonce);
startSecureSession();

try {
    if (!isset($_SESSION['csrf'])) {
        $_SESSION['csrf'] = bin2hex(random_bytes(32));
    }
} catch (Throwable $e) {
    error_log('Failed to generate CSRF token: ' . $e->getMessage());
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

if ($browseDirectories && isset($_GET['folder'])) {
    $requested = sanitizePath((string) $_GET['folder']);
    $realPath = resolveExistingPath($requested, $baseDir, $allowExternalSymlinks);

    if ($realPath !== false && is_dir($realPath) && is_readable($realPath)) {
        $currentDir = $requested;
    }
}

$displayDir = '/' . ltrim($currentDir, '/');

// =================== LIST DIRECTORY ===================
$items = listDirectory($currentDir, $showDirectories, $showHiddenFiles);

// =================== SORTING FILES & DIRECTORIES ===================
$allowedSorts = ['name', 'modified', 'size'];
$sort = isset($_GET['sort']) && in_array((string) $_GET['sort'], $allowedSorts, true)
    ? (string) $_GET['sort']
    : 'name';

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
        'modified' => $a['time'] <=> $b['time'],
        'size'     => $a['size'] <=> $b['size'],
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
    <title><?php echo e($pageTitle); ?> - File Browser</title>
    <meta name="description" content="Browse files and directories securely with hash verification support. Features include CRC32, MD5, SHA-1 checksums, responsive design, and enhanced security.">
    <meta name="keywords" content="file browser, directory listing, hash check, CRC32, MD5, SHA-1, secure browsing, responsive design">
    <meta name="author" content="ALSYUNDAWY IT SOLUTION">
    <meta name="robots" content="index, follow">
    <meta name="language" content="en">
    <meta name="revisit-after" content="7 days">
    <meta property="og:title" content="<?php echo e($pageTitle); ?>">
    <meta property="og:description" content="Secure file and directory browser with hash verification capabilities">
    <meta property="og:type" content="website">
    <meta property="og:url" content="<?php echo e(getCanonicalURL()); ?>">
    <meta property="og:site_name" content="File Browser">
    <meta name="twitter:card" content="summary_large_image">
    <meta name="twitter:title" content="<?php echo e($pageTitle); ?>">
    <meta name="twitter:description" content="Secure file and directory browser">
    <link rel="canonical" href="<?php echo e(getCanonicalURL()); ?>">
    <link rel="icon" href="favicon.ico" type="image/x-icon">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.7/dist/css/bootstrap.min.css">
    <link rel="stylesheet" href="https://unpkg.com/@fortawesome/fontawesome-free@6.7.2/css/all.min.css">
    <style nonce="<?php echo e($nonce); ?>">
        :root {
            --primary-color: #2c3e50;
            --secondary-color: #ffffff;
            --border-color: #dee2e6;
            --hover-color: #f8f9fa;
            --text-color: #212529;
        }

        * {
            box-sizing: border-box;
        }

        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            font-weight: 400;
            color: var(--text-color);
            background-color: var(--secondary-color);
            line-height: 1.6;
            margin: 0;
            padding: 0;
            -webkit-font-smoothing: antialiased;
            -moz-osx-font-smoothing: grayscale;
            text-rendering: optimizeLegibility;
        }

        a {
            text-decoration: none;
            color: inherit;
            transition: opacity 0.2s ease;
        }

        a:hover {
            text-decoration: none;
            opacity: 0.8;
        }

        /* Loading Screen */
        .loading-screen {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(255, 255, 255, 0.95);
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
            z-index: 9999;
            transition: opacity 0.3s ease;
        }

        .loading-screen.fade-out {
            opacity: 0;
            pointer-events: none;
        }

        .spinner {
            width: 48px;
            height: 48px;
            border-radius: 50%;
            display: inline-block;
            border-top: 4px solid #2c3e50;
            border-right: 4px solid transparent;
            animation: rotation 1s linear infinite;
            position: relative;
        }

        .spinner::after {
            content: '';
            position: absolute;
            left: 0;
            top: 0;
            width: 48px;
            height: 48px;
            border-radius: 50%;
            border-bottom: 4px solid #FF3D00;
            border-left: 4px solid transparent;
        }

        @keyframes rotation {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }

        .loading-text {
            margin-top: 20px;
            color: var(--primary-color);
            font-weight: 500;
        }

        /* Header Styles */
        header {
            background: white;
            padding: 2rem 0;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            margin-bottom: 2rem;
        }

        header img {
            max-height: 120px;
            width: auto;
            cursor: pointer;
            transition: transform 0.3s ease;
            image-rendering: -webkit-optimize-contrast;
            image-rendering: crisp-edges;
        }

        header img:hover {
            transform: scale(1.05);
        }

        header h1 {
            font-size: 1.75rem;
            font-weight: 600;
            margin-top: 1rem;
            margin-bottom: 0.5rem;
            letter-spacing: -0.5px;
        }

        /* Container Styles */
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 0 15px;
        }

        /* Page Header */
        .page-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            margin-bottom: 2rem;
            gap: 1rem;
        }

        .page-title h2 {
            font-size: 1.5rem;
            font-weight: 600;
            margin: 0;
            word-break: break-word;
            letter-spacing: -0.3px;
        }

        .page-subtitle {
            color: #6c757d;
            font-size: 0.9rem;
            margin-top: 0.5rem;
        }

        /* Search Input */
        .search-container {
            position: relative;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        .search-input {
            display: flex;
            align-items: center;
            position: relative;
        }

        .search-input input {
            padding: 0.375rem 2.5rem 0.375rem 0.75rem;
            border: 1px solid #ced4da;
            border-radius: 0.25rem;
            font-size: 0.875rem;
            width: 200px;
            transition: all 0.2s ease;
        }

        .search-input input:focus {
            outline: none;
            border-color: #80bdff;
            box-shadow: 0 0 0 0.2rem rgba(0,123,255,.25);
        }

        .search-input .search-icon {
            position: absolute;
            right: 0.75rem;
            color: #6c757d;
            pointer-events: none;
        }

        /* Sort Buttons */
        .sort-buttons {
            display: flex;
            gap: 0.5rem;
            flex-wrap: wrap;
        }

        .sort-buttons .btn {
            font-size: 0.875rem;
            padding: 0.375rem 0.75rem;
            white-space: nowrap;
            font-weight: 500;
        }

        /* Table Styles */
        .table-container {
            background: white;
            border-radius: 8px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            overflow: hidden;
        }

        .table {
            margin-bottom: 0;
            font-size: 0.9rem;
        }

        .table thead th {
            background-color: var(--primary-color);
            color: white;
            font-weight: 500;
            border: none;
            padding: 0.75rem;
            white-space: nowrap;
            letter-spacing: 0.3px;
        }

        .table tbody tr {
            transition: background-color 0.2s ease;
        }

        .table tbody tr:hover {
            background-color: var(--hover-color);
        }

        .table tbody tr.search-hidden {
            display: none;
        }

        .table td {
            padding: 0.75rem;
            vertical-align: middle;
            border-color: var(--border-color);
        }

        /* Column Widths */
        .col-name { width: auto; }
        .col-date { width: 140px; white-space: nowrap; }
        .col-size { width: 80px; text-align: right; }
        .col-hash { width: 80px; text-align: center; }

        /* Icon Styles */
        .file-icon {
            margin-right: 0.5rem;
            width: 16px;
            text-align: center;
            font-size: 1rem;
        }

        .symlink-badge {
            font-size: 0.7rem;
            margin-left: 0.25rem;
            vertical-align: super;
            color: #6c757d;
        }

        /* Back to Top Button */
        .back-to-top {
            position: fixed;
            bottom: 30px;
            right: 30px;
            width: 40px;
            height: 40px;
            background: var(--primary-color);
            color: white;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            cursor: pointer;
            opacity: 0;
            visibility: hidden;
            transition: all 0.3s ease;
            z-index: 1000;
            box-shadow: 0 2px 8px rgba(0,0,0,0.2);
        }

        .back-to-top.show {
            opacity: 1;
            visibility: visible;
        }

        .back-to-top:hover {
            background: #1a252f;
            transform: translateY(-3px);
        }

        /* Footer */
        footer {
            text-align: center;
            padding: 2rem 0;
            margin-top: 4rem;
        }

        /* No results */
        .no-results {
            display: none;
            text-align: center;
            padding: 3rem;
            color: #6c757d;
        }

        .no-results.show {
            display: block;
        }

        /* Responsive Design */
        @media (max-width: 768px) {
            header h1 {
                font-size: 1.5rem;
            }

            .page-header {
                flex-direction: column;
                align-items: flex-start;
            }

            .search-container {
                width: 100%;
                flex-direction: column;
                align-items: stretch;
            }

            .search-input {
                width: 100%;
                margin-bottom: 0.5rem;
            }

            .search-input input {
                width: 100%;
            }

            .sort-buttons {
                width: 100%;
            }

            .sort-buttons .btn {
                flex: 1;
                font-size: 0.75rem;
                padding: 0.25rem 0.5rem;
            }

            .table {
                font-size: 0.8rem;
            }

            .table td, .table th {
                padding: 0.5rem;
            }

            .col-date {
                width: 100px;
                font-size: 0.75rem;
            }

            .col-size {
                width: 60px;
                font-size: 0.75rem;
            }

            .col-hash {
                width: 50px;
            }

            .back-to-top {
                bottom: 20px;
                right: 20px;
                width: 35px;
                height: 35px;
            }
        }

        @media (max-width: 480px) {
            header img {
                max-height: 80px;
            }

            .page-title h2 {
                font-size: 1.2rem;
            }

            .col-date {
                display: none;
            }

            .hide-mobile {
                display: none !important;
            }
        }

        /* High Resolution Support */
        @media (min-width: 1440px) {
            .container {
                max-width: 1320px;
            }

            .table {
                font-size: 1rem;
            }
        }

        @media (min-width: 1920px) {
            .container {
                max-width: 1540px;
            }
        }

        /* Print Styles */
        @media print {
            .search-container,
            .sort-buttons,
            .back-to-top,
            .btn {
                display: none !important;
            }
        }

        /* Font rendering optimization */
        .fas, .fa {
            -webkit-font-smoothing: antialiased;
            -moz-osx-font-smoothing: grayscale;
            font-weight: 900 !important;
        }
    </style>
</head>
<body>
    <!-- Loading Screen -->
    <div class="loading-screen" id="loadingScreen" aria-live="polite" aria-label="Loading">
        <span class="spinner"></span>
        <div class="loading-text">LOADING ...</div>
    </div>

    <!-- Header -->
    <header>
        <div class="container text-center">
            <a href="?" title="Back to Home">
                <img src="logo.png" alt="File Browser Logo" loading="lazy">
            </a>
            <h1>File &amp; Directory Browser</h1>
            <p class="text-muted mb-0">Menampilkan daftar file dan direktori yang tersedia.</p>
        </div>
    </header>

    <!-- Main Content -->
    <main class="container <?php echo e($alignmentClass); ?>">
        <div class="page-header">
            <div class="page-title">
                <h2><?php echo e($pageTitle); ?></h2>
                <p class="page-subtitle">
                    <?php echo e(str_replace(
                        ['{{files}}', '{{size}}'],
                        [(string) $totalFiles, humanizeFilesize($totalSize, $sizeDecimals)],
                        $subtitle
                    )); ?>
                </p>
            </div>
            <div class="search-container">
                <div class="search-input">
                    <input type="text" id="searchInput" placeholder="Search files..." autocomplete="off" aria-label="Search files">
                    <i class="fas fa-search search-icon"></i>
                </div>
                <div class="sort-buttons">
                    <a href="<?php echo e(queryUrl(['folder' => $currentDir, 'sort' => 'name', 'order' => ($sort === 'name' && $order === 'asc') ? 'desc' : 'asc'])); ?>"
                       class="btn btn-outline-secondary btn-sm">
                        <i class="fas fa-sort-alpha-down"></i> Name
                    </a>
                    <a href="<?php echo e(queryUrl(['folder' => $currentDir, 'sort' => 'modified', 'order' => ($sort === 'modified' && $order === 'asc') ? 'desc' : 'asc'])); ?>"
                       class="btn btn-outline-secondary btn-sm">
                        <i class="fas fa-calendar-alt"></i> Date
                    </a>
                    <a href="<?php echo e(queryUrl(['folder' => $currentDir, 'sort' => 'size', 'order' => ($sort === 'size' && $order === 'asc') ? 'desc' : 'asc'])); ?>"
                       class="btn btn-outline-secondary btn-sm">
                        <i class="fas fa-weight-hanging"></i> Size
                    </a>
                </div>
            </div>
        </div>

        <div class="table-container">
            <div class="table-responsive">
                <table class="table table-hover" id="fileTable">
                    <thead>
                        <tr>
                            <th class="col-name">Name</th>
                            <th class="col-date">Date</th>
                            <th class="col-size">Size</th>
                            <th class="col-hash">Hash Check</th>
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
                            <td colspan="4">
                                <a href="<?php echo e(queryUrl(['folder' => $parentDir])); ?>" class="d-flex align-items-center">
                                    <?php if ($showIcons): ?>
                                        <i class="fas fa-arrow-up file-icon"></i>
                                    <?php endif; ?>
                                    Parent Directory
                                </a>
                            </td>
                        </tr>
                        <?php endif; ?>

                        <?php foreach ($items as $item):
                            $itemName = (string) $item['name'];
                            $relativePath = (string) $item['relative'];
                            $iconClass = $item['isDir'] ? 'fa-folder' : getFileIconClass($itemName);
                            $link = $item['isDir']
                                ? queryUrl(['folder' => $relativePath])
                                : encodeRelativePath($relativePath);
                            $itemTime = (int) $item['time'];
                        ?>
                        <tr data-name="<?php echo e(strtolower($itemName)); ?>">
                            <td class="col-name">
                                <a href="<?php echo e($link); ?>" class="d-flex align-items-center">
                                    <?php if ($showIcons): ?>
                                        <i class="fas <?php echo e($iconClass); ?> file-icon"></i>
                                    <?php endif; ?>
                                    <span><?php echo e($itemName); ?></span>
                                    <?php if ($item['isSymlink']): ?>
                                        <small class="symlink-badge" title="Symbolic Link">
                                            <i class="fas fa-link"></i>
                                        </small>
                                    <?php endif; ?>
                                </a>
                            </td>
                            <td class="col-date"><?php echo $itemTime > 0 ? e(date($dateFormat, $itemTime)) : '-'; ?></td>
                            <td class="col-size"><?php echo $item['isDir'] ? '-' : e(humanizeFilesize((int) $item['size'], $sizeDecimals)); ?></td>
                            <td class="col-hash text-center">
                                <?php if (!$item['isDir']): ?>
                                    <a href="<?php echo e(queryUrl(['md5' => $relativePath])); ?>"
                                       class="btn btn-sm btn-outline-info"
                                       title="Check Hash">
                                        <i class="fas fa-key"></i>
                                    </a>
                                <?php else: ?>
                                    -
                                <?php endif; ?>
                            </td>
                        </tr>
                        <?php endforeach; ?>

                        <?php if (empty($items)): ?>
                        <tr>
                            <td colspan="4" class="text-center text-muted py-4">
                                <i class="fas fa-folder-open fa-3x mb-3"></i>
                                <p>No files or directories found</p>
                            </td>
                        </tr>
                        <?php endif; ?>
                    </tbody>
                </table>
                <div class="no-results" id="noResults">
                    <i class="fas fa-search fa-3x mb-3"></i>
                    <p>No files matching your search</p>
                </div>
            </div>
        </div>
    </main>

    <!-- Footer -->
    <footer>
        <div class="container">
            <p class="text-muted mb-0">
                <a href="https://alsyundawy.com" target="_blank" rel="noopener noreferrer">
                    ALSYUNDAWY IT SOLUTION
                </a>
                &copy; <?php echo e(date('Y')); ?> - All Rights Reserved
            </p>
        </div>
    </footer>

    <!-- Back to Top Button -->
    <div class="back-to-top" id="backToTop" title="Back to Top" role="button" tabindex="0" aria-label="Back to Top">
        <i class="fas fa-arrow-up"></i>
    </div>

    <!-- Scripts -->
    <script nonce="<?php echo e($nonce); ?>">
        // Optimized JavaScript
        (function() {
            'use strict';

            // DOM elements cache
            const els = {
                loading: document.getElementById('loadingScreen'),
                backToTop: document.getElementById('backToTop'),
                searchInput: document.getElementById('searchInput'),
                fileTable: document.getElementById('fileTable'),
                noResults: document.getElementById('noResults')
            };

            // Loading Screen
            const isNavigating = sessionStorage.getItem('isNavigating');
            const loadTime = isNavigating === 'true' ? 300 : 500;

            if (els.loading) {
                setTimeout(() => {
                    els.loading.classList.add('fade-out');
                    setTimeout(() => {
                        els.loading.style.display = 'none';
                    }, 300);
                }, loadTime);
            }

            // Navigation flag
            document.querySelectorAll('a').forEach(link => {
                link.addEventListener('click', function() {
                    if (this.href && !this.target && !this.href.includes('#') && !this.href.startsWith('javascript:')) {
                        sessionStorage.setItem('isNavigating', 'true');
                    }
                });
            });

            window.addEventListener('beforeunload', () => {
                setTimeout(() => sessionStorage.removeItem('isNavigating'), 100);
            });

            // Back to Top
            if (els.backToTop) {
                let scrollTimeout;
                const toggleBackToTop = () => {
                    els.backToTop.classList.toggle('show', window.scrollY > 300);
                };

                window.addEventListener('scroll', () => {
                    clearTimeout(scrollTimeout);
                    scrollTimeout = setTimeout(toggleBackToTop, 100);
                }, { passive: true });

                const goTop = () => window.scrollTo({ top: 0, behavior: 'smooth' });
                els.backToTop.addEventListener('click', goTop);
                els.backToTop.addEventListener('keydown', (event) => {
                    if (event.key === 'Enter' || event.key === ' ') {
                        event.preventDefault();
                        goTop();
                    }
                });

                toggleBackToTop();
            }

            // Search functionality
            if (els.searchInput && els.fileTable && els.noResults) {
                const tbody = els.fileTable.querySelector('tbody');
                const rows = Array.from(tbody.querySelectorAll('tr:not(.parent-row)'));
                let searchTimeout;

                const performSearch = () => {
                    const searchTerm = els.searchInput.value.toLowerCase().trim();
                    let visibleCount = 0;

                    rows.forEach(row => {
                        const name = row.getAttribute('data-name');
                        if (!name) {
                            return;
                        }

                        const isVisible = !searchTerm || name.includes(searchTerm);
                        row.classList.toggle('search-hidden', !isVisible);
                        if (isVisible) {
                            visibleCount++;
                        }
                    });

                    els.noResults.classList.toggle('show', searchTerm !== '' && visibleCount === 0);
                };

                els.searchInput.addEventListener('input', () => {
                    clearTimeout(searchTimeout);
                    searchTimeout = setTimeout(performSearch, 150);
                });

                // Clear search on Escape
                els.searchInput.addEventListener('keydown', (event) => {
                    if (event.key === 'Escape') {
                        els.searchInput.value = '';
                        performSearch();
                    }
                });
            }
        })();
    </script>
</body>
</html>
