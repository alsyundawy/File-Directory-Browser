<?php
/**
 * Script Name: File & Directory Browser (index.php)
 * Function    : Menampilkan daftar file & direktori, dengan fitur cek hash (CRC32, MD5, SHA-1) dan search
 * Description : 
 *   - Menampilkan daftar file dan direktori dengan opsi sortir berdasarkan nama, tanggal, atau ukuran
 *   - Fitur search real-time untuk mencari file dan direktori
 *   - Fitur cek hash untuk file (CRC32, MD5, SHA-1) dengan caching untuk performa
 *   - Support penuh untuk symlink folders dan files
 *   - Keamanan diperkuat melalui session cookie HttpOnly & SameSite Strict
 *   - Proteksi CSRF dengan token acak 32-byte
 *   - Sanitasi output untuk mencegah serangan XSS
 *   - Header no-cache untuk memastikan konten selalu baru
 *   - UI responsif menggunakan Bootstrap 5 dan ikon Font Awesome
 *   - Font rendering yang tajam dan jelas
 *   - Performa dioptimalkan dengan minimal CSS dan JS
 * Created By  : HARRY DERTIN SUTISNA
 * Created On  : 26 June 2025
 * Updated On  : 30 June 2025
 * License     : MIT License
 */

declare(strict_types=1);

// Enhanced security session configuration
ini_set('session.cookie_httponly', '1');
ini_set('session.use_strict_mode', '1');
ini_set('session.cookie_samesite', 'Strict');
session_name("consentUUID");
session_set_cookie_params([
    'lifetime' => 1440,
    'path' => '/',
    'domain' => '.' . ($_SERVER["HTTP_HOST"] ?? ''),
    'secure' => true,
    'httponly' => true,
    'samesite' => 'Strict'
]);
session_start();

// Generate secure CSRF token
try {
    if (!isset($_SESSION['csrf'])) {
        $_SESSION['csrf'] = bin2hex(random_bytes(32));
    }
} catch (Exception $e) {
    error_log("Failed to generate CSRF token: " . $e->getMessage());
    exit('Internal server error');
}

// Helper function for output sanitization
function sanitize_output(string $output): string {
    return htmlspecialchars($output, ENT_QUOTES | ENT_HTML5, 'UTF-8');
}

// Validate PHP version
if (version_compare(PHP_VERSION, '8.0', '<')) {
    exit('PHP version ' . PHP_VERSION . ' is not supported. Minimum required version is 8.0');
}

// Validate required extensions
$required_extensions = ['pdo_sqlite', 'openssl', 'session', 'hash', 'json', 'pcre', 'spl', 'fileinfo'];
foreach ($required_extensions as $ext) {
    if (!extension_loaded($ext)) {
        exit("Required PHP extension '{$ext}' is not installed.");
    }
}

// NON-CACHE HEADERS
header("Cache-Control: no-cache, no-store, must-revalidate");
header("Pragma: no-cache");
header("Expires: 0");

// =================== CONFIGURATION ===================
$browseDirectories     = true;
$title                 = 'Index of {{path}}';
$subtitle              = '{{files}} files, {{size}} total';
$showParent            = true;
$showDirectories       = true;
$showDirectoriesFirst  = true;
$showHiddenFiles       = false;
$alignment             = 'left';
$showIcons             = true;
$dateFormat            = 'd-M-Y H:i';
$sizeDecimals          = 1;
$browseDefault         = '';

// Files to hide
$filesToHide = ['robots.txt', 'favicon.ico'];
// Dangerous extensions to hide
$dangerousExtensions   = ['php', 'php3', 'php4', 'php5', 'html', 'htm', 'sh', 'bat', 'js', 'css', 'cmd','png'];
// Base directory
$baseDir = realpath(__DIR__);

// =================== UTILITY FUNCTIONS ===================
// Sanitize path input
function sanitizePath($path) {
    $path = str_replace("\0", '', $path);
    $path = trim($path, "/\\");
    return preg_replace('/\.\.+/', '', $path);
}

// Convert file size to human readable format
function humanizeFilesize($bytes, $decimals = 0) {
    $units = ['B', 'KB', 'MB', 'GB', 'TB'];
    $factor = 0;
    while ($bytes >= 1024 && $factor < count($units) - 1) {
        $bytes /= 1024;
        $factor++;
    }
    return sprintf("%.{$decimals}f", $bytes) . ' ' . $units[$factor];
}

// Get canonical URL
function getCanonicalURL() {
    $protocol = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? "https://" : "http://";
    return $protocol . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
}

// Get file icon class based on extension
function getFileIconClass($filename) {
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
    
    $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
    return $iconMap[$ext] ?? 'fa-file';
}

// Resolve symlink path properly
function resolveSymlinkPath($path) {
    if (is_link($path)) {
        $linkTarget = readlink($path);
        if ($linkTarget && $linkTarget[0] !== '/') {
            $linkTarget = dirname($path) . DIRECTORY_SEPARATOR . $linkTarget;
        }
        return realpath($linkTarget) ?: $path;
    }
    return $path;
}

// =================== HASH CHECK WITH CACHE ===================
if (isset($_GET['md5'])) {
    $requestedFile = sanitizePath($_GET['md5']);
    $fullFilePath = $baseDir . DIRECTORY_SEPARATOR . $requestedFile;
    
    // Handle symlinks properly
    if (is_link($fullFilePath)) {
        $fullFilePath = resolveSymlinkPath($fullFilePath);
    } else {
        $fullFilePath = realpath($fullFilePath);
    }
    
    if ($fullFilePath !== false && is_file($fullFilePath)) {
        $fileName = basename($fullFilePath);
        $fileSize = filesize($fullFilePath);
        $fileSizeHuman = humanizeFilesize($fileSize, 2);
        $chunkSize = ($fileSize > 1073741824) ? 1048576 : 32768;
        
        // Cache mechanism
        $cacheDir = __DIR__ . '/.cache';
        if (!is_dir($cacheDir)) {
            mkdir($cacheDir, 0755, true);
        }
        $cacheKey  = hash('sha256', $fullFilePath . filemtime($fullFilePath));
        $cacheFile = $cacheDir . '/' . $cacheKey . '.cache';
        
        if (file_exists($cacheFile)) {
            $hashData = json_decode(file_get_contents($cacheFile), true);
        } else {
            $handle = fopen($fullFilePath, 'rb');
            if (!$handle) {
                header("HTTP/1.0 500 Internal Server Error");
                echo "Failed to open file.";
                exit;
            }
            $ctx_crc32 = hash_init('crc32b');
            $ctx_md5   = hash_init('md5');
            $ctx_sha1  = hash_init('sha1');
            
            while (!feof($handle)) {
                $buffer = fread($handle, $chunkSize);
                if ($buffer === false) break;
                hash_update($ctx_crc32, $buffer);
                hash_update($ctx_md5, $buffer);
                hash_update($ctx_sha1, $buffer);
            }
            fclose($handle);
            
            $hashData = [
                'crc32' => hash_final($ctx_crc32),
                'md5'   => hash_final($ctx_md5),
                'sha1'  => hash_final($ctx_sha1)
            ];
            file_put_contents($cacheFile, json_encode($hashData));
        }
        
        $crc32hash = $hashData['crc32'];
        $md5hash   = $hashData['md5'];
        $sha1hash  = $hashData['sha1'];
        ?>
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <link rel="icon" type="image/x-icon" href="favicon.ico">
            <title>Hash Check for <?php echo sanitize_output($fileName); ?></title>
            <meta name="description" content="Verify file integrity with CRC32, MD5, and SHA-1 hash algorithms">
            <meta name="keywords" content="hash check, file verification, CRC32, MD5, SHA-1">
            <meta name="author" content="ALSYUNDAWY IT SOLUTION">
            <meta name="robots" content="noindex,nofollow">
            <link rel="canonical" href="<?php echo sanitize_output(getCanonicalURL()); ?>">
            <link rel="preconnect" href="https://fonts.googleapis.com">
            <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
            <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
            <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.7/dist/css/bootstrap.min.css">
            <link rel="stylesheet" href="https://unpkg.com/@fortawesome/fontawesome-free@6.7.2/css/all.min.css">
            <style>
                body { 
                    font-family: 'Inter', sans-serif; 
                    -webkit-font-smoothing: antialiased;
                    -moz-osx-font-smoothing: grayscale;
                }
                .table th { width: 150px; }
            </style>
        </head>
        <body class="bg-white">
            <div class="container py-5">
                <h2 class="mb-4">Hash Check for <small><?php echo sanitize_output($fileName); ?></small></h2>
                <div class="table-responsive">
                    <table class="table table-bordered table-striped">
                        <tbody>
                            <tr>
                                <th>File Size</th>
                                <td><?php echo $fileSizeHuman; ?> (<?php echo number_format($fileSize); ?> bytes)</td>
                            </tr>
                            <tr>
                                <th>CRC32</th>
                                <td><?php echo $crc32hash; ?></td>
                            </tr>
                            <tr>
                                <th>MD5</th>
                                <td><?php echo $md5hash; ?></td>
                            </tr>
                            <tr>
                                <th>SHA-1</th>
                                <td><?php echo $sha1hash; ?></td>
                            </tr>
                        </tbody>
                    </table>
                </div>
                <a href="javascript:history.back()" class="btn btn-secondary mt-3">
                    <i class="fas fa-arrow-left"></i> Back
                </a>
            </div>
            <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.7/dist/js/bootstrap.bundle.min.js"></script>
        </body>
        </html>
        <?php
        exit;
    } else {
        header("HTTP/1.0 404 Not Found");
        echo "File not found or invalid.";
        exit;
    }
}

// =================== SET BROWSED DIRECTORY ===================
$self = basename($_SERVER['PHP_SELF']);
$totalFiles = 0;
$totalSize  = 0;
$currentDir = $browseDefault;
if ($browseDirectories && isset($_GET['folder'])) {
    $requested = sanitizePath($_GET['folder']);
    $requestedPath = $baseDir . DIRECTORY_SEPARATOR . $requested;
    
    // Enhanced symlink support
    if (is_link($requestedPath)) {
        $realPath = resolveSymlinkPath($requestedPath);
        if ($realPath && is_dir($realPath)) {
            $currentDir = $requested;
        }
    } else if (is_dir($requestedPath)) {
        $realPath = realpath($requestedPath);
        if ($realPath !== false && strpos($realPath, $baseDir) === 0) {
            $currentDir = $requested;
        }
    }
}
$displayDir = '/' . ltrim($currentDir, '/');

// =================== LIST DIRECTORY FUNCTION ===================
function listDirectory($path, $show_folders = false, $show_hidden = false) {
    global $totalFiles, $totalSize, $baseDir, $filesToHide, $dangerousExtensions;
    $items = [];
    $requestedPath = $baseDir . DIRECTORY_SEPARATOR . $path;
    
    // Enhanced symlink handling
    if (is_link($requestedPath)) {
        $fullPath = resolveSymlinkPath($requestedPath);
    } else {
        $fullPath = realpath($requestedPath);
    }
    
    if ($fullPath === false || !is_dir($fullPath)) {
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
        if (in_array($file, $filesToHide)) {
            continue;
        }
        if (!$show_hidden && substr($file, 0, 1) === '.') {
            continue;
        }
        
        $itemFullPath = $fullPath . DIRECTORY_SEPARATOR . $file;
        $isDir = is_dir($itemFullPath);
        
        if (!$isDir) {
            $ext = strtolower(pathinfo($file, PATHINFO_EXTENSION));
            if (in_array($ext, $dangerousExtensions)) {
                continue;
            }
        }
        
        $itemSize = $isDir ? 0 : @filesize($itemFullPath);
        $itemTime = @filemtime($itemFullPath);
        $stat = @stat($itemFullPath);
        $itemCreated = (isset($stat['birthtime']) && $stat['birthtime'] > 0)
                       ? $stat['birthtime']
                       : $itemTime;
        
        // Check if item is a symlink
        $isSymlink = is_link($fullPath . DIRECTORY_SEPARATOR . $file);
        
        $items[] = [
            'name'    => $file,
            'isDir'   => $isDir,
            'size'    => $itemSize ?: 0,
            'time'    => $itemTime ?: 0,
            'created' => $itemCreated ?: 0,
            'isSymlink' => $isSymlink
        ];
        
        if (!$isDir) {
            $totalFiles++;
            $totalSize += $itemSize ?: 0;
        }
    }
    return $items;
}
$items = listDirectory($currentDir, $showDirectories, $showHiddenFiles);

// =================== SORTING FILES & DIRECTORIES ===================
$sort  = isset($_GET['sort']) ? $_GET['sort'] : 'name';
$order = isset($_GET['order']) ? strtolower($_GET['order']) : 'asc';
usort($items, function($a, $b) use ($sort, $order, $showDirectoriesFirst) {
    if ($showDirectoriesFirst) {
        if ($a['isDir'] && !$b['isDir']) return -1;
        if (!$a['isDir'] && $b['isDir']) return 1;
    }
    $result = 0;
    switch ($sort) {
        case 'modified':
            $result = $a['time'] <=> $b['time'];
            break;
        case 'size':
            $result = $a['size'] <=> $b['size'];
            break;
        case 'name':
        default:
            $result = strcasecmp($a['name'], $b['name']);
            break;
    }
    return ($order === 'desc') ? -$result : $result;
});

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo sanitize_output(str_replace('{{path}}', $displayDir, $title)); ?> - File Browser</title>
    <meta name="description" content="Browse files and directories securely with hash verification support. Features include CRC32, MD5, SHA-1 checksums, responsive design, and enhanced security.">
    <meta name="keywords" content="file browser, directory listing, hash check, CRC32, MD5, SHA-1, secure browsing, responsive design">
    <meta name="author" content="ALSYUNDAWY IT SOLUTION">
    <meta name="robots" content="index, follow">
    <meta name="language" content="en">
    <meta name="revisit-after" content="7 days">
    <meta property="og:title" content="<?php echo sanitize_output(str_replace('{{path}}', $displayDir, $title)); ?>">
    <meta property="og:description" content="Secure file and directory browser with hash verification capabilities">
    <meta property="og:type" content="website">
    <meta property="og:url" content="<?php echo sanitize_output(getCanonicalURL()); ?>">
    <meta property="og:site_name" content="File Browser">
    <meta name="twitter:card" content="summary_large_image">
    <meta name="twitter:title" content="<?php echo sanitize_output(str_replace('{{path}}', $displayDir, $title)); ?>">
    <meta name="twitter:description" content="Secure file and directory browser">
    <link rel="canonical" href="<?php echo sanitize_output(getCanonicalURL()); ?>">
    <link rel="icon" href="favicon.ico" type="image/x-icon">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.7/dist/css/bootstrap.min.css">
    <link rel="stylesheet" href="https://unpkg.com/@fortawesome/fontawesome-free@6.7.2/css/all.min.css">
    <style>
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
    <div class="loading-screen" id="loadingScreen">
        <span class="spinner"></span>
        <div class="loading-text">LOADING ... DONT FORGET TO SAY "FUCK YOU RADIOSOFTWARE.ONLINE SERVER!</div>
    </div>
    
    <!-- Header -->
    <header>
        <div class="container text-center">
            <a href="?" title="Back to Home">
                <img src="logo.png" alt="File Browser Logo" loading="lazy">
            </a>
            <h1>File & Directory Browser</h1>
            <p class="text-muted mb-0">Menampilkan daftar file dan direktori yang tersedia.</p>
        </div>
    </header>
    
    <!-- Main Content -->
    <main class="container">
        <div class="page-header">
            <div class="page-title">
                <h2><?php echo sanitize_output(str_replace('{{path}}', $displayDir, $title)); ?></h2>
                <p class="page-subtitle">
                    <?php echo str_replace(
                        ['{{files}}', '{{size}}'],
                        [$totalFiles, humanizeFilesize($totalSize, $sizeDecimals)],
                        $subtitle
                    ); ?>
                </p>
            </div>
            <div class="search-container">
                <div class="search-input">
                    <input type="text" id="searchInput" placeholder="Search files..." autocomplete="off">
                    <i class="fas fa-search search-icon"></i>
                </div>
                <div class="sort-buttons">
                    <a href="?folder=<?php echo urlencode($currentDir); ?>&sort=name&order=<?php echo ($sort==='name' && $order==='asc') ? 'desc' : 'asc'; ?>" 
                       class="btn btn-outline-secondary btn-sm">
                        <i class="fas fa-sort-alpha-down"></i> Name
                    </a>
                    <a href="?folder=<?php echo urlencode($currentDir); ?>&sort=modified&order=<?php echo ($sort==='modified' && $order==='asc') ? 'desc' : 'asc'; ?>" 
                       class="btn btn-outline-secondary btn-sm">
                        <i class="fas fa-calendar-alt"></i> Date
                    </a>
                    <a href="?folder=<?php echo urlencode($currentDir); ?>&sort=size&order=<?php echo ($sort==='size' && $order==='asc') ? 'desc' : 'asc'; ?>" 
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
                        <?php if ($showParent && !empty($currentDir)):
                            $parentDir = dirname($currentDir);
                        ?>
                        <tr class="parent-row">
                            <td colspan="4">
                                <a href="?folder=<?php echo urlencode($parentDir); ?>" class="d-flex align-items-center">
                                    <i class="fas fa-arrow-up file-icon"></i> Parent Directory
                                </a>
                            </td>
                        </tr>
                        <?php endif; ?>
                        
                        <?php foreach ($items as $item):
                            $itemName = sanitize_output($item['name']);
                            $iconClass = $item['isDir'] ? 'fa-folder' : getFileIconClass($item['name']);
                            if ($item['isDir']) {
                                $link = '?folder=' . urlencode(trim($currentDir . '/' . $item['name'], '/'));
                            } else {
                                $link = sanitize_output(trim($currentDir . '/' . $item['name'], '/'));
                            }
                        ?>
                        <tr data-name="<?php echo strtolower($itemName); ?>">
                            <td class="col-name">
                                <a href="<?php echo $link; ?>" class="d-flex align-items-center">
                                    <i class="fas <?php echo $iconClass; ?> file-icon"></i>
                                    <span><?php echo $itemName; ?></span>
                                    <?php if ($item['isSymlink']): ?>
                                        <small class="symlink-badge" title="Symbolic Link">
                                            <i class="fas fa-link"></i>
                                        </small>
                                    <?php endif; ?>
                                </a>
                            </td>
                            <td class="col-date"><?php echo date('d-M-Y H:i', $item['time']); ?></td>
                            <td class="col-size"><?php echo $item['isDir'] ? '-' : humanizeFilesize($item['size'], $sizeDecimals); ?></td>
                            <td class="col-hash text-center">
                                <?php if (!$item['isDir']): ?>
                                    <a href="?md5=<?php echo urlencode(trim($currentDir . '/' . $item['name'], '/')); ?>" 
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
                <a href="https://alsyundawy.com" target="_blank" rel="noopener">
                    ALSYUNDAWY IT SOLUTION
                </a> 
                &copy; <?php echo date("Y"); ?> - All Rights Reserved
            </p>
        </div>
    </footer>
    
    <!-- Back to Top Button -->
    <div class="back-to-top" id="backToTop" title="Back to Top">
        <i class="fas fa-arrow-up"></i>
    </div>
    
    <!-- Scripts -->
    <script>
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
            
            setTimeout(() => {
                els.loading.classList.add('fade-out');
                setTimeout(() => els.loading.style.display = 'none', 300);
            }, loadTime);
            
            // Navigation flag
            document.querySelectorAll('a').forEach(link => {
                link.addEventListener('click', function(e) {
                    if (this.href && !this.target && !this.href.includes('#')) {
                        sessionStorage.setItem('isNavigating', 'true');
                    }
                });
            });
            
            window.addEventListener('beforeunload', () => {
                setTimeout(() => sessionStorage.removeItem('isNavigating'), 100);
            });
            
            // Back to Top
            let scrollTimeout;
            const toggleBackToTop = () => {
                els.backToTop.classList.toggle('show', window.scrollY > 300);
            };
            
            window.addEventListener('scroll', () => {
                clearTimeout(scrollTimeout);
                scrollTimeout = setTimeout(toggleBackToTop, 100);
            }, { passive: true });
            
            els.backToTop.addEventListener('click', () => {
                window.scrollTo({ top: 0, behavior: 'smooth' });
            });
            
            toggleBackToTop();
            
            // Search functionality
            if (els.searchInput && els.fileTable) {
                const tbody = els.fileTable.querySelector('tbody');
                const rows = Array.from(tbody.querySelectorAll('tr:not(.parent-row)'));
                let searchTimeout;
                
                const performSearch = () => {
                    const searchTerm = els.searchInput.value.toLowerCase().trim();
                    let visibleCount = 0;
                    
                    rows.forEach(row => {
                        const name = row.getAttribute('data-name');
                        if (!name) return;
                        
                        const isVisible = !searchTerm || name.includes(searchTerm);
                        row.classList.toggle('search-hidden', !isVisible);
                        if (isVisible) visibleCount++;
                    });
                    
                    els.noResults.classList.toggle('show', searchTerm && visibleCount === 0);
                };
                
                els.searchInput.addEventListener('input', () => {
                    clearTimeout(searchTimeout);
                    searchTimeout = setTimeout(performSearch, 150);
                });
                
                // Clear search on Escape
                els.searchInput.addEventListener('keydown', (e) => {
                    if (e.key === 'Escape') {
                        els.searchInput.value = '';
                        performSearch();
                    }
                });
            }
        })();
    </script>
</body>
</html>
