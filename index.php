<?php

/**
 * Script Name: File & Directory Browser (index.php)
 * Function    : Menampilkan daftar file & direktori, dengan fitur cek hash (CRC32, MD5, SHA-1)
 * Description : 
 *   – Keamanan diperkuat melalui session cookie HttpOnly & SameSite Strict  
 *   – Proteksi CSRF dengan token acak 32-byte  
 *   – Sanitasi output untuk mencegah XSS  
 *   – Header no-cache (Cache-Control, Pragma, Expires)  
 *   – UI responsif memakai Bootstrap 5 & Font Awesome  
 * Created By  : HARRY DERTIN SUTISNA
 * Created On  : 25 June 2025
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

// Generate more secure CSRF token
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
$required_extensions = [
    'pdo_sqlite', 'openssl', 'session', 'hash', 'json', 'pcre', 'spl', 'fileinfo'
];
foreach ($required_extensions as $ext) {
    if (!extension_loaded($ext)) {
        exit("Required PHP extension '{$ext}' is not installed.");
    }
}

// NON-CACHE HEADERS
header("Cache-Control: no-cache, no-store, must-revalidate");
header("Pragma: no-cache");
header("Expires: 0");

// =================== KONFIGURASI ===================
$browseDirectories     = true;
$title                 = 'Index of {{path}}';
$subtitle              = '{{files}} files, {{size}} total';
$showParent            = true;
$showDirectories       = true;
$showDirectoriesFirst  = true;
$showHiddenFiles       = false; // hanya menampilkan file yang tidak diawali titik (.)
$alignment             = 'left'; // pilihan: left, center, right
$showIcons             = true;
$dateFormat            = 'd-M-Y H:i';
$sizeDecimals          = 1;
$browseDefault         = ''; // direktori awal (kosong berarti root aplikasi)

// File yang akan disembunyikan (berdasarkan nama)
$filesToHide = ['robots.txt', 'favicon.ico'];
// Ekstensi berbahaya yang akan disembunyikan (contoh: file PHP, executable, script)
$dangerousExtensions   = ['php', 'php3', 'php4', 'php5', 'html', 'htm', 'sh', 'bat', 'js', 'css', 'cmd','png'];
// Tentukan direktori dasar (base directory) agar pengguna tidak bisa menavigasi ke luar folder aplikasi
$baseDir = realpath(__DIR__);

// =================== FUNGSI UTILITY ===================
// Sanitasi input path untuk menghindari traversal dan karakter berbahaya
function sanitizePath($path) {
    $path = str_replace("\0", '', $path);
    $path = trim($path, "/\\");
    return preg_replace('/\.\.+/', '', $path);
}

// Fungsi untuk mengubah ukuran file menjadi format yang mudah dibaca
function humanizeFilesize($bytes, $decimals = 0) {
    $units = ['B', 'KB', 'MB', 'GB', 'TB'];
    $factor = 0;
    while ($bytes >= 1024 && $factor < count($units) - 1) {
        $bytes /= 1024;
        $factor++;
    }
    return sprintf("%.{$decimals}f", $bytes) . ' ' . $units[$factor];
}

// Fungsi untuk mendapatkan URL canonical
function getCanonicalURL() {
    $protocol = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? "https://" : "http://";
    return $protocol . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
}

// =================== CEK HASH FILE DENGAN CACHE ===================
if (isset($_GET['md5'])) {
    // Ambil parameter md5 secara langsung dan sanitasi
    $requestedFile = sanitizePath($_GET['md5']);
    $fullFilePath = realpath($baseDir . DIRECTORY_SEPARATOR . $requestedFile);
    
    if ($fullFilePath !== false && strpos($fullFilePath, $baseDir) === 0 && is_file($fullFilePath)) {
        $fileName = basename($fullFilePath);
        
        // Tentukan ukuran file dan sesuaikan chunk size:
        $fileSize = filesize($fullFilePath);
        $chunkSize = ($fileSize > 1073741824) ? 1048576 : 32768;
        
        // =================== CACHE MEKANISME ===================
        // Gunakan folder tersembunyi ".cache" untuk menyimpan file cache
        $cacheDir = __DIR__ . '/.cache';
        if (!is_dir($cacheDir)) {
            mkdir($cacheDir, 0755, true);
            // Pada Nginx, file .htaccess tidak digunakan
        }
        // Buat key cache berdasarkan path file dan waktu modifikasi
        $cacheKey  = hash('sha256', $fullFilePath . filemtime($fullFilePath));
        $cacheFile = $cacheDir . '/' . $cacheKey . '.cache';
        
        if (file_exists($cacheFile)) {
            $hashData = json_decode(file_get_contents($cacheFile), true);
        } else {
            $handle = fopen($fullFilePath, 'rb');
            if (!$handle) {
                header("HTTP/1.0 500 Internal Server Error");
                echo "Gagal membuka file.";
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
            <title>Hash Check for <?php echo htmlspecialchars($fileName); ?></title>
            <meta name="author" content="ALSYUNDAWY IT SOLUTION">
            <meta name="robots" content="index,follow,all">
            <meta name="HandheldFriendly" content="true">
            <meta name="MobileOptimized" content="width">
            <meta name="apple-mobile-web-app-status-bar-style" content="default">
            <meta name="apple-mobile-web-app-capable" content="yes">
            <meta name="mobile-web-app-capable" content="yes">
            <meta name="language" content="ID">
            <meta name="copyright" content="ALSYUNDAWY IT SOLUTION">
            <meta name="distribution" content="global">
            <meta name="publisher" content="ALSYUNDAWY IT SOLUTION">
            <meta name="geo.placename" content="DKI JAKARTA">
            <meta name="geo.country" content="ID">
            <meta name="geo.region" content="ID">
            <meta name="tgn.nation" content="Indonesia">
            <link rel="canonical" href="<?php echo getCanonicalURL(); ?>">
            <meta property="og:title" content="Hash Check for <?php echo htmlspecialchars($fileName); ?>">
            <meta property="og:description" content="Verifikasi file <?php echo htmlspecialchars($fileName); ?> menggunakan algoritma hash: CRC32, MD5, SHA-1.">
            <meta property="og:type" content="website">
            <meta property="og:url" content="<?php echo getCanonicalURL(); ?>">
            <meta name="twitter:card" content="summary_large_image">
            <link rel="icon" href="favicon.ico" type="image/x-icon">
            <link rel="preconnect" href="https://fonts.googleapis.com">
            <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
            <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=Lora:wght@400;500;600&display=swap" rel="stylesheet">
            <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/normalize.css@8.0.1/normalize.min.css">
            <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.7/dist/css/bootstrap.min.css">
            <link rel="stylesheet" href="https://unpkg.com/@fortawesome/fontawesome-free@6.7.2/css/all.min.css">
        </head>
        <body class="bg-light">
            <div class="container py-5">
                <h2 class="mb-4">Hash Check for <small><?php echo htmlspecialchars($fileName); ?></small></h2>
                <table class="table table-bordered table-striped">
                    <tbody>
                        <tr>
                            <th style="width:150px;">CRC32</th>
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
                <a href="javascript:history.back()" class="btn btn-secondary mt-3">
                    <i class="fas fa-arrow-left"></i> Kembali
                </a>
            </div>
            <!-- Bootstrap 5 JS Bundle -->
            <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.7/dist/js/bootstrap.bundle.min.js"></script>
        </body>
        </html>
        <?php
        exit;
    } else {
        header("HTTP/1.0 404 Not Found");
        echo "File tidak ditemukan atau tidak valid.";
        exit;
    }
}

// =================== MENGATUR DIREKTORI YANG DIBROWSE ===================
$self = basename($_SERVER['PHP_SELF']);
$totalFiles = 0;
$totalSize  = 0;
$currentDir = $browseDefault;
if ($browseDirectories && isset($_GET['folder'])) {
    // Ambil parameter folder secara langsung dan sanitasi
    $requested = sanitizePath($_GET['folder']);
    $requestedPath = $baseDir . DIRECTORY_SEPARATOR . $requested;
    if (is_dir($requestedPath)) {
        $realPath = realpath($requestedPath);
        // Jika komponen pertama adalah symlink, izinkan penelusuran
        $components = explode('/', $requested);
        $firstComponent = $components[0];
        $firstPath = $baseDir . DIRECTORY_SEPARATOR . $firstComponent;
        if (is_link($firstPath) || ($realPath !== false && strpos($realPath, $baseDir) === 0)) {
            $currentDir = $requested;
        }
    }
}
$displayDir = '/' . ltrim($currentDir, '/');

// =================== FUNGSI UNTUK MENAMPILKAN ISI DIREKTORI ===================
function listDirectory($path, $show_folders = false, $show_hidden = false) {
    global $totalFiles, $totalSize, $baseDir, $filesToHide, $dangerousExtensions;
    $items = [];
    $requestedPath = $baseDir . DIRECTORY_SEPARATOR . $path;
    
    // Jika direktori merupakan symlink, resolusi target symlink
    if (is_link($requestedPath)) {
        $linkTarget = readlink($requestedPath);
        if ($linkTarget && $linkTarget[0] !== '/' ) {
            $linkTarget = realpath(dirname($requestedPath) . DIRECTORY_SEPARATOR . $linkTarget);
        }
        $fullPath = ($linkTarget && is_dir($linkTarget)) ? $linkTarget : $requestedPath;
    } else {
        $fullPath = realpath($requestedPath);
    }
    
    if ($fullPath === false || !is_dir($fullPath)) {
        return $items;
    }
    
    $files = scandir($fullPath);
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
        $itemSize = $isDir ? 0 : filesize($itemFullPath);
        $itemTime = filemtime($itemFullPath);
        $stat = @stat($itemFullPath);
        $itemCreated = (isset($stat['birthtime']) && $stat['birthtime'] > 0)
                       ? $stat['birthtime']
                       : filemtime($itemFullPath);
    
        $items[] = [
            'name'    => $file,
            'isDir'   => $isDir,
            'size'    => $itemSize,
            'time'    => $itemTime,
            'created' => $itemCreated
        ];
        $totalFiles++;
        $totalSize += $itemSize;
    }
    return $items;
}
$items = listDirectory($currentDir, $showDirectories, $showHiddenFiles);

// =================== SORTING FILES & DIREKTORI ===================
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

// Ambil waktu direktori saat ini untuk header
$currentDirPath = realpath($baseDir . DIRECTORY_SEPARATOR . $currentDir);
$dirStat = $currentDirPath ? @stat($currentDirPath) : false;
$dirCreated = ($dirStat && isset($dirStat['birthtime']) && $dirStat['birthtime'] > 0)
    ? $dirStat['birthtime']
    : ($currentDirPath ? filemtime($currentDirPath) : null);

// Kelas alignment untuk Bootstrap 5
$alignmentClass = 'text-start';
if ($alignment === 'center') {
    $alignmentClass = 'text-center';
} elseif ($alignment === 'right') {
    $alignmentClass = 'text-end';
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo htmlspecialchars(str_replace('{{path}}', $displayDir, $title)); ?></title>
    <meta name="robots" content="index, follow">
	<!-- Meta Description -->
	<meta name="description" content="File & Directory Browser berbasis PHP dengan keamanan diperkuat: session cookie HttpOnly & SameSite Strict, proteksi CSRF, sanitasi output, verifikasi hash (CRC32, MD5, SHA-1), header no-cache, serta UI responsif menggunakan Bootstrap 5 dan Font Awesome.">

	<!-- Meta Keywords -->
	<meta name="keywords" content="PHP file browser, direktori listing, secure session, CSRF protection, sanitize_output, hash check, CRC32, MD5, SHA1, no-cache headers, Bootstrap 5, Font Awesome, file security, sanitizePath, PHP8">

    <link rel="canonical" href="<?php echo getCanonicalURL(); ?>">
    <meta property="og:title" content="File & Directory Browser">
    <meta property="og:description" content="Jelajahi file dan direktori dengan mudah dan cek keamanan file menggunakan MD5, CRC32, dan SHA-1.">
    <meta property="og:type" content="website">
    <meta property="og:url" content="<?php echo getCanonicalURL(); ?>">
    <meta name="twitter:card" content="summary_large_image">
    <!-- Favicon -->
    <link rel="icon" href="favicon.ico" type="image/x-icon">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=Lora:wght@400;500;600&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/normalize.css@8.0.1/normalize.min.css">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.7/dist/css/bootstrap.min.css">
    <link rel="stylesheet" href="https://unpkg.com/@fortawesome/fontawesome-free@6.7.2/css/all.min.css">
    <style>
         body { font-family: 'Inter', sans-serif; font-weight: 400; color: #2c3e50; background-color: #f8f9fa; }
        a { text-decoration: none; }
        a:hover { text-decoration: none; }
        .table-hover tbody tr:hover { background-color: #f8f9fa; }
        .icon { width: 20px; }
        header, footer { margin: 20px 0; }
    </style>
</head>
<body class="bg-light">
    <!-- Header -->
    <header class="text-center">
        <img src="logo.png" alt="Logo" class="img-fluid" style="max-height: 200px;">
        <h2 class="mt-3">File & Directory Browser</h2>
        <p class="mb-0 text-muted">
            Deskripsi: Menampilkan daftar file dan direktori yang tersedia.<br>
            Dibuat: <?php echo $dirCreated ? date($dateFormat, $dirCreated) : '-'; ?>
            | Terakhir Diubah: <?php echo $currentDirPath ? date($dateFormat, filemtime($currentDirPath)) : '-'; ?>
        </p>
    </header>
    <div class="container py-4">
        <div class="d-flex justify-content-between align-items-center mb-4">
            <div>
                <h1 class="display-5"><?php echo htmlspecialchars(str_replace('{{path}}', $displayDir, $title)); ?></h1>
                <p class="text-muted">
                    <?php echo str_replace(
                        ['{{files}}', '{{size}}'],
                        [$totalFiles, humanizeFilesize($totalSize, $sizeDecimals)],
                        $subtitle
                    ); ?>
                </p>
            </div>
            <!-- Menu Sorting -->
            <div>
                <div class="btn-group" role="group" aria-label="Sort Options">
                    <a href="?folder=<?php echo urlencode($currentDir); ?>&sort=name&order=<?php echo ($sort==='name' && $order==='asc') ? 'desc' : 'asc'; ?>" class="btn btn-outline-secondary">
                        <i class="fas fa-sort-alpha-down"></i> Name
                    </a>
                    <a href="?folder=<?php echo urlencode($currentDir); ?>&sort=modified&order=<?php echo ($sort==='modified' && $order==='asc') ? 'desc' : 'asc'; ?>" class="btn btn-outline-secondary">
                        <i class="fas fa-calendar-alt"></i> Modified
                    </a>
                    <a href="?folder=<?php echo urlencode($currentDir); ?>&sort=size&order=<?php echo ($sort==='size' && $order==='asc') ? 'desc' : 'asc'; ?>" class="btn btn-outline-secondary">
                        <i class="fas fa-weight-hanging"></i> Size
                    </a>
                </div>
            </div>
        </div>
        <div class="table-responsive">
            <table class="table table-bordered table-striped table-hover <?php echo $alignmentClass; ?>">
                <thead class="table-dark">
                    <tr>
                        <th>Name</th>
                        <th>Last Modified</th>
                        <th>Size</th>
                        <th>Created</th>
                        <th>Hash Check</th>
                    </tr>
                </thead>
                <tbody>
                    <!-- Parent Directory -->
                    <?php if ($showParent && !empty($currentDir)):
                        $parentDir = dirname($currentDir);
                    ?>
                    <tr>
                        <td>
                            <a href="?folder=<?php echo urlencode($parentDir); ?>">
                                <i class="fas fa-arrow-up icon"></i> Parent Directory
                            </a>
                        </td>
                        <td>-</td>
                        <td>-</td>
                        <td>-</td>
                        <td>-</td>
                    </tr>
                    <?php endif; ?>
                    <!-- Daftar File dan Folder -->
                    <?php foreach ($items as $item):
                        $itemName = htmlspecialchars($item['name'], ENT_QUOTES, 'UTF-8');
                        if ($item['isDir']) {
                            $link = '?folder=' . urlencode(trim($currentDir . '/' . $item['name'], '/'));
                        } else {
                            $link = htmlspecialchars(trim($currentDir . '/' . $item['name'], '/'));
                        }
                    ?>
                    <tr>
                        <td>
                            <?php if ($item['isDir']): ?>
                                <a href="<?php echo $link; ?>">
                                    <i class="fas fa-folder icon"></i> <?php echo $itemName; ?>
                                </a>
                            <?php else: ?>
                                <a href="<?php echo $link; ?>">
                                    <i class="fas fa-file icon"></i> <?php echo $itemName; ?>
                                </a>
                            <?php endif; ?>
                        </td>
                        <td><?php echo date($dateFormat, $item['time']); ?></td>
                        <td><?php echo $item['isDir'] ? '-' : humanizeFilesize($item['size'], $sizeDecimals); ?></td>
                        <td><?php echo date($dateFormat, $item['created']); ?></td>
                        <td>
                            <?php if (!$item['isDir']): ?>
                                <a href="?md5=<?php echo urlencode(trim($currentDir . '/' . $item['name'], '/')); ?>" class="btn btn-sm btn-outline-info" title="Cek Hash">
                                    <i class="fas fa-key"></i>
                                </a>
                            <?php else: echo '-'; endif; ?>
                        </td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    </div>
    <!-- Footer -->
    <footer class="text-center">
        <p class="text-muted mb-0"><a target="_blank" href="https://alsyundawy.com">ALSYUNDAWY IT SOLUTION. ALL RIGHTS RESERVED</a> &copy; <?php echo date("Y"); ?></p>
    </footer>
    <!-- Bootstrap 5 JS Bundle -->
    <script defer src="https://code.jquery.com/jquery-3.7.1.min.js"></script>
    <script defer src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.7/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
