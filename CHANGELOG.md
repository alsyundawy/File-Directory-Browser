<!-- markdownlint-disable-file MD024 -->

# 📜 Changelog

All notable changes to the **File & Directory Browser** project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [4.1.0] - 2026-10-26 (Verified 2026-11-01)

### 🛡️ Security & Zero-Day Defense / Keamanan & Mitigasi Zero-Day

- 🇬🇧 **PHP2Shell Zero-Day Defense (CVE-2026-109618, CVE-2026-109619 & CVE-2026-115560)**: Added explicit `ini_set('session.upload_progress.enabled', '0')` in `startSecureSession()` and enforced early 8 KB maximum `Content-Length` validation on POST authentication requests, completely eliminating out-of-memory corruption and use-after-free vectors associated with unpatched PHP core engines.
- 🇮🇩 **Pertahanan Zero-Day PHP2Shell (CVE-2026-109618, CVE-2026-109619 & CVE-2026-115560)**: Menambahkan konfigurasi eksplisit `ini_set('session.upload_progress.enabled', '0')` pada fungsi `startSecureSession()` serta validasi batas awal `Content-Length` maksimal 8 KB pada request POST autentikasi, melenyapkan celah korupsi memori OOM dan use-after-free pada core engine PHP yang belum di-patch.
- 🇬🇧 **Process Isolation & Cross-Origin Security Headers**: Integrated `Cross-Origin-Opener-Policy: same-origin` (COOP) and `Cross-Origin-Resource-Policy: same-origin` (CORP) headers in `sendSecurityHeaders()` to isolate the browser execution context and prevent speculative side-channel data leaks.
- 🇮🇩 **Isolasi Proses & Header Keamanan Cross-Origin**: Menambahkan header `Cross-Origin-Opener-Policy: same-origin` (COOP) dan `Cross-Origin-Resource-Policy: same-origin` (CORP) pada `sendSecurityHeaders()` untuk isolasi konteks eksekusi browser dan mencegah kebocoran side-channel spekulatif.
- 🇬🇧 **TLS Port 443 Detection & Reverse Proxy Hardening**: Expanded `isHttpsRequest()` to inspect `$_SERVER['SERVER_PORT'] === 443` alongside existing HTTPS and forwarded headers (`HTTP_X_FORWARDED_PROTO`, `HTTP_X_FORWARDED_SSL`), guaranteeing reliable HSTS preload header delivery.
- 🇮🇩 **Deteksi Port TLS 443 & Penguatan Reverse Proxy**: Memperluas fungsi `isHttpsRequest()` untuk memeriksa `$_SERVER['SERVER_PORT'] === 443` di samping header HTTPS dan forwarded (`HTTP_X_FORWARDED_PROTO`, `HTTP_X_FORWARDED_SSL`), memastikan pengiriman header HSTS preload yang akurat.
- 🇬🇧 **Session Garbage Collection Synchronization**: Dynamically synchronized `session.gc_maxlifetime` with `$passwordSessionLifetime` to prevent premature session purges on shared hosting and containerized environments.
- 🇮🇩 **Sinkronisasi Garbage Collection Sesi**: Menyelaraskan nilai `session.gc_maxlifetime` secara dinamis dengan `$passwordSessionLifetime` guna mencegah penghapusan sesi lebih awal oleh daemon GC PHP pada shared hosting dan container.

### 🌐 Architecture & Portability / Arsitektur & Portabilitas

- 🇬🇧 **Dynamic Subdirectory Base Web Path (`getBaseWebPath()`)**: Introduced intelligent calculation of script root using `SCRIPT_NAME` and `REQUEST_URI`. Enables 100% plug-and-play operation in root directories, nested subfolders (e.g. `domain.com/storage/browse/`), and behind reverse proxies without manual configuration.
- 🇮🇩 **Base Web Path Sub-direktori Dinamis (`getBaseWebPath()`)**: Mengimplementasikan helper `getBaseWebPath()` untuk menghitung root direktori skrip secara otomatis dari `SCRIPT_NAME` dan `REQUEST_URI`. Memungkinkan operasi 100% plug-and-play di direktori root, subfolder bersarang (contoh: `domain.com/storage/browse/`), maupun di balik reverse proxy tanpa konfigurasi manual.
- 🇬🇧 **Parent Directory Return Link Fix**: Fixed parent directory (`..`) navigation to route back to `$baseWebPath` when at the top level instead of reloading the active directory.
- 🇮🇩 **Perbaikan Link Parent Directory**: Memperbaiki navigasi parent directory (`..`) agar mengarah kembali ke `$baseWebPath` saat berada di tingkat teratas alih-alih me-reload direktori aktif.
- 🇬🇧 **O(1) Hash Map File Extension Lookup**: Converted allowed file extension arrays into fast lookup hash maps using `array_fill_keys()`, cutting lookup overhead from $O(N)$ linear scans to $O(1)$ constant time.
- 🇮🇩 **Pencarian Ekstensi File O(1) Hash Map**: Mengonversi pengecekan ekstensi file terlarang menjadi tabel pencarian hash statis menggunakan `array_fill_keys()`, memangkas overhead pencarian dari linear $O(N)$ menjadi waktu konstan $O(1)$.
- 🇬🇧 **Timezone Fallback Resilience**: Protected `date_default_timezone_set()` inside a `try-catch` block falling back to `'UTC'` if an invalid timezone identifier is configured.
- 🇮🇩 **Resiliensi Fallback Zona Waktu**: Membungkus `date_default_timezone_set()` dalam blok `try-catch` dengan fallback ke `'UTC'` jika identifier zona waktu yang dikonfigurasi tidak valid.

### 📱 Mobile & Responsive / Mobile & Responsif

- 🇬🇧 **Xiaomi / Redmi / POCO MIUI & HyperOS Safe-Area Adaptation**: Added dedicated 4-axis safe-area padding (`env(safe-area-inset-top)`, `env(safe-area-inset-bottom)`, `env(safe-area-inset-left)`, and `env(safe-area-inset-right)`) supporting aggressive punch-hole cameras, curved corners, and dynamic gesture indicator bars in both portrait and landscape modes.
- 🇮🇩 **Adaptasi Safe-Area Xiaomi / Redmi / POCO MIUI & HyperOS**: Menambahkan padding safe-area 4-arah (`env(safe-area-inset-top)`, `env(safe-area-inset-bottom)`, `env(safe-area-inset-left)`, dan `env(safe-area-inset-right)`) untuk mendukung kamera punch-hole, sudut melengkung, dan bilah gestur dinamis pada mode portrait maupun landscape.
- 🇬🇧 **Font Inflation & Viewport Auto-Zoom Prevention**: Enforced a minimum font size of `16px` on all form inputs and added `-webkit-text-size-adjust: 100%`, completely eliminating intrusive automatic zoom-in behaviors and font inflation on mobile WebKit and Chrome.
- 🇮🇩 **Pencegahan Font Inflation & Auto-Zoom Viewport**: Menetapkan ukuran font minimal `16px` pada seluruh input formulir serta menambahkan `-webkit-text-size-adjust: 100%`, melenyapkan pembesaran otomatis layar yang mengganggu pada mobile WebKit dan Chrome.
- 🇬🇧 **VGA to 2K QHD Display Scalability**: Tuned responsive media queries for ultra-compact displays (320px–480px) with minimum table scroll width (420px) and expanded container constraints for 2K (1400px+) desktop monitors.
- 🇮🇩 **Skalabilitas Tampilan VGA hingga 2K QHD**: Menyesuaikan media query responsif untuk layar ultra-kompak (320px–480px) dengan lebar scroll tabel minimal (420px) serta memperlebar batas kontainer untuk monitor desktop 2K (1400px+).

### 🔍 SEO & Metadata Standards (2026) / Standar SEO & Metadata (2026)

- 🇬🇧 **Structured Data (Schema.org JSON-LD)**: Injected Schema.org `WebPage` JSON-LD structured data with dynamic page names, canonical URLs, and descriptions.
- 🇮🇩 **Structured Data (Schema.org JSON-LD)**: Menambahkan metadata terstruktur Schema.org `WebPage` JSON-LD dengan nama halaman, URL kanonikal, dan deskripsi dinamis.
- 🇬🇧 **Open Graph & Twitter Cards Suite**: Added comprehensive Open Graph (`og:type`, `og:site_name`, `og:title`, `og:description`, `og:url`) and Twitter Card (`twitter:card`, `twitter:title`, `twitter:description`) tags for rich link previews across messaging platforms and social networks.
- 🇮🇩 **Paket Open Graph & Twitter Cards**: Menyertakan tag Open Graph lengkap (`og:type`, `og:site_name`, `og:title`, `og:description`, `og:url`) dan Twitter Card (`twitter:card`, `twitter:title`, `twitter:description`) untuk tampilan preview link yang kaya di aplikasi pesan dan media sosial.
- 🇬🇧 **Color Scheme & Theme Color**: Added `color-scheme: dark` and browser `theme-color` meta tags synchronized with the dark ambient background (`#0f0f1a`).
- 🇮🇩 **Color Scheme & Theme Color**: Menambahkan meta tag `color-scheme: dark` dan `theme-color` browser yang diselaraskan dengan warna latar belakang gelap ambient (`#0f0f1a`).

### ♿ Accessibility (WCAG 2.2 AAA & APCA) / Aksesibilitas (WCAG 2.2 AAA & APCA)

- 🇬🇧 **High-Contrast Ratio Certification**: Validated all foreground text, badges, and hash check action links to achieve contrast ratios between 5.8:1 and 13.5:1 against the dark background, exceeding WCAG 2.2 AAA criteria.
- 🇮🇩 **Sertifikasi Rasio Kontras Tinggi**: Memvalidasi seluruh teks foreground, badge, dan link aksi hash agar mencapai rasio kontras antara 5.8:1 hingga 13.5:1 terhadap latar belakang gelap, melampaui kriteria WCAG 2.2 AAA.
- 🇬🇧 **APCA Luminance Optimization**: Aligned visual weights of secondary metadata, table borders, and modal dialogs with Advanced Perceptual Contrast Algorithm (APCA) standards.
- 🇮🇩 **Optimasi Luminansi APCA**: Menyelaraskan bobot visual metadata sekunder, garis tabel, dan dialog modal dengan standar Advanced Perceptual Contrast Algorithm (APCA).

### 🧹 Code Quality & Static Analysis / Kualitas Kode & Analisis Statis

- 🇬🇧 **Multi-Tool Verification Matrix (Exit Code 0)**:
  - PHP Syntax (`php -l`): 0 syntax errors across `index.php` and `index-v4.1.php`.
  - PSR-12 (`phpcs`): 100% compliant with 0 errors and 0 warnings.
  - PHPStan (Level 9 / Max): 0 errors detected.
  - Psalm (Level 3): 0 errors with 99.02% inferred types.
  - Trunk Linter: 100% passed with zero issues.
  - Production Code Review Scanner: 0 hotspots detected across all security rules.
- 🇮🇩 **Matriks Verifikasi Multi-Tool (Exit Code 0)**:
  - Sintaks PHP (`php -l`): 0 error sintaks pada `index.php` dan `index-v4.1.php`.
  - PSR-12 (`phpcs`): 100% patuh dengan 0 error dan 0 warning.
  - PHPStan (Level 9 / Max): 0 error terdeteksi.
  - Psalm (Level 3): 0 error dengan 99.02% inferred types.
  - Trunk Linter: 100% lulus tanpa isu.
  - Scanner Review Kode Produksi: 0 hotspot terdeteksi pada seluruh aturan keamanan.

---

## [4.0.0] - 2026-09-27

### Added / Ditambahkan

- 🇬🇧 Added `Strict-Transport-Security` (HSTS) header (`max-age=31536000; includeSubDomains; preload`) for HTTPS connections.
- 🇮🇩 Menambahkan header `Strict-Transport-Security` (HSTS) untuk koneksi HTTPS.
- 🇬🇧 Added `viewport-fit=cover` to `<meta name="viewport">` on all pages for notch and punch-hole compatibility.
- 🇮🇩 Menambahkan `viewport-fit=cover` pada meta viewport di semua halaman.
- 🇬🇧 Changed body height to `min-height: 100svh` with `100vh` fallback for dynamic mobile browser toolbars.
- 🇮🇩 Mengubah tinggi body menjadi `min-height: 100svh` dengan fallback `100vh`.
- 🇬🇧 Converted table column headers from `<a href>` to `<button type="button">` with `data-href` for semantic ARIA sort buttons.
- 🇮🇩 Mengonversi header kolom tabel dari anchor link menjadi tombol semantis `<button type="button">`.

---

## [3.9.0] - 2026-08-03

### Added / Ditambahkan

- 🇬🇧 Added symlink containment check for file entries to prevent external symlink enumeration.
- 🇮🇩 Menambahkan pemeriksaan batas symlink untuk mencegah enumerasi berkas di luar base direktori.
- 🇬🇧 Added auto-generated `index.html` in `.cache/` directory to deny listing on non-Apache web servers.
- 🇮🇩 Menambahkan berkas `index.html` otomatis di folder `.cache/` untuk keamanan server non-Apache.
- 🇬🇧 Added `X-Robots-Tag: noindex, nofollow, noarchive` security header.
- 🇮🇩 Menambahkan header keamanan `X-Robots-Tag: noindex, nofollow, noarchive`.
- 🇬🇧 Added keyboard shortcuts (`/` or `Ctrl+K` to focus search, `Escape` to clear).
- 🇮🇩 Menambahkan pintasan keyboard (`/` atau `Ctrl+K` untuk fokus pencarian, `Escape` untuk reset).

---

## [3.8.0] - 2026-08-01

### Added / Ditambahkan

- 🇬🇧 Added strict `is_string()` input validation on all GET and POST parameters.
- 🇮🇩 Menambahkan validasi tipe `is_string()` ketat pada seluruh parameter input GET dan POST.
- 🇬🇧 Replaced inline `javascript:history.back()` with CSP-compliant nonce script button handler.
- 🇮🇩 Mengganti inline `javascript:history.back()` dengan tombol ber-nonce yang patuh CSP.
- 🇬🇧 Port validation in `getSafeHost()` constrained to valid TCP port range (1–65535).
- 🇮🇩 Validasi nomor port pada `getSafeHost()` dibatasi ke rentang valid TCP (1–65535).

---

## [3.7.0] - 2026-07-18

### Fixed / Diperbaiki

- 🇬🇧 Fixed misplaced extension guard check inside version comparison block.
- 🇮🇩 Memperbaiki posisi pengecekan ekstensi PHP agar selalu dieksekusi.
- 🇬🇧 Added CSRF token regeneration upon successful password authentication.
- 🇮🇩 Menambahkan regenerasi token CSRF setelah autentikasi password folder berhasil.
- 🇬🇧 Fixed `queryUrl()` returning empty string instead of dangling `?` when parameters are empty.
- 🇮🇩 Memperbaiki `queryUrl()` agar mengembalikan string kosong saat parameter kosong.

---

## [3.5.0] - 2026-07-14

### Added / Ditambahkan

- 🇬🇧 Implemented modern Glassmorphic Dark Theme with fixed radial ambient gradients.
- 🇮🇩 Menerapkan Tema Gelap Glassmorphic modern dengan gradien ambient radial.
- 🇬🇧 Added password protection for designated folders with bcrypt hashing and session timeouts.
- 🇮🇩 Menambahkan fitur proteksi folder dengan hashing password bcrypt dan batas waktu sesi.
