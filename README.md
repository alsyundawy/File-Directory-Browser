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

## Bahasa Indonesia

**File & Directory Browser** adalah script PHP tunggal (*single-file PHP script*) yang aman, responsif, dan sangat ringan untuk menampilkan daftar file serta direktori. Dilengkapi dengan fitur pengurutan instan, pencarian real-time tanpa reload halaman, verifikasi hash file (CRC32, MD5, SHA-1) menggunakan sistem cache lokal, perlindungan ketat dari eksploitasi path traversal, proteksi folder berbasis password dengan bcrypt hashing, serta antarmuka modern bertema *glassmorphic* berbasis Bootstrap 5 dan Font Awesome 6.

## English

**File & Directory Browser** is a security-hardened, highly responsive, and lightweight single-file PHP script designed to display file and directory lists. It features real-time search without reloading, instant sorting, file hash verification (CRC32, MD5, SHA-1) with a local caching mechanism, strict protection against path traversal attacks, bcrypt-secured password-protected folders, and a premium glassmorphic user interface built using Bootstrap 5 and Font Awesome 6.

---

## User Interface

### New

![New UI](https://github.com/user-attachments/assets/ec10a8d2-662d-4aac-a1a1-14a6178b86bb)

### Old

![Premium Glassmorphic Dark UI](https://github.com/user-attachments/assets/fdebf249-6bf7-4d49-806b-6399432c9d9d)

---

## Fitur Utama / Key Features

### 🇮🇩 Bahasa Indonesia

- 🔒 **Keamanan Kelas Enterprise:**
  - Proteksi Path Traversal tingkat lanjut dengan normalisasi path segment dan verifikasi canonical path.
  - Pembatasan Symlink eksternal secara default untuk mencegah akses di luar direktori utama.
  - Header Keamanan Lengkap (Content-Security-Policy berbasis nonce, Referrer-Policy, Frame-Options, X-Content-Type-Options).
  - Cookie Sesi dengan konfigurasi `HttpOnly`, `SameSite=Strict`, dan `Secure` flag.
  - Proteksi folder `.cache` otomatis menggunakan file `.htaccess` berisi larangan akses publik.
  - **Proteksi Folder dengan Password** menggunakan bcrypt (`password_hash` / `password_verify`) — password tidak pernah disimpan plaintext.
  - CSRF protection pada form login folder, menggunakan token acak `random_bytes(32)`.
- ⚡ **Sistem Caching Hash Pintar:** Menghitung hash file (CRC32, MD5, SHA-1) hanya saat diperlukan dan menyimpannya ke cache lokal secara aman berbasis ukuran file, waktu modifikasi (*mtime*), dan versi cache.
- 🔍 **Pencarian Real-Time & Sortir Instan:** Cari nama file secara instan menggunakan JavaScript dan urutkan daftar file berdasarkan Nama, Tanggal, atau Ukuran secara cepat tanpa merusak rendering layout.
- 🎨 **Antarmuka Premium & Aksesibilitas:** Desain Glassmorphic dengan dukungan Dark/Light Mode, ikon file berkode warna dinamis, layout responsif penuh, tombol Back-to-Top, dan **floating Home FAB button** yang ramah aksesibilitas keyboard (a11y).
- ⚙️ **CSS Minified:** Seluruh CSS inline di-minify untuk performa loading halaman yang lebih cepat.

### 🇬🇧 English

- 🔒 **Enterprise-Grade Security:**
  - Advanced Path Traversal protection featuring path segment normalization and canonical path verification.
  - Disabled external symlinks by default to prevent file access leaks outside the root directory.
  - Robust Security Headers (Nonce-based Content-Security-Policy, Referrer-Policy, Frame-Options, X-Content-Type-Options).
  - Session Cookies configured with `HttpOnly`, `SameSite=Strict`, and `Secure` attributes.
  - Automatic creation of a protected `.cache` directory featuring auto-generated `.htaccess` public denial access.
  - **Password-Protected Folders** secured with bcrypt (`password_hash` / `password_verify`) — passwords are never stored in plaintext.
  - CSRF protection on the folder login form using `random_bytes(32)` tokens.
- ⚡ **Smart Hash Caching System:** Computes file checksums (CRC32, MD5, SHA-1) on demand and securely caches results locally using file size, modified time (*mtime*), and cache-version checks.
- 🔍 **Real-Time Search & Instant Sorting:** Instantly filter file listings via client-side JavaScript, and sort them seamlessly by Name, Date, or Size without breaking the visual grid.
- 🎨 **Premium UI & Accessibility:** A stunning Glassmorphic layout with Dark/Light Mode toggle, color-coded file type icons, responsive viewport scaling, Back-to-Top button, and a **floating Home FAB button** — all keyboard-accessible (a11y).
- ⚙️ **Minified Inline CSS:** All inline stylesheets are minified for faster page load performance.

---

## Persyaratan / Requirements

| Layanan / Requirement | Versi Minimum / Minimum Version |
| :--- | :--- |
| **PHP** | `8.0` atau lebih baru / or newer |
| **PHP Extensions** | `session`, `hash`, `json`, `pcre`, `spl` |
| **Web Server** | Apache (direkomendasikan / recommended), Nginx, Lighttpd, dll |

---

## Konfigurasi / Configuration

Buka file `index.php` untuk menyesuaikan setelan variabel berikut di bagian paling atas:

```php
$browseDirectories      = true;                  // Mengizinkan penelusuran sub-direktori
$title                  = 'Index of {{path}}';   // Format judul halaman utama
$subtitle               = '{{files}} files';     // Format sub-judul halaman
$showDirectories        = true;                  // Menampilkan direktori
$showDirectoriesFirst   = true;                  // Mengurutkan direktori di posisi atas
$showHiddenFiles        = false;                 // Menyembunyikan/menampilkan file dot (.)
$dateFormat             = 'd-M-Y H:i';           // Format tanggal modifikasi file
$allowExternalSymlinks  = false;                 // Mengizinkan symlink ke luar root
$enableHashCache        = true;                  // Mengaktifkan penyimpanan cache hash file
$passwordSessionLifetime = 2400;                 // Durasi sesi login folder (detik)
```

### Konfigurasi Proteksi Folder / Folder Password Configuration

```php
// Generate bcrypt hash terlebih dahulu:
// php -r "echo password_hash('password_anda', PASSWORD_BCRYPT);"

$protectedFolders = [
    'nama-folder' => '$2y$12$hashBcryptAnda...',
];
```

> **⚠️ PENTING:** Jangan pernah menyimpan password plaintext. Selalu gunakan hasil `password_hash()`.

---

## Riwayat Perubahan / Changelog

### Version 3.5 (14 Juli 2026 / July 14, 2026) — Premium Glassmorphic Dark Theme & Style Customization

- **🎨 UI/UX — Premium Glassmorphic Dark Theme:**
  - Mengimplementasikan tema *Premium Glassmorphic Dark* modern dengan latar belakang *radial-gradient* tetap yang indah dan elegan.
  - Implemented a modern Premium Glassmorphic Dark Theme featuring a beautiful fixed radial-gradient background.
- **🎨 UI/UX — Custom Link & Icon Styling:**
  - Menyesuaikan gaya tautan folder/file dan ikon di mode terang maupun gelap sesuai spesifikasi desain.
  - Custom-styled folder/file links and icons in both Light and Dark modes to match design specifications.
- **🎨 UI/UX — Breadcrumb Open Folder Icon:**
  - Mengintegrasikan ikon folder terbuka (`fa-folder-open`) pada navigasi breadcrumb, sekaligus mempertahankan ikon folder tertutup standar pada tampilan daftar untuk konsistensi visual.
  - Integrated the open folder icon (`fa-folder-open`) in breadcrumb navigation while retaining standard closed folder icons in the file list view for visual consistency.
- **📱 UI/UX — Mobile Responsiveness:**
  - Mengoptimalkan *media query* mobile untuk memperkecil seluruh teks, padding, dan elemen header agar tampilan sangat kompak dan responsif di semua resolusi perangkat.
  - Optimized mobile media queries to scale down all text, paddings, and header elements for a highly compact and responsive layout across all device resolutions.
- **🐛 Bug Fix — Infinite 301 Redirect Loop:**
  - Memperbaiki loop redirect 301 tak terbatas pada parameter folder berlapis yang mengandung karakter `%2F` (slash ter-encode) yang sebelumnya menyebabkan *spinner loader* tidak berhenti.
  - Resolved an infinite 301 redirect loop on nested folder parameters containing URL-encoded slashes (`%2F`) which previously caused the spinner loader to get stuck indefinitely.

### Version 3.4 (14 Juli 2026 / July 14, 2026) — URL Sanitizer, Rate-Limit, Quality Audits & UI Enhancement

- **🔒 Security, Quality Audits & Rate-Limiting:**
  - Menambahkan pembatasan percobaan login salah (`$loginMaxAttempts = 5`) dan durasi penguncian login (`$loginLockSeconds = 300`) untuk proteksi folder dengan tampilan hitung mundur (countdown) secara real-time.
  - Memperbaiki kualitas kode dan menghilangkan peringatan IDE dengan menyederhanakan struktur logic `if` bersarang yang redundan.
  - Memindahkan `ob_end_flush()` dari bagian akhir skrip ke `register_shutdown_function()` terpusat agar buffer selalu dibilas secara otomatis dan aman saat skrip berakhir.
  - Added brute-force/rate-limit protection to folder passwords using login attempt limits (`$loginMaxAttempts = 5`) and temporary lockout timers (`$loginLockSeconds = 300`) with real-time countdown display.
  - Merged nested conditional `if` statements to resolve code analyzer warnings.
  - Relocated `ob_end_flush()` to a centralized `register_shutdown_function()` to ensure proper output buffer cleaning upon termination.
- **⚡ Performance Optimization:**
  - Melakukan minifikasi (*minify*) pada seluruh kode JavaScript internal (termasuk modul peralihan tema, hitung mundur penguncian, pencarian, dan visual halaman) untuk memperkecil ukuran berkas dan meningkatkan kecepatan muat.
  - Minified all internal JavaScript blocks (Theme Switchers, Lock Countdown, Search and lists controller) to minimize payload size and improve execution speed.
- **🎨 UI/UX & Dark Mode Contrast Fix:**
  - Memperbaiki tulisan buram pada halaman Hash Check di mode gelap dengan menetapkan warna teks `h2` menggunakan `var(--text-primary)` dan `.text-muted`/`.text-secondary` agar kontras dan terbaca jelas.
  - Resolved blurry text styling in dark mode on the Hash Check page by setting `h2` heading color via `var(--text-primary)` and updating `.text-muted`/`.text-secondary` rules to use crisp high-contrast colors.
- **🔗 Clean URL Routing:**
  - Mengubah parameter query penelusuran folder dari `folder` menjadi `berkas`.
  - Menghapus segment `index.php` pada URL serta mengarahkan otomatis (HTTP 301) permintaan lama `/index.php?folder=XXX` menjadi `/?berkas=XXX` untuk SEO dan navigasi yang lebih bersih.
  - Swapped directory browsing query parameter from `folder` to `berkas`.
  - Stripped `index.php` path segment from URLs and implemented automatic redirects (HTTP 301) from `/index.php?folder=XXX` to `/?berkas=XXX` for cleaner SEO routing.
  - Mengubah penanganan routing agar karakter `%2F` dalam parameter query `berkas` otomatis diterjemahkan kembali menjadi `/` (`?berkas=folder1/subfolder1`), dan mengarahkan otomatis jika diakses dengan format URL-encoded.
  - Decoded `%2F` in query parameters back to slashes to display clean folder paths (e.g. `?berkas=folder1/subfolder1`), redirecting requests containing URL-encoded `%2F` to clean slash representations.
- **✨ Modern Hash Check UI & Clipboard Support:**
  - Merancang ulang tampilan pengecekan hash (CRC32, MD5, SHA-1) dengan kotak/card yang lebih ringkas dan ramping, ikon perisai yang elegan, serta menambahkan tombol salin cepat (Copy to Clipboard) yang interaktif dan sepenuhnya patuh terhadap kebijakan CSP (Content-Security-Policy).
  - Modernized the Hash Check overlay with a narrower card layout, elegant shield badge styling, and CSP-compliant, one-click clipboard copying buttons with visual success feedback.
- **Footer Encoding Fix:**
  - Memperbaiki pengkodean karakter hak cipta pada footer (`&copy; 2009&ndash;2026 &middot; All Rights Reserved`) guna menghindari kendala rendering simbol di berbagai tipe browser.
  - Replaced copyright character symbols in the footer with robust HTML entities to prevent font encoding glitches.
- **✨ Sorting Interactive Improvement:**
  - Menghilangkan visual terpilih/aktif (default selection state) pada tombol sortir secara bawaan. Pilihan sort hanya akan aktif jika diklik secara eksplisit, dan cukup menampilkan hover style saat disorot saja.
  - Removed default highlighted/active selection state from sorting buttons. Active highlight only appears upon explicit query sort requests; otherwise, buttons display standard interactive hover effects.
- **🛠️ Font Awesome Maintenance:**
  - Menyederhanakan pemetaan ikon Font Awesome dengan memusatkan seluruh relasi ekstensi file ke dalam satu struktur array statis di fungsi `getFileIconClass()`, menghapus 6 sub-fungsi pendukung untuk mempermudah pemeliharaan kode jangka panjang.
  - Consolidated and simplified Font Awesome mappings into a single static array in `getFileIconClass()`, removing six helper subfunctions to maximize readability and ease of maintenance.

### Version 3.3 (13 Juli 2026 / July 13, 2026) — Strict CSP Compliance, Readability Overhaul & Clean Layout

- **🔒 Security & CSP Hardening:**
  - Menghilangkan seluruh sisa atribut inline `style="..."` pada elemen HTML (`#search-form-container`, `#fileTable`, dan tag `<col>`) untuk kepatuhan 100% terhadap Content Security Policy (CSP) tanpa `'unsafe-inline'`.
  - Memperbaiki style tag di dalam block `<noscript>` dengan menyematkan nonce-key CSP secara dinamis.
  - Mengganti manipulasi style `.cssText` di JavaScript menjadi modifikasi properti style individual guna mencegah pemblokiran CSP.
  - Removed all remaining inline `style="..."` attributes on HTML tags (`#search-form-container`, `#fileTable`, and `<col>` elements) to achieve 100% CSP compliance without relying on `'unsafe-inline'`.
  - Added dynamic CSP nonce value to the style tag within the `<noscript>` block.
  - Rewrote JavaScript `.cssText` manipulation to use individual style property settings instead, avoiding CSP style-src blocks.
- **🎨 UI/UX & Light Mode Contrast Enhancement:**
  - Mengoptimalkan warna kontras tinggi pada Light Mode agar menyerupai `repo.alsyundawy.com` — tulisan tajam, terang, tidak buram, dan ramah mata.
  - Memperbaiki transisi warna pada mode gelap (Dark Mode) agar teks utama dan sekunder tidak buram dan sakit mata.
  - Penyelarasan posisi tombol Back-to-Top dan Home FAB button di sisi kanan bawah agar presisi, mudah dijangkau, dan tidak terlalu ke bawah.
  - Optimized Light Mode contrast to match the design aesthetics of `repo.alsyundawy.com` — featuring high readability, crisp text, and zero eye-strain.
  - Hardened text and color contrast in Dark Mode to ensure high legibility and eliminate blurry fonts.
  - Aligned the Back-to-Top and Home FAB button coordinates on the bottom-right for clean, non-overlapping floating layouts.
- **🐛 Bug Fix:**
  - Memperbaiki tombol kembali pada halaman verifikasi hash agar berfungsi dengan baik di bawah aturan CSP strict.
  - Fixed the back-to-listing button on the file hash verification page to function correctly under strict CSP headers.

### Version 3.2 (13 Juli 2026 / July 13, 2026) — Security Hardening, Audit & UI Enhancement

- **🔒 Security:**
  - Migrasi password folder protection dari plaintext ke `password_hash(PASSWORD_BCRYPT)` / `password_verify()`.
  - Ganti perbandingan password plaintext `===` menjadi `password_verify()` untuk mencegah timing attack.
- **🐛 Bug Fix:**
  - Tombol "Back to Listing" di halaman Hash Check tidak berfungsi karena `onclick` diblokir oleh Content-Security-Policy — dipindah ke nonce-tagged script block.
  - Perbaiki logika breadcrumb path accumulation menggunakan `array_values()` setelah `array_filter()` untuk menghindari off-by-one pada subfolder dalam.
- **✨ Feature:**
  - Tambahkan floating **Home FAB button** (ikon rumah, warna indigo) di atas tombol Back-to-Top, muncul saat halaman di-scroll lebih dari 300px.
  - Tombol Home FAB navigasi langsung ke halaman root (`?`) dengan animasi hover dan dukungan dark/light mode.
- **⚡ Performance:**
  - Minify seluruh CSS inline menggunakan regex-based minifier — menghemat ±16.7 KB (15.3%) ukuran file.
  - Pindahkan `array_change_key_case($protectedFolders)` ke luar loop `foreach` pada render tabel — dari O(n) menjadi O(1).
- **♿ Accessibility & Code Quality:**
  - Post-login redirect diarahkan ke folder yang baru di-unlock, bukan canonical URL umum.
  - Tambahkan `aria-label` pada hash fingerprint link dan `aria-hidden="true"` pada ikon dekoratif.
  - Pisahkan helper `findOriginalFolderKey()` untuk mereduksi cognitive complexity pada `getFirstLockedFolder()`.

### Version 3.1 (13 Juli 2026 / July 13, 2026)

- **Refactoring & Clean Code:**
  - Mengurangi kompleksitas kognitif (*Cognitive Complexity*) pada fungsi utama (`listDirectory`, `processDirectoryItem`, `readHashCache`) dengan memisahkannya ke helper functions yang modular dan memiliki satu jalur return.
  - Mengurangi parameter masukan pada fungsi daftar file untuk mematuhi standar parameter maksimum.
  - Mengonversi elemen inline HTML dalam README menjadi format Markdown standar guna mematuhi aturan analisis Markdownlint.
- **Security & Standards Hardening:**
  - Mengintegrasikan kode Subresource Integrity (SRI) SHA-384 dan parameter crossorigin pada seluruh library eksternal (CSS/JS Bootstrap dan Font Awesome).
  - Menyederhanakan penanganan cookie sesi secara terpusat dan menerapkan tanda keamanan `secure` secara eksplisit.
- **Accessibility & CSS Enhancements:**
  - Menghadirkan kompatibilitas penuh properti standard `background-clip` bersama dengan `-webkit-background-clip`.
  - Mengonversi tombol Back-to-Top dari tag non-standar menjadi tag native `<button>` untuk menunjang kontrol aksesibilitas via keyboard.

### Version 3.0 (08 Juli 2026 / July 8, 2026)

- **Performance Optimizations:**
  - Mengoptimalkan pembacaan direktori dengan memangkas pemanggilan fungsi `realpath` yang berat pada symlink.
  - Memperkenalkan validasi folder aman `isDisplayableFolder` guna mencegah kebocoran direktori tersembunyi.
- **Aesthetic Overhaul:**
  - Memperbarui total desain UI menjadi bertema Glassmorphism bernuansa gelap (*Glassmorphic Dark Theme*) dengan animasi mikro yang halus serta ikon file berkode warna dinamis.
  - Menambahkan *noscript styling fallback* untuk transisi loading layar saat JavaScript dinonaktifkan.

---

## Catatan Penting / Documentation Notes

> [!IMPORTANT]
>
> ### 🇮🇩 Bahasa Indonesia (DocNote)
>
> 1. **Hak Akses Direktori Cache:** Pastikan direktori tempat script dijalankan memiliki izin tulis (*write permission*) agar script dapat membuat direktori `.cache` otomatis. Jika hak akses tidak tersedia, fitur penyimpanan cache hash akan dinonaktifkan demi keselamatan runtime.
> 2. **Dukungan SSL/HTTPS:** Untuk keamanan optimal, jalankan script ini di lingkungan yang didukung HTTPS untuk menjamin enkripsi cookie sesi CSRF dan token transit.
> 3. **Pemblokiran File Sensitif:** Secara bawaan, script memblokir file berekstensi seperti `.php`, `.bat`, `.env`, `.sql`, dan sejenisnya untuk mencegah eksekusi kode berbahaya serta kebocoran informasi kredensial.
> 4. **Password Folder — Wajib Hash:** Password untuk fitur proteksi folder **TIDAK BOLEH** disimpan dalam bentuk teks biasa (plaintext). Gunakan selalu hasil dari `password_hash('password_anda', PASSWORD_BCRYPT)`. Jalankan perintah berikut untuk generate hash: `php -r "echo password_hash('password_anda', PASSWORD_BCRYPT);"`.
> 5. **CSP & Inline Event Handler:** Script ini menggunakan Content-Security-Policy berbasis nonce. Inline `onclick=""` attribute pada HTML akan diblokir oleh CSP — semua event listener harus didaftarkan dalam `<script nonce="...">` block.
>
> ### 🇬🇧 English (DocNote)
>
> 1. **Cache Folder Permissions:** Ensure that the directory where the script executes has write permissions so it can spawn the `.cache` folder automatically. If permissions are missing, hash caching will be bypassed gracefully to ensure execution.
> 2. **HTTPS/SSL Deployment:** It is highly recommended to host this script under an SSL/HTTPS enabled domain to guarantee safe transit of session cookies and browser tokens.
> 3. **Exclusion of Sensitive Files:** By default, critical file formats including `.php`, `.bat`, `.env`, `.sql`, and others are locked from being displayed or hashed to prevent unauthorized code execution and credential leakage.
> 4. **Folder Passwords — Must Be Hashed:** Folder protection passwords **MUST NOT** be stored as plaintext. Always use the output of `password_hash('your_password', PASSWORD_BCRYPT)`. Generate a hash with: `php -r "echo password_hash('your_password', PASSWORD_BCRYPT);"`.
> 5. **CSP & Inline Event Handlers:** This script uses a nonce-based Content-Security-Policy. Inline `onclick=""` HTML attributes will be blocked by CSP — all event listeners must be registered inside a `<script nonce="...">` block.

---

## Donation

Anda bebas untuk mengubah, mendistribusikan script ini untuk keperluan anda.

If you find this project helpful and would like to support it, please consider donating via <https://www.paypal.me/alsyundawy>. Thank you for your support!

Jika Anda merasa terbantu dan ingin mendukung proyek ini, pertimbangkan untuk berdonasi melalui <https://www.paypal.me/alsyundawy>. Terima kasih atas dukungannya!

Jika Anda merasa terbantu dan ingin mendukung proyek ini, pertimbangkan untuk berdonasi melalui QRIS. Terima kasih atas dukungannya!

![QRIS Donation](https://github.com/user-attachments/assets/a0126f28-6dde-43da-ba14-d7c9a27de0df)

## License

MIT License — Copyright © 2026 **HARRY DS ALSYUNDAWY** — ALSYUNDAWY IT SOLUTION

> **Note:** Please retain credit to the original author (HARRY DS ALSYUNDAWY — ALSYUNDAWY IT SOLUTION) if you use or modify this script. Attribution is appreciated but not legally required under the MIT License.

---

![Alt](https://repobeats.axiom.co/api/embed/78ddb5f1a231029b742cc467a74bcce400941d0f.svg "Repobeats analytics image")
