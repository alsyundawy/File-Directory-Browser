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

## Stargazers over time

[![Star History Chart](https://api.star-history.com/svg?repos=alsyundawy/File-Directory-Browser&type=Date)](https://www.star-history.com/#alsyundawy/File-Directory-Browser&Date)

---

### Bahasa Indonesia

**File & Directory Browser** adalah script PHP tunggal (*single-file PHP script*) yang aman, responsif, dan sangat ringan untuk menampilkan daftar file serta direktori. Dilengkapi dengan fitur pengurutan instan, pencarian real-time tanpa reload halaman, verifikasi hash file (CRC32, MD5, SHA-1) menggunakan sistem cache lokal, perlindungan ketat dari eksploitasi path traversal, proteksi folder berbasis password dengan bcrypt hashing, serta antarmuka modern bertema *glassmorphic* berbasis Bootstrap 5 dan Font Awesome 6.

### English

**File & Directory Browser** is a security-hardened, highly responsive, and lightweight single-file PHP script designed to display file and directory lists. It features real-time search without reloading, instant sorting, file hash verification (CRC32, MD5, SHA-1) with a local caching mechanism, strict protection against path traversal attacks, bcrypt-secured password-protected folders, and a premium glassmorphic user interface built using Bootstrap 5 and Font Awesome 6.

---

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
$passwordSessionLifetime = 3600;                 // Durasi sesi login folder (detik)
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

## Lisensi / License

Didistribusikan di bawah **MIT License**. Lihat file [LICENSE](LICENSE) untuk informasi lebih lanjut.
