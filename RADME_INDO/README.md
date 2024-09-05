
# NetCut-like API 
![Dashboard Screenshot](../screenshots/gambar.jpg)

NetCut-like API adalah aplikasi berbasis Python yang dibangun menggunakan Flask untuk mengelola ARP spoofing, pemindaian jaringan, whitelist IP, dan fitur lainnya pada jaringan lokal. Aplikasi ini memungkinkan Anda melakukan pemindaian jaringan, memulai serangan ARP spoofing, mengelola IP yang di-whitelist, dan menyediakan dashboard berbasis web untuk memudahkan pengelolaan.

## Daftar Isi

- [Fitur](#fitur)
- [Persyaratan](#persyaratan)
- [Instalasi](#instalasi)
- [Instalasi Npcap dan Rekomendasi Virtual Machine](#instalasi-npcap-dan-rekomendasi-virtual-machine)
- [Instalasi WinPcap (Untuk Windows)](#instalasi-winpcap-untuk-windows)
- [Instalasi Visual C++ Build Tools (Untuk Windows)](#instalasi-visual-c-build-tools-untuk-windows)
- [Penggunaan](#penggunaan)
  - [Menjalankan Aplikasi](#menjalankan-aplikasi)
  - [Mengakses Dashboard](#mengakses-dashboard)
  - [Menjalankan `index.html` Secara Lokal](#menjalankan-indexhtml-secara-lokal)
  - [Endpoint API](#endpoint-api)
  - [Fungsi Dashboard Web](#fungsi-dashboard-web)
- [Menjalankan di Termux](#menjalankan-di-termux)
  - [Instalasi di Termux](#instalasi-di-termux)
  - [Menjalankan API di Termux](#menjalankan-api-di-termux)
  - [Menjalankan `index.html` di Termux](#menjalankan-indexhtml-di-termux)
  - [Mengakses API di Termux](#mengakses-api-di-termux)
- [Peringatan](#peringatan)
  - [Kelebihan Thread dan BSOD](#kelebihan-thread-dan-bsod)
- [Catatan](#catatan)
- [Lisensi](#lisensi)

## Fitur

- **ARP Spoofing**: Memulai dan menghentikan serangan ARP spoofing pada jaringan tertentu dengan kemampuan untuk menyesuaikan jumlah thread yang digunakan.
- **Pemindaian Jaringan**: Memindai jaringan lokal untuk menemukan perangkat dan alamat MAC-nya, dengan opsi untuk memuat perangkat yang telah dipindai sebelumnya dari file JSON.
- **Whitelist IP**: Menambahkan dan menghapus IP dari whitelist untuk mengecualikan mereka dari ARP spoofing. Whitelist disimpan dalam file JSON untuk persistensi.
- **Dashboard Berbasis Web**: Mengelola semua fitur dari antarmuka web sederhana, termasuk pemindaian jaringan, ARP spoofing, dan manajemen whitelist.
- **Dukungan Cross-Platform**: Aplikasi dapat berjalan di Windows (menggunakan WMI) dan Linux/Android (menggunakan psutil) untuk deteksi antarmuka jaringan.
- **Pemindaian Jaringan Periodik**: Memperbarui daftar IP target secara otomatis dengan memindai jaringan secara berkala.
- **Penanganan Kesalahan dan Manajemen Thread**: Secara paksa menghentikan ARP spoofing jika terjadi kesalahan, memastikan manajemen thread yang aman.
- **CORS Diaktifkan**: Cross-Origin Resource Sharing diaktifkan untuk memudahkan penggunaan di lingkungan yang beragam.

## Persyaratan

- Python 3.x
- Flask
- Flask-CORS
- Scapy
- WMI (untuk Windows)
- psutil (untuk Linux/Android)
- Netifaces
- Threading
- JSON

## Instalasi Npcap dan Rekomendasi Virtual Machine

> **Penting**: Jika Anda menjalankan aplikasi ini di **Windows**, sangat disarankan untuk menginstal **Npcap** daripada WinPcap. Npcap adalah versi terbaru dan lebih stabil dari WinPcap.

Selain itu, demi alasan keamanan dan stabilitas, disarankan untuk menjalankan ARP spoofing di lingkungan **virtual machine (VM)** seperti **VMware** atau **VirtualBox**. Ini mencegah gangguan yang tidak diinginkan pada sistem operasi utama Anda.

### Instalasi Npcap

1. **Unduh Npcap**:
   - Anda bisa mengunduh Npcap dari situs resmi: [Unduh Npcap](https://nmap.org/npcap/).

2. **Instal Npcap**:
   - Jalankan penginstal dan pastikan untuk memilih opsi **"WinPcap API-compatible mode"** selama instalasi.

3. **Verifikasi Instalasi Npcap**:
   - Setelah instalasi, Anda dapat memverifikasi bahwa Npcap berfungsi dengan menjalankan perintah berikut di terminal:
     ```bash
     nping --version
     ```

### Rekomendasi Virtual Machine

Untuk menghindari masalah seperti **Blue Screen of Death (BSOD)** atau gangguan jaringan selama ARP spoofing, sangat disarankan untuk menjalankan aplikasi ini di dalam **virtual machine (VM)**:

- **VMware**: [Unduh VMware](https://www.vmware.com/products/workstation-player/workstation-player-evaluation.html)
- **VirtualBox**: [Unduh VirtualBox](https://www.virtualbox.org/)

Menjalankan dalam lingkungan virtual akan mengisolasi aktivitas ARP spoofing dari sistem host, sehingga mengurangi risiko ketidakstabilan sistem atau crash.

## Instalasi WinPcap (Untuk Windows)

Jika Anda menjalankan aplikasi ini di Windows dan lebih memilih **WinPcap**, Anda harus menginstalnya agar Scapy dapat menangkap dan menyuntikkan paket. Namun, **Npcap** lebih disarankan karena memiliki dukungan yang lebih modern.

1. **Unduh WinPcap**:
   - Anda dapat mengunduh WinPcap dari situs resmi: [Unduh WinPcap](https://www.winpcap.org/install/default.htm).

2. **Instal WinPcap**:
   - Jalankan penginstal dan ikuti petunjuk di layar untuk menyelesaikan instalasi.

3. **Verifikasi Instalasi**:
   - Setelah menginstal WinPcap, verifikasi bahwa WinPcap berfungsi dengan menjalankan perintah berikut di terminal:
     ```bash
     nping --version
     ```

## Instalasi Visual C++ Build Tools (Untuk Windows)

Beberapa pustaka Python memerlukan **Visual C++ Build Tools** untuk dikompilasi, terutama saat menggunakan ekstensi C/C++. Berikut cara menginstalnya:

1. **Unduh Visual C++ Build Tools**:
   - Anda dapat mengunduhnya dari situs resmi Microsoft: [Unduh Visual C++ Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/).

2. **Instal Visual C++ Build Tools**:
   - Jalankan penginstal dan pastikan untuk memilih komponen berikut:
     - **Desktop development with C++**.
     - **Windows 10 SDK** (jika tersedia).

3. **Selesaikan Instalasi**:
   - Setelah instalasi selesai, Python akan dapat mengompilasi pustaka yang memerlukan build tools ini.

## Instalasi

1. **Clone Repository**:
   ```bash
   git clone https://github.com/zimibot/Spoofing_Network.git
   cd netcut-like-api
   ```

2. **Instal Dependencies yang Diperlukan**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Instal WMI di Windows** (jika belum terinstal):
   ```bash
   pip install WMI
   ```

4. **Jalankan Aplikasi**:
   ```bash
   python api.py
   ```

## Penggunaan

### Menjalankan Aplikasi
1. Mulai aplikasi Flask dengan menjalankan `python api.py` di terminal Anda.
2. API akan dapat diakses di `http://localhost:5000`.
   - **Catatan**: Port `5000` digunakan secara eksklusif untuk API.

### Mengakses Dashboard
- Dashboard itu sendiri tidak disajikan oleh API Flask. Untuk mengakses dashboard, Anda perlu membuka file `index.html` secara terpisah.

### Menjalankan `index.html` Secara Lokal

1. **Pastikan API Flask Berjalan**: Pastikan API Flask berjalan di mesin Anda (`http://localhost:5000`).

2. **Buka File `index.html` Menggunakan Python**:
   - Arahkan ke direktori tempat `index.html` berada:
     ```bash
     cd /path/to/your/index.html
     ```
   - Mulai server HTTP sederhana menggunakan Python:
     ```bash
     python -m http.server 8080
     ```
     Perintah ini akan menyajikan file di direktori tersebut di port `8080`.

3. **Akses Dashboard**:
   - **Dari Komputer Anda**: Buka browser dan buka `http://localhost:8080/index.html`.
   - **Dari Perangkat Lain**: Gunakan alamat IP mesin Anda (misalnya, `http://<Your-IP>:8080/index.html`).

### Endpoint API
- **`GET /scan_interfaces`**: Memindai antarmuka jaringan yang tersedia dan menyimpannya ke JSON.
- **`GET /interface_data`**: Mengambil daftar antarmuka jaringan dari file JSON.
- **`GET /scan_network`**: Memindai perangkat di jaringan, kecuali IP yang di-wh

itelist.
  - Parameter: `interface` (Indeks dari antarmuka jaringan)
- **`GET /scan_network_data`**: Mengambil data jaringan yang dipindai sebelumnya dari file JSON.
- **`POST /start_netcut`**: Memulai ARP spoofing pada IP yang ditentukan.
  - Parameter: `interface`, `target_ips`, `num_threads`
- **`POST /stop_netcut`**: Menghentikan semua serangan ARP spoofing yang sedang berjalan.
- **`POST /force_stop_netcut`**: Secara paksa menghentikan semua serangan ARP spoofing yang sedang berjalan dan menghapus sesi.
- **`POST /whitelist`**: Menambahkan IP ke whitelist.
  - Parameter: `ip` (Alamat IP yang akan ditambahkan)
- **`DELETE /whitelist`**: Menghapus IP dari whitelist.
  - Parameter: `ip` (Alamat IP yang akan dihapus)
- **`GET /whitelist`**: Mengambil daftar IP yang di-whitelist.
- **`GET /help`**: Menampilkan dokumentasi API dan informasi bantuan.

### Fungsi Dashboard Web
- **Manajemen Whitelist**: Menambahkan atau menghapus alamat IP dari whitelist langsung dari dashboard.
- **Manajemen ARP Spoofing**: Memulai, menghentikan, atau secara paksa menghentikan serangan ARP spoofing. Sesuaikan IP target dan jumlah thread yang digunakan.
- **Pemindaian Jaringan**: Melakukan pemindaian jaringan untuk menemukan perangkat. Perangkat yang dipindai ditampilkan di dashboard dan dapat digunakan untuk memilih IP target untuk ARP spoofing.
- **Pemilihan IP Target Ganda**: Memilih beberapa alamat IP dari perangkat yang dipindai untuk ditargetkan dengan ARP spoofing, dengan opsi untuk memilih semua perangkat.
- **Notifikasi Kesalahan**: Menerima notifikasi kesalahan secara real-time melalui pop-up menggunakan SweetAlert2.

## Menjalankan di Termux

### Instalasi di Termux
> **Penting**: Pastikan perangkat Anda di-root sebelum melanjutkan. Akses root diperlukan untuk menjalankan ARP spoofing dan pemindaian jaringan pada Android melalui Termux.

1. **Instal Termux**: Unduh dan instal [Termux](https://termux.com/) dari Google Play Store atau F-Droid.

2. **Perbarui dan Tingkatkan Paket Termux**:
   ```bash
   pkg update -y
   pkg upgrade -y
   ```

3. **Instal Python dan Pip**:
   ```bash
   pkg install python -y
   ```

4. **Instal Paket Python yang Diperlukan**:
   ```bash
   pip install flask flask-cors scapy psutil netifaces
   ```

5. **Clone Repository**:
   ```bash
   pkg install git -y
   git clone https://github.com/zimibot/Spoofing_Network.git
   cd Spoofing_Network
   ```

### Menjalankan API di Termux
1. Mulai aplikasi Flask di Termux:
   ```bash
   python api.py
   ```

### Menjalankan `index.html` di Termux

1. **Pastikan API Flask Berjalan**:
   - Pastikan API Flask Anda berjalan di `http://localhost:5000` dengan menjalankan:
     ```bash
     python api.py
     ```

2. **Sajikan `index.html` Menggunakan Python**:
   - Instal server HTTP Python untuk menyajikan file `index.html`:
     ```bash
     cd /path/to/your/index.html
     python -m http.server 8080
     ```
   - Perintah ini akan menyajikan file di direktori tersebut di port `8080`.

3. **Akses Dashboard**:
   - **Dari Perangkat Android Anda**: Buka browser web dan navigasikan ke `http://localhost:8080/index.html`.
   - **Dari Perangkat Lain**: Temukan alamat IP perangkat Android Anda dengan menjalankan `ifconfig` di Termux. Akses dashboard menggunakan `http://<Your-IP>:8080/index.html`.

### Mengakses API di Termux
- **Dari Perangkat Android Anda**: Buka browser dan buka `http://localhost:5000`.
- **Dari Perangkat Lain**: Temukan alamat IP perangkat Android Anda dengan menjalankan `ifconfig` di Termux, lalu akses API menggunakan `http://<Your-IP>:5000`.

## Peringatan

### Kelebihan Thread dan BSOD

> **Peringatan**: Jika jumlah thread yang digunakan untuk ARP spoofing terlalu banyak, ini bisa menyebabkan **Blue Screen of Death (BSOD)** pada sistem Windows. Disarankan untuk membatasi jumlah thread yang digunakan untuk menghindari kelebihan beban pada driver jaringan. Jika Anda mengalami masalah BSOD, pertimbangkan untuk mengurangi jumlah thread yang digunakan atau menjalankan aplikasi di lingkungan virtual seperti **VMware** atau **VirtualBox**.

## Catatan
- Pastikan Anda memiliki izin dan hak legal yang tepat untuk melakukan pemindaian jaringan dan ARP spoofing pada jaringan yang Anda uji.
- Untuk sistem Windows, pastikan modul `wmi` diinstal dan tersedia.
- Untuk Termux, pastikan skrip mendeteksi lingkungan dengan benar dan menggunakan `psutil` untuk deteksi antarmuka jaringan.
- **Akses root diperlukan di Android** saat menggunakan Termux untuk melakukan pemindaian jaringan dan ARP spoofing.
- **Pengguna Windows harus menginstal [Npcap](https://nmap.org/npcap/)** untuk menangkap dan menyuntikkan paket jaringan. Disarankan untuk menjalankan aplikasi di **VMware** atau **VirtualBox** untuk memastikan stabilitas sistem selama ARP spoofing.
- **Pengguna Windows juga harus menginstal [Visual C++ Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/)** untuk mengompilasi pustaka Python tertentu.

## Lisensi
Proyek ini dilisensikan di bawah Lisensi MIT. Lihat file [LICENSE](LICENSE) untuk detail lebih lanjut.
