# Laporan Perjalanan Proyek: API Observability Dua Arah (Windows ↔ Kali)

*Ditulis 24 September 2026. Dokumen ini menceritakan apa yang dikerjakan, masalah apa saja yang
ditemukan, di tahap mana, dan bagaimana diselesaikan. Setiap **istilah teknis** ditulis dengan nama
aslinya (supaya bisa dicari dan dipelajari lebih lanjut), lalu langsung dijelaskan dengan bahasa
sederhana dan — kalau membantu — sebuah perumpamaan. Rincian perintah dan konfigurasi ada di
[`README.md`](../README.md).*

**Cara membaca:** istilah teknis ditulis **tebal**, penjelasan sederhananya mengikuti setelah tanda
"—", dan perumpamaan ditandai 📮.

---

## Ringkasan

Kami membangun **lab** kecil berisi dua komputer: laptop **Windows** (host) dan **Kali Linux** yang
berjalan sebagai **virtual machine (VM)** — komputer "tiruan" di dalam laptop yang sama, dijalankan
oleh **VirtualBox**. Keduanya saling memanggil **API** secara teratur, dan di keduanya dipasang
**observer** yang mencatat setiap panggilan: siapa memanggil siapa, kapan, berapa lama, apa hasilnya,
dan apa isinya.

📮 Bayangkan dua kantor yang saling berkirim surat, dan di masing-masing kantor ada petugas yang
mencatat setiap surat masuk dan keluar.

Tahap pertama komunikasinya memakai **HTTP** (📮 kartu pos: isinya bisa dibaca siapa saja yang
melihat). Tahap kedua memakai **HTTPS**, yaitu HTTP yang dibungkus **TLS** (📮 surat dalam amplop
tersegel). Hasil utamanya:

- Dengan HTTPS, observer yang menyadap jaringan **tidak bisa lagi membaca isi maupun nomor resi**
  (`request_id`) sebuah pesan, tetapi **masih bisa melihat waktu, arah, dan ukuran**-nya.
- Sebagian besar keterlambatan yang terukur ternyata **bukan** karena enkripsi, melainkan karena
  **Nagle's algorithm** yang tidak sengaja masih aktif di server Windows, ditambah **handshake** yang
  diulang di setiap request. Keduanya dibuktikan lewat eksperimen terkontrol.

---

## Kamus istilah

### Komunikasi dasar

| Istilah | Penjelasan sederhana | 📮 Perumpamaan |
|---|---|---|
| **API** (*Application Programming Interface*) | Pintu resmi sebuah program untuk menerima permintaan dari program lain. | Loket pelayanan. |
| **Endpoint** | Alamat spesifik di dalam API, mis. `/api/test` atau `/health`. | Nomor loket. |
| **HTTP method** | Jenis permintaan: `GET` (minta data), `POST` (kirim data). | "Saya mau bertanya" vs "saya mau menyerahkan berkas". |
| **Request / Response** | Pesan permintaan dan pesan balasan. | Surat permintaan dan surat balasan. |
| **Status code** | Angka hasil di balasan: `200` berhasil, `422` data tidak valid, `500` server error. | Cap "DITERIMA" / "DITOLAK" di surat balasan. |
| **Payload** | Isi data pesan. Di proyek ini berbentuk **JSON** — format teks terstruktur seperti `{"sender": "kali"}`. | Isi surat. |
| **Header** | Keterangan tambahan di bagian atas pesan, mis. `X-Request-ID`. | Tulisan di sampul surat. |
| **Server** | Program yang menunggu dan menjawab request. Di proyek ini dibuat dengan **FastAPI** dan dijalankan oleh **uvicorn**. | Petugas loket. |
| **Client** | Program yang mengirim request. Di proyek ini: **traffic generator** berbasis library **httpx**. | Warga yang datang ke loket. |
| **Health check** | Request ringan ke `/health` untuk memastikan server hidup. | "Halo, loketnya buka?" |

### Jaringan

| Istilah | Penjelasan sederhana | 📮 Perumpamaan |
|---|---|---|
| **IP address** | Alamat sebuah komputer di jaringan, mis. `192.168.56.10`. | Alamat rumah. |
| **Port** | Nomor "pintu" di satu komputer tempat program tertentu mendengarkan, mis. `8000`. | Nomor kamar di rumah itu. |
| **Subnet** | Kelompok alamat yang dianggap satu lingkungan, mis. semua `192.168.56.x`. | Satu kompleks perumahan. |
| **Gateway / router** | Perangkat yang meneruskan pesan antar-subnet. | Pos satpam antar-kompleks. |
| **NIC** (*Network Interface Card*) | Kartu jaringan; tiap sambungan jaringan punya satu. | Pintu keluar-masuk rumah. |
| **TCP** | Protokol yang menjamin data sampai utuh dan berurutan, dengan cara saling mengirim tanda terima (**ACK**). | Kurir tercatat yang meminta tanda tangan penerima. |
| **TCP connection** | Sambungan antara dua program sebelum data dikirim; dibuka dengan **TCP handshake** (3 langkah). | Sambungan telepon. |
| **4-tuple** | Empat hal yang mengidentifikasi satu koneksi: IP asal, port asal, IP tujuan, port tujuan. | Nomor telepon pemanggil + nomor yang dipanggil. |
| **Segment / packet** | Potongan data yang dikirim lewat jaringan. | Satu paket kiriman. |
| **MTU** (*Maximum Transmission Unit*) | Ukuran paket terbesar yang boleh lewat, biasanya **1500 byte** di Ethernet. Data yang lebih besar dipotong. | Batas ukuran kardus kurir. |
| **Loopback** (`127.0.0.1`) | Jaringan "ke diri sendiri" di dalam satu komputer; tidak ada batas MTU 1500. | Menitipkan surat ke diri sendiri tanpa lewat kantor pos. |
| **Firewall** | Penjaga yang memutuskan koneksi mana yang boleh masuk. | Satpam gerbang. |
| **Firewall rule** | Aturan satpam, mis. "port 8000 boleh dari jalur lab saja". | Daftar tamu yang diizinkan. |

### Mode jaringan VirtualBox

| Istilah | Penjelasan sederhana |
|---|---|
| **Bridged** | VM tampil sebagai perangkat terpisah di jaringan fisik (mis. Wi-Fi), mendapat IP dari router. Sering gagal di Wi-Fi publik. |
| **NAT** | VM menumpang koneksi internet host. Internet selalu jalan, tapi host tidak bisa menghubungi VM langsung. |
| **Host-Only** | Jaringan pribadi antara host dan VM saja, tanpa internet. IP-nya tetap walaupun host pindah Wi-Fi. |
| **DHCP** | Layanan yang membagikan IP otomatis. Lawannya: **IP statis** (diatur manual, tidak berubah). |
| **Captive portal** | Halaman login di Wi-Fi publik (mis. kafe). Tiap perangkat harus login sendiri. |

### Observability dan pengukuran

| Istilah | Penjelasan sederhana | 📮 Perumpamaan |
|---|---|---|
| **Observability** | Kemampuan memahami apa yang terjadi di sistem dari data yang dihasilkannya (log, rekaman, metrik). | Kemampuan menjelaskan apa yang terjadi di kantor pos dari catatan dan CCTV. |
| **Application log** (log aplikasi) | Catatan yang ditulis sendiri oleh server/client. Disimpan sebagai **JSONL** (satu objek JSON per baris). | Buku harian petugas. |
| **Packet capture** | Merekam paket yang lewat di NIC. Alatnya **TShark** (versi baris-perintah Wireshark) atau **tcpdump**. Di Windows butuh driver **Npcap**. | CCTV di pintu kantor. |
| **BPF filter** | Filter rekaman, mis. `tcp port 8000` — hanya rekam yang lewat port 8000. | CCTV hanya merekam pintu nomor 8000. |
| **TCP stream** | Nomor urut koneksi yang diberikan TShark. | Nomor sambungan telepon ke-sekian. |
| **Correlation ID** / `request_id` | ID unik (**UUID**) di setiap request untuk memasangkan request dengan response-nya di semua catatan. | Nomor resi. |
| **Correlation** | Menggabungkan bukti dari beberapa sumber tentang pesan yang sama. | Mencocokkan buku harian dengan rekaman CCTV. |
| **Evidence** | Sumber bukti di tiap event: `client_log`, `server_log`, `capture`, `capture_tls`. | Saksi mana saja yang melihat surat itu. |
| **Latency** | Lama waktu, dalam **milidetik (ms)**; 1 ms = 0,001 detik. | Lama surat sampai dibalas. |
| **RTT** (*Round-Trip Time*) / `client_rtt_ms` | Waktu dari client mulai mengirim sampai seluruh balasan diterima. | Dari surat dikirim sampai balasan di tangan. |
| **Server processing time** | Waktu server bekerja, tanpa perjalanan jaringan. | Lama petugas memproses surat di meja. |
| **Wire latency** | Waktu yang terlihat di rekaman jaringan: dari request lewat NIC sampai response lewat NIC. | Dari surat masuk pintu sampai balasan keluar pintu. |
| **TTFB** (*Time To First Byte*) / `wire_ttfb_ms` | Waktu sampai potongan **pertama** balasan terlihat. | Lembar pertama balasan keluar pintu. |
| **Vantage point** | Posisi pengamat: di sisi client atau sisi server. | Petugas di kantor pengirim atau kantor penerima. |

### Keamanan dan enkripsi

| Istilah | Penjelasan sederhana | 📮 Perumpamaan |
|---|---|---|
| **Encryption** | Mengacak data sehingga hanya pemilik kunci yang bisa membacanya. | Menyegel surat. |
| **HTTPS / TLS** (*Transport Layer Security*) | Enkripsi di tingkat koneksi. Versi yang dipakai: **TLS 1.3**. | Amplop tersegel untuk setiap surat di sambungan itu. |
| **TLS handshake** | Proses awal koneksi TLS: saling kenalan, cek identitas, sepakati kunci. Terdiri dari **ClientHello**, **ServerHello**, sertifikat, dan **Finished**. | Salam perkenalan + tukar KTP + sepakati gembok. |
| **TLS record** | Satu "lembar" data terenkripsi. Tiap record TLS 1.3 menambah ±17 byte (**AEAD overhead**). | Satu lembar dalam amplop, plus berat kertas amplopnya. |
| **Cipher suite** | Kombinasi algoritma enkripsi, mis. `TLS_AES_256_GCM_SHA384`. | Jenis gembok. |
| **SNI** (*Server Name Indication*) | Nama server yang disebut client saat handshake. Kosong jika client memakai IP langsung. | Menyebut nama kantor tujuan di sampul luar. |
| **Session ticket** (*NewSessionTicket*) | Tiket yang diberikan server TLS 1.3 setelah handshake supaya koneksi berikutnya bisa lebih cepat. | Kartu member. |
| **close_notify** | Pesan TLS kecil "saya menutup koneksi". | "Sampai jumpa" sebelum menutup telepon. |
| **Certificate** | Identitas digital server. | KTP. |
| **CA** (*Certificate Authority*) | Pihak yang menandatangani sertifikat. Di proyek ini dibuat **CA lab** sendiri. | Kantor penerbit KTP. |
| **SAN** (*Subject Alternative Name*) | Daftar IP/nama yang sah untuk sertifikat itu. | Alamat yang tertulis di KTP. |
| **Private key** | Kunci rahasia pasangan sertifikat. Tidak boleh bocor, tidak di-commit ke GitHub. | Stempel asli kantor. |
| **Certificate verification** | Client memeriksa sertifikat server terhadap CA yang dipercaya. Tidak pernah dimatikan (`verify=False` tidak dipakai). | Mencocokkan KTP dengan data kantor penerbit. |
| **Fernet** | Enkripsi di tingkat aplikasi (isi pesan dienkripsi program sebelum dikirim). Disiapkan untuk tahap berikutnya. | Isi surat ditulis dengan sandi, lalu tetap dimasukkan amplop. |

### Perilaku TCP yang ternyata penting

| Istilah | Penjelasan sederhana | 📮 Perumpamaan |
|---|---|---|
| **Nagle's algorithm** | Aturan TCP: jangan kirim potongan data kecil berikutnya sebelum potongan sebelumnya di-ACK, supaya jaringan tidak dibanjiri paket kecil. | Kurir tidak mau berangkat mengantar paket kecil kedua sebelum tanda terima paket pertama kembali. |
| **Delayed ACK** | Penerima menunda mengirim ACK (di Linux sekitar **40 ms**) supaya bisa menitipkannya bersama data balasan. | Penerima menunda tanda tangan, berharap bisa sekalian menitip surat balik. |
| **`TCP_NODELAY`** | Pengaturan socket untuk **mematikan** Nagle. | Kurir disuruh langsung berangkat tanpa menunggu tanda terima. |
| **Socket** | "Colokan" program ke jaringan; tempat pengaturan seperti `TCP_NODELAY` dipasang. | Pesawat telepon. |
| **Keep-alive** | Koneksi tidak langsung ditutup setelah satu request, supaya bisa dipakai lagi. | Telepon tidak ditutup setelah satu percakapan. |
| **Idle timeout** | Batas lama koneksi boleh menganggur sebelum ditutup. uvicorn dan httpx sama-sama default **5 detik**. | Telepon otomatis ditutup kalau diam 5 detik. |
| **Cold start** | Request pertama setelah program dinyalakan lebih lambat dari berikutnya. | Petugas yang baru datang masih menyiapkan meja. |
| **asyncio** | Mesin di Python yang menjalankan banyak koneksi bersamaan; dipakai uvicorn. Di Windows memakai **ProactorEventLoop**. | Pengatur antrean di kantor. |

### Pengembangan perangkat lunak

| Istilah | Penjelasan sederhana |
|---|---|
| **Conda environment** | "Kotak peralatan" Python terpisah untuk proyek ini (`api-observability`), didefinisikan di `environment.yml`. |
| **PATH** | Daftar folder tempat sistem mencari program yang diketik di terminal. |
| **`.env`** | File konfigurasi berisi pengaturan per komputer (IP, port, sertifikat). Tidak di-commit karena berisi data lokal. |
| **Git / commit / push** | Sistem pencatat versi kode. *Commit* = satu versi tersimpan; *push* = mengirimnya ke GitHub. |
| **Unit test / pytest** | Program kecil yang otomatis memeriksa kode bekerja benar. |
| **Fixture** | Contoh data tetap untuk test. Di proyek ini banyak fixture berasal dari **rekaman asli**. |
| **Regression test** | Test yang dibuat dari sebuah bug, supaya bug yang sama tidak muncul lagi tanpa ketahuan. |
| **Mutation check** | Sengaja "merusak" perbaikan untuk memastikan test benar-benar gagal tanpanya — bukti test itu berguna. |
| **Smoke test** | Uji cepat menjalankan seluruh sistem sekali untuk memastikan semuanya menyala. |
| **Heuristic** | Aturan tebakan yang biasanya benar, tapi tidak dijamin. |

---

## Tahap 0 — Persiapan lingkungan

**Yang dilakukan:** inspeksi laptop Windows: Python, Conda, dan TShark.

**Yang ditemukan dan dilakukan:**
- **TShark terpasang tetapi tidak ada di PATH**, jadi perintah `tshark` tidak dikenal di terminal.
  → Observer dibuat mencari TShark sendiri di folder instalasi Wireshark.
- **Kali belum bisa diinspeksi dari Windows.** → Dibuat skrip `setup_kali.sh` untuk memeriksa Python,
  Conda, tcpdump/TShark, IP, dan firewall di sisi Kali.
- Dibuat **Conda environment** `api-observability` (Python 3.12, FastAPI, uvicorn, httpx, pydantic,
  python-dotenv, cryptography, pytest) supaya tidak mengganggu Python lain di laptop.

---

## Tahap 1 — Fase 1: HTTP (pesan terbuka)

### Apa yang dibangun
1. **API server** (FastAPI + uvicorn) dengan endpoint `GET /health` dan `POST /api/test`. Setiap
   request dicatat ke log aplikasi (`server-events.jsonl`) beserta IP:port pengirim dan **server
   processing time**.
2. **Traffic generator** (httpx) yang mengirim sejumlah request dengan **delay** antar-request (bukan
   **infinite loop**), masing-masing dengan `request_id` (UUID) di **payload** dan di **header**
   `X-Request-ID`. Header dipakai karena selalu ada di **segment** TCP pertama, sehingga packet capture
   tetap bisa membacanya walaupun body terpotong ke beberapa segment.
3. **Observer** yang melakukan **correlation** dari tiga **evidence**: client log, server log, dan
   packet capture (TShark), lalu menulis satu **event** `api_exchange` per pasangan request–response ke
   `api-events.jsonl`.

### Masalah yang ditemukan

| # | Masalah | Istilah terkait | Penjelasan sederhana | Solusi |
|---|---|---|---|---|
| 1 | Field TShark `http.response_for.uri` tidak dikenal | TShark field | Kami meminta TShark mencatat kolom yang tidak ada di versi terpasang (4.6). | Dicek daftar field resmi (`tshark -G fields`), field itu dibuang. |
| 2 | Test gagal membaca contoh rekaman | fixture | Contoh rekaman dibuat sebelum daftar field berubah, jadi jumlah kolomnya tidak cocok. | Fixture direkam ulang memakai **perintah yang persis sama** dengan program. |
| 3 | Komentar di `.env` terbaca sebagai nilai | `.env`, python-dotenv | Menulis `TARGET_HOST=   # komentar` membuat nilainya menjadi "# komentar". | Semua komentar dipindah ke baris sendiri; dicek ulang dengan membaca konfigurasi. |
| 4 | Kali di subnet lain | subnet, gateway, bridged | Kali (bridged ke Wi-Fi) mendapat `192.168.34.x`, Windows `192.168.33.x`; lewat 1 router (terlihat dari **TTL 63**). Firewall rule "hanya **LocalSubnet**" tidak akan mencakup Kali. | Lihat #5. |
| 5 | IP berubah saat pindah Wi-Fi | DHCP, Host-Only, IP statis | Karena bridged, IP Kali mengikuti Wi-Fi yang sedang dipakai (saat itu Wi-Fi publik kafe). | Dibuat jaringan **Host-Only** dengan **IP statis**: Windows `192.168.56.1`, Kali `192.168.56.10`. |
| 6 | Kali tidak bisa internet | NAT, NetworkManager, captive portal | Bridged gagal di Wi-Fi publik (captive portal, isolasi client). Setelah diganti ke NAT, `eth0` tidak aktif karena **profil koneksi** NetworkManager yang tidak terikat ke interface "pindah" ke `eth1`. | Adapter 1 = **NAT** (internet), adapter 2 = **Host-Only** (lab); tiap adapter punya profil sendiri yang terikat ke interface-nya. |
| 7 | Server bisa diakses dari Wi-Fi publik | firewall rule, profile Public | Saat server pertama jalan, Windows membuat rule "izinkan python.exe" untuk **profil Public** — berlaku di semua Wi-Fi publik. | Dibuat rule sempit: port 8000 hanya di adapter `Ethernet 2` (Host-Only). Rule lama disarankan dinonaktifkan. |

### Hasil
Traffic dua arah tercatat lengkap: **12 event, semua status 200**. RTT Windows → Kali rata-rata
**9,1 ms**, sedangkan server processing di Kali hanya **~1,7 ms**.

**Pelajaran:** karena **keep-alive**, beberapa request bisa lewat **TCP stream** yang sama. Jadi nomor
stream bukan correlation ID. Yang bisa diandalkan hanyalah `request_id`.

---

## Tahap 2 — Fase 2: HTTPS/TLS (pesan dalam amplop)

### Apa yang dibangun
1. **CA lab** dan **certificate** untuk server Windows dan Kali, dengan **SAN** berisi IP masing-masing.
   **Private key** CA tidak pernah keluar dari Windows dan semua file rahasia ada di `secrets/` yang
   tidak di-commit. Sertifikat Kali disalin lewat jaringan lab dengan **scp** (salin file lewat SSH).
2. Server menjalankan **HTTPS**; client selalu melakukan **certificate verification** terhadap CA lab.
   Diuji: tanpa CA yang benar, koneksi **ditolak** (`CERTIFICATE_VERIFY_FAILED`).
3. Observer diajari membaca **TLS record** tanpa **decryption**: melihat **ClientHello**,
   **ServerHello** (versi dan cipher), lalu ukuran dan waktu record terenkripsi. Tidak ada private
   key server, tidak ada **SSLKEYLOGFILE**, tidak ada bypass.

### Apa yang terlihat dan yang hilang

| Informasi | HTTP (Fase 1) | HTTPS (Fase 2) |
|---|---|---|
| IP, port, TCP stream, waktu | terlihat | **masih terlihat** |
| Ukuran pesan | ukuran HTTP | ukuran TLS record — **tetap bocor** |
| Versi TLS, cipher suite | – | terlihat (`TLSv1.3`, `TLS_AES_256_GCM_SHA384`) |
| SNI | – | kosong (client memakai IP, bukan hostname) |
| Method, URI, status code, header, `request_id`, payload | terlihat | **tidak terlihat** |

Contoh nyata: request yang sama berukuran **438 byte** di HTTP dan **472 byte** di HTTPS. Selisih 34
byte = 2 TLS record × **17 byte AEAD overhead**. Artinya pengamat luar tetap bisa memperkirakan ukuran
isi pesan.

Karena `request_id` tersegel, observer harus memasangkan capture dengan log aplikasi lewat
**4-tuple** dan **waktu**, sebuah **heuristic** yang jauh lebih rapuh. Metode ini dicatat di setiap
event sebagai `capture_match`: `request_id` (Fase 1) atau `4tuple_time` (Fase 2).

### Masalah yang ditemukan

| # | Masalah | Di mana ketahuan | Istilah terkait | Penjelasan sederhana | Solusi |
|---|---|---|---|---|---|
| 8 | Session ticket dianggap response | Smoke test di loopback | NewSessionTicket, TLS record | Setelah handshake, server TLS 1.3 mengirim session ticket (📮 kartu member). Kadang tiket datang **setelah** request pertama, sehingga dikira balasannya. Wire latency tercatat 0,06 ms, padahal server processing 3 ms — mustahil. | Record server pertama setelah handshake selalu dianggap tiket. Ada regression test dari rekaman asli. |
| 9 | Server Kali gagal start | Uji dua host | private key, scp | `.env` Kali sudah diisi, tetapi file sertifikat belum disalin (sengaja tidak ikut ke GitHub). | Disalin dengan scp lewat jaringan Host-Only; `chmod 600` untuk private key. |
| 10 | Exchange "hantu" dan latency mustahil | Uji dua host (jaringan nyata) | MTU, ServerHello, Finished | Di jaringan nyata (**MTU 1500**) sisa handshake server datang di **frame terpisah** dari ServerHello (di loopback tidak pernah terpotong). Potongan itu dikira session ticket, sehingga ticket asli dikira response. Muncul 2 exchange hantu dan wire latency < server processing. | Record server sebelum **Finished** dari client dianggap bagian handshake. Regression test dari capture dua host. |
| 11 | Wire latency terlalu kecil | Membandingkan capture Windows dengan RTT di Kali | TTFB, wire latency | Response kadang terkirim dalam 2 record, dan record kedua tertahan ~40 ms. Observer hanya mengukur sampai record pertama (3,9 ms), padahal client baru selesai di 49,2 ms. | `wire_latency_ms` diukur sampai record **terakhir**; record pertama dicatat terpisah sebagai **TTFB** (`wire_ttfb_ms`). |
| 12 | Exchange tertukar (1) | Observer Kali | correlation, keep-alive, mutual best match | Health check tidak ditulis ke client log. Di koneksi keep-alive yang sama, exchange `/health` "mengambil" log request berikutnya karena waktunya masih dekat. | Pasangan hanya sah jika **saling memilih sebagai yang terbaik** (*mutual best match*), termasuk mempertimbangkan exchange yang masih berlangsung. **Mutation check** membuktikan test-nya menangkap bug ini. |

Awalnya kami menduga **timestamp** capture di Kali salah. Setelah timeline kedua host dibandingkan,
**keduanya cocok** (45,8 ms vs 45,6 ms untuk exchange yang sama). Yang salah adalah logika
correlation di observer, bukan jamnya.

---

## Tahap 3 — Investigasi: kenapa ada jeda ~40 ms?

### Gejala
RTT dari Kali ke Windows **46–96 ms**, padahal server processing hanya **~1 ms**. Capture di kedua
host sepakat: setiap kali server Windows mengirim record kedua (response setelah session ticket, atau
body setelah header response), record itu tertahan **~40 ms**.

### Hipotesis dan bukti
1. **Nagle's algorithm + delayed ACK.** Server Windows (Nagle aktif) tidak mengirim data kecil kedua
   sebelum data pertama di-ACK, sementara Kali (Linux) menunda ACK sekitar 40 ms. 📮 Kurir menunggu
   tanda terima, penerima menunda tanda tangan, dan keduanya saling menunggu.
2. **Kenapa Nagle aktif di Windows?** uvicorn memakai **asyncio**, dan asyncio *mencoba* memasang
   `TCP_NODELAY` di setiap koneksi. Tapi di Windows, **socket** yang diterima melaporkan `proto=0`
   (bukan `IPPROTO_TCP`), sehingga asyncio **diam-diam melewatkannya**. Ini dibuktikan langsung dengan
   membaca opsi socket: `TCP_NODELAY=0`.
3. **Perbaikan untuk eksperimen:** server diberi opsi `--tcp-nodelay` yang memasang `TCP_NODELAY` di
   **listening socket**; koneksi baru **mewarisinya** (diverifikasi di Windows).

### Eksperimen terkontrol (HTTPS, Kali → Windows, 5 request, delay 5 detik)

| Run | Server Windows | Client Kali | RTT rata-rata | Arti |
|---|---|---|---|---|
| A | default | default | **57,7 ms** | kondisi awal |
| B | `--tcp-nodelay` | default | **9,7 ms** | jeda ~40 ms hilang → **Nagle terbukti penyebabnya** |
| C | `--tcp-nodelay --keep-alive 10` | default | **12,3 ms** | tidak membaik: **client** masih menutup koneksi di 5 detik |
| D | `--tcp-nodelay --keep-alive 10` | `--keep-alive 10` | **5,3 ms** | 1 koneksi TLS untuk semua request → **biaya handshake ~4–5 ms terbukti** |

### Kesimpulan
1. **Nagle's algorithm** di server Windows adalah penyebab jeda ~40 ms (A → B).
2. **Idle timeout** default 5 detik di **kedua** sisi (uvicorn dan httpx) membuat setiap request
   dengan delay 5 detik membuka **TCP connection + TLS handshake** baru. Keep-alive baru efektif kalau
   **kedua** sisi dinaikkan (C → D).
3. Satu request di Run A butuh **95,7 ms**. Kemungkinan besar terjadi *race*: server menutup koneksi
   tepat saat client mau memakainya lagi (timeout 5 detik bertemu delay 5 detik). Anomali ini tidak
   muncul di B–D, tapi **belum terbukti langsung**, karena capture hanya berisi TLS record, bukan
   paket **FIN/RST** (paket penutup koneksi TCP).

### Masalah yang ditemukan

| # | Masalah | Istilah terkait | Penjelasan sederhana | Solusi |
|---|---|---|---|---|
| 13 | Exchange tertukar (2) | cold start, causality | Request pertama setelah server di-restart baru dicatat middleware ~19 ms setelah tiba di NIC (**cold start**). Waktu log-nya jadi lebih dekat ke request **berikutnya**, sehingga pasangannya tertukar. | Pencocokan memakai **kausalitas**: log server harus berada **di dalam** rentang exchange di kabel, log client harus **mencakup**-nya. Sebelumnya diukur dulu: jam log aplikasi dan jam capture di host yang sama selaras **±1 ms**. |
| 14 | `--keep-alive` di server tidak berefek | idle timeout, httpx `keepalive_expiry` | Client (httpx) juga punya batas idle 5 detik sendiri. | Opsi `--keep-alive` ditambahkan di traffic generator. |

---

## Hal lain di luar eksperimen

- **Co-author Claude di GitHub.** Commit pertama sempat memuat baris `Co-Authored-By`. Riwayat
  dibersihkan dengan **amend** + **force push**, dan commit berikutnya dibuat tanpa atribusi. GitHub
  masih menyimpan commit lama sebagai **unreachable commit** (terlihat dari halaman *Activity*).
  Pilihan penyelesaiannya (GitHub Support atau membuat ulang repositori) **belum diputuskan**.

---

## Daftar semua masalah

| # | Tahap | Masalah singkat | Kategori | Status |
|---|---|---|---|---|
| 1 | 1 — HTTP | Field TShark tidak ada | tooling | Selesai |
| 2 | 1 — HTTP | Fixture usang | testing | Selesai |
| 3 | 1 — HTTP | Komentar `.env` terbaca sebagai nilai | konfigurasi | Selesai |
| 4 | 1 — HTTP | Kali di subnet berbeda | jaringan | Selesai (Host-Only) |
| 5 | 1 — HTTP | IP berubah saat pindah Wi-Fi | jaringan | Selesai (IP statis) |
| 6 | 1 — HTTP | Kali tidak bisa internet | jaringan | Selesai (NAT + Host-Only) |
| 7 | 1 — HTTP | Firewall rule terlalu luas | keamanan | Rule sempit dibuat; rule lama perlu dinonaktifkan pemilik laptop |
| 8 | 2 — HTTPS | Session ticket dikira response | observer | Selesai + regression test |
| 9 | 2 — HTTPS | Sertifikat Kali belum disalin | operasional | Selesai |
| 10 | 2 — HTTPS | Exchange hantu di MTU 1500 | observer | Selesai + regression test |
| 11 | 2 — HTTPS | Wire latency hanya sampai TTFB | observer | Selesai + regression test |
| 12 | 2 — HTTPS | Exchange tertukar (health check) | observer | Selesai + regression test + mutation check |
| 13 | 3 — Investigasi | Exchange tertukar (cold start) | observer | Selesai + regression test + mutation check |
| 14 | 3 — Investigasi | Keep-alive client terlewat | eksperimen | Selesai |
| – | 3 — Investigasi | Penyebab **cold start** 20–50 ms | terbuka | **Belum diketahui** |

Total **81 unit test** lulus. Semua bug observer (#8, #10–#13) punya regression test berbasis
**rekaman asli** dari kejadiannya.

---

## Pelajaran untuk penelitian

1. **Enkripsi (TLS) menyembunyikan konten, bukan metadata.** Waktu, arah, dan ukuran tetap terlihat
   dan bisa dipakai menebak isi (*traffic analysis*).
2. **Tanpa bisa membaca isi, observer harus memakai heuristic, dan heuristic mudah keliru.** Kelima
   bug observer di Tahap 2–3 berakar dari sini: tiga karena batas pesan harus ditebak dari ukuran dan
   urutan TLS record (#8, #10, #11), dua karena `request_id` tersembunyi sehingga pasangan harus
   ditebak dari 4-tuple dan waktu (#12, #13).
3. **Satu vantage point bisa menyesatkan.** Hampir semua bug baru ketahuan karena ada **dua titik
   capture** (Windows dan Kali) dan **dua jenis evidence** (capture dan log aplikasi) yang saling
   dicocokkan.
4. **Loopback tidak mewakili jaringan nyata.** Bug #10 hanya muncul dengan MTU 1500.
5. **Default bisa diam-diam salah.** Kegagalan asyncio memasang `TCP_NODELAY` di Windows tidak
   menghasilkan error apa pun; baru ketahuan dari pengukuran.
6. **Ukur dulu sebelum menyimpulkan.** Dua dugaan awal terbukti keliru oleh data: bahwa jeda 40 ms
   hanya karena session ticket, dan bahwa timestamp capture di Kali salah.

---

## Yang belum dikerjakan

1. **Perbandingan ulang HTTP vs HTTPS secara adil.** Fase 1 dan Fase 2 diukur dengan pengaturan
   Run A (Nagle aktif, handshake per request), sehingga selisihnya bercampur efek lain. Perlu diulang
   dengan pengaturan Run D di kedua arah.
2. **Mencari penyebab cold start** pada request pertama setelah server di-restart.
3. **Fase 3 — application-layer encryption (Fernet):** payload dienkripsi oleh aplikasi sebelum masuk
   HTTPS. Fungsi `encrypt_payload` / `decrypt_payload` sudah dibuat dan diuji, tapi belum dipasang.
4. **Keputusan soal unreachable commit** yang masih memuat co-author Claude di GitHub.
