# Laporan Perjalanan Proyek: Mengamati Percakapan Antar-Komputer

*Ditulis 24 September 2026. Dokumen ini menceritakan apa yang dikerjakan, masalah apa saja yang
ditemukan, di tahap mana, dan bagaimana diselesaikan, dengan bahasa yang bisa dipahami tanpa latar
belakang IT. Penjelasan teknis lengkap ada di [`README.md`](../README.md).*

---

## Ringkasan dalam satu paragraf

Kami membangun laboratorium kecil berisi dua komputer, sebuah laptop Windows dan sebuah komputer
virtual Kali Linux, yang saling "berkirim surat" secara teratur. Lalu kami memasang "pengamat" di
kedua komputer untuk mencatat setiap surat: siapa mengirim, ke siapa, kapan, berapa lama sampai
dibalas, dan apa isinya. Tahap pertama suratnya dikirim terbuka (seperti kartu pos). Tahap kedua
suratnya dimasukkan ke amplop tersegel (enkripsi HTTPS). Hasilnya: ketika amplop tersegel, pengamat
dari luar tidak bisa lagi membaca isi maupun "nomor resi" surat, tetapi **masih bisa melihat kapan
surat dikirim, ke mana, dan seberapa tebal amplopnya**. Di perjalanan kami juga menemukan bahwa
sebagian besar keterlambatan balasan ternyata bukan karena amplopnya, melainkan karena **kebiasaan
"kurir" di Windows yang menunda pengiriman** — dan itu berhasil dibuktikan lewat eksperimen.

---

## Kamus kecil

| Istilah | Artinya dalam bahasa sehari-hari |
|---|---|
| **API** | "Loket" di sebuah program tempat program lain bisa mengajukan permintaan dan mendapat jawaban. |
| **Server** | Pihak yang menjaga loket dan menjawab permintaan. |
| **Client / traffic generator** | Pihak yang datang ke loket dan mengajukan permintaan. Di proyek ini: program yang mengirim 5 permintaan dengan jeda beberapa detik. |
| **Request / response** | Surat permintaan dan surat balasan. |
| **Observer (pengamat)** | Program pencatat yang merangkum setiap pasangan surat permintaan–balasan. |
| **Packet capture** | Menyadap "kabel" jaringan di komputer sendiri untuk melihat surat yang lewat, seperti CCTV di kantor pos. Alatnya bernama TShark. |
| **Log aplikasi** | Buku harian yang ditulis sendiri oleh server dan client: "jam sekian saya terima/kirim surat nomor sekian". |
| **request_id** | Nomor resi unik di setiap surat, supaya surat dan balasannya bisa dipasangkan. |
| **Latency** | Lama waktu dari surat dikirim sampai balasan diterima, dalam milidetik (ms). 1 ms = seperseribu detik. |
| **HTTP** | Surat terbuka seperti kartu pos: siapa pun yang melihat bisa membaca isinya. |
| **HTTPS / TLS** | Surat dalam amplop tersegel. Hanya pengirim dan penerima yang bisa membuka. |
| **Sertifikat** | "KTP" server yang ditandatangani pihak yang dipercaya, supaya client yakin sedang bicara dengan server yang benar, bukan penipu. |
| **Koneksi / keep-alive** | "Sambungan telepon" antara dua komputer. Keep-alive = telepon tidak langsung ditutup setelah satu percakapan, supaya bisa dipakai lagi. |
| **Handshake** | Salam perkenalan di awal sambungan. Untuk HTTPS, salamnya lebih panjang karena harus saling cek KTP dan sepakat kunci amplop. |

---

## Tahap 0 — Persiapan (memeriksa peralatan)

**Yang dilakukan:** memeriksa apa yang sudah ada di laptop Windows: Python, Conda (pengelola
"kotak peralatan" program), dan TShark (alat penyadap jaringan).

**Yang ditemukan:**
- TShark sudah terpasang, tetapi tidak terdaftar di "daftar alamat" Windows (PATH), sehingga
  perintah `tshark` biasa tidak jalan. → Program pengamat dibuat supaya bisa menemukan TShark sendiri.
- Komputer Kali belum bisa diperiksa dari Windows. → Dibuat skrip pemeriksa khusus untuk Kali.
- Dibuat "kotak peralatan" khusus proyek (lingkungan Conda `api-observability`) supaya tidak
  mengganggu program lain di laptop.

---

## Tahap 1 — Surat terbuka (HTTP)

### Apa yang dibangun
1. **Server** di kedua komputer yang menjawab setiap surat dengan "diterima" plus lama waktu memprosesnya.
2. **Client** yang mengirim 5 surat dengan jeda teratur (tidak membanjiri), masing-masing dengan nomor resi unik.
3. **Pengamat** yang menggabungkan tiga sumber bukti: buku harian client, buku harian server, dan rekaman CCTV kabel.

### Masalah yang ditemukan di tahap ini

| # | Masalah | Penjelasan sederhana | Solusi |
|---|---|---|---|
| 1 | Satu nama "kolom" di TShark tidak ada | Kami meminta TShark mencatat kolom yang ternyata sudah dihapus di versi terbarunya. | Dicek daftar kolom yang benar di versi terpasang, kolom itu dibuang. |
| 2 | Contoh data untuk uji otomatis sudah usang | Contoh rekaman direkam sebelum daftar kolom berubah, jadi uji otomatis gagal membacanya. | Rekaman diulang memakai perintah yang persis sama dengan program. |
| 3 | Catatan di file pengaturan terbaca sebagai nilai | Menulis `TARGET_HOST=   # komentar` membuat komputer mengira alamatnya adalah "# komentar". | Semua catatan dipindah ke baris tersendiri. |
| 4 | Kali ada di "lingkungan" jaringan lain | Kali tersambung lewat Wi-Fi dengan alamat berbeda kelompok (192.168.34.x) dari Windows (192.168.33.x); lewat satu router. Aturan firewall "hanya dari jaringan lokal" tidak akan mencakupnya. | Lihat #6. |
| 5 | Alamat berubah kalau pindah Wi-Fi | Karena menumpang Wi-Fi, alamat Kali berganti setiap pindah tempat. Saat itu laptop sedang di Wi-Fi publik kafe. | Dibuat "jalur pribadi" antara Windows dan Kali (VirtualBox Host-Only): Windows **192.168.56.1**, Kali **192.168.56.10**, tidak berubah di mana pun. |
| 6 | Kali tidak bisa internet | Mode jaringan lama (bridged) gagal di Wi-Fi publik. Setelah diganti, sambungan internet Kali tidak aktif karena profil pengaturannya "pindah" ke kartu jaringan yang lain. | Kali diberi dua kartu jaringan: satu untuk internet (NAT), satu untuk lab (Host-Only), masing-masing dengan profil sendiri. |
| 7 | Server bisa diakses orang lain di Wi-Fi publik | Saat server pertama kali jalan, Windows menawarkan izin firewall dan izin itu berlaku untuk semua jaringan publik. | Dibuat aturan firewall yang hanya membuka pintu di jalur lab; aturan lama disarankan dinonaktifkan. |

### Hasil
Traffic dua arah berhasil dicatat lengkap: 12 pasangan surat, semua berstatus berhasil (200). Rata-rata
waktu balasan Windows → Kali sekitar **9 ms**, padahal server hanya butuh sekitar **2 ms** untuk
memproses — sisanya habis di perjalanan dan di sisi pengirim.

**Pelajaran penting:** beberapa surat berturut-turut bisa lewat "sambungan telepon" yang sama. Jadi
nomor sambungan tidak bisa dipakai sebagai nomor resi — yang bisa diandalkan hanyalah nomor resi
(`request_id`) di dalam surat itu sendiri.

---

## Tahap 2 — Surat dalam amplop tersegel (HTTPS)

### Apa yang dibangun
1. **"Kantor penerbit KTP" lokal** (CA lab) dan KTP untuk server Windows dan Kali. Kunci utama
   penerbit tidak pernah keluar dari laptop Windows dan tidak pernah diunggah ke GitHub.
2. Server kini hanya menerima surat beramplop. Client **selalu memeriksa KTP server** — kalau KTP
   palsu atau tidak dikenal, client menolak. (Diuji: tanpa KTP penerbit yang benar, sambungan ditolak.)
3. Pengamat diajari membaca **amplop** tanpa membukanya: kapan dikirim, dari mana ke mana, dan
   seberapa tebal. Tidak ada upaya membongkar segel.

### Apa yang masih terlihat dan apa yang hilang

| Informasi | Surat terbuka (Tahap 1) | Amplop tersegel (Tahap 2) |
|---|---|---|
| Pengirim, penerima, waktu | terlihat | **masih terlihat** |
| Tebal surat | terlihat | **masih terlihat** (hanya bertambah sedikit karena amplop) |
| Jenis permintaan, isi, nomor resi | terlihat | **tidak terlihat** |
| Jenis segel (versi TLS) | – | terlihat: TLS 1.3 |

Contoh nyata: surat yang sama tebalnya **438 byte** tanpa amplop dan **472 byte** dengan amplop.
Selisih 34 byte itu tepat 2 × 17 byte "kertas amplop" TLS 1.3 (surat dikirim dalam dua lembar). Artinya
**orang luar tetap bisa menebak ukuran isi surat**, walaupun tidak bisa membacanya.

Karena nomor resi kini tersegel, pengamat harus memasangkan rekaman CCTV dengan buku harian lewat cara
lain: **"sambungan telepon yang sama" + "waktu yang masuk akal"**. Cara ini ternyata jauh lebih rapuh
— dan di situlah sebagian besar masalah berikut muncul.

### Masalah yang ditemukan di tahap ini

| # | Masalah | Di mana ketahuan | Penjelasan sederhana | Solusi |
|---|---|---|---|---|
| 8 | "Kartu member" dianggap balasan | Uji di satu komputer | Setelah salam perkenalan, server TLS 1.3 memberi "kartu member" (session ticket) supaya lain kali perkenalan lebih cepat. Kadang kartu ini datang *setelah* surat pertama dikirim, sehingga dikira balasannya — waktu balasan tercatat 0,06 ms, padahal server saja butuh 3 ms. Mustahil. | Kiriman pertama server setelah perkenalan selalu dianggap kartu member. |
| 9 | Server Kali menolak jalan | Uji dua komputer | Pengaturan HTTPS sudah diisi, tapi file KTP Kali belum disalin dari Windows (sengaja tidak ikut di GitHub karena rahasia). | KTP disalin lewat jalur lab dengan `scp`. |
| 10 | Surat "hantu" dan waktu mustahil | Uji dua komputer, jaringan sungguhan | Di jaringan sungguhan, salam perkenalan server terpotong jadi dua paket (di uji satu komputer tidak pernah terpotong). Potongan kedua dikira kartu member, sehingga kartu member yang asli dikira balasan. Akibatnya muncul 2 surat hantu dan waktu balasan lebih kecil dari waktu kerja server. | Pengamat kini tahu: semua kiriman server sebelum client selesai berkenalan adalah bagian perkenalan. |
| 11 | Waktu balasan tercatat terlalu cepat | Membandingkan hasil Windows dengan hasil Kali | Balasan kadang dikirim dalam dua lembar, dan lembar kedua tertahan ~40 ms. Pengamat hanya mencatat sampai lembar pertama (3,9 ms), padahal client baru selesai menerima di 49 ms. | Waktu balasan kini dihitung sampai lembar **terakhir**; waktu lembar pertama dicatat terpisah. |
| 12 | Surat tertukar pasangan (1) | Hasil pengamat di Kali | Di Kali, surat pemeriksaan awal (`/health`) tidak dicatat di buku harian client. Pengamat lalu "memberikan" catatan surat berikutnya ke surat pemeriksaan itu, karena waktunya cukup dekat. | Pasangan hanya sah kalau **saling memilih sebagai yang terbaik**, dengan memperhitungkan surat yang masih dalam perjalanan. |

Awalnya kami menduga jam rekaman di Kali salah. Setelah dibandingkan, **jam kedua komputer ternyata
cocok** (45,8 ms vs 45,6 ms untuk surat yang sama) — yang salah adalah cara pengamat memasangkan surat.

---

## Tahap 3 — Mengapa balasan tertahan ~40 ms?

### Gejala
Surat dari Kali ke Windows butuh **46–96 ms**, padahal server Windows hanya bekerja **~1 ms**. Rekaman
dari kedua komputer sepakat: setiap kali server Windows mengirim lembar kedua (kartu member lalu balasan,
atau kepala balasan lalu isinya), lembar kedua tertahan **~40 ms**.

### Dugaan
Ada aturan lama di jaringan bernama **Nagle**: seorang kurir yang tidak mau mengantar paket kecil
berikutnya sebelum menerima tanda terima untuk paket sebelumnya. Di sisi lain, penerima di Linux
punya kebiasaan **menunda tanda terima (delayed ACK)** sampai ~40 ms, berharap bisa menitipkan tanda
terima bersama surat balasan. Kurir menunggu tanda terima, penerima menunggu surat berikutnya — keduanya
saling menunggu ~40 ms.

Lalu ditemukan penyebab dasarnya: di Windows, program server **mencoba mematikan kurir Nagle tetapi
diam-diam gagal**, karena sambungan yang diterima mencatat jenis protokolnya sebagai "0" alih-alih
"TCP", sehingga perintah mematikan Nagle dilewati tanpa pesan apa pun. Ini dibuktikan langsung dengan
memeriksa pengaturan sambungannya.

### Eksperimen

| Percobaan | Apa yang diubah | Waktu balasan rata-rata di Kali |
|---|---|---|
| A | tidak ada (kondisi awal) | **57,7 ms** |
| B | kurir Nagle di server Windows dimatikan | **9,7 ms** |
| C | + server mau menunggu 10 detik sebelum menutup telepon | **12,3 ms** (tidak membaik) |
| D | + client juga mau menunggu 10 detik | **5,3 ms** |

### Kesimpulan
1. **Kurir Nagle di Windows** adalah penyebab jeda ~40 ms (A → B). Terbukti.
2. Sisa ~4–5 ms datang dari **salam perkenalan HTTPS yang diulang di setiap surat**. Client dan server
   sama-sama menutup telepon setelah diam 5 detik — dan jeda antar-surat juga 5 detik, jadi setiap
   surat harus menelepon ulang dan berkenalan ulang. Menaikkan batas hanya di server (C) tidak cukup;
   **keduanya** harus dinaikkan (D), baru satu sambungan dipakai untuk semua surat. Terbukti.
3. Satu surat di percobaan A butuh 95,7 ms. Kemungkinan besar telepon ditutup tepat saat client mau
   memakainya lagi (batas 5 detik bertemu jeda 5 detik). Tidak muncul lagi di B–D, tapi belum
   terbukti langsung.

### Masalah yang ditemukan di tahap ini

| # | Masalah | Penjelasan sederhana | Solusi |
|---|---|---|---|
| 13 | Surat tertukar pasangan (2) | Surat pertama setelah server dinyalakan ulang "melamun" ~20 ms sebelum dicatat server (disebut *cold start*). Karena itu catatannya lebih dekat ke surat berikutnya, dan pasangannya tertukar. | Pencocokan kini memakai **logika sebab-akibat**: catatan server harus terjadi *di antara* surat masuk dan balasan keluar di kabel. Sebelumnya dipastikan dulu bahwa jam program dan jam rekaman di komputer yang sama cocok dalam ±1 ms. |
| 14 | Menaikkan batas waktu di server tidak berefek | Ternyata client juga punya batas 5 detik sendiri. | Opsi `--keep-alive` ditambahkan di client juga. |

---

## Hal lain di luar eksperimen

- **Nama Claude sebagai co-author di GitHub.** Commit pertama sempat memuat baris co-author. Baris itu
  sudah dihapus dari riwayat, dan semua commit berikutnya dibuat tanpa atribusi. Namun GitHub masih
  menyimpan salinan commit lama (terlihat dari halaman *Activity*). Pilihan penyelesaian (minta
  GitHub Support menghapusnya, atau membuat ulang repositori) **belum diputuskan**.

---

## Daftar semua masalah per tahap

| # | Tahap | Masalah singkat | Status |
|---|---|---|---|
| 1 | 1 — HTTP | Kolom TShark tidak ada di versi terpasang | Selesai |
| 2 | 1 — HTTP | Contoh data uji usang | Selesai |
| 3 | 1 — HTTP | Catatan di file pengaturan terbaca sebagai nilai | Selesai |
| 4 | 1 — HTTP | Kali di kelompok alamat berbeda | Selesai (jalur Host-Only) |
| 5 | 1 — HTTP | Alamat berubah saat pindah Wi-Fi | Selesai (alamat tetap) |
| 6 | 1 — HTTP | Kali tidak bisa internet | Selesai |
| 7 | 1 — HTTP | Izin firewall terlalu luas di Wi-Fi publik | Aturan sempit dibuat; izin lama perlu dinonaktifkan pemilik laptop |
| 8 | 2 — HTTPS | Kartu member dikira balasan | Selesai |
| 9 | 2 — HTTPS | KTP server Kali belum disalin | Selesai |
| 10 | 2 — HTTPS | Surat hantu di jaringan sungguhan | Selesai |
| 11 | 2 — HTTPS | Waktu balasan hanya sampai lembar pertama | Selesai |
| 12 | 2 — HTTPS | Surat tertukar (pemeriksaan awal tanpa catatan) | Selesai |
| 13 | 3 — Investigasi | Surat tertukar (cold start) | Selesai |
| 14 | 3 — Investigasi | Batas waktu client terlewat | Selesai |
| – | 3 — Investigasi | Penyebab *cold start* 20–50 ms setelah server dinyalakan ulang | **Belum diketahui** |

Setiap masalah pengamat (#8, #10–#13) kini punya **uji otomatis yang memakai rekaman asli** dari
kejadiannya, sehingga kalau masalah yang sama muncul lagi, uji itu akan gagal. Total 81 uji otomatis lulus.

---

## Pelajaran untuk penelitian

1. **Enkripsi menyembunyikan isi, bukan kebiasaan.** Waktu, arah, dan ukuran surat tetap terlihat
   dari luar, dan ukuran bisa dipakai menebak isi.
2. **Tanpa bisa membaca isi, pengamat harus menebak — dan tebakan mudah keliru.** Kelima kesalahan
   pengamat di Tahap 2–3 berakar dari hal ini: tiga karena pengamat harus menebak di mana satu surat
   berakhir dari ukuran amplop saja (#8, #10, #11), dua karena nomor resi tersembunyi sehingga
   pasangan surat harus ditebak dari waktu dan sambungan (#12, #13).
3. **Hasil dari satu titik pengamatan bisa tampak meyakinkan padahal salah.** Hampir semua kesalahan
   di atas baru ketahuan karena ada **dua komputer yang mengamati** dan **dua jenis bukti** (rekaman
   kabel dan buku harian program) yang saling dicocokkan.
4. **Uji di satu komputer tidak cukup.** Masalah #10 hanya muncul di jaringan sungguhan, karena di
   dalam satu komputer paket tidak pernah terpotong.
5. **Pengaturan bawaan bisa diam-diam salah.** Kurir Nagle yang gagal dimatikan di Windows tidak
   memberi pesan error apa pun; baru ketahuan dari pengukuran.

---

## Yang belum dikerjakan

1. **Membandingkan ulang surat terbuka vs amplop tersegel secara adil.** Perbandingan Tahap 1 vs
   Tahap 2 dilakukan saat kurir Nagle masih aktif dan telepon selalu ditutup, sehingga selisihnya
   bercampur dengan efek lain. Perlu diulang dengan pengaturan percobaan D.
2. **Mencari penyebab *cold start*** pada surat pertama setelah server dinyalakan ulang.
3. **Tahap 4: enkripsi isi surat (Fernet)** — isi surat dienkripsi lagi oleh program sebelum dimasukkan
   ke amplop HTTPS. Alatnya sudah disiapkan dan diuji, tapi belum dipasang.
4. **Keputusan soal commit lama** yang masih memuat nama Claude di GitHub.
