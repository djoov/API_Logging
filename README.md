# API Observability Lab — POC 1 (HTTP plaintext, dua arah)

Eksperimen terkontrol untuk mengamati komunikasi API dua arah antara **Windows (host)** dan
**Kali Linux (VM)**: request masuk/keluar, source/destination, endpoint, method, status code,
payload, latency, timestamp, correlation ID (`request_id`), dan arah traffic.

> Lingkup: lab milik sendiri, traffic dengan delay terkontrol. Tidak ada cracking, bypass, atau
> breaking encryption. Fase 2 (HTTPS/TLS) sudah tersedia (§15); Fase 3 (Fernet) baru disiapkan.

---

## Daftar isi
1. [Tujuan eksperimen](#1-tujuan-eksperimen)
2. [Arsitektur](#2-arsitektur)
3. [Instalasi Conda](#3-instalasi-conda)
4. [Instalasi dependency](#4-instalasi-dependency)
5. [Konfigurasi IP](#5-konfigurasi-ip)
6. [Menjalankan server](#6-menjalankan-server)
7. [Menjalankan client](#7-menjalankan-client-traffic-generator)
8. [Menjalankan observer](#8-menjalankan-observer)
9. [Testing dua arah (4 skenario)](#9-testing-dua-arah)
10. [Troubleshooting firewall](#10-troubleshooting-firewall)
11. [Troubleshooting port](#11-troubleshooting-port)
12. [Troubleshooting packet capture](#12-troubleshooting-packet-capture)
13. [Contoh output](#13-contoh-output)
14. [Keterbatasan POC](#14-keterbatasan-poc)
15. [Fase 2: HTTPS/TLS](#15-fase-2-httpstls)
16. [Eksperimen transport (Run A–D)](#16-eksperimen-transport-jeda-40-ms-dan-koneksi-baru-per-request)
17. [Roadmap application-layer encryption](#17-roadmap-fase-3-application-layer-encryption-fernet)
18. [Fase 4: Ollama lewat HTTPS gateway](#18-fase-4-ollama-lewat-https-gateway-prompt--jawaban-di-kedua-host)

Cerita lengkap proyek ini — tahap, masalah, dan solusinya, dengan istilah teknis yang dijelaskan
dalam bahasa sederhana: [`docs/laporan-perjalanan.md`](docs/laporan-perjalanan.md).
Konteks untuk sesi Claude Code: [`CLAUDE.md`](CLAUDE.md); log kerja bersama Windows ↔ Kali:
[`docs/collab-log.md`](docs/collab-log.md).

---

## 1. Tujuan eksperimen

Membuktikan bahwa, pada HTTP plaintext, setiap pertukaran API dapat diamati dan dikorelasikan
dari tiga sudut pandang independen:

| Sumber bukti | File | Apa yang dilihat |
|---|---|---|
| **Client log** | `logs/client-events.jsonl` | request yang *dikirim* host ini, round-trip latency |
| **Server log** | `logs/server-events.jsonl` | request yang *diterima* host ini, processing time, IP:port sumber |
| **Packet capture** | `logs/capture-events.jsonl` | apa yang benar-benar lewat di kabel (TShark/tcpdump) |

Observer menggabungkan ketiganya per `request_id` menjadi satu event `api_exchange` di
`logs/api-events.jsonl`. Hasil ini menjadi **baseline**: pada Fase 2/3, kita akan melihat bukti mana
yang hilang ketika transport atau payload dienkripsi.

## 2. Arsitektur

```
              Local / Virtual Network (mis. VirtualBox Host-Only)
  +------------------------------+          +------------------------------+
  |           WINDOWS            |          |          KALI LINUX          |
  |                              |  HTTP    |                              |
  |  server/api_server.py  :8000 | <------- | client/traffic_generator.py  |
  |  client/traffic_generator.py | -------> | server/api_server.py  :8000  |
  |  observer/observer.py        |          | observer/observer.py         |
  |    ├─ baca logs/*.jsonl      |          |    ├─ baca logs/*.jsonl      |
  |    └─ TShark (Npcap)         |          |    └─ TShark atau tcpdump    |
  +------------------------------+          +------------------------------+
```

Struktur project:

```
api-observability-lab/
├── README.md, environment.yml, .env.example, pytest.ini
├── config/example.env          # referensi semua variabel konfigurasi
├── common/                     # config.py, logging_utils.py, jsonl.py
├── models/schemas.py           # skema Pydantic request/response/event
├── server/api_server.py        # FastAPI: GET /health, POST /api/test
├── client/traffic_generator.py # generator traffic dengan count + delay
├── client/llm_client.py        # FASE 4: kirim prompt ke Ollama lewat gateway
├── observer/
│   ├── observer.py             # entry point observer
│   ├── capture_backend.py      # abstraksi TShark / tcpdump (HTTP + TLS)
│   ├── tls_flows.py            # FASE 2: rekonstruksi exchange dari record TLS terenkripsi
│   └── correlator.py           # penggabungan bukti per request_id / 4-tuple
├── gateway/ollama_gateway.py   # FASE 4: HTTPS gateway di depan Ollama (log prompt & jawaban)
├── llm/ollama_protocol.py      # FASE 4: membaca format streaming Ollama
├── tools/mock_ollama.py        # FASE 4: pengganti Ollama untuk lab tanpa model
├── security/
│   ├── tls_certs.py            # FASE 2: CA lab + sertifikat server
│   └── payload_crypto.py       # FASE 3: interface Fernet (belum dipakai)
├── secrets/                    # sertifikat & key (tidak di-commit)
├── scripts/                    # setup_windows.ps1, setup_kali.sh, run_demo.ps1, make_certs.py
├── logs/                       # output JSONL (tidak di-commit)
└── tests/                      # pytest
```

**Correlation ID.** Setiap request membawa `request_id` (UUID4) di **body JSON** *dan* di header
`X-Request-ID`. Server menggemakan ID itu di header response. Header ada di segmen TCP pertama,
sehingga packet capture tetap bisa membaca ID walaupun body terpecah ke beberapa segmen.
`tcp.stream` **bukan** correlation ID: dengan HTTP keep-alive, banyak request memakai satu koneksi
TCP yang sama (terbukti di smoke test: semua request ada di `tcp_stream=0`). `tcp_stream` hanya
disimpan sebagai metadata.

**Arah traffic.** Diambil dari `sender` (body / header `X-Sender`) dan `receiver` (response /
header `X-Receiver`), jadi `windows_to_kali` / `kali_to_windows`. Jika header tidak ada,
observer memakai peta `PEER_NAMES` (IP → nama).

## 3. Instalasi Conda

`environment.yml` adalah *source of truth* untuk kedua host.

**Windows (PowerShell)** — Miniconda sudah terpasang di laptop ini. Jika `conda` tidak dikenal di
PowerShell, jalankan sekali `conda init powershell` lalu buka terminal baru.

**Kali (Bash)**:
```bash
wget https://repo.anaconda.com/miniconda/Miniconda3-latest-Linux-x86_64.sh
bash Miniconda3-latest-Linux-x86_64.sh      # ikuti prompt, lalu buka terminal baru
```

Jika Conda tidak tersedia/tidak ingin dipasang di Kali, pakai venv sebagai alternatif (versi paket
mengikuti daftar di `environment.yml`, yang tetap menjadi acuan):
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install fastapi uvicorn httpx pydantic python-dotenv cryptography pytest
```

## 4. Instalasi dependency

**Windows (PowerShell)**:
```powershell
cd D:\Project\researcher_01\api-observability-lab
conda env create -f environment.yml
conda activate api-observability
# atau semuanya sekaligus + inspeksi host:
powershell -ExecutionPolicy Bypass -File scripts\setup_windows.ps1
```

**Kali (Bash)** — salin folder project ke Kali (shared folder, `scp`, atau git), lalu:
```bash
cd ~/api-observability-lab
conda env create -f environment.yml
conda activate api-observability
# atau semuanya sekaligus + inspeksi host:
bash scripts/setup_kali.sh
```

Update env setelah `environment.yml` berubah: `conda env update -f environment.yml --prune`.

Tools capture (opsional, di luar Conda):
- Windows: Wireshark + Npcap (menyertakan `tshark.exe`). Tidak perlu ada di PATH — observer
  mencari di `C:\Program Files\Wireshark\` atau `TSHARK_PATH`.
- Kali: `sudo apt install tcpdump tshark`

## 5. Konfigurasi IP

Tidak ada IP yang di-hard-code. Semua ada di `.env` masing-masing host
(`Copy-Item .env.example .env` / `cp .env.example .env`). Referensi lengkap: `config/example.env`.

**Cari IP**

| | Perintah | Cari |
|---|---|---|
| Windows | `ipconfig` | adapter yang terhubung ke VM, mis. *VirtualBox Host-Only* (`Ethernet 2`) |
| Kali | `ip addr` atau `ip -brief addr` | interface ke host, mis. `eth0`/`eth1` |

> **Mode jaringan VM penting.** VirtualBox **NAT** (default) *tidak* mengizinkan Windows → Kali.
> Pakai **Host-Only Adapter** (disarankan untuk lab; Windows biasanya `192.168.56.1`) atau
> **Bridged**. Bisa juga NAT + Host-Only (dua adapter) agar Kali tetap punya internet.

**Isi `.env`**

```ini
# Windows .env                         # Kali .env
NODE_NAME=windows                      NODE_NAME=kali
APP_HOST=0.0.0.0                       APP_HOST=0.0.0.0
APP_PORT=8000                          APP_PORT=8000
TARGET_HOST=<KALI_IP>                  TARGET_HOST=<WINDOWS_IP>
TARGET_PORT=8000                       TARGET_PORT=8000
OBSERVER_INTERFACE=<nomor dari -D>     OBSERVER_INTERFACE=<eth0/eth1>
CAPTURE_FILTER=tcp port 8000           CAPTURE_FILTER=tcp port 8000
```

Komentar di `.env` harus di baris sendiri — `TARGET_HOST=   # komentar` dibaca python-dotenv
sebagai nilai `# komentar`.

**Uji konektivitas**

| Arah | Perintah |
|---|---|
| Windows → Kali | `ping <KALI_IP>` |
| Kali → Windows | `ping <WINDOWS_IP>` *(bisa gagal karena Windows memblokir ICMP; lihat §10 — tidak berarti port 8000 tertutup)* |
| Port di Kali (dari Windows) | `Test-NetConnection <KALI_IP> -Port 8000` → `TcpTestSucceeded : True` |
| Port di Windows (dari Kali) | `curl http://<WINDOWS_IP>:8000/health` → `{"status":"ok"}` |

Uji port hanya berhasil jika server di host tujuan sedang berjalan (§6).

## 6. Menjalankan server

Jalankan dari root project, dengan env aktif.

**Windows (PowerShell)**
```powershell
conda activate api-observability
python server/api_server.py
# [10:00:00] SERVER node=windows listening on 0.0.0.0:8000
```
Saat pertama kali bind ke `0.0.0.0`, Windows bisa menampilkan dialog firewall untuk python.exe.
Izinkan hanya untuk **Private**/jaringan yang relevan, atau pakai rule di §10.

**Kali (Bash)**
```bash
conda activate api-observability
python server/api_server.py
```

Opsi: `--host`, `--port`, `--node-name` (override `.env`). `SIMULATED_WORK_MS=50` menambah kerja
buatan di server agar beda processing time vs. network time terlihat jelas.

Endpoint:
- `GET /health` → `{"status": "ok"}`
- `POST /api/test` → body `{message, sender, request_id, sequence, sent_at}`; response
  `{status, message, receiver, request_id, sequence, received_at, processing_time_ms}`.
  Validasi: `request_id` harus UUID, `sequence ≥ 1`, `sent_at` wajib ber-timezone, `sender`
  huruf kecil/angka/`-`, field tambahan ditolak (422).

## 7. Menjalankan client (traffic generator)

```bash
python client/traffic_generator.py --target http://<IP_TUJUAN>:8000 --sender <nama> --count 5 --delay 5
```
(Bisa juga `cd client` lalu `python traffic_generator.py ...`.)

| Opsi | Default | Keterangan |
|---|---|---|
| `--target` | `TARGET_HOST:TARGET_PORT` | base URL host tujuan |
| `--sender` | `NODE_NAME` | nama host ini |
| `--count` | `DEFAULT_REQUEST_COUNT` (5) | 1..1000, **tidak ada infinite loop** |
| `--delay` | `DEFAULT_DELAY_SECONDS` (5) | detik antar-request |
| `--timeout` | 5 | timeout per request |
| `--retries` / `--retry-backoff` | 2 / 1 s | retry hanya untuk error koneksi/timeout/5xx, tidak untuk 4xx; `request_id` sama di setiap retry |
| `--skip-health` | – | lewati pengecekan `/health` di awal |

Sebelum mengirim, client memanggil `/health`; jika gagal, ia berhenti dengan petunjuk diagnosis.
Exit code: 0 semua sukses, 1 ada yang gagal, 2 target tidak terjangkau/konfigurasi salah.

## 8. Menjalankan observer

```bash
python observer/observer.py --list-interfaces      # lihat interface capture
python observer/observer.py                        # mode both: app logs + packet capture
python observer/observer.py --mode app             # tanpa capture (tidak butuh TShark/tcpdump/admin)
```

| Opsi | Keterangan |
|---|---|
| `--mode app\|capture\|both` | sumber bukti (default `both`; jika capture gagal, otomatis lanjut dengan app logs) |
| `--interface` | override `OBSERVER_INTERFACE` |
| `--filter` | override `CAPTURE_FILTER` (BPF, default `tcp port <APP_PORT>`) |
| `--backend auto\|tshark\|tcpdump` | `auto` memilih TShark (reassembly TCP), lalu tcpdump |
| `--duration N` | berhenti setelah N detik (default: sampai Ctrl+C) |
| `--from-start` | ikut memproses baris lama di log aplikasi |
| `--replay` | bangun ulang event dari log aplikasi yang sudah ada, lalu keluar |
| `--read-pcap FILE` | analisis pcap/pcapng offline dengan TShark, lalu keluar |

**Windows** — interface dipilih lewat nomor atau nama dari `tshark -D`
(`& "C:\Program Files\Wireshark\tshark.exe" -D`). Di laptop ini VirtualBox Host-Only adalah
`Ethernet 2`, saat inspeksi bernomor **8** — tapi nomor bisa berubah saat adapter bertambah/berkurang,
jadi cek ulang. Nama device `\Device\NPF_{...}` lebih stabil daripada nomor.

**Kali** — capture butuh hak khusus:
```bash
# opsi A (disarankan): user masuk grup wireshark, lalu logout/login
sudo usermod -aG wireshark "$USER"
python observer/observer.py --interface eth1
# opsi B: jalankan dengan sudo memakai python dari env
sudo -E "$(which python)" observer/observer.py --interface eth1
# opsi C: capture ke file dengan tcpdump, lalu analisis offline dengan TShark
sudo tcpdump -i eth1 -w lab.pcap tcp port 8000     # Ctrl+C setelah traffic selesai
python observer/observer.py --mode capture --read-pcap lab.pcap
```

Observer menulis:
- `logs/api-events.jsonl` — event `api_exchange` hasil korelasi (satu per exchange)
- `logs/capture-events.jsonl` — record HTTP mentah dari capture (untuk analisis lanjutan)

### Tiga jenis latency (jangan disamakan)

| Field | Diukur oleh | Rentang waktu |
|---|---|---|
| `client_rtt_ms` | client | mulai kirim request → seluruh response diterima. Termasuk jaringan dua arah, TCP handshake (request pertama saja, berikutnya reuse koneksi keep-alive), antrean dan processing server |
| `server_processing_ms` | server | request diterima middleware → response siap. **Tidak** termasuk jaringan |
| `wire_latency_ms` | packet capture di host observer | paket request terlihat → paket response terlihat. Di host **client** ≈ RTT jaringan + processing; di host **server** ≈ processing + stack server (hampir tanpa jaringan) |

`latency_ms` = angka round-trip terbaik yang tersedia; `latency_source` menjelaskan asalnya
(`client_rtt`, `wire`, atau `wire_server_side`). `vantage` menandai posisi observer terhadap exchange
(`client_side` / `server_side`). Selisih `client_rtt_ms − server_processing_ms` ≈ biaya jaringan +
serialisasi + overhead client.

## 9. Testing dua arah

Siapkan dulu: `.env` di kedua host sudah terisi (§5) dan konektivitas port sudah diuji.

### Skenario 1 — Windows server, Kali client
```powershell
# Windows, terminal 1
python server/api_server.py
# Windows, terminal 2
python observer/observer.py
```
```bash
# Kali
python client/traffic_generator.py --target http://<WINDOWS_IP>:8000 --sender kali --count 5 --delay 5
```
Hasil di Windows: event `kali_to_windows`, `vantage=server_side`.

### Skenario 2 — Kali server, Windows client
```bash
# Kali, terminal 1
python server/api_server.py
# Kali, terminal 2
python observer/observer.py --interface eth1
```
```powershell
# Windows
python client/traffic_generator.py --target http://<KALI_IP>:8000 --sender windows --count 5 --delay 5
```
Hasil di Kali: event `windows_to_kali`. Jalankan juga observer di Windows untuk melihat sisi client
(`vantage=client_side`, `latency_source=client_rtt`).

### Skenario 3 — keduanya server + client (traffic dua arah bersamaan)
Di **setiap** host jalankan 3 terminal: server, observer, lalu traffic generator ke host lawan.
Observer di tiap host akan mencatat **kedua arah**: exchange keluar (dari client log + capture) dan
masuk (dari server log + capture).

### Skenario 4 — controlled traffic, masing-masing arah
```bash
# Kali -> Windows: 5 request, delay 5 detik
python client/traffic_generator.py --target http://<WINDOWS_IP>:8000 --sender kali --count 5 --delay 5
```
```powershell
# Windows -> Kali: 5 request, delay 7 detik
python client/traffic_generator.py --target http://<KALI_IP>:8000 --sender windows --count 5 --delay 7
```
Delay berbeda membuat request kedua arah saling berselang-seling, sehingga korelasi
berbasis `request_id` teruji pada traffic bersamaan.

Verifikasi (di host mana pun):
```powershell
# Windows
Get-Content logs\api-events.jsonl | ConvertFrom-Json | Group-Object direction | Select-Object Name, Count
```
```bash
# Kali
python -c "import json,collections; print(collections.Counter(json.loads(l)['direction'] for l in open('logs/api-events.jsonl')))"
```
Harapan: `windows_to_kali: 5` dan `kali_to_windows: 5` (ditambah event `GET /health` dari
pengecekan awal client).

### Smoke test satu mesin (sebelum melibatkan Kali)
```powershell
powershell -ExecutionPolicy Bypass -File scripts\run_demo.ps1            # app logs saja
powershell -ExecutionPolicy Bypass -File scripts\run_demo.ps1 -Capture   # + TShark di loopback Npcap
```
Memakai port 8765 dan `logs/demo/` sehingga tidak tercampur dengan log eksperimen.

### Unit test
```bash
python -m pytest
```

## 10. Troubleshooting firewall

Jangan matikan firewall. Tambahkan hanya rule minimal, lalu hapus setelah eksperimen.

**Windows** (PowerShell **Run as Administrator**)
```powershell
# Diagnosis
Get-NetFirewallProfile | Select-Object Name, Enabled
Get-NetConnectionProfile                            # profil jaringan aktif
Get-NetFirewallRule -Direction Inbound -Enabled True |
    Where-Object DisplayName -like "*python*" | Select-Object DisplayName, Action, Profile
# Rule "block" untuk python.exe (dari klik "Cancel" di dialog firewall) mengalahkan rule allow — nonaktifkan rule itu.

# Izinkan TCP 8000 hanya dari subnet lokal (adapter Host-Only biasanya berprofil Public/Unidentified, maka Profile Any)
New-NetFirewallRule -DisplayName "API Observability Lab TCP 8000" -Direction Inbound -Protocol TCP `
    -LocalPort 8000 -RemoteAddress LocalSubnet -Action Allow -Profile Any
# (sama dengan: scripts\setup_windows.ps1 -AddFirewallRule)

# PENTING: LocalSubnet hanya mencakup subnet adapter Windows sendiri. Jika Kali ada di subnet lain
# yang di-route (mis. Windows 192.168.33.x, Kali 192.168.34.x -> `tracert`/TTL 63 menunjukkan 1 hop router),
# batasi ke IP Kali:
New-NetFirewallRule -DisplayName "API Observability Lab TCP 8000" -Direction Inbound -Protocol TCP `
    -LocalPort 8000 -RemoteAddress <KALI_IP> -Action Allow -Profile Any
# (sama dengan: scripts\setup_windows.ps1 -AddFirewallRule -RemoteAddress <KALI_IP>)

# Opsional: izinkan ping dari subnet lokal
New-NetFirewallRule -DisplayName "API Observability Lab ICMPv4" -Direction Inbound -Protocol ICMPv4 `
    -IcmpType 8 -RemoteAddress LocalSubnet -Action Allow -Profile Any

# Hapus setelah selesai
Remove-NetFirewallRule -DisplayName "API Observability Lab TCP 8000"
Remove-NetFirewallRule -DisplayName "API Observability Lab ICMPv4"
```

**Kali** — default Kali tidak punya firewall aktif. Jika ada:
```bash
sudo ufw status                     # jika aktif:
sudo ufw allow from <WINDOWS_IP> to any port 8000 proto tcp
sudo ufw delete allow from <WINDOWS_IP> to any port 8000 proto tcp   # setelah selesai
sudo nft list ruleset               # atau: sudo iptables -S INPUT
```

## 11. Troubleshooting port

| Gejala | Kemungkinan penyebab | Cek |
|---|---|---|
| `connection failed ... refused` | server tidak jalan, atau bind ke `127.0.0.1` | log server harus `listening on 0.0.0.0:8000` |
| timeout | firewall / mode jaringan VM (NAT) / IP salah | §5, §10; `Test-NetConnection` |
| `address already in use` / `[WinError 10048]` | port dipakai proses lain | lihat di bawah; atau pakai `APP_PORT` lain |
| 422 | payload tidak valid | pesan `detail` di response |

```powershell
# Windows: siapa yang memakai port 8000?
Get-NetTCPConnection -LocalPort 8000 -State Listen | Select-Object LocalAddress, OwningProcess
Get-Process -Id <PID>
```
```bash
# Kali
sudo ss -ltnp 'sport = :8000'
```

## 12. Troubleshooting packet capture

| Gejala | Penyebab / solusi |
|---|---|
| `CAPTURE disabled: no capture interface configured` | isi `OBSERVER_INTERFACE` atau `--interface` (lihat `--list-interfaces`) |
| Tidak ada baris `WIRE ...` padahal traffic ada | interface salah (mis. memilih Wi-Fi padahal traffic lewat Host-Only), atau port di `CAPTURE_FILTER` berbeda dengan `APP_PORT` |
| Windows: `The capture session could not be initiated` / tidak ada interface | Npcap belum terpasang atau terpasang dengan opsi "restrict to Administrators" → jalankan terminal sebagai Administrator atau pasang ulang Npcap tanpa opsi itu |
| Kali: `You don't have permission to capture` | lihat §8 (grup `wireshark`, `sudo`, atau `tcpdump -w` + `--read-pcap`) |
| `--read-pcap` menghasilkan 0 event | filter port tidak cocok; pakai `--filter "tcp port <PORT>"` |
| Traffic lokal (127.0.0.1) tidak tertangkap di Windows | pakai interface `\Device\NPF_Loopback` |
| `payload` kosong pada event capture-only (tcpdump) | tcpdump tidak melakukan TCP reassembly; body sering di segmen terpisah (httpx mengirim header dan body dalam segmen berbeda). Payload diambil dari app log — gunakan `--mode both` |

## 13. Contoh output

**Server**
```
[11:08:21] SERVER node=local-server listening on 127.0.0.1:8765
[11:08:26] REQUEST POST /api/test from=127.0.0.1:53434 request_id=c75759cf-2bcf-409a-96f6-c06e117d742f sender=local-client
[11:08:26] RESPONSE request_id=c75759cf-2bcf-409a-96f6-c06e117d742f status=200 processing=19.9ms
```

**Client**
```
[11:08:26] HEALTH http://127.0.0.1:8765/health ok
[11:08:26] SEND #1 request_id=c75759cf-2bcf-409a-96f6-c06e117d742f target=http://127.0.0.1:8765/api/test attempt=1
[11:08:26] RESPONSE #1 status=200 latency=27.7ms server_processing=19.9ms receiver=local-server
[11:08:26] WAIT 2.0s
...
[11:08:30] SUMMARY planned=3 sent=3 ok=3 failed=0
[11:08:30] SUMMARY client_rtt min=13.4ms avg=19.8ms max=27.7ms | server_processing avg=9.7ms
```

**Observer**
```
[11:08:27] WIRE 127.0.0.1:53434 -> 127.0.0.1:8765 POST /api/test stream=0 bytes=449 request_id=c75759cf-...
[11:08:27] WIRE 127.0.0.1:8765 -> 127.0.0.1:53434 status=200 stream=0 bytes=433 request_id=c75759cf-...
[11:08:28] OBSERVED local-client -> local-server POST /api/test status=200 latency=27.7ms (client_rtt) request_id=c75759cf-... evidence=capture,client_log,server_log
```
(Output di atas adalah hasil smoke test nyata di laptop ini. Di eksperimen dua host, arahnya
menjadi `windows -> kali` / `kali -> windows`.)

**`logs/api-events.jsonl`** — ilustrasi format untuk skenario dua host (nilai angka hanya contoh;
di file asli satu event = satu baris)
```json
{
  "event_type": "api_exchange",
  "timestamp": "2026-09-24T04:08:26.851Z",
  "observer": "windows",
  "direction": "windows_to_kali",
  "vantage": "client_side",
  "source_ip": "192.168.56.1", "source_port": 53434,
  "destination_ip": "<KALI_IP>", "destination_port": 8000,
  "method": "POST", "endpoint": "/api/test", "status_code": 200,
  "latency_ms": 25.4, "latency_source": "client_rtt",
  "client_rtt_ms": 25.4, "server_processing_ms": 3.1, "wire_latency_ms": 22.9,
  "request_id": "c75759cf-2bcf-409a-96f6-c06e117d742f",
  "tcp_stream": 0, "request_bytes": 449, "response_bytes": 433,
  "evidence": ["capture", "client_log"],
  "payload": {"message": "hello from windows #1", "sender": "windows", "sequence": 1},
  "error": null
}
```
Event arah sebaliknya di observer Windows: `"direction": "kali_to_windows"`, `"vantage": "server_side"`,
`"evidence": ["capture", "server_log"]`, `"latency_source": "wire_server_side"`.

## 14. Keterbatasan POC

- **HTTP plaintext.** Payload terbaca di kabel — memang itu yang ingin dibuktikan sebagai baseline.
- **Packet capture tidak selalu melihat body utuh.** TShark melakukan TCP reassembly sehingga
  biasanya bisa membaca JSON; tcpdump tidak. Jika capture dimulai di tengah koneksi, paket hilang,
  atau body besar, body bisa tidak terbaca. Karena itu payload juga diambil dari app log.
- **Satu titik capture per host.** Observer hanya melihat traffic di interface host itu sendiri.
  `wire_latency_ms` bermakna berbeda di sisi client dan server (§8).
- **Jam kedua host tidak disinkronkan.** Jangan mengurangkan timestamp Windows dari timestamp Kali
  untuk menghitung one-way latency; gunakan durasi yang diukur di satu host saja
  (`client_rtt_ms`, `server_processing_ms`, `wire_latency_ms`). Untuk one-way latency perlu NTP/PTP.
- **Korelasi hanya untuk traffic lab.** Request tanpa `X-Request-ID` (mis. `curl`) tetap dicatat
  dengan ID yang dibuat server (dipasangkan lewat `http.request_in` di TShark), tetapi tidak ada
  client log-nya.
- **Konkurensi sederhana.** Korelasi aman untuk request yang saling bertumpuk, tetapi observer
  menulis JSONL biasa (tanpa rotasi, tanpa database) — cocok untuk puluhan hingga ratusan request.
- **Parsing tcpdump berbasis teks** (`-A`), cukup untuk request kecil; TShark lebih andal.
- Console memakai waktu lokal; semua JSONL memakai **UTC**.

## 15. Fase 2: HTTPS/TLS

Traffic yang sama seperti Fase 1, tetapi transport-nya TLS. Observer **tidak mendekripsi apa pun**
(tidak ada private key server, tidak ada `SSLKEYLOGFILE`, tidak ada `verify=False`). Tujuannya
mengukur apa yang *masih* bisa diamati dari luar ketika transport dienkripsi.

### 15.1 Sertifikat lab
Satu CA lab lokal menandatangani sertifikat server tiap host. SubjectAltName berisi IP yang
dipakai client, jadi verifikasi hostname/IP tetap aktif. Buat **di Windows** (CA key tetap di sana):

```powershell
python scripts/make_certs.py ca
python scripts/make_certs.py server --name windows --ip 192.168.56.1 --ip 127.0.0.1 --dns localhost
python scripts/make_certs.py server --name kali --ip 192.168.56.10
python scripts/make_certs.py show
```

Hasil di `secrets/` (di-`.gitignore`, tidak pernah ke GitHub):

| File | Tinggal di | Salin ke Kali? |
|---|---|---|
| `ca.key` | Windows | **tidak pernah** |
| `ca.pem` | Windows + Kali | ya (publik, untuk verifikasi) |
| `windows.pem` / `windows.key` | Windows | tidak |
| `kali.pem` / `kali.key` | Kali | ya, lalu boleh dihapus dari Windows |

Salin lewat jaringan lab (Host-Only), misalnya dengan SSH di Kali:
```bash
# Kali
sudo systemctl start ssh
mkdir -p ~/API_Logging/secrets
```
```powershell
# Windows (scp bawaan Windows)
scp secrets\ca.pem secrets\kali.pem secrets\kali.key <user-kali>@192.168.56.10:~/API_Logging/secrets/
```
```bash
# Kali
chmod 600 ~/API_Logging/secrets/kali.key
sudo systemctl stop ssh      # jika SSH tidak dipakai lagi
```

### 15.2 Konfigurasi
```ini
# Windows .env (tambahan)               # Kali .env (tambahan)
TLS_CERT_FILE=secrets/windows.pem       TLS_CERT_FILE=secrets/kali.pem
TLS_KEY_FILE=secrets/windows.key        TLS_KEY_FILE=secrets/kali.key
TARGET_SCHEME=https                     TARGET_SCHEME=https
TLS_CA_FILE=secrets/ca.pem              TLS_CA_FILE=secrets/ca.pem
```
Kosongkan keempat baris untuk kembali ke HTTP (Fase 1). Restart server setelah mengubah `.env`.

### 15.3 Menjalankan
Perintahnya **sama** dengan Fase 1 (§6–§9). Server menampilkan `listening on https://...`, client
menampilkan `HEALTH ... ok (TLSv1.3, TLS_AES_256_GCM_SHA384)`. Observer otomatis memakai
`--transport https` jika `TLS_CERT_FILE` atau `TARGET_SCHEME=https` diisi; opsi ini memaksa TShark
mendekode port API sebagai TLS (`-d tcp.port==8000,tls`).

Uji lokal satu mesin (CA demo sekali pakai di `logs/demo/certs`):
```powershell
powershell -ExecutionPolicy Bypass -File scripts\run_demo.ps1 -Capture -Tls
```

Uji manual dari Kali: `curl --cacert secrets/ca.pem https://192.168.56.1:8000/health`
(tanpa `--cacert` curl harus **menolak** — itu tanda verifikasi bekerja).

### 15.4 Apa yang berubah pada observasi (hasil smoke test nyata)

| Yang diamati | Fase 1 (HTTP) | Fase 2 (HTTPS) |
|---|---|---|
| IP, port, TCP stream | terlihat di kabel | terlihat di kabel |
| Waktu request/response (`wire_latency_ms`) | terlihat | **terlihat** (dari timing record terenkripsi): sampai record response *terakhir*; `wire_ttfb_ms` = sampai record *pertama* |
| Ukuran request/response | ukuran HTTP | ukuran record TLS (≈ HTTP + ~17 B overhead per record) — **ukuran tetap bocor** |
| Versi TLS, cipher | – | terlihat (ServerHello), mis. `TLSv1.3`, `TLS_AES_256_GCM_SHA384` |
| SNI | – | kosong, karena client memakai IP (akan terlihat jika memakai hostname) |
| Method, URI, status, header | terlihat | **tidak terlihat** |
| `X-Request-ID`, body JSON | terlihat | **tidak terlihat** |
| Korelasi capture ↔ app log | `capture_match=request_id` | `capture_match=4tuple_time` (lihat bawah) |
| Observer tanpa app log (host ketiga) | event lengkap | hanya `evidence=["capture_tls"]`: arah, waktu, ukuran; `request_id`/endpoint/status `null` |

**Korelasi tanpa `request_id` di kabel.** Karena ID terenkripsi, observer memasangkan exchange TLS
dengan log aplikasi di host yang sama dengan tiga syarat:
1. **4-tuple koneksi sama** (IP:port client → port server);
2. **kausalitas waktu**: log server harus berada *di dalam* rentang exchange di kabel
   (request masuk ≤ `received_at`, `completed_at` ≤ response keluar), log client harus *mencakup*
   rentang itu. Jam aplikasi dan jam capture di host yang sama terukur selaras ±1 ms; toleransi 2 ms;
3. **pasangan terbaik timbal-balik**: exchange dan log harus saling memilih sebagai kandidat terbaik,
   termasuk mempertimbangkan exchange yang masih berlangsung.

Ini bekerja karena HTTP/1.1 dalam satu koneksi berurutan. Inilah titik di mana metadata TCP yang di
Fase 1 hanya "tambahan" menjadi satu-satunya jembatan — dan hasilnya lebih rapuh: dua kali pencocokan
sederhana "waktu terdekat" menukar pasangan di koneksi keep-alive (lihat §16 dan
`docs/laporan-perjalanan.md`).

**Cara exchange direkonstruksi dari record terenkripsi** (`observer/tls_flows.py`): record data dari
client membuka request, record dari server setelahnya adalah response, record client berikutnya
menutup exchange sebelumnya. Yang dilewati:
- record terenkripsi server **sebelum** Finished dari client (sisa handshake; di NIC nyata dengan MTU
  1500 datang di frame terpisah dari ServerHello, di loopback tidak);
- gelombang pertama record server setelah handshake TLS 1.3 (*NewSessionTicket*) — bisa datang sebelum,
  sesudah, atau bahkan di tengah request pertama;
- record seukuran alert (≤ 24 B, mis. close_notify).

`wire_latency_ms` diukur sampai record response **terakhir**; `wire_ttfb_ms` sampai yang **pertama**.
Keduanya bisa berbeda jauh ketika response terpecah dan bagian kedua tertahan (lihat §16).

### 15.5 Keterbatasan Fase 2
- Rekonstruksi exchange mengasumsikan HTTP/1.1 (tanpa pipelining) dan satu gelombang session ticket
  per koneksi (default OpenSSL/Python `ssl`). HTTP/2 multiplexing akan mematahkan asumsi ini.
- Klasifikasi TLS hanya dengan TShark. tcpdump di Kali: rekam `tcpdump -w` lalu `--read-pcap`.
- Ukuran record adalah ukuran terenkripsi, bukan ukuran payload persis.
- Korelasi 4-tuple hanya mungkin di host yang punya app log; observer pihak ketiga hanya punya
  metadata.
- Pengecekan `/health` dari traffic generator tidak ditulis ke client log, jadi di host client
  exchange itu muncul sebagai `evidence=["capture_tls"]` saja (benar secara data, bukan error).
- Rekonstruksi mengasumsikan client ala OpenSSL yang mengirim ChangeCipherSpec sebelum Finished.

### 15.6 Troubleshooting TLS

| Pesan | Arti / solusi |
|---|---|
| `TLS certificate rejected: ... CERTIFICATE_VERIFY_FAILED` | `TLS_CA_FILE` bukan `ca.pem` lab, atau IP target tidak ada di SAN sertifikat server (`make_certs.py show`) |
| `TLS handshake failed ... server is probably plain HTTP` | target `https://` tapi server belum HTTPS (cek `TLS_CERT_FILE` di host server, restart) |
| Client `http://` ke server HTTPS: `RemoteProtocolError`/disconnect | ubah `TARGET_SCHEME=https` |
| `CONFIG ERROR TLS_CERT_FILE not found` | path relatif dihitung dari root project; cek `ls secrets/` |
| Observer tidak menampilkan `WIRE TLS` | observer dijalankan dengan `--transport http` atau interface salah |

## 16. Eksperimen transport: jeda ~40 ms dan koneksi baru per request

Dijalankan 24 September 2026, HTTPS, arah **Kali → Windows**, 5 request, `--delay 5`, jaringan
Host-Only. Server Windows memakai opsi baru `--tcp-nodelay` dan `--keep-alive`; client memakai
`--keep-alive` (default semua opsi = perilaku asli).

| Run | Server Windows | Client Kali | RTT client rata-rata (rentang) | Wire di server (POST) |
|---|---|---|---|---|
| A | default | default | 57,7 ms (46,0–95,7) | 39–48 ms |
| B | `--tcp-nodelay` | default | 9,7 ms (5,8–13,8) | 3,2–4,3 ms |
| C | `--tcp-nodelay --keep-alive 10` | default | 12,3 ms (7,1–17,1) | 2,9–3,9 ms |
| D | `--tcp-nodelay --keep-alive 10` | `--keep-alive 10` | 5,3 ms (4,8–5,7) | 2,8–5,2 ms |

**Temuan:**
1. **Nagle di server Windows** (A → B). uvicorn/asyncio di Windows *tidak* mematikan Nagle: socket
   yang diterima melaporkan `proto=0`, sehingga `asyncio.base_events._set_nodelay` melewatkannya
   (diverifikasi langsung: `TCP_NODELAY=0` pada socket yang diterima). Setiap kali server mengirim
   data kedua (response setelah session ticket, atau body setelah header) sementara data pertama
   belum di-ACK, data itu ditahan sampai delayed ACK dari Linux (≈40 ms). Terlihat konsisten di dua
   titik capture (Windows dan Kali). `--tcp-nodelay` memasang `TCP_NODELAY` di socket listening;
   socket yang diterima mewarisinya (diverifikasi di Windows).
2. **Handshake TCP+TLS per request** (B/C → D). Koneksi hanya dipakai ulang jika jeda antar-request
   lebih pendek dari batas idle **di kedua sisi**; uvicorn dan httpx sama-sama default 5 detik. Run C
   (hanya server yang dinaikkan) tidak membaik; Run D (keduanya) memakai **satu koneksi TLS** untuk
   semua request. Biaya handshake di link ini ≈ 4–5 ms.
3. **Anomali 95,7 ms di Run A (#4)**: konsisten dengan pacu batas idle 5 detik di client dan server
   dengan jeda tepat 5 detik; tidak muncul di B–D. *Tidak terbukti langsung* — capture hanya berisi
   record TLS, bukan FIN/RST.
4. **Terbuka:** request pertama setelah server di-restart tertahan 20–50 ms *sebelum* middleware
   mencatat `received_at` (terlihat di Fase 1, Run B, Run C). Penyebab belum diketahui.

**Implikasi untuk perbandingan Fase 1 vs Fase 2:** kedua fase dijalankan dengan pengaturan Run A,
sehingga selisih RTT yang terlihat bercampur dengan efek Nagle dan handshake per request.
Perbandingan yang adil perlu diulang dengan pengaturan Run D di kedua arah (belum dilakukan).

## 17. Roadmap Fase 3: application-layer encryption (Fernet)

```
plaintext → Fernet encrypt → HTTPS/TLS → network → TLS terminate → Fernet decrypt → original payload
```

Interface sudah tersedia di `security/payload_crypto.py` (dan diuji di
`tests/test_payload_crypto.py`), **belum** dipakai oleh server/client:

```python
from security.payload_crypto import generate_key, load_key, encrypt_payload, decrypt_payload

key = load_key()                          # dari FERNET_KEY atau file FERNET_KEY_FILE (bukan hard-code)
token = encrypt_payload(payload, key)     # dict -> str (Fernet token)
payload = decrypt_payload(token, key)     # str -> dict; key salah / token diubah -> PayloadCryptoError
```

Rencana integrasi:
1. Buat key: `python -c "from security.payload_crypto import generate_key; print(generate_key().decode())" > secrets/fernet.key`
   lalu salin ke host lain lewat jalur aman (bukan lewat API yang sedang diamati).
2. Client mengirim `{"request_id": ..., "sender": ..., "ciphertext": "<token>"}` — `request_id`
   tetap plaintext agar observasi/korelasi tetap mungkin di app layer; isi pesan dienkripsi.
3. Server mendekripsi dengan key yang sah, lalu memvalidasi isi dengan `ApiTestRequest`.
4. Ekspektasi observasi: bahkan pihak yang melihat body setelah TLS terminate (mis. reverse proxy,
   log middleware) hanya melihat ciphertext; hanya pemilik key yang melihat payload asli.

## 18. Fase 4: Ollama lewat HTTPS gateway (prompt & jawaban di kedua host)

Lanjutan dari POC awal (Ubuntu → Ollama di Windows lewat HTTP polos, `POST /api/generate`, capture
TShark). Sekarang traffic LLM **terenkripsi (HTTPS)** di jaringan, tetapi **prompt dan jawaban
lengkap tetap tercatat di kedua host** — di titik-titik yang memang sah melihat plaintext: client
(sebelum enkripsi) dan gateway (pemilik sertifikat server, setelah TLS dibuka). Lingkup: lab
pribadi, tidak keluar dari jaringan lokal.

```
 CLIENT HOST (Kali VM / Ubuntu PC)                 GATEWAY HOST (Windows laptop / Windows PC)
 client/llm_client.py ──HTTPS :8443──▶ gateway/ollama_gateway.py ──HTTP──▶ Ollama 127.0.0.1:11434
   log: prompt + jawaban (client-events)      log: prompt + jawaban (server-events)   (atau tools/mock_ollama.py)
 observer: app log + capture TLS             observer: app log + capture TLS
```

| Titik | Prompt & jawaban | Waktu, arah, ukuran |
|---|---|---|
| Log LLM client | ✔ | ✔ (+ TTFT dari sisi client) |
| Log gateway | ✔ | ✔ (+ TTFT dari sisi gateway, statistik Ollama) |
| Capture jaringan (TLS) | ✘ | ✔ — termasuk **ukuran tiap potongan streaming** |

### 18.1 Komponen
| File | Fungsi |
|---|---|
| `gateway/ollama_gateway.py` | HTTPS reverse proxy di depan Ollama; `POST /api/generate`, `POST /api/chat`, `GET /api/tags`, `GET /api/version`. Meneruskan streaming apa adanya, menyusun jawaban lengkap untuk log. `--tcp-nodelay` **aktif default** (lihat §16). |
| `client/llm_client.py` | Kirim prompt (`--prompt`, `--prompts-file`), `--endpoint generate\|chat`, `--stream/--no-stream`, `--count`, `--delay`; jawaban tampil live di terminal. Tanpa retry otomatis. |
| `llm/ollama_protocol.py` | Membaca format Ollama (NDJSON streaming / JSON tunggal) + statistik (`eval_count`, `load_duration`, …). |
| `tools/mock_ollama.py` | Pengganti Ollama untuk lab tanpa model/GPU (laptop ini). Jawabannya teks tiruan bertanda `[SIMULASI mock-ollama]`. |
| `scripts/run_llm_demo.ps1` | Smoke test satu mesin (mock + gateway + observer + client), opsi `-Capture`, `-NoStream`, `-RealOllama`. |

### 18.2 Lingkungan A — sekarang: laptop Windows + VM Kali (Host-Only)
**Windows (gateway host)**, `.env` tambahan:
```ini
OLLAMA_URL=http://127.0.0.1:11434
GATEWAY_HOST=192.168.56.1
GATEWAY_PORT=8443
OBSERVER_TLS_IDLE_SECONDS=30
OBSERVER_INCOMPLETE_TIMEOUT_SECONDS=900
```
```powershell
python tools/mock_ollama.py                       # atau Ollama asli (ollama serve)
python gateway/ollama_gateway.py
python observer/observer.py --filter "tcp port 8443"
# firewall (Administrator), hanya di adapter lab:
New-NetFirewallRule -DisplayName "API Observability Lab TCP 8443" -Direction Inbound -Protocol TCP `
    -LocalPort 8443 -InterfaceAlias "Ethernet 2" -RemoteAddress LocalSubnet -Action Allow -Profile Any
```
Sertifikat `secrets/windows.pem` sudah memuat `192.168.56.1`.

**Kali (client host)**, `.env` tambahan:
```ini
LLM_TARGET_URL=https://192.168.56.1:8443
LLM_MODEL=mock-llm
OBSERVER_TLS_IDLE_SECONDS=30
OBSERVER_INCOMPLETE_TIMEOUT_SECONDS=900
```
```bash
python observer/observer.py --filter "tcp port 8443"
python client/llm_client.py --prompt "Jelaskan TCP handshake" --count 3 --delay 5 --keep-alive 10
```

### 18.3 Lingkungan B — nanti: PC Windows (Ollama) + PC Ubuntu, satu LAN
Sama seperti A, dengan perbedaan:
1. **IP tetap**: buat *DHCP reservation* di router untuk kedua PC (atau IP statis), karena IP masuk ke
   SAN sertifikat.
2. **Sertifikat baru** untuk IP LAN PC Windows (di host yang memegang `ca.key`):
   `python scripts/make_certs.py server --name windows-pc --ip <IP_PC_WINDOWS>`; salin `ca.pem` ke Ubuntu.
3. **Ollama asli tetap di `127.0.0.1`** — jangan set `OLLAMA_HOST=0.0.0.0` (di POC awal Ollama dibuka
   langsung ke jaringan; sekarang hanya gateway yang terbuka). `LLM_MODEL` = model yang sudah di-*pull*.
4. **Firewall** Windows untuk 8443 dibatasi ke IP Ubuntu: `-RemoteAddress <IP_UBUNTU>` (bukan
   `LocalSubnet` jika LAN dipakai orang lain).
5. Ubuntu: `sudo apt install tshark`, tambahkan user ke grup `wireshark` (lihat §8).

### 18.4 Metrik LLM
| Field (`event.llm`) | Arti |
|---|---|
| `prompt`, `response` | teks lengkap (jawaban streaming disambung) |
| `client_ttft_ms` | *time to first token* dilihat client: kirim → potongan teks pertama |
| `gateway_ttft_ms` | TTFT dilihat gateway (tanpa jaringan client↔gateway) |
| `ollama_load_ms` | waktu memuat model = *cold start* sebenarnya |
| `response_tokens`, `tokens_per_s` | dari statistik Ollama (`eval_count`, `eval_duration`) |
| `client_total_ms`, `gateway_total_ms` | total waktu sampai jawaban selesai |

`wire_ttfb_ms` di event adalah waktu sampai **header HTTP** response lewat di jaringan — gateway
mengirim header begitu Ollama mulai merespons, jadi ini **bukan** token pertama. Untuk token
pertama pakai `llm.client_ttft_ms`.

### 18.5 Temuan awal (smoke test satu mesin, mock)
- Prompt dan jawaban identik di log client dan gateway, `request_id` sama, TLS 1.3.
- *Cold start* terlihat: request pertama TTFT ~570–650 ms (`ollama_load_ms`=500, simulasi), berikutnya ~25–40 ms.
- **Setiap potongan streaming = satu TLS record terenkripsi (~125–135 B)**. Isi tidak terbaca, tetapi
  jumlah dan ukuran potongan (≈ panjang token) terlihat oleh siapa pun yang merekam jaringan
  (*token-length side channel*).
- TShark bisa butuh >15 detik untuk mulai merekam; `run_llm_demo.ps1` menunggu sampai "Capturing on"
  sebelum mengirim prompt.

### 18.6 Keterbatasan
- Mock Ollama tidak menjalankan model sungguhan; waktu dan token-nya tiruan.
- `GET /health` gateway tidak dicatat sebagai exchange LLM, sehingga di capture muncul sebagai
  exchange terenkripsi tanpa log (sama seperti Fase 2).
- Prompt dan jawaban disimpan **utuh** di `logs/` (disengaja untuk penelitian). `logs/` tidak di-commit;
  jangan pakai data sensitif sungguhan di luar lab.
