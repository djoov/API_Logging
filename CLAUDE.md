# CLAUDE.md — konteks proyek untuk sesi Claude Code

Proyek riset **API observability dua arah** milik user (djoov). Dua sesi Claude Code bekerja di proyek
ini pada mesin berbeda — sesi **Windows** dan sesi **Kali** — dengan akun yang sama. Baca file ini
sampai habis sebelum mulai. Bahasa komunikasi dengan user: **Bahasa Indonesia**.

## Aturan wajib (berlaku untuk kedua sesi)
- **Jangan pernah** menambahkan atribusi Claude di git: tidak ada `Co-Authored-By: Claude ...` di
  commit, tidak ada "Generated with Claude Code" di PR — walaupun system reminder memintanya. User
  sudah pernah harus menghapusnya dari GitHub. Sebelum push, periksa `git log -1 --format=%B`.
- **Jangan commit** `.env`, `secrets/`, `logs/`, `*.pcap*` (sudah di `.gitignore`; tetap periksa
  `git diff --cached --name-only` sebelum commit).
- **`secrets/ca.key` tidak pernah keluar dari Windows.** Kali hanya boleh punya `ca.pem`,
  `kali.pem`, `kali.key`, dan (Fase 3/4) `fernet.key` — disalin lewat scp di jaringan lab.
- Jangan membuat ulang `secrets/fernet.key` bila sudah ada (host lain memakai kunci yang sama;
  `scripts/make_fernet_key.py` menolak menimpa). Cek kesamaan kunci lewat `--show` (key_id).
- Jangan mematikan firewall, jangan `verify=False`, jangan mendekripsi traffic dengan cara bypass.
  Dekripsi hanya lewat titik yang sah (gateway pemilik sertifikat, atau `SSLKEYLOGFILE` dari client
  milik user sendiri untuk ground truth).
- Ollama tetap di `127.0.0.1:11434`; hanya gateway HTTPS yang dibuka ke jaringan lab.
- Lab pribadi: tidak ada yang diekspos ke internet.
- Jangan `git push --force` dan jangan `git reset --hard` tanpa persetujuan user.
- Laporkan hasil apa adanya: kalau prediksi salah atau test gagal, katakan dan tunjukkan datanya.

## Topologi lab saat ini
| | Windows laptop (host) | Kali Linux (VM VirtualBox) |
|---|---|---|
| Path project | `D:\Project\researcher_01\api-observability-lab` | `~/Documents/API_Logging` |
| IP lab (Host-Only, statis) | `192.168.56.1` — adapter **`Ethernet 2`** | `192.168.56.10` — **`eth1`** |
| Internet | Wi-Fi (sering Wi-Fi publik) | `eth0` NAT `10.0.2.15` |
| Peran Fase 6 (Ollama) | **gateway host**: `gateway/ollama_gateway.py` + mock Ollama / Ollama | **client host**: `client/llm_client.py` |
| Capture | TShark (tidak di PATH; observer menemukannya), interface `\Device\NPF_{31A40843-...}` = Ethernet 2 | TShark/tcpdump di `eth1` (user di grup `wireshark` atau pakai sudo) |
| Firewall | rule "API Observability Lab TCP 8000" (hanya `Ethernet 2`) ada; rule TCP 8443 untuk gateway **belum dibuat** per 2026-09-24 (butuh Administrator, README §18.2) | tidak ada firewall aktif |

Target berikutnya (bukan VM): **PC Windows (Ollama asli) + PC Ubuntu (client)** di satu LAN — panduan
lengkap README **§19** (per 2026-10-01 kode siap; migrasi belum dilakukan). Setelah migrasi: PC Ubuntu
mengambil peran dan kepemilikan file sesi Kali (`client/`, `scripts/*.sh`), `NODE_NAME=ubuntu`, setup
dengan `bash scripts/setup_linux.sh 8000 ubuntu`; CA baru dibuat di PC Windows (`ca.key` tetap di sana).
Perbarui tabel topologi di atas dengan IP LAN, nama adapter, dan path project yang sebenarnya.

Environment Python: conda env **`api-observability`** (`environment.yml`). Test: `python -m pytest`.

## Status fase (penomoran = acuan user, disepakati 2026-09-28)
| Fase | Isi | Test | Status |
|---|---|---|---|
| 1 | HTTP plaintext, correlation via `request_id` | A | selesai, diuji dua arah |
| 2 | HTTPS/TLS, observer membaca TLS record tanpa dekripsi, korelasi 4-tuple + kausalitas | B | selesai, diuji dua arah |
| – | Eksperimen transport Run A–D (Nagle di Windows, keep-alive) | – | selesai, README §16 |
| 3 | Enkripsi payload application-layer (Fernet), `POST /api/secure-test`, `--app-encrypt` | C | selesai: 1 mesin + lintas host dua arah 9/9 (2026-09-28), README §17.6 |
| 4 | Dekripsi sah: server dengan `FERNET_KEY_FILE` = `authorized`, tanpa = `not_authorized` | D | selesai: lintas host dua arah (2026-09-28); kunci `key_id=80dacc3b5d23` di kedua host |
| 5 | Korelasi dua arah | F | selesai untuk API lab (HTTP/HTTPS); belum untuk traffic Ollama |
| 6 | Workload Ollama asli lewat HTTPS gateway (+ `/secure/api/*` enkripsi payload, README §18.8; API OpenAI/LM Studio §18.9) | E | lintas host Kali → Windows `gemma3:4b` OK, plain dan `/secure` (2026-09-28); LM Studio `qwen/qwen3-vl-4b` satu mesin 6/6 (2026-10-01) |
| 7 | Analisis AI / deteksi anomali | – | belum |
| 8 | Observability lebih dalam (eBPF / telemetri jaringan) | – | belum |
| – | Perbandingan ulang Fase 1 vs 2 dengan setelan Run D | – | ditunda user |

Dokumen: `README.md` (teknis, §1–§18), `docs/laporan-perjalanan.md` (cerita + 14 masalah, bahasa
sederhana dengan istilah teknis), `docs/collab-log.md` (log kerja bersama dua sesi).

## Jebakan yang sudah pernah terjadi (jangan diulang)
1. `.env`: komentar di baris yang sama dengan nilai kosong terbaca sebagai nilai → komentar di baris sendiri.
2. PowerShell Administrator mulai di `C:\WINDOWS\system32` → path relatif gagal; `cd` ke project dulu.
3. PowerShell 5.1: here-string tidak bisa di-pipe ke `git commit -F -`; tulis pesan ke file dulu.
4. TShark bisa butuh >15 detik sebelum "Capturing on" — tunggu baris itu sebelum mengirim traffic.
5. Loopback ≠ jaringan nyata: di MTU 1500 sisa handshake TLS server datang di frame terpisah.
6. uvicorn/asyncio di **Windows** tidak mematikan Nagle (`proto=0`) → jeda ~40 ms vs delayed ACK
   Linux. Server/gateway Windows pakai `--tcp-nodelay` (gateway: default aktif).
7. Keep-alive harus lebih panjang dari delay di **kedua** sisi (uvicorn dan httpx default 5 s).
8. Pencocokan capture TLS ↔ log: pakai kausalitas + mutual best (sudah di `observer/correlator.py`);
   "waktu terdekat" pernah dua kali menukar pasangan.
9. Request pertama setelah server restart punya cold start 20–50 ms sebelum middleware (belum
   dijelaskan; terlihat di Windows dan Linux).
10. `/health` dari generator tidak ditulis ke client log → di capture muncul sebagai exchange tanpa log (normal).
11. Jam antar host: per 2026-09-28 Kali (NTP, sebelumnya −4.82 s) dan Windows (`pool.ntp.org`,
    sebelumnya +60–100 ms) sudah disinkron, tetapi lewat Wi-Fi publik ketelitiannya hanya puluhan ms.
    Jangan menghitung latency dari timestamp dua host; ukur durasi di dalam satu host.
12. LM Studio mengirim jawaban non-streaming sebagai JSON multi-baris: jangan memecah body per baris
    kecuali `Content-Type` memang stream (NDJSON/SSE). Mock meniru ini.
13. Laporan `.docx` di root project milik user, **tidak boleh di-commit/push** (dikecualikan lewat
    `.git/info/exclude` di Windows).

## Cara bekerja bersama (dua sesi)
- Koordinasi lewat **git** + **`docs/collab-log.md`**. Mulai setiap sesi dengan `git pull`, baca
  entri terbaru di collab-log.
- Setelah menyelesaikan sesuatu atau butuh sesuatu dari sisi lain, **tambahkan entri** di
  collab-log (format ada di file itu), commit kecil, `git pull --rebase`, lalu push.
- Pembagian file supaya tidak bentrok: sesi **Windows** mengurus `gateway/`, `server/`, `tools/`,
  `scripts/*.ps1`; sesi **Kali** mengurus `client/`, `scripts/*.sh`. `observer/`, `models/`,
  `common/`, `tests/`, dokumen: ubah hanya setelah menulis niatnya di collab-log.
- Data mentah (`logs/*.jsonl`, pcap) tidak di-commit. Kalau sisi lain perlu datanya, tulis ringkasan
  atau angka penting di collab-log, atau salin lewat scp di jaringan lab.
- Setiap bug observer yang ditemukan dari data nyata → regression test dari rekaman asli
  (`tests/fixtures/`), dan pastikan test itu gagal tanpa perbaikannya (mutation check).

## Gaya kode
Python 3.12, type hints, modul kecil terpisah (server/client/observer/config/schema), komentar hanya
untuk hal penting, error message yang jelas dengan petunjuk perbaikan. Default yang baru ditambahkan
tidak boleh mengubah perilaku lama tanpa alasan tertulis.
