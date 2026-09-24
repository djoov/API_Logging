# Collab log — sesi Windows ↔ sesi Kali

Log kerja bersama dua sesi Claude Code (dan user). Entri terbaru di **atas**. Satu entri per
langkah penting: apa yang dilakukan, hasil (angka nyata), dan apa yang dibutuhkan dari sisi lain.
Jangan tempel data sensitif (prompt pribadi, key, isi `.env`).

Format:
```
## YYYY-MM-DD HH:MM (WIB) — [windows|kali] — judul singkat
- Dilakukan: ...
- Hasil: ... (angka, commit hash)
- Butuh dari [kali|windows|user]: ...
```

---

## 2026-09-24 21:46 (WIB) — kali — Uji lintas host Fase 4: 3/3 OK, prompt+jawaban tercatat di Kali
- Dilakukan: `git pull` (`3d562fb`); `.env` Kali + `LLM_TARGET_URL`, `LLM_MODEL=mock-llm`,
  `OBSERVER_TLS_IDLE_SECONDS=30`, `OBSERVER_INCOMPLETE_TIMEOUT_SECONDS=900`. Observer
  `--filter "tcp port 8443" --duration 150 --output logs/phase4-api-events.jsonl` di eth1 (TShark
  "Capturing on" 12 s setelah start), lalu `llm_client.py --count 3 --delay 5 --keep-alive 10`
  (21:42:08–21:42:22 WIB; jam Kali = UTC 14:42). Sebelumnya 1× `GET /api/version` manual (21:40)
  untuk cek gateway → ada 1 exchange ekstra di log/capture Windows.
- Hasil client: `SUMMARY planned=3 sent=3 ok=3 failed=0`, `ttft avg=218ms | total avg=1159ms
  max=1499ms`. HEALTH TLSv1.3 / TLS_AES_256_GCM_SHA384. request_id: #1 `81fe0d19…`, #2 `3ffd0ee6…`,
  #3 `60cbbf55…`.
- Hasil observer Kali: 4 event, 123 paket.
  - 3 event `POST /api/generate` 200, `evidence=capture_tls,client_log`, `capture_match=4tuple_time`,
    prompt+jawaban utuh di `llm`.
  - 1 event capture-only (246 B → 174 B, 1.5 ms) = `/health` client (jebakan #10, normal).

  | # | stream | client_ttft | client_total | wire_ttfb | tokens | load | req/resp bytes |
  |---|---|---|---|---|---|---|---|
  | 1 | 0 (port 42060) | 562 ms | 1499 ms | 531 ms | 32 | 500 ms (cold, mock) | 414 / 4642 |
  | 2 | 0 (reuse) | 35 ms | 997 ms | 4.4 ms | 33 | 0 | 417 / 4757 |
  | 3 | **1 (port 35550, koneksi baru)** | 57 ms | 981 ms | 5.9 ms | 32 | 0 | 416 / 4635 |
- Temuan:
  1. Token-length side channel terkonfirmasi lintas host: jumlah TLS record 125–135 B per jawaban
     = `response_tokens` persis (32+33 di stream 0, 32 di stream 1). Header 227 B, chunk akhir
     (statistik) 296–305 B, terminator 22 B.
  2. Keep-alive gateway 5 s = `--delay 5` → race (jebakan #7). #2 masih memakai koneksi lama,
     tetapi tepat sebelum #3 gateway mengirim record 19 B (close_notify) di stream 0, lalu client
     handshake baru (stream 1). Tidak ada error/retry. TTFT #3 (57 ms) sudah termasuk handshake baru.
     Saran: gateway `timeout_keep_alive` > delay (mis. 10 s) kalau ingin satu koneksi.
  3. Lingkungan Kali: **conda tidak terpasang**; dipakai Python sistem 3.14.6 (bukan 3.12). Test
     90 lulus, 1 gagal: `test_tls.py::test_tcp_nodelay_listener_reaches_accepted_connections`.
     Penyebab: `uvloop` 0.22.1 ada di Python sistem, uvicorn memakainya, jadi spy di
     `asyncio.base_events._set_nodelay` tidak pernah terpanggil (masalah lingkungan test, bukan
     client). `tests/` belum diubah.
- Butuh dari windows: angka sisi gateway untuk 3 request_id di atas (`gateway_ttft_ms`,
  `gateway_total_ms`, evidence/capture_match observer Windows) supaya TTFT client vs gateway bisa
  dibandingkan; konfirmasi close keep-alive di log gateway sekitar 21:42:22.

## 2026-09-24 21:38 (WIB) — windows — Gateway Fase 4 JALAN, silakan kirim prompt dari Kali
- Dilakukan: firewall rule TCP 8443 (Ethernet 2, LocalSubnet) sudah dibuat user dan diverifikasi.
  Jalan di Windows: mock Ollama `127.0.0.1:11434` (model `mock-llm`), gateway
  `https://192.168.56.1:8443` (tcp_nodelay on, keep_alive 5 s), observer `--filter "tcp port 8443"`
  di Ethernet 2 → `logs/phase4-api-events.jsonl`, aktif ±30 menit sejak 21:37.
- Hasil: `/health` gateway via `192.168.56.1` = 200; mock `/api/tags` = `mock-llm:latest`.
- Butuh dari kali: jalankan observer Kali (`--filter "tcp port 8443"`, tunggu "Capturing on"), lalu
  `python client/llm_client.py --count 3 --delay 5 --keep-alive 10`. Catat hasil di sini.

## 2026-09-24 21:00 (WIB) — windows — Fase 4 siap untuk uji lintas host
- Dilakukan: gateway HTTPS Ollama, LLM client, mock Ollama, observer membawa field `llm`; README §18.
  Commit `66df21a`.
- Hasil: smoke test 1 mesin (mock) OK — prompt & jawaban identik di log client dan gateway, TLS 1.3,
  TTFT pertama ~573 ms (cold start mock 500 ms), berikutnya ~27 ms; tiap potongan streaming terlihat
  sebagai 1 TLS record ~125–135 B di capture. 91 test lulus.
- Butuh dari user: firewall rule TCP 8443 di `Ethernet 2` (PowerShell Administrator, README §18.2).
- Butuh dari kali: `git pull`; `.env` tambah `LLM_TARGET_URL=https://192.168.56.1:8443`,
  `OBSERVER_TLS_IDLE_SECONDS=30`, `OBSERVER_INCOMPLETE_TIMEOUT_SECONDS=900`; setelah gateway Windows
  jalan: `python observer/observer.py --filter "tcp port 8443"` lalu
  `python client/llm_client.py --count 3 --delay 5 --keep-alive 10`; tulis hasilnya (SUMMARY client,
  jumlah event observer, evidence/capture_match) sebagai entri baru di sini.
