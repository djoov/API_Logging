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
