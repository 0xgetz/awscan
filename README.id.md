# awscan

Automated web vulnerability scanner untuk **security testing yang berwenang** — tanpa dependency, Python 3.9+, cukup stdlib.

[![python](https://img.shields.io/badge/python-3.9%2B-blue)](#requirements) [![license](https://img.shields.io/badge/license-MIT-green)](LICENSE)

🇬🇧 [English](README.md) · 🇨🇳 [中文](README.zh-CN.md)

## Fitur

Arahkan ke satu URL — atau cukup root-nya pakai `--crawl` dan dia nemuin sendiri semua parameter yang bisa diinjeksi — lalu sejalan rangkaian cek teruji:

| Cek | Teknik |
|---|---|
| Crawl same-origin | BFS link/form/JS buat page + semua GET param; path forbidden (401/403) otomatis dikumpulin buat baterai bypass |
| SQL injection | sniff error-marker DBMS + diferensial TRUE/FALSE pada state anchor — bukan delta panjang respons mentah |
| Blind extraction | recovery char-per-char via oracle yang sudah terkonfirmasi (equality `substr()` yang portable, jalan di SQLite/MySQL/PostgreSQL) |
| Time-based blind SQLi | payload stacked-delay (MySQL `SLEEP`, Postgres `pg_sleep`, MSSQL `WAITFOR`) vs median latency baseline — selalu ditandai buat cek manual |
| Reflected XSS | refleksi byte-identical dari probe unik (kutipan tidak di-encode), konfirmasi dengan payload event-handler |
| SSTI | probe template aritmatika (kelas `{{7*7}}`, `${{…}}`, ERB, Freemarker) — temuan butuh probe balik **terkomputasi**, bukan ke-echo |
| Open redirect | tukar param ke canary host eksternal, diverifikasi lewat header `Location` |
| Host header injection | header `Host:` canary yang nyangkut di body/link respons — kelas password-reset poisoning |
| Baterai bypass 403/401 | trik path (`;/`, `..;`, `%2e`, double-slash) + trik header (`X-Forwarded-For`, `X-Original-URL`, `X-Rewrite-URL`) ke semua forbidden path yang ketemu |
| GraphQL | probe introspection `__schema` read-only di endpoint umum |
| Secret di JS bundle | sapuan file `.js` hasil crawl buat pola AWS/GCP/GitHub/Stripe/JWT/private-key — **di-mask di laporan**, gak pernah ada secret utuh di disk |
| Security headers + cookie | hilangnya CSP / XFO / HSTS / XCTO / Referrer-Policy / Permissions-Policy, audit `HttpOnly/Secure/SameSite` cookie, disclosure versi server |
| Exposed paths | path sensitif konvensional (`.env`, `.git/HEAD`, backup) dengan konfirmasi leak berbasis konten |
| WAF/CDN fingerprint | analisis pasif header + respons payload benign (Cloudflare, AWS WAF, Akamai, mod_security, Imperva, …) — informatif, mengubah strategi encoding lo |

Setiap temuan bawa URL vektor persis yang dipakai — bisa lo reproduksi atau lanjutin manual. Laporan keluar dalam **JSON + Markdown + SARIF 2.1.0** — SARIF-nya bisa langsung di-ingest GitHub Security tab, VS Code, atau DefectDojo.

## Gerbang scope

**awscan menolak mengirim satu request pun ke host yang gak ada di scope file lo.** Ini gerbang keras, bukan sekadar flag — crawler juga ngecek ulang sebelum tiap hop:

```
$ python3 -m awscan.cli --target https://situs-milik-orang-lain.com/x?q=TEST --scope my-scope.txt
[!] host 'situs-milik-orang-lain.com' is NOT in the scope file — refusing to send any request.
```

Tambahin host hanya kalau lo pegang otorisasi tertulis/resmi: aset sendiri, lab, atau scope resmi program bug bounty.

## Mulai cepat

```bash
git clone https://github.com/0xgetz/awscan && cd awscan
cp scope.example.txt my-scope.txt        # edit: tambahin host berwenang

# 1) self-test pakai lab bawaan yang sengaja rapuh (loopback only)
python3 lab_server.py --port 8777 &
python3 -m awscan.cli --crawl --root http://127.0.0.1:8777 \
  --scope my-scope.txt --delay 0.05
# → 10 temuan termasuk secret hasil blind-extract, /admin ke-bypass, sapuan key di JS

# 2) satu surface manual, pakai session lo + demo blind extraction
python3 -m awscan.cli --target "http://127.0.0.1:8777/search?q=TEST" \
  --scope my-scope.txt --delay 0.05 \
  --extract-sql "SELECT secret FROM secrets LIMIT 1"

# 3) target produksi berwenang (hormati default: delay ≥ 1s)
python3 -m awscan.cli --crawl --root https://in-scope.example.com \
  --scope my-scope.txt --header "Cookie: session=<punya-lo>"
```

`TEST` di URL target manual itu placeholder injeksi — scanner menggantinya per payload. Pakai `--crawl` gak butuh placeholder.

## Opsi

| Flag | Default | Arti |
|---|---|---|
| `--target` | — | URL dengan nilai param placeholder `TEST` (surface manual) |
| `--crawl` | off | crawl same-origin buat nemuin surface injeksi otomatis |
| `--root` | dari target | URL seed crawl |
| `--max-pages` | 60 | plafon halaman crawl |
| `--scope` | `scope.example.txt` | file host berwenang (`*.domain` = wildcard subdomain) |
| `--delay` | `1.0` | detik antar request (pertahankan ≥ 1 untuk produksi) |
| `--budget` | `900` | detik wall-clock sebelum hard-exit SIGALRM — pacing sleep gak bisa kabur dari cek kooperatif kalau socket hang; backstop ini flush lalu keluar |
| `--header` | none | header auth/custom, repeatable, mis. `--header "Cookie: sid=abc"` (berburu surface ter-autentikasi) |
| `--extract-sql` | off | demo blind satu ekspresi `SELECT` |
| `--out` | `reports` | direktori output (JSON + MD + SARIF) |

## Model confidence (anti ngecoh diri sendiri)

Perubahan jumlah byte tidak pernah jadi temuan. Klaim injection butuh error marker DBMS **atau** diferensial TRUE/FALSE di state anchor yang stabil (jumlah baris). Payload yang lolos WAF tapi anchor-nya gak berubah = *bukan vulnerable* — alat ini ngomong gitu, bukan ngebanjirin lo pakai noise raw-scanner. Temuan timing selalu ditandai `manual verification required` karena jitter bisa nipuin. Ini mencerminkan disiplin validasi manual yang dituntut program bug bounty.

## Pengembangan

```bash
python3 -m unittest discover -s test   # 27 tes, full offline (spawn lab loopback, port ephemeral)
```

Aturan yang bikin tool ini layak dipercaya ada di [CONTRIBUTING.md](CONTRIBUTING.md).

## Penggunaan bertanggung jawab

- Hanya target berwenang — gerbang scope dibuat biar jalur jujur jadi jalur termudah.
- Hasil adalah temuan *kandidat*; validasi manual sebelum lapor atau benerin.
- `lab_server.py` bawaan sengaja insecure dan cuma bind loopback. Jangan pernah di-deploy.

## Lisensi

MIT — lihat [LICENSE](LICENSE).
