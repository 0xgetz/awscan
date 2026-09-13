# awscan

Automated web vulnerability scanner untuk **security testing yang berwenang** — tanpa dependency, Python 3.9+, cukup stdlib.

[![python](https://img.shields.io/badge/python-3.9%2B-blue)](#requirements) [![license](https://img.shields.io/badge/license-MIT-green)](LICENSE)

🇬🇧 [English](README.md) · 🇨🇳 [中文](README.zh-CN.md)

## Fitur

Arahkan ke URL dengan placeholder parameter, alat ini menjalankan rangkaian cek teruji:

| Cek | Teknik |
|---|---|
| SQL injection | sniff error-marker DBMS + diferensial TRUE/FALSE pada state anchor — bukan delta panjang respons mentah |
| Blind extraction | recovery char-per-char via oracle yang sudah terkonfirmasi (equality `substr()` yang portable, jalan di SQLite/MySQL/PostgreSQL) |
| Reflected XSS | refleksi byte-identical dari probe unik (kutipan tidak di-encode), konfirmasi dengan payload event-handler |
| Open redirect | tukar param ke canary host eksternal, diverifikasi lewat header `Location` |
| Security headers | hilangnya CSP / XFO / HSTS / XCTO + disclosure versi server |
| Exposed paths | path sensitif konvensional (`.env`, `.git/HEAD`, backup) dengan konfirmasi leak berbasis konten |

Setiap temuan membawa URL vektor persis yang dipakai — bisa lo reproduksi atau lanjutin manual. Laporan keluar dalam JSON + Markdown.

## Gerbang scope

**awscan menolak mengirim satu request pun ke host yang gak ada di scope file lo.** Ini gerbang keras, bukan sekadar flag:

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
python3 -m awscan.cli --target "http://127.0.0.1:8777/search?q=TEST" \
  --scope my-scope.txt --delay 0.05 \
  --extract-sql "SELECT secret FROM secrets LIMIT 1"
# → reports/scan-*.md berisi 5 temuan termasuk secret yang diekstraksi

# 2) scanning produksi (hormati default: delay ≥ 1s)
python3 -m awscan.cli --target "https://in-scope.example.com/search?q=TEST" --scope my-scope.txt
```

`TEST` di URL target itu placeholder injeksi — scanner menggantinya per payload.

## Opsi

| Flag | Default | Arti |
|---|---|---|
| `--target` | wajib | URL dengan nilai param placeholder `TEST` |
| `--scope` | `scope.example.txt` | file host berwenang (`*.domain` = wildcard subdomain) |
| `--delay` | `1.0` | detik antar request (pertahankan ≥ 1 untuk produksi) |
| `--budget` | `900` | detik wall-clock sebelum hard-exit SIGALRM — pacing sleep gak bisa kabur dari cek kooperatif kalau socket hang; backstop ini flush lalu keluar |
| `--extract-sql` | off | demo blind satu ekspresi `SELECT` |
| `--out` | `reports` | direktori output laporan |

## Model confidence (anti ngecoh diri sendiri)

Perubahan jumlah byte tidak pernah jadi temuan. Klaim injection butuh error marker DBMS **atau** diferensial TRUE/FALSE di state anchor yang stabil (jumlah baris). Payload yang lolos WAF tapi anchor-nya gak berubah = *bukan vulnerable* — alat ini ngomong gitu, bukan ngebanjirin lo pakai noise raw-scanner. Ini mencerminkan disiplin validasi manual yang dituntut program bug bounty.

## Pengembangan

```bash
python3 -m unittest discover -s test   # 17 tes, full offline (lab spawn sendiri, ephemeral port)
```

Aturan yang bikin tool ini layak dipercaya ada di [CONTRIBUTING.md](CONTRIBUTING.md).

## Penggunaan bertanggung jawab

- Hanya target berwenang — gerbang scope dibuat biar jalur jujur jadi jalur termudah.
- Hasil adalah temuan *kandidat*; validasi manual sebelum lapor atau benerin.
- `lab_server.py` bawaan sengaja insecure dan cuma bind loopback. Jangan pernah di-deploy.

## Lisensi

MIT — lihat [LICENSE](LICENSE).
