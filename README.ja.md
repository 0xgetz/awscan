<div align="center">
  <img src="assets/logo.png" alt="awscan ロゴ" width="128" height="128">
  <h1>awscan</h1>
  <p>認可されたセキュリティテストのための自動化 Web 脆弱性スキャナー。<br>
  依存関係ゼロ。Python 3.9+、標準ライブラリのみ。</p>
  <p>
    <a href="https://github.com/0xgetz/awscan/releases"><img src="https://img.shields.io/github/v/release/0xgetz/awscan?color=e8a33d" alt="リリース"></a>
    <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-green" alt="MIT ライセンス"></a>
    <img src="https://img.shields.io/badge/python-3.9%2B-blue" alt="Python 3.9+">
    <img src="https://img.shields.io/badge/deps-none-informational" alt="依存関係ゼロ">
  </p>
  <p>
    <a href="README.md">English</a> · <a href="README.id.md">Bahasa Indonesia</a> · <a href="README.zh-CN.md">中文</a> · 日本語 · <a href="README.ko.md">한국어</a>
  </p>
</div>

## 概要

awscan は対象サイトに対して、実証されたインジェクション・情報漏えい・設定不備の検査群を実行し、すべての指摘事項に再現可能な正確なリクエストベクトルを添えて報告する。同类のツールの多くが省略している 2 つの規律を中心に設計されている：

1. **厳格なスコープゲート。** スコープファイルにないホストへは、リクエストを 1 本たりとも送らない。回避フラグは存在せず、クローラーはすべての移動前にゲートを再検証する。
2. **確信度モデル。** 単なるバイト長の差分は指摘事項にならない。インジェクションの主張には DBMS エラーマーカー、または安定した指標に基づく TRUE/FALSE 差分検証が必要だ。タイミング系の結果はジッターが偽造しうるため、必ず手動再確認フラグが付く。

報告は JSON・Markdown・SARIF 2.1.0 で出力される。SARIF ファイルは GitHub Security タブ、VS Code、DefectDojo にそのまま取り込め、各結果に CWE マッピングが付いている。

## 検査項目

| 領域 | 手法 |
|---|---|
| 同一オリジン クロール | リンク・フォーム・JS バンドルを BFS で辿り、ページと全 GET パラメータを自動発見。401/403 のパスはバイパス検査列に收集される |
| SQL インジェクション | DBMS エラーマーカーの検知に加え、安定した状態指標での TRUE/FALSE 差分オラクル |
| ブールブラインド抽出 | 確定したオラクル経由で 1 文字ずつ復元。移植性の高い `substr()` 等値比較（SQLite・MySQL・PostgreSQL 形状に対応） |
| 時間ブラインド SQLi | スタック遅延ペイロード（MySQL `SLEEP`、PostgreSQL `pg_sleep`、MSSQL `WAITFOR`）をベースライン中央値レイテンシと比較 |
| 反射型 XSS | クォートがエンコードされない一意プローブのバイト一致リフレクションを確認後、イベントハンドラペイロードで再確認 |
| SSTI | 算術テンプレートプローブ（`{{7*7}}` 系、`${...}`、ERB、Freemarker）。ヒット判定はプローブが反響ではなく**計算された**結果として戻ってきた場合のみ |
| オープンリダイレクト | パラメータを外部カナリアホストに差し替え、`Location` ヘッダーで検証 |
| Host ヘッダーインジェクション | カナリア `Host:` ヘッダーが本文やリンクに反射する、パスワードリセットポイズニングの類型 |
| 403/401 バイパス | パス細工（`;/`、`..;`、`%2e`、ダブルスラッシュ）とヘッダー細工（`X-Forwarded-For`、`X-Original-URL`、`X-Rewrite-URL`）を発見された全禁止パスに実行 |
| GraphQL | 一般エンドポイントに対する読み取り専用 `__schema` インスペクション probe |
| JS 内のシークレット | クロールしたバンドルから AWS・GCP・GitHub・Stripe・JWT・秘密鍵パターンを sweep。報告書では必ずマスクされ、完全な値はディスクに残さない |
| ヘッダーと Cookie | 欠落している CSP・X-Frame-Options・HSTS・XCTO・Referrer-Policy・Permissions-Policy。Cookie の HttpOnly/Secure/SameSite 監査。サーバーバージョン開示 |
| 露出したパス | 慣例的な機微パス（`.env`、`.git/HEAD`、バックアップ）を内容認識付きで確認 |
| WAF/CDN 指紋 | 受動的なヘッダーおよび良性ペイロード応答分析（Cloudflare・AWS WAF・Akamai・mod_security・Imperva）。情報提供目的で、どのエンコーディング戦略に切り替えるべきかを教える |

## 必要条件

- Python 3.9 以降、サードパーティパッケージなし
- 向けるすべての対象に対する書面による認可

## インストール

```bash
# GitHub から（pipx・uv・pip すべて可）
pipx install git+https://github.com/0xgetz/awscan.git
# または clone から直接実行、インストール手順不要
git clone https://github.com/0xgetz/awscan && cd awscan
python3 -m awscan.cli --help
```

## スコープゲート

```
$ awscan --target https://someone-elses-site.com/x?q=TEST --scope my-scope.txt
[!] host 'someone-elses-site.com' is NOT in the scope file. Refusing to send any request.
```

ホストの追加は認可を持つ場合に限る：バグバウンティプログラムの宣言済みスコープ、自己の資産、または演習ラボ。サンプルファイルはループバックのみをあらかじめ記載している。

## クイックスタート

```bash
cp scope.example.txt my-scope.txt   # 編集：認可済みホストを追加

# 1) 同梱の意図的に脆弱なラボでの自己テスト（ループバック限定）
python3 lab_server.py --port 8777 &
awscan --crawl --root http://127.0.0.1:8777 --scope my-scope.txt --delay 0.05
# → ラボで 10 件の指摘：SQLi（ブラインド抽出シークレット含む）、SSTI、XSS、
#   オープンリダイレクト、Host ヘッダー注入、貫通した /admin、GraphQL、JS シークレット、
#   露出パス、ヘッダー衛生

# 2) 認証セッション付きの単一 surface 手動モード + ブラインド抽出デモ
awscan --target "http://127.0.0.1:8777/search?q=TEST" --scope my-scope.txt \
  --delay 0.05 --extract-sql "SELECT secret FROM secrets LIMIT 1"

# 3) 認可済み本番ターゲット（礼儀正しいデフォルトを維持：delay >= 1 秒）
awscan --crawl --root https://in-scope.example.com --scope my-scope.txt \
  --header "Cookie: session=<あなたの>"
```

手動 `--target` URL における `TEST` は、ペイロードごとに差し替えられる注入プレースホルダ。`--crawl` を使えばプレースホルダは不要。

## オプション

| フラグ | デフォルト | 意味 |
|---|---|---|
| `--target` | （クロール以外必須） | `TEST` プレースホルダ値を含む URL |
| `--crawl` | off | 注入可能 surface を自動発見する同一オリジンクロール |
| `--root` | target から | クロールのシード URL |
| `--max-pages` | 60 | クロール页数上限 |
| `--scope` | `scope.example.txt` | 認可ホストファイル。`*.domain` はサブドメイン一致 |
| `--delay` | 1.0 | リクエスト間秒数（本番では >= 1 を維持） |
| `--budget` | 900 | 強制終了までの実時間秒。ハングした socket も回避できない最後方の担保 |
| `--header` | なし | 繰り返し指定可能なカスタムヘッダー。例 `--header "Cookie: sid=abc"` |
| `--extract-sql` | off | 1 つの SELECT 式をブラインドで取り出すデモ抽出 |
| `--out` | `reports` | JSON・Markdown・SARIF の出力先 |

## 開発

```bash
python3 -m unittest discover -s test   # 27 テスト、完全オフライン
```

テストスイートは各ケースでエフェメラなループバックポートにラボを起動する。ネットワークには一切触れない。このツールを信頼できるものとして保つ規則は [CONTRIBUTING.md](CONTRIBUTING.md) に明文化されている。

## 責任ある使用

- 認可された対象のみ。スコープゲートは「正直な道がいちばん楽な道」にするために存在する。
- 指摘はすべて候補。報告や修正の前に必ず手動で検証する。
- `lab_server.py` は意図的に不安定でループバック限定。外部に公開してはならない。

## ライセンス

MIT。[LICENSE](LICENSE) 参照。
