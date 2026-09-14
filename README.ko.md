<div align="center">
  <img src="assets/logo.png" alt="awscan 로고" width="128" height="128">
  <h1>awscan</h1>
  <p>권한 있는 보안 테스트를 위한 자동화 웹 취약점 스캐너.<br>
  의존성 없음. Python 3.9+, 표준 라이브러리만 사용.</p>
  <p>
    <a href="https://github.com/0xgetz/awscan/releases"><img src="https://img.shields.io/github/v/release/0xgetz/awscan?color=e8a33d" alt="릴리스"></a>
    <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-green" alt="MIT 라이선스"></a>
    <img src="https://img.shields.io/badge/python-3.9%2B-blue" alt="Python 3.9+">
    <img src="https://img.shields.io/badge/deps-none-informational" alt="의존성 없음">
  </p>
  <p>
    <a href="README.md">English</a> · <a href="README.id.md">Bahasa Indonesia</a> · <a href="README.zh-CN.md">中文</a> · <a href="README.ja.md">日本語</a> · 한국어
  </p>
</div>

## 개요

awscan은 대상 사이트에 검증된 인젝션·정보 노출·설정 오류 검사 세트를 실행하고, 모든 findings를 직접 재현할 수 있는 정확한 요청 벡터와 함께 보고한다. 동종 도구가 흔히 생략하는 두 가지 규율을 중심에 두고 설계되었다:

1. **엄격한 scope gate.** scope 파일에 없는 호스트에는 요청 한 건도 보내지 않는다. 우회 플래그가 없고, 크롤러는 모든 이동 전에 게이트를 다시 검증한다.
2. **신뢰도 모델.** 단순 바이트 길이 차이는 절대 findings가 되지 않는다. 인젝션 주장은 DBMS 오류 마커 또는 안정적 앵커에 대한 TRUE/FALSE differential을 요구한다. 타이밍 결과는 지터가 위조할 수 있으므로 항상 수동 재확인 표시가 붙는다.

보고서는 JSON, Markdown, SARIF 2.1.0으로 출력된다. SARIF 파일은 GitHub Security 탭, VS Code, DefectDojo에 그대로 가져올 수 있으며 각 결과에 CWE 매핑이 포함된다.

## 검사 항목

| 영역 | 기법 |
|---|---|
| 동일 출처 크롤 | 링크·폼·JS 번들을 BFS로 따라가며 페이지와 모든 GET 파라미터를 자동 발견. 401/403 경로는 우회 검사 대기열에 수집 |
| SQL 인젝션 | DBMS 오류 마커 스닝 + 안정적 상태 앵커에 대한 TRUE/FALSE differential 오라클 |
| 불린 블라인드 추출 | 확인된 오라클을 통해 문자 단위 복원. 이식성 있는 `substr()` 등치 비교 (SQLite·MySQL·PostgreSQL 형태) |
| 시간 기반 블라인드 SQLi | 스택드 지연 페이로드(MySQL `SLEEP`, PostgreSQL `pg_sleep`, MSSQL `WAITFOR`)를 baseline 지연 중앙값과 비교 |
| 반사형 XSS | 따옴표가 인코딩되지 않은 고유 프로브의 바이트 단위 동일 반영 확인 후, 이벤트 핸들러 페이로드로 재확인 |
| SSTI | 산술 템플릿 프로브(`{{7*7}}` 계열, `${...}`, ERB, Freemarker). 반사가 아니라 **계산된** 값으로 돌아와야만 감지 |
| 오픈 리다이렉트 | 파라미터를 외부 카나리 호스트로 교체한 뒤 `Location` 헤더로 검증 |
| Host 헤더 인젝션 | 카나리 `Host:` 헤더가 본문이나 링크에 반사되는, 비밀번호 재설정 poisoning 계열 |
| 403/401 우회 | 경로 조작(`;/`, `..;`, `%2e`, double-slash) + 헤더 조작(`X-Forwarded-For`, `X-Original-URL`, `X-Rewrite-URL`)을 발견된 모든 금지 경로에 실행 |
| GraphQL | 일반 엔드포인트에서 읽기 전용 `__schema` introspection probe |
| JS 내 시크릿 | 크롤한 번들에서 AWS·GCP·GitHub·Stripe·JWT·개인키 패턴을 sweep한다. 보고서에서는 항상 마스킹되며 완전한 값은 디스크에 남기지 않음 |
| 헤더·쿠키 | 누락된 CSP·X-Frame-Options·HSTS·XCTO·Referrer-Policy·Permissions-Policy, 쿠키 HttpOnly/Secure/SameSite 감사, 서버 버전 노출 |
| 노출된 경로 | 관례적 민감 경로(`.env`, `.git/HEAD`, 백업)를 내용 인지 확인과 함께 |
| WAF/CDN 지문 | 수동적 헤더 및 무해한 페이로드 응답 분석(Cloudflare·AWS WAF·Akamai·mod_security·Imperva). 정보 제공용이며 어떤 인코딩 전략으로 전환할지 알려준다 |

## 요구 사항

- Python 3.9 이상, 서드파티 패키지 없음
- 향하는 모든 대상에 대한 서면 권한

## 설치

```bash
# GitHub에서 (pipx, uv, pip 모두 가능)
pipx install git+https://github.com/0xgetz/awscan.git
# 또는 clone 후 설치 없이 바로 실행
git clone https://github.com/0xgetz/awscan && cd awscan
python3 -m awscan.cli --help
```

## Scope gate

```
$ awscan --target https://someone-elses-site.com/x?q=TEST --scope my-scope.txt
[!] host 'someone-elses-site.com' is NOT in the scope file. Refusing to send any request.
```

권한을 보유한 경우에만 호스트를 추가한다: 버그바운티 프로그램이 선언한 scope, 자신의 자산, 또는 실습 lab. 예제 파일은 일부러 loopback 항목만 담고 있다.

## 빠른 시작

```bash
cp scope.example.txt my-scope.txt   # 편집: 권한 있는 호스트 추가

# 1) 기본 제공 의도적 취약 lab 대상 자가 테스트 (loopback 전용)
python3 lab_server.py --port 8777 &
awscan --crawl --root http://127.0.0.1:8777 --scope my-scope.txt --delay 0.05
# → lab에서 findings 10건: SQLi (블라인드 추출 시크릿 포함), SSTI, XSS,
#   오픈 리다이렉트, Host 헤더 인젝션, 돌파된 /admin, GraphQL, JS 시크릿,
#   노출 경로, 헤더 위생

# 2) 인증 세션을 갖춘 단일 surface 수동 모드 + 블라인드 추출 데모
awscan --target "http://127.0.0.1:8777/search?q=TEST" --scope my-scope.txt \
  --delay 0.05 --extract-sql "SELECT secret FROM secrets LIMIT 1"

# 3) 권한 있는 프로덕션 대상 (예의 바른 기본값 유지: delay >= 1s)
awscan --crawl --root https://in-scope.example.com --scope my-scope.txt \
  --header "Cookie: session=<본인>"
```

수동 `--target` URL에서 `TEST`는 페이로드마다 교체되는 인젝션 자리표시자다. `--crawl`을 쓰면 자리표시자가 전혀 필요 없다.

## 옵션

| 플래그 | 기본값 | 의미 |
|---|---|---|
| `--target` | (크롤이 아니면 필수) | `TEST` 자리표시자 파라미터 값을 담은 URL |
| `--crawl` | off | 주입 가능 surface를 자동 발견하는 동일 출처 크롤 |
| `--root` | target에서 유도 | 크롤 시드 URL |
| `--max-pages` | 60 | 크롤 페이지 상한 |
| `--scope` | `scope.example.txt` | 권한 호스트 파일. `*.domain`은 서브도메인 일치 |
| `--delay` | 1.0 | 요청 간 격차 초 (프로덕션에서는 >= 1 유지) |
| `--budget` | 900 | 강제 종료까지의 wall-clock 초. 멈춘 socket도 무시할 수 없는 최후 안전장치 |
| `--header` | 없음 | 반복 가능한 커스텀 헤더, 예 `--header "Cookie: sid=abc"` |
| `--extract-sql` | off | SELECT 표현식 하나를 블라인드로 뽑아내는 데모 |
| `--out` | `reports` | JSON·Markdown·SARIF 출력 디렉터리 |

## 개발

```bash
python3 -m unittest discover -s test   # 27개 테스트, 완전 오프라인
```

테스트 스위트는 각 케이스마다 임시 loopback 포트에 lab을 띄운다. 네트워크에는 전혀 접근하지 않는다. 이 도구를 신뢰할 만하게 유지하는 규칙은 [CONTRIBUTING.md](CONTRIBUTING.md)에 적혀 있다.

## 책임 있는 사용

- 권한 있는 대상만. scope gate는 정직한 경로가 가장 쉬운 경로가 되도록 존재한다.
- findings는 후보일 뿐이다. 보고하거나 수정하기 전에 하나씩 수동으로 검증한다.
- `lab_server.py`는 의도적으로 불안전하고 loopback 전용이다. 절대 외부에 노출하지 말 것.

## 라이선스

MIT. [LICENSE](LICENSE) 참조.
