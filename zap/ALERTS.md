# Сводка алертов OWASP ZAP

Цель: http://host.docker.internal:3000 (OWASP Juice Shop 20.2.0)

## Baseline scan (пассивный) — FAIL 0 / WARN 8 / PASS 59

| Alert | Риск | Кол-во | CWE |
|---|---|---|---|
| Content Security Policy (CSP) Header Not Set | Medium (High) | 5 | CWE-693 |
| Cross-Domain Misconfiguration | Medium (Medium) | 5 | CWE-264 |
| Cross-Origin-Embedder-Policy Header Missing or Invalid | Low (Medium) | 5 | CWE-693 |
| Cross-Origin-Opener-Policy Header Missing or Invalid | Low (Medium) | 5 | CWE-693 |
| Dangerous JS Functions | Low (Low) | 1 | CWE-749 |
| Deprecated Feature Policy Header Set | Low (Medium) | 5 | CWE-16 |
| Timestamp Disclosure - Unix | Low (Low) | 5 | CWE-497 |
| Modern Web Application | Informational (Medium) | 5 | CWE--1 |
| Storable and Cacheable Content | Informational (Medium) | 2 | CWE-524 |
| Storable but Non-Cacheable Content | Informational (Medium) | 4 | CWE-524 |

## Full scan (активный Active Scan) — FAIL 0 / WARN 10 / PASS 131

| Alert | Риск | Кол-во | CWE |
|---|---|---|---|
| Backup File Disclosure | Medium (Medium) | 31 | CWE-530 |
| Bypassing 403 | Medium (Medium) | 6 | CWE-348 |
| CORS Misconfiguration | Medium (High) | 5 | CWE-942 |
| Content Security Policy (CSP) Header Not Set | Medium (High) | 5 | CWE-693 |
| Cross-Domain Misconfiguration | Medium (Medium) | 5 | CWE-264 |
| HTTP Only Site | Medium (Medium) | 1 | CWE-311 |
| Cross-Origin-Embedder-Policy Header Missing or Invalid | Low (Medium) | 5 | CWE-693 |
| Cross-Origin-Opener-Policy Header Missing or Invalid | Low (Medium) | 5 | CWE-693 |
| Dangerous JS Functions | Low (Low) | 1 | CWE-749 |
| Deprecated Feature Policy Header Set | Low (Medium) | 5 | CWE-16 |
| Timestamp Disclosure - Unix | Low (Low) | 5 | CWE-497 |
| Modern Web Application | Informational (Medium) | 5 | CWE--1 |
| Non-Storable Content | Informational (Medium) | 2 | CWE-524 |
| Storable and Cacheable Content | Informational (Medium) | 1 | CWE-524 |
| Storable but Non-Cacheable Content | Informational (Medium) | 5 | CWE-524 |
| User Agent Fuzzer | Informational (Medium) | 5 | CWE-0 |

> Active Scan независимо подтвердил ручные находки: **Backup File Disclosure**
> (x31) — это файлы в `/ftp`; **Bypassing 403** (x6) — обход запрета через
> Poison Null Byte; **CORS Misconfiguration** (x5). SQLi и XSS верифицированы
> вручную (README, раздел 2), т.к. завязаны на бизнес-логику приложения.
