# Сводка алертов OWASP ZAP (baseline scan)

Цель: http://host.docker.internal:3000 (OWASP Juice Shop 20.2.0)

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

> Активный full-scan (zap-full-report.html) дополняет пассивные находки
> подтверждением инъекций. SQLi и XSS дополнительно верифицированы вручную
> (см. README, раздел 2).
