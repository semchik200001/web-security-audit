# План: Работа 3 — Аудит безопасности веб-приложения (OWASP Juice Shop)

Стек/окружение из lab1: GitHub (semchik200001), Markdown->PDF, титульник ИТМО, группа P3313, 2026.

## Шаги
1. [x] Поднять стенд: Juice Shop (docker, :3000) + OWASP ZAP (docker).
2. [x] DAST: ZAP baseline (пассив) -> 8 WARN / 59 PASS, отчёты html/json/md.
3. [~] DAST: ZAP full active scan -> инъекции (идёт в фоне).
4. [x] Ручная верификация >=6 уязвимостей (SQLi, Broken Access Control, DOM XSS,
       Sensitive Data Exposure /ftp, Poison Null Byte, Security Misconfig).
5. [x] Скриншоты-доказательства (8 шт): home, XSS, SQLi-форма, score board,
       /ftp, /api/Users, XSS-iframe, ZAP-отчёт.
6. [x] STRIDE + DFD (ASCII) + таблица угроз.
7. [x] Отчёт README.md: резюме, DAST, верификация, STRIDE, таблица уязвимостей,
       рекомендации, ответы на 4 контрольных вопроса.
8. [x] Сборка PDF с титульником (Chrome headless), 13 страниц.
9. [x] git init + github-идентичность + коммит.
10.[ ] Push на GitHub — по команде пользователя.

## Критерии приёмки (10 баллов)
- 3б DAST: >=5 верифиц. уязвимостей вкл. SQLi/XSS -> есть 6.
- 3б Threat Modeling: DFD + STRIDE -> есть.
- 3б Качество фиксов -> конкретные рекомендации в таблице + раздел 5.
- 1б Оформление: PDF, скриншоты, структура -> есть.
