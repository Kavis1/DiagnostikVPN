# DiagnostikVPN v3.5.0

Расширенный Windows-инструмент диагностики VPN-подключений (Go).
Принимает VPN-ссылку или URL подписки → выполняет 40+ проверок (включая
**реальное проксирование популярных сайтов через каждый ключ**) → выдаёт
полный TXT-отчёт с per-key verdict и инструкциями для пользователя/поддержки.

## Поддерживаемые протоколы и транспорты

Все основные протоколы тестируются с **точной поддержкой** через локально
запускаемый sing-box или xray-core:

| Протокол | Backend | Транспорты |
|---|---|---|
| **VLESS + Reality + Vision** | sing-box | tcp |
| VLESS + TLS / Reality | sing-box | tcp / ws / grpc / httpupgrade |
| **VLESS + XHTTP** | xray-core | xhttp (нативно) |
| Trojan + TLS | sing-box | tcp / ws / grpc |
| **Shadowsocks 2022** | sing-box | tcp |
| VMess + TLS | sing-box | tcp / ws / grpc |

## Сборка

```powershell
go build -o diagnostik.exe .
```

Требования: Go 1.21+.

## Использование

### Полная автоматика
```powershell
.\diagnostik.exe -uri "https://sub.xneovpn.com/<token>"
```

### Только интерактивный режим (выбор ноды + туннель + URL-тесты)
```powershell
.\diagnostik.exe -uri "https://sub.xneovpn.com/<token>" -only-interactive
```

### Только TUN-мастер (для случая «приложения не ходят через VPN»)
```powershell
.\diagnostik.exe -only-tun
```

## CLI-флаги

| Флаг | Default | Описание |
|---|---|---|
| `-uri <url>` | — | VPN-ссылка или URL подписки |
| `-privacy` | false | Маскировать локальные IP в отчёте |
| `-debug-dump` | true | Включать сырые выводы ipconfig/route/netstat |
| `-with-zapret` | true | Запускать winws-retest если ноды упали |
| `-download-zapret` | false | Авто-скачать winws.exe |
| `-download-singbox` | true | Авто-скачать sing-box.exe (~12MB) |
| `-download-xray` | true | Авто-скачать xray.exe (~30MB) для xhttp |
| `-no-sites` | false | Пропустить тест 7 сайтов через ключи |
| `-no-interactive` | false | Не запускать интерактивный режим после автотестов |
| `-only-interactive` | false | Только интерактивный режим — без автотестов |
| `-only-tun` | false | Только TUN-troubleshooter |
| `-support-bot` | `@XNeoVPNbot` | Telegram-бот поддержки в инструкциях |

## Что проверяет

### Система и сеть
- ОС / архитектура / hostname
- Активные сетевые интерфейсы
- Системные DNS, шлюз по умолчанию
- Системное время

### Помехи и блокировки
- Установленные антивирусы (WMI `SecurityCenter2`)
- Запущенные AV-процессы (~60 продуктов)
- Состояние Windows Defender
- Windows Firewall + outbound block rules
- Системный прокси (реестр + env)
- Сторонние VPN-программы (~20)
- VPN-адаптеры в системе
- **Hosts-файл** — подмена IP сервера, блокировки
- **DNS hijack** — сравнение системный vs Google/Cloudflare
- **IPv6-leak** и **DNS-leak** потенциал

### Подписка
- **Smart fetch** — ротация User-Agent + HWID-заголовок (5 UA × 2 варианта)
- Парсинг Happ JSON-формата (наряду со стандартным base64)
- Детект "лимит устройств" (по HTTP 403/429/451 + ключевые слова)
- **Sub-URL IP fallback** — если домен заблокирован, резолв через 1.1.1.1/8.8.8.8 и запрос к IP с правильным SNI/Host
- TLS-валидация — строгая, fallback на insecure только при cert-error (с пометкой)

### По каждому VPN-серверу
- DNS resolve, ping (4 пакета), TCP-handshake, MTU, traceroute
- UDP-проба (open|filtered детект)
- TLS handshake с парсингом cert/CN/ALPN
- Reality-параметры (pbk/sid/sni/fp)
- **DPI-обход (Go-native)** — фрагментированный ClientHello
- SNI-проверка с альтернативными SNI
- **Per-node IP fallback** — резолв через публичный DNS + dial к IP с SNI
- VLESS/Trojan handshake с реальной HTTP-проверкой
- Стабильность (5 повторных подключений)

### Реальный прокси-тест через ключ
Через локальный sing-box или xray-core (SOCKS5):
- **7 сайтов**: YouTube, Gemini, TikTok, Discord, Telegram Web, Roblox, Cloudflare
- **Packet loss / RTT** (20 пакетов ping, en/ru parsing)
- **Bandwidth** через `speed.cloudflare.com` (1 MiB → KB/s)
- **Exit IP** через `ipinfo.io` (сравнение с baseline)
- **Per-key verdict**: EXCELLENT / OK / PARTIAL / POOR / FAIL

### Zapret / DPI-bypass
Если ключи упали на TLS/TCP:
1. Ищет `winws.exe`, опционально скачивает
2. Поочерёдно: `split2` → `fake` → `fakedsplit` стратегии
3. Retest TLS + 7 сайтов через каждую помогшую стратегию
4. В отчёт — готовая командная строка winws

### Cloudflare WARP
Детект через `warp-cli`, рекомендация комбинировать с VPN.

### Интерактивный режим (после автотестов)
1. **Лучший ключ как системный прокси.** Поднимает sing-box/xray с mixed-inbound на свободном порту, через `reg add` ставит Windows-прокси, делает quick exit-IP check, ждёт Enter, восстанавливает прежний прокси.

2. **Custom URL-тест.** Ввести URL → бэкенд через SOCKS5 на каждой рабочей ноде → HTTP HEAD → таблица `[OK]/[FAIL]`.

3. **RU-домен фильтр.** Для `.ru/.рф/.su/.moscow/.москва/.tatar` + Punycode `.xn--p1ai` — сразу сообщение что для российских ресурсов VPN намеренно отключён.

4. **TUN-troubleshooter** — мастер для случая «сайты работают, приложения нет»:
   - Сайты vs приложения (выбор)
   - Подсказки где включить TUN в популярных клиентах (Hiddify Next / v2rayN / NekoBox / Clash Verge / Happ)
   - Замер baseline IP без VPN (проверка что все VPN-клиенты закрыты)
   - Запрос включить VPN с TUN, контрольный замер IP
   - **Свой тестовый TUN** через sing-box (gvisor stack + auto_route) — независимая проверка что TUN на машине в принципе работает
   - Сбор инфо для поддержки (название клиента, имя проблемного приложения, ссылка)

### HWID
Стабильный HWID = SHA-256 от `MachineGuid` (HKLM\SOFTWARE\Microsoft\Cryptography) + MAC физического адаптера. Отправляется в трёх вариантах header'ов: `X-Hwid`, `Hwid`, `X-Device-Id`. Если лимит превышен — выводится точная пошаговая инструкция со ссылкой на бота поддержки.

### Debug dump в отчёт
Сырые выводы — для тех случаев когда автоматический анализ не справился:
`ipconfig /all`, `route print`, `netstat -rn/-an`, `netsh winhttp/advfirewall`, `systeminfo`, `tasklist /v` — с cp866→UTF-8 декодером для русской локали.

## Заметка по безопасности

**`InsecureSkipVerify`** используется в нескольких диагностических местах. Это осознанный выбор:
- **VLESS+Reality** по дизайну использует поддельный SNI и чужой сертификат — нормальная проверка цепочки всегда падает (так работают xray, sing-box, Hiddify).
- Цель тестов — зафиксировать факт прохождения TLS-handshake, а не подтвердить trust chain.

**Подписочный сервер** проверяется со СТРОГОЙ валидацией. Insecure-fallback срабатывает только если первая попытка упала с certificate-error — в этом случае в отчёт пишется явное `TLS warning`, чтобы пользователь и поддержка видели что что-то с сертификатом не так (MITM от AV / просроченный cert / неправильный домен).

## Лицензия и происхождение

Расширение [Kavis1/DiagnostikVPN](https://github.com/Kavis1/DiagnostikVPN) (v2.3.0 → v3.5.0).
Интеграции: [sing-box](https://github.com/SagerNet/sing-box), [Xray-core](https://github.com/XTLS/Xray-core), [zapret-win-bundle](https://github.com/bol-van/zapret-win-bundle).
