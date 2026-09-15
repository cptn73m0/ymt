# YMT — Yandex Music Tunnel

VPN/прокси протокол, маскирующий трафик под легитимные запросы к API Яндекс Музыки.

Трафик неотличим от настоящего `api.music.yandex.net` для DPI: тот же TLS fingerprint (JA3), те же HTTP/2 параметры, те же паттерны таймингов. Внутри — шифрованный (XChaCha20-Poly1305) туннель с мультиплексированием (smux).

## Архитектура

```
Клиент → TLS 1.3 (YM fingerprint) → HTTP/2 (YM SETTINGS) → smux tunnel → AEAD → YM-подобный JSON → VPS → интернет
```

## Быстрый старт

### Сервер

```bash
# Генерация ключа админа
export YMT_ADMIN_TOKEN=$(openssl rand -hex 16)

# Запуск
go build -o ymt-server ./cmd/server
./ymt-server -listen :443 -cert cert.pem -key key.pem -admin-token $YMT_ADMIN_TOKEN -db /var/lib/ymt/users.db
```

### Клиент (SOCKS5)

```bash
# Генерация мастер-ключа
KEY=$(openssl rand -hex 32)

# Создание пользователя на сервере
curl -X POST https://your.server/api/users \
  -H "Authorization: Bearer $YMT_ADMIN_TOKEN" \
  -d '{"client_id":"my-phone","key_hex":"'$KEY'"}'

# Запуск клиента
go build -o ymt-client ./cmd/client
./ymt-client -server your.server:443 -name your.server -client-id my-phone -key $KEY -mode socks5
# SOCKS5 теперь на 127.0.0.1:1080
curl --socks5-hostname 127.0.0.1:1080 https://ifconfig.me
```

## Структура проекта

```
cmd/server/        — точка входа сервера
cmd/client/        — точка входа клиента
internal/server/   — серверная логика (TLS, h2, smux, прокси)
internal/client/   — клиентская логика (SOCKS5, TUN)
internal/protocol/ — общий протокольный слой (crypto, TLS, masquerade)
internal/db/       — SQLite persistence
internal/api/      — REST API для веб-морды
internal/web/      — Веб-интерфейс
docs/              — Фингерпринты, архитектура, протокол
```

## План реализации

См. [PLAN.md](PLAN.md)

## Лицензия

WTFPL