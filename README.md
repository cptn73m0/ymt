# YMT Server — Yandex Music Tunnel

Полностью автономный сервер. Всё управление через веб-морду.

## Быстрый запуск (Docker)

```bash
docker run -d \
  --name ymt \
  --restart unless-stopped \
  -p 443:443 \
  -v ymt-data:/data \
  ghcr.io/cptn73m0/ymt:latest
```

Логи покажут первый запуск:

```
=== FIRST RUN ===
Admin panel: http://localhost:8080/admin
Login: admin / a1b2c3d4
API token: ...
```

Через VPS: пробрось порт через SSH или открой веб-морду через туннель.

## Запуск (бинарник)

```bash
# Linux amd64
curl -L -o ymt-server https://github.com/cptn73m0/ymt/releases/latest/download/ymt-server-linux-amd64
chmod +x ymt-server
./ymt-server -listen :443 -data /var/lib/ymt
```

## Веб-морда

После запуска: **http://localhost:8080/admin**

Там можно:
- Смотреть статистику (активные подключения, трафик)
- Создавать/удалять пользователей (автогенерация ключа)
- Получать готовые URL для клиентов

## Клиент

```bash
ymt-client -server your.server:443 -key <hex-key> -mode socks5
# SOCKS5 на 127.0.0.1:1080
```