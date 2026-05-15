# Настройка nginx для pkica

Запускайте веб-сервер после инициализации корневого и промежуточного УЦ:

```bash
pkica web start --host pkica.local --port 8000
```

Команда выпускает сертификат профиля `server_tls` через промежуточный УЦ, записывает TLS-файлы в `data/web/certs/`, создаёт `data/web/nginx/pkica-web.conf`, запускает FastAPI на `127.0.0.1:8000` и выводит команды для ручного подключения nginx.

Если приватный ключ промежуточного УЦ зашифрован, добавьте флаг `--intermediate-key-encrypted`; команда запросит пароль интерактивно.

Ручное подключение:

```bash
sudo cp data/web/nginx/pkica-web.conf /etc/nginx/sites-available/pkica-web.conf
sudo ln -sf /etc/nginx/sites-available/pkica-web.conf /etc/nginx/sites-enabled/pkica-web.conf
sudo nginx -t
sudo systemctl reload nginx
```

Автоматическая настройка системного nginx выполняется только по явному флагу:

```bash
pkica web start --host pkica.local --port 8000 --configure-nginx
```

Без `--configure-nginx` команда `pkica` не пишет в `/etc/nginx`.
