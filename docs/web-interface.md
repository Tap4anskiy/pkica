# Веб-интерфейс

Сначала инициализируйте корневой и промежуточный УЦ, затем запустите веб-интерфейс:

```bash
pkica web start --host pkica.local --port 8000
```

Команда `pkica web start` создаёт или переиспользует ключ `data/web/private/pkica-web.key.pem`, генерирует CSR для указанного имени хоста, выпускает сертификат профиля `server_tls` через промежуточный УЦ, записывает `data/web/certs/pkica-web.fullchain.pem`, создаёт конфигурацию `data/web/nginx/pkica-web.conf` и запускает FastAPI на `127.0.0.1:<port>`.

Если приватный ключ промежуточного УЦ был создан с шифрованием, используйте флаг:

```bash
pkica web start --host pkica.local --port 8000 --intermediate-key-encrypted
```

Сгенерированная конфигурация nginx по умолчанию не устанавливается в системный каталог. Для ручного подключения выполните:

```bash
sudo cp data/web/nginx/pkica-web.conf /etc/nginx/sites-available/pkica-web.conf
sudo ln -sf /etc/nginx/sites-available/pkica-web.conf /etc/nginx/sites-enabled/pkica-web.conf
sudo nginx -t
sudo systemctl reload nginx
```

Чтобы `pkica` попытался установить системную конфигурацию nginx автоматически, передайте флаг `--configure-nginx`:

```bash
pkica web start --host pkica.local --port 8000 --configure-nginx
```

После настройки nginx откройте `https://pkica.local/`. Через портал можно отправлять CSR-заявки, одобрять или отклонять заявки, выпускать и отзывать сертификаты, публиковать CRL, проверять сертификаты и просматривать журнал аудита.

Полезные команды:

```bash
pkica web status
pkica web stop
pkica reset --force
```

Команда `pkica reset` останавливает процесс FastAPI, удаляет `data/web` и удаляет системный сайт nginx только в том случае, если он был установлен самой `pkica`.
