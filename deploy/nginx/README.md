# pkica nginx setup

Run the web server after Root CA and Intermediate CA are initialized:

```bash
pkica web start --host pkica.local --port 8000
```

The command issues a `server_tls` certificate from the Intermediate CA, writes TLS files to `data/web/certs/`, generates `data/web/nginx/pkica-web.conf`, starts FastAPI on `127.0.0.1:8000`, and prints manual nginx commands.

Manual setup:

```bash
sudo cp data/web/nginx/pkica-web.conf /etc/nginx/sites-available/pkica-web.conf
sudo ln -sf /etc/nginx/sites-available/pkica-web.conf /etc/nginx/sites-enabled/pkica-web.conf
sudo nginx -t
sudo systemctl reload nginx
```

Automatic system nginx setup is opt-in:

```bash
pkica web start --host pkica.local --port 8000 --configure-nginx
```

Without `--configure-nginx`, pkica does not write to `/etc/nginx`.

