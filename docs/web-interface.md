# Web Interface

Initialize Root CA and Intermediate CA first, then start the web interface:

```bash
pkica web start --host pkica.local --port 8000
```

`pkica web start` creates or reuses `data/web/private/pkica-web.key.pem`, generates a CSR for the selected host, issues a `server_tls` certificate through the Intermediate CA, writes `data/web/certs/pkica-web.fullchain.pem`, generates `data/web/nginx/pkica-web.conf`, and starts FastAPI on `127.0.0.1:<port>`.

The generated nginx config is not installed automatically unless `--configure-nginx` is passed. For manual installation:

```bash
sudo cp data/web/nginx/pkica-web.conf /etc/nginx/sites-available/pkica-web.conf
sudo ln -sf /etc/nginx/sites-available/pkica-web.conf /etc/nginx/sites-enabled/pkica-web.conf
sudo nginx -t
sudo systemctl reload nginx
```

To let pkica try this step:

```bash
pkica web start --host pkica.local --port 8000 --configure-nginx
```

Open `https://pkica.local/` through nginx. The portal supports CSR submission, request approval or rejection, certificate issuance, certificate revocation, CRL publication, certificate verification, and audit log viewing.

Useful commands:

```bash
pkica web status
pkica web stop
pkica reset --force
```

`pkica reset` stops the FastAPI process, removes `data/web`, and removes the system nginx site only when it was installed by pkica.

