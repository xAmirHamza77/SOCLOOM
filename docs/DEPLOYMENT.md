# SOCloom Deployment Guide

## Local Development

```bash
# Terminal 1 — API
source .venv/bin/activate
PYTHONPATH=backend uvicorn aegis.main:app --reload --port 8000

# Terminal 2 — Dashboard
cd frontend && npm run dev

# Terminal 3 — Demo traffic
python scripts/traffic_simulator.py
```

---

## Docker (Recommended for Production)

### Prerequisites
- Docker + Docker Compose
- Anthropic Cybersecurity Skills repo cloned locally

### Setup

```bash
cp .env.example .env

# Set skills path (absolute path on host machine)
echo "AEGIS_SKILLS_PATH=/Users/you/Downloads/Anthropic-Cybersecurity-Skills-main" >> .env
```

### Run

```bash
docker compose up --build -d
```

| Service | Port | URL |
|---------|------|-----|
| API | 8000 | http://localhost:8000 |
| Dashboard | 5173 | http://localhost:5173 |

### Logs

```bash
docker compose logs -f api
docker compose logs -f frontend
```

### Stop

```bash
docker compose down
```

---

## Production Checklist

### Security
- [ ] Set `AEGIS_CORS_ORIGINS` to your actual frontend domain
- [ ] Use PostgreSQL instead of SQLite: `AEGIS_DATABASE_URL=postgresql://user:pass@host:5432/socloom`
- [ ] Put API behind reverse proxy (nginx/Caddy) with TLS
- [ ] Restrict API keys to environment variables (never commit `.env`)
- [ ] Enable rate limiting on `/api/v1/analyze`

### Performance
- [ ] Pre-train ML model: run traffic simulator once, model saves to `data/anomaly_model.pkl`
- [ ] Use gunicorn/uvicorn workers: `uvicorn aegis.main:app --workers 4 --host 0.0.0.0`
- [ ] Mount skills catalog as read-only volume (Docker)

### Monitoring
- [ ] Health check endpoint: `GET /api/v1/health`
- [ ] Docker healthcheck configured in `docker-compose.yml`
- [ ] Log aggregation (stdout → your logging stack)

---

## Cloud Deployment Options

### Railway / Render (API only)

```bash
# Start command
PYTHONPATH=backend uvicorn aegis.main:app --host 0.0.0.0 --port $PORT

# Environment variables
AEGIS_SKILLS_PATH=/skills
OPENAI_API_KEY=sk-...
AEGIS_DATABASE_URL=postgresql://...
```

### Vercel (Frontend only)

```bash
cd frontend
npm run build
# Deploy dist/ folder
# Set API proxy to your backend URL
```

### VPS (Full stack)

```bash
# Install dependencies
sudo apt update && sudo apt install -y python3.12 python3.12-venv nginx

# Clone and setup
git clone https://github.com/YOUR_USERNAME/socloom.git
cd socloom
python3.12 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Systemd service
sudo tee /etc/systemd/system/socloom.service << EOF
[Unit]
Description=SOCloom API
After=network.target

[Service]
User=www-data
WorkingDirectory=/opt/socloom
Environment=PYTHONPATH=/opt/socloom/backend
ExecStart=/opt/socloom/.venv/bin/uvicorn aegis.main:app --host 127.0.0.1 --port 8000 --workers 2
Restart=always

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl enable socloom
sudo systemctl start socloom
```

### nginx reverse proxy

```nginx
server {
    listen 443 ssl;
    server_name soc.yourdomain.com;

    location /api/ {
        proxy_pass http://127.0.0.1:8000/api/;
    }

    location /ws/ {
        proxy_pass http://127.0.0.1:8000/ws/;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }

    location / {
        root /opt/socloom/frontend/dist;
        try_files $uri $uri/ /index.html;
    }
}
```

---

## Database Migration (SQLite → PostgreSQL)

```bash
# Install PostgreSQL driver
pip install psycopg2-binary

# Update .env
AEGIS_DATABASE_URL=postgresql://socloom:password@localhost:5432/socloom

# Tables auto-create on first startup via SQLAlchemy
PYTHONPATH=backend python -c "from aegis.database import Base, engine; Base.metadata.create_all(bind=engine)"
```

---

## Skills Catalog Setup

SOCloom works without the full catalog (5 built-in skills), but for the full 817-skill experience:

```bash
git clone https://github.com/mukul975/Anthropic-Cybersecurity-Skills.git
```

Set in `.env`:
```env
AEGIS_SKILLS_PATH=/absolute/path/to/Anthropic-Cybersecurity-Skills
```

Verify:
```bash
curl http://localhost:8000/api/v1/health | jq .skills.total_skills
# Expected: 817
```