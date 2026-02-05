# LogAnalyzer Agent (SIEM Lab)

A lightweight log analyzer that runs on a free-tier backend and uses **Ollama** locally for analysis. It accepts any text logs (syslog, nginx, apache, windows event, or generic) and produces a concise incident-style report.

## Structure
- `backend/` FastAPI API (Render-friendly)
- `frontend/` static UI (GitHub Pages or Vercel)

## Local Run

### 1) Start Ollama
Install Ollama and pull a model, for example:

```bash
ollama pull llama3.2
ollama serve
```

### 2) Start the API

```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### 3) Open the UI

Serve `frontend/` with any static server, or open `frontend/index.html` directly.

Update the Backend URL field to `http://localhost:8000` if needed.

## Environment Variables (API)
- `OLLAMA_BASE_URL` (default `http://localhost:11434`)
- `OLLAMA_MODEL` (default `llama3.2`)
- `CORS_ORIGINS` (default `*`, comma-separated)

## Deployment (Free Tier)

### Frontend: GitHub Pages
- Push this repo to GitHub
- In GitHub Pages settings, choose the `frontend/` folder (or move files to `/docs`)

### Frontend: Vercel
- Import repo in Vercel
- Set **Root Directory** to `frontend`
- Framework preset: **Other**

### Backend: Render (Free)
- Create a Render Web Service from `backend/`
- Render will use `backend/render.yaml`
- Set `OLLAMA_BASE_URL` to a reachable Ollama instance (see below)

## Using Ollama in Free Hosting
Free tiers do **not** provide GPU. The most reliable setup is:
- Run **Ollama** on your lab machine
- Expose it securely (Tunnel/VPN)
- Point `OLLAMA_BASE_URL` at that endpoint

If you want everything public, consider keeping both Ollama and API inside your lab network and only hosting the static UI externally.

## API Endpoints
- `GET /health`
- `POST /analyze` JSON: `{ text, log_type?, mode? }`
- `POST /analyze-file` multipart: `file`, `log_type?`, `mode?`

## Modes
- `quick` fewer chunks, faster
- `standard` balanced (default)
- `deep` more chunks, slower but thorough
