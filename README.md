# Threat Intelligence Dashboard

Complete MVP based on the attached requirements.

## Start database

```bash
docker compose up -d db
```

## Start backend

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
alembic upgrade head
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

## Start frontend

```bash
cd frontend
npm install
npm run dev
```
