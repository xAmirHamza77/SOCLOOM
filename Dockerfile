FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY backend/ ./backend/

RUN pip install --no-cache-dir -e .

RUN mkdir -p /data

ENV PYTHONPATH=/app/backend
ENV AEGIS_DATABASE_URL=sqlite:////data/aegis.db

EXPOSE 8000

CMD ["uvicorn", "aegis.main:app", "--host", "0.0.0.0", "--port", "8000"]