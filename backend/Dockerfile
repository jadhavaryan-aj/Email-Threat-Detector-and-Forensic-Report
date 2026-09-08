FROM python:3.11-slim

WORKDIR /app

# Layer separately from source so `docker build` only reinstalls deps when
# requirements.txt actually changes.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/

# Default SQLite path is ./data/sih.db, relative to WORKDIR — override
# DATABASE_URL (e.g. to postgresql://...) for anything beyond a demo. See the
# root README's "Deploying" section for the full env var list.
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
