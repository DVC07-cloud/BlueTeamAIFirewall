FROM python:3.12-slim
WORKDIR /app
ENV PYTHONUNBUFFERED=1
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY firewall_models.py firewall_engine.py main.py demo.html ./
# Cloud Run supplies $PORT
CMD exec uvicorn main:app --host 0.0.0.0 --port ${PORT:-8080}
