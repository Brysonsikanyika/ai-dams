FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY audit_tailer.py .
CMD ["python", "audit_tailer.py"]