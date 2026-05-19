FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    SCANNER_REPORT_DIR=/app/reports

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN mkdir -p /app/reports \
    && useradd --create-home scanner \
    && chown -R scanner:scanner /app

USER scanner

CMD ["python", "main.py", "--help"]
