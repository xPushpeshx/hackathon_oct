FROM python:3.11-slim

WORKDIR /app
COPY app /app

RUN pip install --no-cache-dir Flask==3.0.3

EXPOSE 5000

CMD ["python", "app.py"]
