FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends openssl ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY . .
ENV PORT=8000
CMD ["python", "server.py"]
