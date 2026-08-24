FROM python:3.12-slim

WORKDIR /app

# Docker CLI only (for `docker exec caddy caddy reload`)
COPY --from=docker:27-cli /usr/local/bin/docker /usr/local/bin/docker

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

EXPOSE 8080

CMD ["python", "app.py"]
