# ---- stage 1: build drand's tle (time-lock encryption CLI)
FROM golang:1.24-alpine AS tle
RUN go install github.com/drand/tlock/cmd/tle@v1.2.0

# ---- stage 2: the bot
FROM python:3.12-slim
COPY --from=tle /go/bin/tle /usr/local/bin/tle
RUN apt-get update && apt-get install -y --no-install-recommends fonts-dejavu-core && rm -rf /var/lib/apt/lists/*
RUN useradd -m -u 10001 nullbyte && mkdir /data && chown nullbyte:nullbyte /data
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY nullbyte ./nullbyte
USER nullbyte
ENV DATA_DIR=/data PYTHONUNBUFFERED=1 WEBAPP_HOST=0.0.0.0
VOLUME /data
EXPOSE 2222 8088
CMD ["python", "-m", "nullbyte"]
