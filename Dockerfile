FROM golang:1.24 AS builder

WORKDIR /app
COPY . .

RUN CGO_ENABLED=0 go build -o onvif-viewer .

FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y ffmpeg ca-certificates && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /app/onvif-viewer .

RUN mkdir -p /tmp/onvif-hls && chmod 777 /tmp/onvif-hls

EXPOSE 7878

CMD ["./onvif-viewer"]
