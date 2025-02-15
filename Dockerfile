FROM golang:1.24 AS builder

WORKDIR /app
COPY . .
RUN CGO_ENABLED=0 go build -o onvif-viewer .

FROM ubuntu:24.04

# Avoid prompts from apt
ENV DEBIAN_FRONTEND=noninteractive

# Install FFmpeg and CA certificates
RUN apt-get update && \
    apt-get install -y ffmpeg ca-certificates && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /app/onvif-viewer .
COPY static /app/static

# Create static directory
RUN mkdir -p /app/static/hls

EXPOSE 7878

CMD ["./onvif-viewer"]
