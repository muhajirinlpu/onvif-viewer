# ONVIF Camera Streaming App

A web application for streaming ONVIF-compatible IP cameras using HLS (HTTP Live Streaming).

## Features

- ONVIF device discovery and control
- RTSP to HLS streaming conversion
- Multiple simultaneous camera streams
- Live video playback in browser
- Device information and capabilities query
- Secure connection with digest authentication

## Prerequisites

- Go 1.16 or later
- FFmpeg installed on the system
- ONVIF-compatible IP camera
- Modern web browser with HLS support

## Installation

1. Clone the repository:

```bash
git clone https://github.com/muhajirinlpu/onvif-viewer
cd camera-streamer
```

2. Install FFmpeg:

```bash
# Arch Linux
sudo pacman -S ffmpeg

# Ubuntu/Debian
sudo apt update
sudo apt install ffmpeg

# macOS
brew install ffmpeg
```

3. Build and run:

```bash
go build
./camera-streamer
```

The server will start on port 7878.

## Usage

1. Open your browser and navigate to `http://localhost:7878`

2. Enter your camera details:

   - IP address (e.g., 192.168.0.125)
   - Port (default: 8000)
   - Username
   - Password

3. Click "Fetch Stream" to start streaming
