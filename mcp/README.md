# ONVIF Viewer MCP

This stdio MCP server exposes `get_current_picture`, which captures the newest JPEG
frame from a running ONVIF Viewer HLS stream. An agent can inspect the returned image
for questions such as “what is my boy doing?” or send the image to the user.

## Run locally

```bash
cd mcp
npm ci
npm start
```

The server connects to the viewer at `http://127.0.0.1:7878` by default. Set
`ONVIF_VIEWER_URL` to use another address, for example while testing:

```bash
ONVIF_VIEWER_URL=http://127.0.0.1:7879 npm start
```

## Configure Hermes

Add this repository-contained server through the Hermes CLI (do not hand-edit
`config.yaml`):

```bash
hermes config set mcp_servers.onvif_camera.command /home/muhajirin/.local/bin/node
hermes config set mcp_servers.onvif_camera.args '["/home/muhajirin/onvif-viewer/mcp/onvif-camera.mjs"]'
hermes config set mcp_servers.onvif_camera.timeout 30
```

Restart the Hermes gateway/session so it discovers the MCP tool as
`mcp_onvif_camera_get_current_picture`.

The MCP server only reaches the local viewer endpoint and never receives camera
credentials or RTSP URLs. The viewer itself binds all interfaces (`:7878`) so the
remote reverse proxy (`10.5.3.1`) can reach it; authentication is enforced at that
proxy, not at the viewer.

## Tests

```bash
npm ci
npm test
```

The Go API and snapshot extraction tests remain in the repository root:

```bash
go test ./...
```

## HTTP API

The viewer exposes a snapshot route (reachable without auth on the loopback and LAN,
as are the existing stream/HLS routes; public access is gated by the reverse proxy):

```text
GET /api/stream/snapshot?id=<running-stream-id>
```

It returns `image/jpeg`, uses `Cache-Control: no-store`, and only operates on a
known active HLS stream.
