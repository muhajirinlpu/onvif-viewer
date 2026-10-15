# Opt-in recording (experimental; not deployed)

Recording is entirely off unless `ONVIF_RECORDING_ENABLED=1` **and** a 32+ character `ONVIF_RECORDING_TOKEN` are supplied. Existing live endpoints remain unchanged; recording APIs use `Authorization: Bearer <token>` and never return object keys. Serve only behind HTTPS/trusted network and keep the token private. The UI token is tab-local (never persisted); `hls.js` must be reachable. No per-user authorization exists: anyone holding the recording token can read all recordings. The legacy live API is unauthenticated and should be protected separately at the reverse proxy.

Recording a camera additionally requires `recording_settings.enabled=1` for its `provider:profile-token` key. This is now settable from the UI (`POST /api/recordings/settings`) as well as directly in the database. The observer reuses completed segments from the existing FFmpeg HLS playlist; it does not open another camera connection. Receipt timestamps are estimated except when `EXT-X-PROGRAM-DATE-TIME` is emitted by the source. Playlist gaps/discontinuities are represented in coverage and VOD.

Default storage is `~/.local/share/onvif-viewer/recordings/{spool,objects}`. Set `ONVIF_RECORDING_DIR` to an absolute home-backed location, `ONVIF_RECORDING_QUOTA_BYTES` (default 1 GiB), `ONVIF_RECORDING_RESERVE_BYTES` (default 2 GiB), and `ONVIF_RECORDING_RETENTION_DAYS` (default 7). Spool staging fails closed at the quota/reserve threshold without stalling live FFmpeg. The quota now counts physical bytes in both spool and local object roots, including orphan and temporary files, and reserves space for simultaneous stage/object publication; S3 request-body staging is included. A rejected closed segment is reported as a coverage gap, never silently accepted. This bounded archive is still experimental: it uses directory scans rather than a filesystem-enforced quota, and concurrent unrelated writers on the same volume are outside its control. Do not enable on production without operator review.

`ONVIF_RECORDING_STORE=s3` selects the SigV4 path-style adapter, with `ONVIF_S3_ENDPOINT` (HTTPS, unless `ONVIF_S3_ALLOW_HTTP=1`), `ONVIF_S3_BUCKET`, `ONVIF_S3_REGION`, `ONVIF_S3_ACCESS_KEY`, `ONVIF_S3_SECRET_KEY`, optionally `ONVIF_S3_SESSION_TOKEN`. No S3 bucket exists for testing, so real endpoint interoperability, TLS, multipart, and failure recovery remain **unverified**. The catalog binds a store identity and refuses a backend switch rather than silently stranding footage; copying/migrating old objects is future work. S3 uses the home-backed spool for bounded request bodies. The adapter's mock integration is not proof of compatibility with a provider.

## Storage configuration is database-backed, and secrets are sealed

Storage settings resolve as **database row if present, otherwise the environment defaults**, and the resolved values are written back to `recording_storage_settings` (single row, `id=1`) on first boot so the UI has concrete values to show and edit. Row PRESENCE, not field emptiness, decides precedence: a field the operator deliberately cleared is not silently refilled from the environment. The environment stays the boot default. `recording_settings` gained `updated_ns` additively; existing rows are preserved.

| Endpoint (all behind the bearer token, including HEAD) | Purpose |
| --- | --- |
| `GET /api/recordings/status` | driver, **redacted** location, live capacity, upload/deletion backlog, health, per-camera enablement, app-key availability, driver-switch guard |
| `GET /api/recordings/summary?camera&from&to&buckets` | bounded coverage histogram (cap 240 buckets, 1000 segments) with `recordedSeconds`/`gapSeconds`/`segments` per bucket, plus `truncated` |
| `GET /api/recordings/settings` | effective editable configuration |
| `POST /api/recordings/settings` | `{camera, enabled}` and/or `{retentionDays, quotaBytes, reserveBytes}` |

Unknown fields in a write are rejected, so a client cannot believe it saved something the server ignored.

**Retention and quota are editable at runtime.** Saving a value applies it under the recorder mutex, so it takes effect on the next capture and the next retention pass with no restart, and reads back through `status`. It is also persisted to the settings row, so it survives a restart. `ONVIF_RECORDING_ENABLED` and `ONVIF_RECORDING_TOKEN` stay environment-only and are never settable in the UI: a UI-triggered recording enable would be a privilege-escalation path, and the bearer token is the single authorization.

**Driver switching is a migration, not a setting.** `BindStore` still refuses a changed store identity and that guard is untouched. The UI offers a switch only while the catalog holds zero segments and otherwise explains that a migration is required.

`ONVIF_APP_KEY` is a base64-encoded 32-byte key, or `ONVIF_APP_KEY_FILE` names a file holding the same value (it must not be group- or world-readable). `internal/secrets` seals credentials with AES-256-GCM using a fresh random 12-byte nonce per value against `nonce || ciphertext || tag`, base64 in one column, and binds each value to a context string through the GCM additional-authenticated-data (`recording.s3.secret`, `recording.s3.session`) so a value cannot be replayed into another field. Only the S3 secret and session token are sealed; endpoint, bucket, region and access key are configuration and stay plaintext. A sealed credential that cannot be opened (wrong key, tampered ciphertext, missing app key) is a **configuration error that refuses to start the store** and never degrades to an empty credential. With no app key everything except S3 still works, and `status` reports `appKeyAvailable:false` and why.

## Synthetic QA only

Generate finite H.264 footage and use `go run ./cmd/recording_fixture DB RECORDING_DIR HLS_DIR onvif:synthetic` to import to disposable state; this command is not a camera capture. Build and run from the isolated worktree only, binding `127.0.0.1:7997` after confirming it is free. Run `QA_TOKEN=... node scripts/recording-browser.mjs` against that disposable server to check decoded frames, seek and advancing currentTime. The script assumes the fixture is in the specified date interval. Never run this fixture command against the live DB.

## Known pre-production gaps

- Startup reconciles orphan spool files, missing staged data, and missing upload jobs; retention covers staged, ready, gap, and deleting states. Deletions are idempotent and retry after storage errors. Upload leases remain schema-only: the in-process uploader is serialized, but multiple processes against one catalog are unsupported. Do not point multiple app processes at the same recording directory.
- The observer still polls the published playlist every 500 ms. Missing closed files, quota refusal, and skipped media sequences are recorded as explicit gaps in coverage, including a first observed playlist with a nonzero sequence; the UI labels them. The observer is not lossless: a playlist can roll and disappear entirely before any poll, or FFmpeg can restart before publication is seen. These cases cannot be reconstructed from the playlist. Do not rely on this for continuous lossless footage.
- Program-date-time accuracy for actual ONVIF/Tuya sources and codec changes are not validated. S3 mock tests do not validate a real provider. No real camera recording was enabled.
- `Coverage` and `Summary` each read at most 1000 segments, so a very wide window can be truncated. `Summary` reports `truncated:true` and the timeline says so rather than drawing a misleadingly short strip.
- Gaps are recorded only for attempted-but-failed segments, so an absent gap row does not prove continuity. The UI says "no gap recorded", never "continuous".
