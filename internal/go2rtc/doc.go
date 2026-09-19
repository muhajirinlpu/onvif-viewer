// Package go2rtc is the vendoring root for a subset of github.com/AlexxIT/go2rtc.
//
// # Provenance
//
//	Upstream:  https://github.com/AlexxIT/go2rtc
//	Commit:    c245815e75e2a5fd60b4290f12bfc04e55a984d3 (c245815, 2026-07-13)
//	License:   MIT, Copyright (c) 2022 Alexey Khit
//	Vendored:  2026-09-19
//
// The full upstream license text is in LICENSE-go2rtc next to this file. This
// package exists only so the directory has a doc.go naming the provenance; it
// contains no code.
//
// # What is here and why
//
// The upstream package layout is preserved verbatim (aac, bits, core, h264,
// h265, mjpeg, pcm, rtsp, shell, tcp, tcp/websocket, tuya, webrtc, xnet, y4m).
// The only edit applied to every file is the import rewrite
//
//	github.com/AlexxIT/go2rtc/pkg/X -> dengan.dev/camera-streamer/internal/go2rtc/X
//
// plus the three small vet-driven patches and the Tuya session patch described
// in README.md and patches/.
//
// Nothing under go2rtc's internal/ (internal/app, internal/streams,
// internal/rtsp) is vendored: the packages here have zero dependency on that
// application layer, which is what makes an in-process subset possible.
package go2rtc
