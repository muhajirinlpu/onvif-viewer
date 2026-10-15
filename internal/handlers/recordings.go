package handlers

import (
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"dengan.dev/camera-streamer/internal/recording"
	"dengan.dev/camera-streamer/internal/recording/storage"
)

// RecordingRoutes is deliberately separate from legacy unauthenticated live APIs.
// A missing token denies every method, including HEAD, before catalog access.
func RecordingRoutes(rec *recording.Recorder, token string, opts ...RecordingOption) http.Handler {
	cfg := recordingRouteConfig{}
	for _, opt := range opts {
		opt(&cfg)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		if token == "" || subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+token)) != 1 {
			http.Error(w, "recording authorization required", http.StatusUnauthorized)
			return
		}
		if rec == nil {
			http.Error(w, "recording unavailable", http.StatusServiceUnavailable)
			return
		}
		path := strings.TrimPrefix(r.URL.Path, "/api/recordings")
		// The status/config surface accepts POST on settings only; the media
		// surface accepts GET/HEAD only. Method rules are decided per route so a
		// write cannot ride in on the read path.
		readOnly := path != "/settings"
		if readOnly && r.Method != "GET" && r.Method != "HEAD" {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", 405)
			return
		}
		if !readOnly && r.Method != "GET" && r.Method != "HEAD" && r.Method != "POST" {
			w.Header().Set("Allow", "GET, HEAD, POST")
			http.Error(w, "method not allowed", 405)
			return
		}
		switch {
		case path == "" || path == "/":
			camera := r.URL.Query().Get("camera")
			from, e1 := time.Parse(time.RFC3339, r.URL.Query().Get("from"))
			to, e2 := time.Parse(time.RFC3339, r.URL.Query().Get("to"))
			if e1 != nil || e2 != nil {
				http.Error(w, "from/to required in RFC3339", 400)
				return
			}
			segs, e := rec.Coverage(camera, from, to)
			if e != nil {
				http.Error(w, "invalid coverage query", 400)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			if r.Method == "GET" {
				_ = json.NewEncoder(w).Encode(map[string]any{"segments": segs, "camera": camera})
			}
		case path == "/status":
			status, e := rec.Status()
			if e != nil {
				http.Error(w, "recording status unavailable", http.StatusInternalServerError)
				return
			}
			writeRecordingJSON(w, r, status)
		case path == "/summary":
			camera := r.URL.Query().Get("camera")
			from, e1 := time.Parse(time.RFC3339, r.URL.Query().Get("from"))
			to, e2 := time.Parse(time.RFC3339, r.URL.Query().Get("to"))
			if e1 != nil || e2 != nil {
				http.Error(w, "from/to required in RFC3339", 400)
				return
			}
			buckets, e := parseBuckets(r.URL.Query().Get("buckets"))
			if e != nil {
				http.Error(w, "buckets must be a positive integer", 400)
				return
			}
			summary, e := rec.Summary(camera, from, to, buckets)
			if e != nil {
				http.Error(w, "invalid summary query", 400)
				return
			}
			writeRecordingJSON(w, r, summary)
		case path == "/settings":
			handleSettings(w, r, rec, cfg)
		case path == "/playlist.m3u8":
			from, e1 := time.Parse(time.RFC3339, r.URL.Query().Get("from"))
			to, e2 := time.Parse(time.RFC3339, r.URL.Query().Get("to"))
			if e1 != nil || e2 != nil {
				http.Error(w, "invalid interval", 400)
				return
			}
			playlist, e := rec.Playlist(r.URL.Query().Get("camera"), from, to)
			if errors.Is(e, sql.ErrNoRows) {
				http.NotFound(w, r)
				return
			}
			if e != nil {
				http.Error(w, "invalid interval", 400)
				return
			}
			w.Header().Set("Content-Type", "application/vnd.apple.mpegurl")
			if r.Method == "GET" {
				io.WriteString(w, playlist)
			}
		case strings.HasPrefix(path, "/segments/"):
			id, e := strconv.ParseInt(strings.TrimPrefix(path, "/segments/"), 10, 64)
			if e != nil || id <= 0 {
				http.NotFound(w, r)
				return
			}
			s, e := rec.Segment(id)
			if e != nil {
				http.NotFound(w, r)
				return
			}
			var span *storage.ByteRange
			rangeHeader := r.Header.Get("Range")
			if rangeHeader != "" {
				if !strings.HasPrefix(rangeHeader, "bytes=") || strings.Contains(rangeHeader, ",") {
					w.Header().Set("Content-Range", fmt.Sprintf("bytes */%d", s.Size))
					http.Error(w, "invalid range", 416)
					return
				}
				bits := strings.SplitN(strings.TrimPrefix(rangeHeader, "bytes="), "-", 2)
				if len(bits) != 2 {
					http.Error(w, "invalid range", 416)
					return
				}
				start, e := strconv.ParseInt(bits[0], 10, 64)
				if e != nil {
					http.Error(w, "invalid range", 416)
					return
				}
				end := s.Size - 1
				if bits[1] != "" {
					end, e = strconv.ParseInt(bits[1], 10, 64)
					if e != nil {
						http.Error(w, "invalid range", 416)
						return
					}
				}
				span = &storage.ByteRange{Offset: start, Length: end - start + 1}
				if storage.ValidateRange(span, s.Size) != nil {
					w.Header().Set("Content-Range", fmt.Sprintf("bytes */%d", s.Size))
					http.Error(w, "invalid range", 416)
					return
				}
			}
			reader, info, e := rec.Open(r.Context(), id, span)
			if e != nil {
				http.NotFound(w, r)
				return
			}
			defer reader.Close()
			w.Header().Set("Content-Type", "video/mp2t")
			w.Header().Set("Accept-Ranges", "bytes")
			size := info.Size
			if span != nil {
				size = span.Length
				w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", span.Offset, span.Offset+span.Length-1, info.Size))
			}
			w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
			if span != nil {
				w.WriteHeader(http.StatusPartialContent)
			}
			if r.Method == "GET" {
				_, _ = io.Copy(w, io.LimitReader(reader, size))
			}
		default:
			http.NotFound(w, r)
		}
	})
}
