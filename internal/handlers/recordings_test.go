package handlers

import (
 "net/http"
 "net/http/httptest"
 "testing"
)
func TestRecordingRoutesRequireCredential(t *testing.T){h:=RecordingRoutes(nil,"secret");for _,route:=range []string{"/api/recordings?camera=cam&from=2026-10-04T12:00:00Z&to=2026-10-04T13:00:00Z","/api/recordings/segments/1","/api/recordings/playlist.m3u8"}{for _,method:=range []string{"GET","HEAD"}{r:=httptest.NewRequest(method,route,nil);w:=httptest.NewRecorder();h.ServeHTTP(w,r);if w.Code!=http.StatusUnauthorized{t.Fatalf("%s %s status %d",method,route,w.Code)}}}}
