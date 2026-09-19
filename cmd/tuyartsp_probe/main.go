// Command tuyartsp_probe is a bring-up harness: it serves one Tuya stream over
// the in-process RTSP server and prints the SDP an RTSP client would see.
//
// Usage:
//
//	go run ./cmd/tuyartsp_probe -session <file> -device <id> -resolution sd
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"dengan.dev/camera-streamer/internal/tuyartsp"
	"dengan.dev/camera-streamer/internal/tuyaengine"
)

func main() {
	session := flag.String("session", os.Getenv("TUYA_ENGINE_SESSION_FILE"), "read-only Tuya session file")
	device := flag.String("device", "eb9f1d6e677b1b39f222ag", "Tuya device id")
	resolution := flag.String("resolution", "sd", "sd or hd")
	host := flag.String("host", "protect-us.ismartlife.me", "Tuya region host")
	flag.Parse()

	if *session == "" {
		fmt.Fprintln(os.Stderr, "no session file")
		os.Exit(2)
	}

	spec := tuyaengine.DeviceSpec{DeviceID: *device, SessionFile: *session, Resolution: *resolution, Host: *host}
	normalized, err := spec.Normalize(tuyaengine.DeviceSpec{})
	if err != nil {
		fmt.Fprintln(os.Stderr, "spec:", err)
		os.Exit(2)
	}
	name, err := normalized.StreamName()
	if err != nil {
		fmt.Fprintln(os.Stderr, "name:", err)
		os.Exit(2)
	}
	source, err := normalized.EngineURL()
	if err != nil {
		fmt.Fprintln(os.Stderr, "source:", err)
		os.Exit(2)
	}

	server := tuyartsp.New()
	if err := server.Listen("127.0.0.1:0"); err != nil {
		fmt.Fprintln(os.Stderr, "listen:", err)
		os.Exit(1)
	}
	defer server.Close()
	if err := server.AddStream(name, source); err != nil {
		fmt.Fprintln(os.Stderr, "add stream:", err)
		os.Exit(1)
	}

	url := fmt.Sprintf("rtsp://127.0.0.1:%d/%s", server.Port(), name)
	fmt.Printf("rtsp_url=%s\n", url)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	start := time.Now()
	code, sdp, err := tuyaengine.RTSPDescribe(ctx, url, 55*time.Second)
	fmt.Printf("describe_code=%d elapsed=%s err=%v\n", code, time.Since(start).Round(time.Millisecond), err)
	if sdp != "" {
		fmt.Printf("sdp:\n%s\n", sdp)
	}
	if code != 200 {
		os.Exit(1)
	}
}
