// Command tuyartsp_serve serves one Tuya stream over the in-process RTSP server
// and blocks until interrupted. It is the bring-up harness used to prove that
// RTP reaches an RTSP client (ffmpeg) with no external engine binary.
//
// Usage:
//
//	go run ./cmd/tuyartsp_serve -session <file> -addr 127.0.0.1:PORT
package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"dengan.dev/camera-streamer/internal/tuyartsp"
	"dengan.dev/camera-streamer/internal/tuyaengine"
)

func main() {
	session := flag.String("session", os.Getenv("TUYA_ENGINE_SESSION_FILE"), "read-only Tuya session file")
	device := flag.String("device", "eb9f1d6e677b1b39f222ag", "Tuya device id")
	resolution := flag.String("resolution", "sd", "sd or hd")
	host := flag.String("host", "protect-us.ismartlife.me", "Tuya region host")
	addr := flag.String("addr", "127.0.0.1:0", "RTSP listen address")
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
	if err := server.Listen(*addr); err != nil {
		fmt.Fprintln(os.Stderr, "listen:", err)
		os.Exit(1)
	}
	defer server.Close()
	if err := server.AddStream(name, source); err != nil {
		fmt.Fprintln(os.Stderr, "add stream:", err)
		os.Exit(1)
	}

	fmt.Printf("ready rtsp://127.0.0.1:%d/%s\n", server.Port(), name)
	os.Stdout.Sync()

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	<-signals
	fmt.Println("stopping")
}
