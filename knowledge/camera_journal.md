# ONVIF Debugging Journal: Happytimesoft Camera Firmware

**Date:** March 5, 2026  
**Target:** 10.2.56.194:8000  
**Firmware Version:** Happytime onvif server V9.1  

## Overview
This journal tracks the reverse engineering and testing of the ONVIF capabilities of a test camera. The purpose of this investigation was to identify exactly what SOAP endpoints behave correctly according to the ONVIF spec and which features are buggy or emulated. We created a bespoke CLI tool (`cmd/onvif-debug`) to individually probe each capability.

---

## 📸 Phase 1: Media Service Evaluation

### 1. RTSP Video Streaming (H.264)
- **Status:** ✅ Fully Working
- **Command Used:** `get-stream-uri` -> `ExtractUri` -> `ffmpeg` TCP pull
- **Discoveries:** The camera strictly exposes two main profiles (a `2304x1296` mainstream and a `640x360` substream). The ONVIF `GetStreamUri` successfully negotiates and extracts a dynamic RTSP port (`5543`). FFmpeg pulls this stream cleanly with HTTP Digest constraints correctly verified.

### 2. JPEG Snapshot Extraction
- **Status:** ❌ Defective / Spec Violation
- **Command Used:** `get-snapshot-uri` -> `curl` with Basic / Digest auth
- **Discoveries:** The `/snapshot/PROFILE_...` HTTP endpoint negotiated by the ONVIF `GetSnapshotUri` command violates the HTTP Auth specification. Standard HTTP clients (Go native `http.Client`, `curl`) expect a `401 Unauthorized` with a `WWW-Authenticate` header to negotiate the Digest `nonce` challenge. Instead, the firmware forcefully returns a `500 Internal Server Error` containing the challenge payload. While workarounds could be built, this is a firmware-level bug unique to this version.

---

## 🕹️ Phase 2: PTZ (Pan, Tilt, Zoom) Service Evaluation

### 1. PTZ Endpoints and Configuration
- **Status:** ⚠️ Incomplete Capability Declaration
- **Discoveries:** The root `GetCapabilities` XML oddly leaves the PTZ service `XAddr` completely blank. However, `GetProfiles` affirmatively declares a `<tt:PTZConfiguration>` bounds limits on a `-1.0` to `1.0` grid. 

### 2. PTZ Movement Probing
- **Status:** ❌ Emulated / Fake Implementation
- **Commands Used:** `ptz-move`, `ptz-stop`, `ptz-status`
- **Discoveries:** Because the endpoint was blank, we manually targeted the generic `/onvif/ptz_service` endpoint with a `ContinuousMove` SOAP envelope.
  - Submitting speeds outside constraints (e.g., `x=10.0`) correctly triggers an XML Fault (`ter:InvalidVelocity - The requested speed is out of bounds`), proving the camera *understands* the commands.
  - Submitting a valid speed sequence (`x=1.0`) yields an apparent success (`<tptz:ContinuousMoveResponse />`).
  - **However, upon physical testing and verification via `GetStatus`**, the theoretical coordinates of the camera do not change (`x=0.0`, `y=0.0`). Furthermore, querying the PTZ state reveals it gets perpetually stuck in a `<tt:PanTilt>MOVING</tt:PanTilt>` state, even explicitly after a `<tptz:StopResponse />` is accepted.

**Conclusion on PTZ:** "Happytime onvif server" implements a *virtual/mock* PTZ handler. It conforms to parsing the SOAP semantics and validation logic but acts as a black hole with no physical lens motors bound to it. 

---

## 🔮 Phase 3: Events / Motion Detection

### 1. Event Properties & Subscription
- **Status:** ✅ Successfully Implemented
- **Commands Used:** `get-event-properties`, `create-pull-point`, `pull-messages`
- **Discoveries:**
  - `GetEventProperties` correctly returns supported topics: The camera affirmatively supports `tns1:VideoSource/MotionAlarm`, `ImageTooDark`, `ImageTooBlurry`, `SignalLoss`, and `GlobalSceneChange`!
  - `CreatePullPointSubscription` works as expected and provisions a unique mailbox address, generally at `http://10.2.56.194:8000/event_service/0`.
  - Hitting `PullMessages` over that PullPoint correctly waits, long-polls, and streams back initialization event data. For example, upon first connecting, the camera broadcasts an `Initialized` state for `ImageTooDark` and `ImageTooBlurry`. 
  - To implement Motion alerts in the Golang backend, we just need a goroutine that runs an infinite loop calling `PullMessages` on the PullPoint URL!
