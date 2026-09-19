# How the XHome SmartLife app connects to the camera

**Source:** decompiled `com.sdmc.iot.android` v5.3.2.0618 (XHome SmartLife)
**Location:** `~/Codelabs/experiment/apk-re-xhome-smartlife-sdmc/` on the PC
**Date:** 2026-09-17

## TL;DR

The app does **not** connect to the camera over P2P on your LAN. It:

1. Authenticates to the SDMC cloud (`xhome-api.sdmc.tv`, `/api/v2.5/`, `/api/v3.0/`)
2. Requests a **MQTT broker URL + STUN/TURN servers** for the device (`device/connect`)
3. Establishes **WebRTC** to the camera using those STUN/TURN servers, using MQTT for signalling

Media is WebRTC, not TUTK/Kalay. That is why the packet capture showed UDP flowing
to/from one public IP: the STUN/TURN server and the WebRTC media path are both
external, by design.

## Two media stacks in the app

| Stack | Library | Used for |
|---|---|---|
| **WebRTC** | `org.webrtc` / `libjingle_peerconnection_so.so` (`com/sdmc/module_ipc/webrtc/`) | the IPC cameras |
| TUTK/Kalay | `com.tutk.IOTC`, `libIOTCAPIs.so`, `libAVAPIs.so` | legacy path, still present |

The choice is made by a **cloud-supplied capability flag**:

```java
capabilitySet.getWebrtcModel()  // if non-null -> use WebRTC
```

Seen in `MainActivityKt`, `IpcCommonVM`, `SingleIpcHomeCardFragment`,
`IPCCommonActivity`, `AlarmMessageUtilsKt`. So the server decides which transport
the app must use for a given device.

## The connection sequence (`com/sdmc/module_ipc/webrtc/d.java`)

```
POST device/connect  {deviceUuid, productUuid, serviceId, cmdCode, msgId, ...}
  -> DeviceConnectRsp {
         clientId, deviceClientId, mqttUrl, stunInfo, turnInfo, topic
     }
```

**Every field is AES-encrypted by the server** and decrypted client-side:

```java
strDecrypt = Api5ExtKt.decrypt(clientId);
... same for deviceClientId, mqttUrl, stunInfo, topic, turnInfo
```

`Api5ExtKt.decrypt` → `AESEncryptUtil.decrypt(...)` (SpongyCastle AES).
The encryption key comes from **`ApiHelper.INSTANCE.getSecretKey()`**, which is
read from a **tenant config** fetched at runtime - it is not a hardcoded literal.

### MQTT credentials

```java
mqttUrl        = rsp.getMqttUrl()             // AES-decrypted broker URL
username       = SPUtils.getUserName()        // the logged-in account name
password       = md5HexString(secretKey + (System.currentTimeMillis() / 1000))
subscribe(topic)                              // rsp.getTopic(), AES-decrypted
```

So the MQTT password is `MD5(tenantSecretKey + unixSeconds)` - **time-based**.

### After signalling

```java
str3 = stunInfo != null ? stunInfo : "";
c0Var.setValue(new p(sdpInfo, x.g(turnInfo, str3)));   // local SDP + STUN/TURN
```

WebRTC then negotiates media directly with the camera, using the supplied
STUN/TURN servers.

## Why this cannot be done locally without the cloud

1. **`device/connect` is an authenticated cloud call.** It requires a logged-in
   account token, and returns the certificate/relay information.
2. **The response is AES-encrypted with a tenant secret key** obtained from a
   separate config endpoint at runtime.
3. **The MQTT password is `MD5(secretKey + time)`** - it changes every second and
   is derived from that same secret.
4. **Signalling rides on MQTT** to a cloud broker; the STUN/TURN servers are
   cloud-supplied.

There is no local discovery path in this flow. `com.freeman.ipcam`'s
`IOTC_Lan_Search()` still exists but the camera did not answer TUTK LAN search
(verified with a UDP probe), and the IPC path does not use it.

## Camera-side ports (measured on 10.2.56.194)

| Port | Proto | What answered |
|---|---|---|
| 8000 | TCP | Happytime onvif server V9.1 (ONVIF SOAP + HTTP) |
| 5543 | TCP | RTSP - **no auth required** |
| 3702 | UDP | WS-Discovery responder |
| - | UDP | **no P2P / TUTK service; no reply on broadcast 32768** |

## Practical consequences

- **The ONVIF/RTSP surface is the only local path that works today.** RTSP needs
  no credentials and delivers main stream 2304x1296 H.264 + G.711 audio.
- **PTZ and two-way audio are only in the cloud/WebRTC path** - consistent with
  the observation that the camera advertises no ONVIF PTZ service at all
  (`GetServices` lists device/media/media2/image/event, but no PTZ).
- **The RTSP stall** ("connected but no frames") is a camera-side defect in the
  stream path, not an auth problem - worth attacking separately by testing
  sustained reads and TCP vs UDP transport.
- **Reproducing the app's connection locally would require impersonating the
  cloud API** (account login + tenant secret + device/connect + MQTT
  signalling). That is a much larger project than the local probe initially
  suggested, and it depends on the vendor's servers staying reachable.

## Honest limits

- The tenant `secretKey` was **not recovered** - it is fetched at runtime, and I
  did not locate the config endpoint that returns it.
- `AESEncryptUtil`'s mode/IV/key-derivation were not fully analysed.
- No credentials were extracted and none are stored in this document.
