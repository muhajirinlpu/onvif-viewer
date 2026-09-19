package tuyaqr

import (
	"encoding/json"
	"strconv"
)

// Camera categories the Tuya cloud uses for cameras. MEASURED: "sp" is the
// category of the account's Security Camera; "dghsxj" is the second camera
// category the reference implementations accept.
const (
	CategorySmartCamera = "sp"
	CategoryCamera2     = "dghsxj"
)

// IsCamera reports whether a device category denotes a camera.
func IsCamera(category string) bool {
	return category == CategorySmartCamera || category == CategoryCamera2
}

// Home is one home/group on the account (from /api/new/common/homeList).
type Home struct {
	Admin            bool    `json:"admin"`
	Background       string  `json:"background"`
	DealStatus       int     `json:"dealStatus"`
	DisplayOrder     int     `json:"displayOrder"`
	GeoName          string  `json:"geoName"`
	Gid              int     `json:"gid"`
	GmtCreate        int64   `json:"gmtCreate"`
	GmtModified      int64   `json:"gmtModified"`
	GroupID          int     `json:"groupId"`
	GroupUserID      int     `json:"groupUserId"`
	ID               int     `json:"id"`
	Lat              float64 `json:"lat"`
	Lon              float64 `json:"lon"`
	ManagementStatus bool    `json:"managementStatus"`
	Name             string  `json:"name"`
	OwnerID          string  `json:"ownerId"`
	Role             int     `json:"role"`
	Status           bool    `json:"status"`
	UID              string  `json:"uid"`
}

// HomeID returns the identifier to pass as homeId on the room-list endpoint,
// preferring gid. MEASURED: roomList accepts homeId=169827587, which is the
// gid on this account.
func (h Home) HomeID() string {
	if h.Gid != 0 {
		return strconv.Itoa(h.Gid)
	}
	return strconv.Itoa(h.ID)
}

// RoomListRequest is the body for /api/new/common/roomList.
type RoomListRequest struct {
	HomeID string `json:"homeId"`
}

// Room is a room (or the synthetic all-devices room) with its devices.
type Room struct {
	DeviceCount int      `json:"deviceCount"`
	DeviceList  []Device `json:"deviceList"`
	RoomID      string   `json:"roomId"`
	RoomName    string   `json:"roomName"`
}

// Device is a device as returned by the room-list endpoint. Online/DeviceType
// are populated by the cloud and useful for the UI.
type Device struct {
	Category            string        `json:"category"`
	DeviceID            string        `json:"deviceId"`
	DeviceName          string        `json:"deviceName"`
	DeviceType          int           `json:"deviceType"`
	Online              bool          `json:"online"`
	P2PType             int           `json:"p2pType"`
	ProductID           string        `json:"productId"`
	SupportCloudStorage bool          `json:"supportCloudStorage"`
	UUID                string        `json:"uuid"`
	Config              *DeviceConfig `json:"-"` // filled by Cameras(); never persisted
}

// DeviceConfigRequest is the body for /api/jarvis/config.
type DeviceConfigRequest struct {
	DevID         string `json:"devId"`
	ClientTraceID string `json:"clientTraceId"`
}

// DeviceConfig is the per-device streaming configuration. It carries the
// p2p auth token and local key, so treat instances as secrets.
type DeviceConfig struct {
	AudioAttributes     json.RawMessage `json:"audioAttributes"`
	Auth                string          `json:"auth"`
	GatewayID           string          `json:"gatewayId"`
	ID                  string          `json:"id"`
	LocalKey            string          `json:"localKey"`
	MotoID              string          `json:"motoId"`
	NodeID              string          `json:"nodeId"`
	P2PConfig           P2PConfig       `json:"p2pConfig"`
	P2PType             int             `json:"p2pType"`
	Rotate              string          `json:"rotate"`
	Skill               string          `json:"skill"`
	Sub                 bool            `json:"sub"`
	SupportWebrtcRecord bool            `json:"supportWebrtcRecord"`
	SupportsPtz         bool            `json:"supportsPtz"`
	SupportsWebrtc      bool            `json:"supportsWebrtc"`
	VideoClarity        json.RawMessage `json:"videoClarity"`
	VideoClaritys       json.RawMessage `json:"videoClaritys"`
	VedioClarity        json.RawMessage `json:"vedioClarity"`
}

// P2PConfig holds the ICE servers and P2P auth used by the WebRTC engine.
type P2PConfig struct {
	Auth   string   `json:"auth"`
	Ices   []ICESrv `json:"ices"`
	MotoID string   `json:"motoId"`
}

// ICESrv is one ICE server entry (stun/turn).
type ICESrv struct {
	URLs       string `json:"urls"`
	Credential string `json:"credential,omitempty"`
	Username   string `json:"username,omitempty"`
	TTL        int    `json:"ttl,omitempty"`
}

// Skill is the decoded `skill` JSON blob: the device's WebRTC capability
// descriptor. MEASURED for the account's camera:
//
//	{"webrtc":115,"audios":[{"channels":1,"dataBit":16,"codecType":101,"sampleRate":8000}],
//	 "videos":[{"streamType":2,"profileId":"","width":2560,"codecType":4,...},
//	           {"streamType":4,"width":640,"codecType":2,...}]}
type Skill struct {
	WebRTC int         `json:"webrtc"`
	Audios []AudioSpec `json:"audios"`
	Videos []VideoSpec `json:"videos"`
}

// AudioSpec describes one audio stream profile.
type AudioSpec struct {
	Channels   int `json:"channels"`
	DataBit    int `json:"dataBit"`
	CodecType  int `json:"codecType"`
	SampleRate int `json:"sampleRate"`
}

// VideoSpec describes one video stream profile.
type VideoSpec struct {
	StreamType int    `json:"streamType"`
	ProfileID  string `json:"profileId"`
	Width      int    `json:"width"`
	Height     int    `json:"height"`
	CodecType  int    `json:"codecType"`
	SampleRate int    `json:"sampleRate"`
}

// Skill decodes the device's skill JSON. It returns an error when the blob is
// empty or malformed; a device with an undecodable skill is still a device, so
// callers may ignore it.
func (d *Device) Skill() (*Skill, error) {
	if d == nil || d.Config == nil || d.Config.Skill == "" {
		return nil, errNoSkill
	}
	var s Skill
	if err := json.Unmarshal([]byte(d.Config.Skill), &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// VideoStream returns the video profile with the given streamType, or nil.
// Conventional values: 2 = HD (2560x1440), 4 = SD (640x360).
func (s *Skill) VideoStream(streamType int) *VideoSpec {
	if s == nil {
		return nil
	}
	for i := range s.Videos {
		if s.Videos[i].StreamType == streamType {
			return &s.Videos[i]
		}
	}
	return nil
}

// MQTTCredentials is returned by /api/jarvis/mqtt. Secret: do not log.
type MQTTCredentials struct {
	Msid     string `json:"msid"`
	Password string `json:"password"`
}

var errNoSkill = errSkillUnavailable{}

type errSkillUnavailable struct{}

func (errSkillUnavailable) Error() string { return "tuyaqr: device has no skill metadata" }

// Redacted returns a copy of the device with all secret material removed,
// suitable for logging or exposing over an HTTP API.
func (d Device) Redacted() Device {
	out := d
	out.Config = nil
	if d.Config != nil {
		cfg := *d.Config
		cfg.Auth = redacted
		cfg.LocalKey = redacted
		cfg.P2PConfig.Auth = redacted
		for i := range cfg.P2PConfig.Ices {
			cfg.P2PConfig.Ices[i].Credential = redacted
			cfg.P2PConfig.Ices[i].Username = redacted
		}
		if len(cfg.P2PConfig.Ices) == 0 {
			cfg.P2PConfig.Ices = nil
		}
		out.Config = &cfg
	}
	return out
}

const redacted = "<redacted>"
