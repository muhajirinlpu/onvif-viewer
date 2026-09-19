package tuyaqr

import (
	"errors"
	"fmt"
)

// Sentinel errors the HTTP layer switches on with errors.Is.
var (
	// ErrQRExpired means the displayed QR token is no longer usable
	// (cloud errorCode USER_QR_LOGIN_TOKEN_EXPIRE / _INVALID). The caller
	// must call BeginLogin again and show the new image.
	ErrQRExpired = errors.New("tuyaqr: QR login token expired")

	// ErrQRScanned means the token was consumed elsewhere or the scan was
	// cancelled (cloud errorCode USER_QR_LOGIN_TOKEN_SCANED). Also terminal
	// for this token.
	ErrQRScanned = errors.New("tuyaqr: QR login token already scanned or cancelled")

	// ErrSessionExpired means the stored session cookies were rejected by the
	// cloud (HTTP 401 / errorCode USER_SESSION_LOSS). A fresh QR login is
	// required; retrying cannot help.
	ErrSessionExpired = errors.New("tuyaqr: stored session is no longer valid")

	// ErrNoSession means there is nothing usable to load: missing file, or a
	// session without the fast-sid/s-sid cookie pair that every authenticated
	// call needs.
	ErrNoSession = errors.New("tuyaqr: no usable session")
)

// QRExpiredError is the concrete typed error for an expired QR token.
type QRExpiredError struct {
	ErrorCode string
	ErrorMsg  string
}

func (e *QRExpiredError) Error() string {
	if e.ErrorMsg == "" {
		return fmt.Sprintf("tuyaqr: QR token expired (%s)", e.ErrorCode)
	}
	return fmt.Sprintf("tuyaqr: QR token expired (%s): %s", e.ErrorCode, e.ErrorMsg)
}

// Is makes errors.Is(err, ErrQRExpired) true.
func (e *QRExpiredError) Is(target error) bool { return target == ErrQRExpired }

// QRScannedError is the concrete typed error for a token consumed elsewhere.
type QRScannedError struct {
	ErrorCode string
	ErrorMsg  string
}

func (e *QRScannedError) Error() string {
	return fmt.Sprintf("tuyaqr: QR token already used (%s): %s", e.ErrorCode, e.ErrorMsg)
}

// Is makes errors.Is(err, ErrQRScanned) true.
func (e *QRScannedError) Is(target error) bool { return target == ErrQRScanned }

// SessionExpiredError is returned when the cloud rejects the stored cookies.
type SessionExpiredError struct {
	StatusCode int
	ErrorCode  string
	ErrorMsg   string
}

func (e *SessionExpiredError) Error() string {
	return fmt.Sprintf("tuyaqr: session rejected by cloud (HTTP %d, %s): %s",
		e.StatusCode, e.ErrorCode, e.ErrorMsg)
}

// Is makes errors.Is(err, ErrSessionExpired) true.
func (e *SessionExpiredError) Is(target error) bool { return target == ErrSessionExpired }

// APIError is any other well-formed cloud refusal.
type APIError struct {
	StatusCode int
	ErrorCode  string
	ErrorMsg   string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("tuyaqr: cloud refused request (HTTP %d, %s): %s",
		e.StatusCode, e.ErrorCode, e.ErrorMsg)
}
