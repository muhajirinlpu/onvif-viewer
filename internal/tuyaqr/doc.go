// Package tuyaqr implements Tuya/Bardi QR-code login, on-disk session storage
// and camera discovery for the Tuya Smart "protect" cloud.
//
// Only QR authentication is implemented. Password login is deliberately absent:
// it is proven dead for the accounts this package serves (the cloud answers
// PASSWORD_NOT_SET / USER_PASSWD_WRONG regardless of countryCode or ifencrypt).
//
// The package is self-contained: it depends only on the standard library plus
// github.com/skip2/go-qrcode for rendering the login QR image. It does not know
// anything about the viewer's provider abstraction, the stream engine or the
// ONVIF code paths.
//
// Typical HTTP-layer use:
//
//	token, png, err := tuyaqr.BeginLogin(ctx)      // show png, start ~12min countdown
//	// poll every 1-2s:
//	sess, done, err := tuyaqr.PollLogin(ctx, token)
//	if errors.Is(err, tuyaqr.ErrQRExpired) { /* re-run BeginLogin */ }
//	if done {
//	    tuyaqr.SaveSession(path, sess)
//	    devices, _ := tuyaqr.NewClient(sess).Cameras(ctx)
//	}
//
// Secrets discipline: this package never logs, prints or returns QR tokens to
// callers other than through BeginLogin's return value, and never emits cookie
// values except inside the marshalled session file.
package tuyaqr
