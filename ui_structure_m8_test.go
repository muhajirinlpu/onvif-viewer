package main

import (
	"strings"
	"testing"
)

// --- M8: the session lives in the project database ---------------------------
//
// ADDITIVE, as every earlier block was. Nothing above these lines was changed:
// the M6 assertions on tuyaSession.filePresent, .cloudVerified, .expiryKnown,
// .expirySource, the expiry countdown gating and the "Expiry unknown" branch all
// guard the same tokens they always did, and they still pass unmodified.
//
// These additions cover the NEW facts the panel must state now that the
// credential is a row in onvif_logs.db rather than a side-car JSON file.

func TestFrontendSaysWhereTheSessionIsStored(t *testing.T) {
	html := readIndexHTML(t)
	for _, token := range []string{
		// The store axes are consumed by the panel.
		"tuyaSession.storeKind",
		"tuyaSession.storeLocation",
		"tuya-session-store",
		// The claim is stated, not implied.
		"never in a world-readable file",
	} {
		if !strings.Contains(html, token) {
			t.Errorf("missing session-store token %q", token)
		}
	}
	// The store line must be gated on a real value from the server, so it cannot
	// render an empty sentence when the API does not report one.
	if !strings.Contains(html, `v-if="tuyaSession.storeKind"`) {
		t.Error("the store line must be gated on tuyaSession.storeKind coming from the server")
	}
}

func TestFrontendKeepsTheHonestAxesAlongsideTheStoreLine(t *testing.T) {
	html := readIndexHTML(t)
	// The M6 axes and the M8 store line must coexist in the SAME panel: replacing
	// "file present/absent" with a storage-medium line would silently drop the
	// distinction between "a credential is stored" and "the cloud accepted it".
	for _, token := range []string{
		"tuyaSession.filePresent",
		"tuyaSession.cloudVerified",
		"tuyaSession.expiryKnown",
		"tuyaSession.storeKind",
	} {
		if !strings.Contains(html, token) {
			t.Errorf("missing honesty token %q", token)
		}
	}
	// filePresent must still be rendered as its own statement.
	if !strings.Contains(html, "file {{ tuyaSession.filePresent ? 'present' : 'absent' }}") {
		t.Error("the filePresent axis must still be rendered verbatim, not replaced by the store line")
	}
}

func TestFrontendDoesNotClaimTheCredentialIsGoneFromTheHostWhenItIsInTheDatabase(t *testing.T) {
	html := readIndexHTML(t)
	// Sign-out is still local credential removal. The wording must not have been
	// narrowed to "the FILE was removed", because with database storage no file
	// is removed and that sentence would be false.
	if strings.Contains(html, "the stored Tuya session FILE was removed") {
		t.Error("the sign-out copy must not claim a FILE was removed: with the database store there is no session file")
	}
	// The M6 local-only honesty note must survive untouched.
	for _, token := range []string{
		"Tuya has no server-side logout",
		"Sign out on this device",
		"fetch('/api/tuya/logout'",
	} {
		if !strings.Contains(html, token) {
			t.Errorf("missing logout honesty token %q", token)
		}
	}
}
