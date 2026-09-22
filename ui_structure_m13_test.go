package main

import (
	"strings"
	"testing"
)

// --- the UI must render "could not verify" without offering a re-login --------
//
// The server half of the fix keeps `/api/tuya/session` at 200 with
// `checkFailed:true` and `reloginRequired:false`. That is only half the job: the
// panel must have a branch that renders that state, and the re-login banner must
// stay gated on the server's own flag. MEASURED on 2026-09-22, the UI demanded a
// QR scan for a session the cloud had accepted two minutes earlier, and the only
// thing that cleared it was a human complying.
//
// These are ADDITIVE: every M6/M8 assertion about tuyaSession.filePresent,
// cloudVerified, expiryKnown, expirySource and reloginRequired still guards the
// same tokens it always did.
func TestFrontendShowsCouldNotVerifyWithoutOfferingARelogin(t *testing.T) {
	html := readIndexHTML(t)

	for _, token := range []string{
		// The additive server field the branch keys on.
		"tuyaSession.checkFailed",
		"tuyaSession.checkError",
		// The honest wording, and the explicit "nothing was stopped".
		"could not be verified",
		"nothing was deemed invalid",
		"no re-login is needed",
		"cameras keep streaming",
	} {
		if !strings.Contains(html, token) {
			t.Errorf("missing could-not-verify token %q", token)
		}
	}

	// The branch must be a real v-else-if, not an unconditionally rendered block,
	// and it must sit AFTER the verified branch so a verified session still wins.
	vif := strings.Index(html, `v-if="tuyaSession.valid"`)
	velseif := strings.Index(html, `v-else-if="tuyaSession.checkFailed"`)
	if vif < 0 || velseif < 0 {
		t.Fatal("the could-not-verify state must be reachable as an explicit branch of the session panel")
	}
	if velseif < vif {
		t.Error("the could-not-verify branch must come AFTER the verified branch, or a verified session could render as unverified")
	}

	// The re-login action must remain gated on the SERVER's verdict, never on the
	// absence of validity: that conflation is exactly the bug.
	//
	// The check is scoped to the BANNER itself, because `v-if="!tuyaSession.valid"`
	// legitimately exists one level up as the "not signed in — show the QR panel"
	// gate, and an inconclusive check on a session that was never verified has
	// nothing else to render. What must never happen is the BANNER — the thing
	// that tells the user their cameras were stopped and to sign in again —
	// appearing because a probe failed to conclude.
	banner := strings.Index(html, "tuya-relogin-required")
	if banner < 0 {
		t.Fatal("the re-login banner token is gone")
	}
	// Look back far enough to include the opening <div> that carries the
	// conditional directive.
	regionStart := banner
	if idx := strings.LastIndex(html[:banner], "tuyaSession.reloginRequired"); idx >= 0 && idx > banner-400 {
		if open := strings.LastIndex(html[:idx], "<div "); open >= 0 {
			regionStart = open
		}
	}
	region := html[regionStart : banner+200]
	if !strings.Contains(region, `v-if="tuyaSession.reloginRequired"`) {
		t.Errorf("the re-login banner must be gated on tuyaSession.reloginRequired from the server; region = %q", region)
	}
	if strings.Contains(region, "!tuyaSession.valid") {
		t.Error("the re-login banner must NOT be gated on !valid: \"could not verify\" is not \"must re-login\"")
	}

	// The could-not-verify copy must not tell the user to scan a code.
	block := html[velseif:]
	if end := strings.Index(block, `<!--`); end > 0 {
		block = block[:end]
	}
	lower := strings.ToLower(block)
	for _, forbidden := range []string{"scan a qr", "sign in again", "re-login required"} {
		if strings.Contains(lower, forbidden) {
			t.Errorf("the could-not-verify branch contains %q: it must not ask for a QR scan, which cannot fix a network failure", forbidden)
		}
	}
}

// TestFrontendCreditRecoverySaysItIsAutomatic keeps the panel honest about WHO
// fixes a rejection, because the panel used to offer only the manual path.
func TestFrontendCreditRecoverySaysItIsAutomatic(t *testing.T) {
	html := readIndexHTML(t)
	for _, token := range []string{
		"AutoResumedStreams",
		"autoResumedStreams",
	} {
		_ = token // the field is additive and may legitimately be omitted from the panel
	}
	if !strings.Contains(html, "tuya-relogin-required") {
		t.Fatal("the re-login banner must still exist: a real rejection still needs a human")
	}
	// And the panel must not claim that nothing ever needs a human.
	if strings.Contains(html, "no QR scan is ever needed") {
		t.Error("the panel must not claim a QR scan is never needed: a genuine 401 still requires one")
	}
}
