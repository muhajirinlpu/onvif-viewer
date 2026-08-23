package main

import (
	"os"
	"strings"
	"testing"
)

func TestFrontendResponsiveStructure(t *testing.T) {
	data, err := os.ReadFile("static/index.html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(data)
	required := []string{
		"class=\"app-shell\"",
		"class=\"topbar",
		"class=\"dashboard-grid\"",
		"class=\"modal-shell\"",
		"class=\"modal-body ",
		"class=\"modal-footer\"",
		"@media (max-width: 767px)",
		"min-height:44px",
	}
	for _, token := range required {
		if !strings.Contains(html, token) {
			t.Errorf("missing responsive UI token %q", token)
		}
	}
	streams := strings.Index(html, "<!-- Active Streams -->")
	logs := strings.Index(html, "<!-- Logs Panel -->")
	if streams < 0 || logs < 0 || streams > logs {
		t.Error("active streams must appear before diagnostic logs")
	}
}

func TestFrontendModalLocksBodyScroll(t *testing.T) {
	data, err := os.ReadFile("static/index.html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(data)
	if !strings.Contains(html, "document.body.classList.toggle('modal-open'") {
		t.Error("camera setup modal must lock background scrolling")
	}
}
