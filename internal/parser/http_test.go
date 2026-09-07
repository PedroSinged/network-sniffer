package parser

import (
	"testing"

	"github.com/PedroSinged/network-sniffer/internal/event"
)

func TestHTTPRequest(t *testing.T) {
	payload := []byte("GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/8.0\r\nAccept: */*\r\n\r\n")

	info, kind := HTTP(payload)
	if info == nil {
		t.Fatal("expected request info, got nil")
	}
	if kind != event.KindHTTPRequest {
		t.Fatalf("kind = %q, want %q", kind, event.KindHTTPRequest)
	}
	if info.Method != "GET" || info.Path != "/index.html" {
		t.Fatalf("method/path = %q %q", info.Method, info.Path)
	}
	if info.Host != "example.com" {
		t.Fatalf("host = %q", info.Host)
	}
	if info.UserAgent != "curl/8.0" {
		t.Fatalf("user-agent = %q", info.UserAgent)
	}
}

func TestHTTPResponse(t *testing.T) {
	payload := []byte("HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\n\r\n")

	info, kind := HTTP(payload)
	if info == nil || kind != event.KindHTTPResponse {
		t.Fatalf("info=%v kind=%q", info, kind)
	}
	if info.Status != "404 Not Found" {
		t.Fatalf("status = %q", info.Status)
	}
}

func TestHTTPNonHTTP(t *testing.T) {
	cases := [][]byte{
		nil,
		[]byte("short"),
		[]byte("\x16\x03\x01\x00\x50 this is a TLS record not http at all"),
		[]byte("SSH-2.0-OpenSSH_9.0\r\n"),
	}
	for i, payload := range cases {
		if info, _ := HTTP(payload); info != nil {
			t.Fatalf("case %d: expected nil, got %+v", i, info)
		}
	}
}
