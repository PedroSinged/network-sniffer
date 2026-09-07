package event

import (
	"strings"
	"testing"
	"time"
)

func TestStringTCP(t *testing.T) {
	e := Event{
		Timestamp: time.Now(), Kind: KindTCP, Protocol: "tcp",
		SrcIP: "10.0.0.1", SrcPort: 51000, DstIP: "1.1.1.1", DstPort: 443,
	}
	if got := e.String(); got != "[TCP] 10.0.0.1:51000 -> 1.1.1.1:443" {
		t.Fatalf("String() = %q", got)
	}
}

func TestStringHTTPRequestWithGeo(t *testing.T) {
	e := Event{
		Kind:  KindHTTPRequest,
		SrcIP: "10.0.0.1", SrcPort: 51000, DstIP: "93.184.216.34", DstPort: 80,
		HTTP:   &HTTPInfo{Method: "GET", Path: "/", Host: "example.com"},
		DstGeo: &GeoInfo{CountryCode: "US", City: "Norwalk"},
	}
	got := e.String()
	if !strings.Contains(got, "GET / Host: example.com") {
		t.Fatalf("missing http detail: %q", got)
	}
	if !strings.Contains(got, "geo: ? -> Norwalk/US") {
		t.Fatalf("missing geo suffix: %q", got)
	}
}

func TestDetailDNS(t *testing.T) {
	e := Event{Kind: KindDNSResponse, DNS: &DNSInfo{
		Answers: []DNSRecord{{Name: "example.com", Type: "A", Value: "1.2.3.4"}},
	}}
	if got := e.Detail(); got != "Answer: example.com A 1.2.3.4" {
		t.Fatalf("Detail() = %q", got)
	}
}
