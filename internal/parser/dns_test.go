package parser

import (
	"net"
	"testing"

	"github.com/google/gopacket/layers"

	"github.com/PedroSinged/network-sniffer/internal/event"
)

func TestDNSQuery(t *testing.T) {
	dns := &layers.DNS{
		QR: false,
		Questions: []layers.DNSQuestion{
			{Name: []byte("example.com."), Type: layers.DNSTypeA},
			{Name: []byte("cdn.example.org"), Type: layers.DNSTypeAAAA},
		},
	}

	info, kind := DNS(dns)
	if info == nil || kind != event.KindDNSQuery {
		t.Fatalf("info=%v kind=%q", info, kind)
	}
	want := []string{"example.com", "cdn.example.org"}
	if len(info.Questions) != len(want) {
		t.Fatalf("questions = %v", info.Questions)
	}
	for i := range want {
		if info.Questions[i] != want[i] {
			t.Fatalf("question[%d] = %q, want %q", i, info.Questions[i], want[i])
		}
	}
}

func TestDNSResponse(t *testing.T) {
	dns := &layers.DNS{
		QR: true,
		Answers: []layers.DNSResourceRecord{
			{Name: []byte("example.com"), Type: layers.DNSTypeA, IP: net.IPv4(93, 184, 216, 34)},
			{Name: []byte("example.com"), Type: layers.DNSTypeCNAME, CNAME: []byte("edge.example.net.")},
			{Name: []byte("example.com"), Type: layers.DNSTypeMX}, // unsupported -> skipped
		},
	}

	info, kind := DNS(dns)
	if info == nil || kind != event.KindDNSResponse {
		t.Fatalf("info=%v kind=%q", info, kind)
	}
	if len(info.Answers) != 2 {
		t.Fatalf("answers = %+v", info.Answers)
	}
	if info.Answers[0].Value != "93.184.216.34" {
		t.Fatalf("A value = %q", info.Answers[0].Value)
	}
	if info.Answers[1].Value != "edge.example.net" {
		t.Fatalf("CNAME value = %q", info.Answers[1].Value)
	}
}

func TestDNSEmpty(t *testing.T) {
	if info, _ := DNS(nil); info != nil {
		t.Fatal("nil layer should yield nil info")
	}
	if info, _ := DNS(&layers.DNS{QR: true}); info != nil {
		t.Fatal("response with no answers should yield nil info")
	}
}
