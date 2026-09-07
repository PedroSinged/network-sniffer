package stats

import (
	"strings"
	"testing"

	"github.com/PedroSinged/network-sniffer/internal/event"
)

func TestRecordAndReport(t *testing.T) {
	s := New()

	s.Record(event.Event{Kind: event.KindTCP, SrcIP: "10.0.0.1", DstIP: "1.1.1.1", Length: 100})
	s.Record(event.Event{Kind: event.KindTCP, SrcIP: "10.0.0.1", DstIP: "1.1.1.1", Length: 40})
	s.Record(event.Event{
		Kind:  event.KindDNSQuery,
		SrcIP: "10.0.0.1", DstIP: "8.8.8.8", Length: 60,
		DNS: &event.DNSInfo{Questions: []string{"example.com"}},
	})

	r := s.Report()
	if r.Packets != 3 {
		t.Fatalf("packets = %d, want 3", r.Packets)
	}
	if r.Bytes != 200 {
		t.Fatalf("bytes = %d, want 200", r.Bytes)
	}
	if r.ByKind[event.KindTCP] != 2 {
		t.Fatalf("tcp count = %d, want 2", r.ByKind[event.KindTCP])
	}
	if len(r.TopTalkers) == 0 || r.TopTalkers[0].Name != "10.0.0.1 -> 1.1.1.1" || r.TopTalkers[0].Count != 2 {
		t.Fatalf("top talker = %+v", r.TopTalkers)
	}
	if len(r.TopDomains) == 0 || r.TopDomains[0].Name != "example.com" {
		t.Fatalf("top domains = %+v", r.TopDomains)
	}

	if !strings.Contains(r.String(), "Session summary") {
		t.Fatal("report string missing header")
	}
}

func TestTopNOrdering(t *testing.T) {
	m := map[string]int{"a": 1, "b": 5, "c": 3, "d": 5}
	got := topN(m, 2)
	if len(got) != 2 || got[0].Name != "b" || got[1].Name != "d" {
		t.Fatalf("topN = %+v", got)
	}
}
