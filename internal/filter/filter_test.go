package filter

import "testing"

func TestNewValidation(t *testing.T) {
	if _, err := New("", "sctp", 0); err == nil {
		t.Fatal("expected error for unknown protocol")
	}
	if _, err := New("", "tcp", 70000); err == nil {
		t.Fatal("expected error for out-of-range port")
	}
	if _, err := New("1.1.1.1", "TCP", 443); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestBPF(t *testing.T) {
	cases := []struct {
		ip       string
		protocol string
		port     int
		want     string
	}{
		{"", "", 0, ""},
		{"8.8.8.8", "", 0, "host 8.8.8.8"},
		{"", "udp", 53, "udp and port 53"},
		{"1.2.3.4", "tcp", 443, "host 1.2.3.4 and tcp and port 443"},
	}
	for _, c := range cases {
		f, err := New(c.ip, c.protocol, c.port)
		if err != nil {
			t.Fatalf("New(%q,%q,%d): %v", c.ip, c.protocol, c.port, err)
		}
		if got := f.BPF(); got != c.want {
			t.Fatalf("BPF() = %q, want %q", got, c.want)
		}
	}
}

func TestMatchEndpoints(t *testing.T) {
	f, _ := New("10.0.0.5", "", 443)

	if !f.MatchEndpoints("10.0.0.5", "93.184.216.34", 51000, 443) {
		t.Fatal("expected match on dst port + src ip")
	}
	if f.MatchEndpoints("10.0.0.9", "93.184.216.34", 51000, 80) {
		t.Fatal("expected no match: wrong ip and wrong port")
	}
}

func TestNilFilterAllowsEverything(t *testing.T) {
	var f *Filter
	if !f.MatchIP("1.2.3.4") || !f.MatchPort(80) || !f.MatchProtocol("tcp") {
		t.Fatal("nil filter must allow all")
	}
	if f.BPF() != "" {
		t.Fatal("nil filter BPF must be empty")
	}
}
