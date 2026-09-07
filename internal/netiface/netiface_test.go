package netiface

import (
	"strings"
	"testing"
)

func fixture() []Device {
	return []Device{
		{Name: `\Device\NPF_{CEC9BAA9}`, Description: "Realtek PCIe GbE Family Controller", Friendly: "Ethernet", Addrs: []string{"192.168.1.75"}},
		{Name: `\Device\NPF_{AEBBC370}`, Description: "Bluetooth Device (Personal Area Network)"},
		{Name: `\Device\NPF_Loopback`, Description: "Adapter for loopback traffic capture", Addrs: []string{"127.0.0.1"}},
		{Name: `\Device\NPF_{062AF63E}`, Description: "WAN Miniport (IP)"},
	}
}

func TestResolveByIndex(t *testing.T) {
	d := fixture()
	got, err := Resolve("0", d)
	if err != nil || got != d[0].Name {
		t.Fatalf("Resolve(0) = %q, %v", got, err)
	}
	if got, _ := Resolve("2", d); got != d[2].Name {
		t.Fatalf("Resolve(2) = %q", got)
	}
}

func TestResolveByName(t *testing.T) {
	d := fixture()
	cases := map[string]string{
		"Realtek":   d[0].Name,
		"realtek":   d[0].Name, // case-insensitive
		"real":      d[0].Name, // partial
		"bluetooth": d[1].Name,
		"loopback":  d[2].Name,
		"WAN":       d[3].Name, // first match wins
	}
	for in, want := range cases {
		got, err := Resolve(in, d)
		if err != nil || got != want {
			t.Fatalf("Resolve(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
}

func TestResolveByConnectionName(t *testing.T) {
	d := fixture()
	for _, in := range []string{"Ethernet", "ethernet", "ETHERNET"} {
		got, err := Resolve(in, d)
		if err != nil || got != d[0].Name {
			t.Fatalf("Resolve(%q) = %q, %v; want %q", in, got, err, d[0].Name)
		}
	}
	// partial match on the connection name
	if got, _ := Resolve("ether", d); got != d[0].Name {
		t.Fatalf(`Resolve("ether") = %q`, got)
	}
}

func TestResolveByExactDeviceName(t *testing.T) {
	d := fixture()
	got, err := Resolve(`\Device\NPF_{CEC9BAA9}`, d)
	if err != nil || got != d[0].Name {
		t.Fatalf("Resolve(exact) = %q, %v", got, err)
	}
}

func TestResolveErrors(t *testing.T) {
	d := fixture()

	_, err := Resolve("xyz", d)
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("expected not-found error, got %v", err)
	}
	if !strings.Contains(err.Error(), "-list-interfaces") {
		t.Fatalf("error should mention -list-interfaces: %v", err)
	}

	_, err = Resolve("999", d)
	if err == nil || !strings.Contains(err.Error(), "out of range") {
		t.Fatalf("expected out-of-range error, got %v", err)
	}

	if _, err := Resolve("  ", d); err == nil {
		t.Fatal("expected error for blank input")
	}
}

func TestFormat(t *testing.T) {
	out := Format(fixture())
	for _, want := range []string{"[0]", "Realtek", `\Device\NPF_Loopback`, "192.168.1.75"} {
		if !strings.Contains(out, want) {
			t.Fatalf("Format() missing %q:\n%s", want, out)
		}
	}
	if Format(nil) == "" {
		t.Fatal("Format(nil) should not be empty")
	}
}
