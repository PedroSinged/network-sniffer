package netiface

import "testing"

func TestParseNetAdapterJSONArray(t *testing.T) {
	in := []byte(`[{"Name":"Ethernet","InterfaceGuid":"{CEC9BAA9-BF55-4390-A24C-D007D943B5F9}"},` +
		`{"Name":"Wi-Fi","InterfaceGuid":"{AAAA1111-2222-3333-4444-555566667777}"}]`)

	m := parseNetAdapterJSON(in)
	if m["cec9baa9-bf55-4390-a24c-d007d943b5f9"] != "Ethernet" {
		t.Fatalf("ethernet: %v", m)
	}
	if m["aaaa1111-2222-3333-4444-555566667777"] != "Wi-Fi" {
		t.Fatalf("wifi: %v", m)
	}
}

func TestParseNetAdapterJSONSingle(t *testing.T) {
	in := []byte(` {"Name":"Ethernet","InterfaceGuid":"{CEC9BAA9-BF55-4390-A24C-D007D943B5F9}"} `)
	m := parseNetAdapterJSON(in)
	if len(m) != 1 || m["cec9baa9-bf55-4390-a24c-d007d943b5f9"] != "Ethernet" {
		t.Fatalf("single: %v", m)
	}
}

func TestParseNetAdapterJSONBad(t *testing.T) {
	for _, bad := range [][]byte{nil, []byte("   "), []byte("null"), []byte("[]"), []byte("not json"),
		[]byte(`{"Name":"","InterfaceGuid":""}`)} {
		if m := parseNetAdapterJSON(bad); m != nil {
			t.Fatalf("parseNetAdapterJSON(%q) = %v, want nil", bad, m)
		}
	}
}

func TestDeviceGUID(t *testing.T) {
	cases := map[string]string{
		`\Device\NPF_{CEC9BAA9-BF55-4390-A24C-D007D943B5F9}`: "cec9baa9-bf55-4390-a24c-d007d943b5f9",
		`\Device\NPF_Loopback`:                               "",
		"eth0":                                               "",
		"":                                                   "",
	}
	for in, want := range cases {
		if got := deviceGUID(in); got != want {
			t.Fatalf("deviceGUID(%q) = %q, want %q", in, got, want)
		}
	}
}
