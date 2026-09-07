package parser

import (
	"encoding/binary"
	"testing"
)

// clientHello builds a minimal TLS 1.2 ClientHello record carrying the given
// SNI host (or no SNI extension when host is empty).
func clientHello(host string) []byte {
	var ext []byte
	if host != "" {
		name := []byte(host)
		sni := []byte{0x00} // name_type = host_name
		sni = appendU16(sni, len(name))
		sni = append(sni, name...)

		body := appendU16(nil, len(sni)) // server_name_list length
		body = append(body, sni...)

		ext = appendU16(nil, 0x0000) // extension type = server_name
		ext = appendU16(ext, len(body))
		ext = append(ext, body...)
	}

	hs := []byte{0x03, 0x03}             // client_version
	hs = append(hs, make([]byte, 32)...) // random
	hs = append(hs, 0x00)                // session_id length
	hs = appendU16(hs, 2)                // cipher_suites length
	hs = append(hs, 0x00, 0x2f)          // one cipher suite
	hs = append(hs, 0x01, 0x00)          // compression: length 1, method null
	hs = appendU16(hs, len(ext))         // extensions length
	hs = append(hs, ext...)

	handshake := []byte{0x01} // ClientHello
	handshake = append(handshake, byte(len(hs)>>16), byte(len(hs)>>8), byte(len(hs)))
	handshake = append(handshake, hs...)

	rec := []byte{0x16, 0x03, 0x01}
	rec = appendU16(rec, len(handshake))
	rec = append(rec, handshake...)
	return rec
}

func appendU16(b []byte, v int) []byte {
	return binary.BigEndian.AppendUint16(b, uint16(v))
}

func TestTLSClientHelloSNI(t *testing.T) {
	info := TLSClientHello(clientHello("api.example.com"))
	if info == nil {
		t.Fatal("expected TLS info, got nil")
	}
	if info.SNI != "api.example.com" {
		t.Fatalf("sni = %q", info.SNI)
	}
	if info.Version != "1.2" {
		t.Fatalf("version = %q", info.Version)
	}
}

func TestTLSClientHelloNoSNI(t *testing.T) {
	info := TLSClientHello(clientHello(""))
	if info == nil {
		t.Fatal("expected TLS info, got nil")
	}
	if info.SNI != "" {
		t.Fatalf("sni = %q, want empty", info.SNI)
	}
}

func TestTLSNotHandshake(t *testing.T) {
	cases := [][]byte{
		nil,
		[]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
		{0x17, 0x03, 0x03, 0x00, 0x10}, // application data record
	}
	for i, c := range cases {
		if info := TLSClientHello(c); info != nil {
			t.Fatalf("case %d: expected nil, got %+v", i, info)
		}
	}
}
