package parser

import (
	"encoding/binary"

	"github.com/PedroSinged/network-sniffer/internal/event"
)

// TLS records / handshake constants.
const (
	tlsRecordHandshake = 0x16
	tlsHandshakeHello  = 0x01
	tlsExtServerName   = 0x0000
	tlsSNIHostName     = 0x00
)

var tlsVersions = map[uint16]string{
	0x0301: "1.0",
	0x0302: "1.1",
	0x0303: "1.2",
	0x0304: "1.3",
}

// TLSClientHello parses the beginning of a TLS record. If the payload is a
// ClientHello it returns an *event.TLSInfo (with the SNI when present).
func TLSClientHello(payload []byte) *event.TLSInfo {
	b := payload
	if len(b) < 43 || b[0] != tlsRecordHandshake {
		return nil
	}
	// Record header: type(1) version(2) length(2)
	recVer := binary.BigEndian.Uint16(b[1:3])
	b = b[5:]

	if len(b) < 38 || b[0] != tlsHandshakeHello {
		return nil
	}
	// Handshake header: type(1) length(3)
	b = b[4:]

	info := &event.TLSInfo{Version: tlsVersions[recVer]}

	// client_version(2) random(32)
	if len(b) < 34 {
		return info
	}
	if v, ok := tlsVersions[binary.BigEndian.Uint16(b[0:2])]; ok {
		info.Version = v
	}
	b = b[34:]

	// session_id
	b, ok := skipVec8(b)
	if !ok {
		return info
	}
	// cipher_suites (uint16 length)
	b, ok = skipVec16(b)
	if !ok {
		return info
	}
	// compression_methods (uint8 length)
	b, ok = skipVec8(b)
	if !ok {
		return info
	}
	// extensions (uint16 length)
	if len(b) < 2 {
		return info
	}
	extLen := int(binary.BigEndian.Uint16(b[0:2]))
	b = b[2:]
	if extLen > len(b) {
		extLen = len(b)
	}
	ext := b[:extLen]

	for len(ext) >= 4 {
		extType := binary.BigEndian.Uint16(ext[0:2])
		l := int(binary.BigEndian.Uint16(ext[2:4]))
		ext = ext[4:]
		if l > len(ext) {
			return info
		}
		if extType == tlsExtServerName {
			if name := parseSNI(ext[:l]); name != "" {
				info.SNI = name
			}
			return info
		}
		ext = ext[l:]
	}
	return info
}

// parseSNI reads a server_name extension body and returns the first host name.
func parseSNI(b []byte) string {
	if len(b) < 2 {
		return ""
	}
	listLen := int(binary.BigEndian.Uint16(b[0:2]))
	b = b[2:]
	if listLen > len(b) {
		listLen = len(b)
	}
	b = b[:listLen]
	for len(b) >= 3 {
		nameType := b[0]
		nameLen := int(binary.BigEndian.Uint16(b[1:3]))
		b = b[3:]
		if nameLen > len(b) {
			return ""
		}
		if nameType == tlsSNIHostName {
			return string(b[:nameLen])
		}
		b = b[nameLen:]
	}
	return ""
}

// skipVec8 drops a length-prefixed vector whose length is a single byte.
func skipVec8(b []byte) ([]byte, bool) {
	if len(b) < 1 {
		return b, false
	}
	n := int(b[0])
	if 1+n > len(b) {
		return b, false
	}
	return b[1+n:], true
}

// skipVec16 drops a length-prefixed vector whose length is a uint16.
func skipVec16(b []byte) ([]byte, bool) {
	if len(b) < 2 {
		return b, false
	}
	n := int(binary.BigEndian.Uint16(b[0:2]))
	if 2+n > len(b) {
		return b, false
	}
	return b[2+n:], true
}
