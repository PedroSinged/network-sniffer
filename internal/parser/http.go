// Package parser turns raw application-layer payloads into structured
// event fields for HTTP, DNS and TLS.
package parser

import (
	"strings"

	"github.com/PedroSinged/network-sniffer/internal/event"
)

// httpMethods is the set of tokens that may start an HTTP request line.
var httpMethods = map[string]bool{
	"GET": true, "POST": true, "PUT": true, "DELETE": true, "HEAD": true,
	"OPTIONS": true, "PATCH": true, "CONNECT": true, "TRACE": true,
}

// HTTP inspects a TCP payload and returns an *event.HTTPInfo describing a
// request or response, or nil if the payload is not the start of an HTTP
// message. The second return value is the matching event.Kind.
func HTTP(payload []byte) (*event.HTTPInfo, event.Kind) {
	if len(payload) < 16 {
		return nil, ""
	}
	text := string(payload)
	line, _, ok := strings.Cut(text, "\r\n")
	if !ok {
		line, _, ok = strings.Cut(text, "\n")
		if !ok {
			return nil, ""
		}
	}

	fields := strings.Fields(line)
	if len(fields) < 3 {
		return nil, ""
	}

	switch {
	case strings.HasPrefix(fields[0], "HTTP/"):
		return &event.HTTPInfo{Status: strings.Join(fields[1:], " ")}, event.KindHTTPResponse
	case httpMethods[fields[0]] && strings.HasPrefix(fields[len(fields)-1], "HTTP/"):
		info := &event.HTTPInfo{Method: fields[0], Path: fields[1]}
		parseHeaders(text, info)
		return info, event.KindHTTPRequest
	default:
		return nil, ""
	}
}

func parseHeaders(text string, info *event.HTTPInfo) {
	for _, raw := range strings.Split(text, "\r\n")[1:] {
		if raw == "" {
			return // end of headers
		}
		name, value, ok := strings.Cut(raw, ":")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "host":
			info.Host = value
		case "user-agent":
			info.UserAgent = value
		}
	}
}
