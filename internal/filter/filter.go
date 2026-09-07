// Package filter decides which packets the sniffer keeps. It produces both a
// kernel-side BPF expression (so unwanted packets never reach user space) and
// an in-process check for the fields BPF cannot express cleanly.
package filter

import (
	"fmt"
	"strings"
)

// validProtocols are the values accepted for the protocol filter. Empty means
// "any". The values double as valid BPF primitives.
var validProtocols = map[string]bool{
	"":      true,
	"tcp":   true,
	"udp":   true,
	"icmp":  true,
	"icmp6": true,
}

// Filter holds the active capture constraints.
type Filter struct {
	IP       string
	Protocol string
	Port     int
}

// New validates and builds a Filter.
func New(ip, protocol string, port int) (*Filter, error) {
	protocol = strings.ToLower(strings.TrimSpace(protocol))
	if !validProtocols[protocol] {
		return nil, fmt.Errorf("invalid protocol %q (want tcp, udp, icmp or icmp6)", protocol)
	}
	if port < 0 || port > 65535 {
		return nil, fmt.Errorf("invalid port %d (want 0-65535)", port)
	}
	return &Filter{IP: strings.TrimSpace(ip), Protocol: protocol, Port: port}, nil
}

// BPF renders the filter as a libpcap filter expression. An empty string means
// "capture everything".
func (f *Filter) BPF() string {
	if f == nil {
		return ""
	}
	var parts []string
	if f.IP != "" {
		parts = append(parts, "host "+f.IP)
	}
	if f.Protocol != "" {
		parts = append(parts, f.Protocol)
	}
	if f.Port != 0 {
		parts = append(parts, fmt.Sprintf("port %d", f.Port))
	}
	return strings.Join(parts, " and ")
}

// MatchIP reports whether ip satisfies the IP filter.
func (f *Filter) MatchIP(ip string) bool {
	return f == nil || f.IP == "" || ip == f.IP
}

// MatchProtocol reports whether protocol satisfies the protocol filter.
func (f *Filter) MatchProtocol(protocol string) bool {
	return f == nil || f.Protocol == "" || strings.EqualFold(protocol, f.Protocol)
}

// MatchPort reports whether port satisfies the port filter.
func (f *Filter) MatchPort(port int) bool {
	return f == nil || f.Port == 0 || port == f.Port
}

// MatchEndpoints reports whether a src/dst pair passes the IP and port filters
// (a match on either side is enough).
func (f *Filter) MatchEndpoints(srcIP, dstIP string, srcPort, dstPort int) bool {
	if !f.MatchIP(srcIP) && !f.MatchIP(dstIP) {
		return false
	}
	if !f.MatchPort(srcPort) && !f.MatchPort(dstPort) {
		return false
	}
	return true
}
