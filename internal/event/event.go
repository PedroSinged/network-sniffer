// Package event defines the unified representation of an observed network
// event. Every capture path (raw TCP/UDP, HTTP, DNS, TLS) produces an Event,
// and every consumer (console output, file logger, exporter, stats) reads one.
package event

import (
	"fmt"
	"strings"
	"time"
)

// Kind identifies what a captured Event represents.
type Kind string

const (
	KindTCP            Kind = "TCP"
	KindUDP            Kind = "UDP"
	KindOther          Kind = "OTHER"
	KindHTTPRequest    Kind = "HTTP-Request"
	KindHTTPResponse   Kind = "HTTP-Response"
	KindDNSQuery       Kind = "DNS-Query"
	KindDNSResponse    Kind = "DNS-Response"
	KindTLSClientHello Kind = "TLS-ClientHello"
)

// HTTPInfo holds fields extracted from a plaintext HTTP request or response.
type HTTPInfo struct {
	Method    string `json:"method,omitempty"`
	Path      string `json:"path,omitempty"`
	Host      string `json:"host,omitempty"`
	UserAgent string `json:"user_agent,omitempty"`
	Status    string `json:"status,omitempty"`
}

// DNSRecord is a single answer inside a DNS response.
type DNSRecord struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Value string `json:"value"`
}

// DNSInfo holds the questions or answers carried by a DNS message.
type DNSInfo struct {
	Questions []string    `json:"questions,omitempty"`
	Answers   []DNSRecord `json:"answers,omitempty"`
}

// TLSInfo holds fields extracted from a TLS ClientHello.
type TLSInfo struct {
	SNI     string `json:"sni,omitempty"`
	Version string `json:"version,omitempty"`
}

// GeoInfo holds the geographic enrichment for an IP address.
type GeoInfo struct {
	Country     string `json:"country,omitempty"`
	CountryCode string `json:"country_code,omitempty"`
	City        string `json:"city,omitempty"`
}

// Event is the single value type flowing through the pipeline.
type Event struct {
	Timestamp time.Time `json:"timestamp"`
	Kind      Kind      `json:"kind"`
	Protocol  string    `json:"protocol,omitempty"`
	SrcIP     string    `json:"src_ip"`
	SrcPort   int       `json:"src_port,omitempty"`
	DstIP     string    `json:"dst_ip"`
	DstPort   int       `json:"dst_port,omitempty"`
	Length    int       `json:"length,omitempty"`

	HTTP *HTTPInfo `json:"http,omitempty"`
	DNS  *DNSInfo  `json:"dns,omitempty"`
	TLS  *TLSInfo  `json:"tls,omitempty"`

	SrcGeo *GeoInfo `json:"src_geo,omitempty"`
	DstGeo *GeoInfo `json:"dst_geo,omitempty"`
}

// Endpoints renders the "src -> dst" portion, with ports when known. IPv6
// addresses are bracketed so the port stays unambiguous.
func (e Event) Endpoints() string {
	if e.SrcPort > 0 || e.DstPort > 0 {
		return fmt.Sprintf("%s:%d -> %s:%d",
			hostport(e.SrcIP), e.SrcPort, hostport(e.DstIP), e.DstPort)
	}
	return fmt.Sprintf("%s -> %s", e.SrcIP, e.DstIP)
}

func hostport(ip string) string {
	if strings.Contains(ip, ":") {
		return "[" + ip + "]"
	}
	return ip
}

// Detail renders the protocol-specific summary shown after the endpoints.
func (e Event) Detail() string {
	switch {
	case e.HTTP != nil:
		if e.HTTP.Status != "" {
			return "Status: " + e.HTTP.Status
		}
		s := strings.TrimSpace(e.HTTP.Method + " " + e.HTTP.Path)
		if e.HTTP.Host != "" {
			s += " Host: " + e.HTTP.Host
		}
		return s
	case e.TLS != nil:
		if e.TLS.SNI != "" {
			return "SNI: " + e.TLS.SNI
		}
		return strings.TrimSpace("TLS " + e.TLS.Version)
	case e.DNS != nil:
		if len(e.DNS.Questions) > 0 {
			return "Query: " + strings.Join(e.DNS.Questions, ", ")
		}
		if len(e.DNS.Answers) > 0 {
			parts := make([]string, 0, len(e.DNS.Answers))
			for _, a := range e.DNS.Answers {
				parts = append(parts, fmt.Sprintf("%s %s %s", a.Name, a.Type, a.Value))
			}
			return "Answer: " + strings.Join(parts, ", ")
		}
	case e.Kind == KindOther && e.Protocol != "":
		return e.Protocol
	}
	return ""
}

func geoLabel(g *GeoInfo) string {
	if g == nil {
		return ""
	}
	switch {
	case g.City != "" && g.CountryCode != "":
		return g.City + "/" + g.CountryCode
	case g.CountryCode != "":
		return g.CountryCode
	case g.Country != "":
		return g.Country
	}
	return ""
}

// GeoSuffix renders the "geo: src -> dst" tail when enrichment is present.
func (e Event) GeoSuffix() string {
	src, dst := geoLabel(e.SrcGeo), geoLabel(e.DstGeo)
	if src == "" && dst == "" {
		return ""
	}
	if src == "" {
		src = "?"
	}
	if dst == "" {
		dst = "?"
	}
	return fmt.Sprintf("geo: %s -> %s", src, dst)
}

// String renders the one-line console representation of the Event.
func (e Event) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "[%s] %s", e.Kind, e.Endpoints())
	if d := e.Detail(); d != "" {
		fmt.Fprintf(&b, " | %s", d)
	}
	if g := e.GeoSuffix(); g != "" {
		fmt.Fprintf(&b, " | %s", g)
	}
	return b.String()
}
