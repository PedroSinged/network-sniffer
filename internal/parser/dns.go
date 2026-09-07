package parser

import (
	"strings"

	"github.com/google/gopacket/layers"

	"github.com/PedroSinged/network-sniffer/internal/event"
)

// DNS converts a decoded DNS layer into an *event.DNSInfo and the matching
// event.Kind (query or response).
func DNS(dns *layers.DNS) (*event.DNSInfo, event.Kind) {
	if dns == nil {
		return nil, ""
	}

	if !dns.QR { // question
		info := &event.DNSInfo{}
		for _, q := range dns.Questions {
			info.Questions = append(info.Questions, trimName(string(q.Name)))
		}
		if len(info.Questions) == 0 {
			return nil, ""
		}
		return info, event.KindDNSQuery
	}

	info := &event.DNSInfo{}
	for _, a := range dns.Answers {
		rec := event.DNSRecord{Name: trimName(string(a.Name)), Type: a.Type.String()}
		switch a.Type {
		case layers.DNSTypeA, layers.DNSTypeAAAA:
			if a.IP != nil {
				rec.Value = a.IP.String()
			}
		case layers.DNSTypeCNAME:
			rec.Value = trimName(string(a.CNAME))
		case layers.DNSTypeNS:
			rec.Value = trimName(string(a.NS))
		case layers.DNSTypePTR:
			rec.Value = trimName(string(a.PTR))
		case layers.DNSTypeTXT:
			rec.Value = string(joinTXT(a.TXTs))
		default:
			continue
		}
		info.Answers = append(info.Answers, rec)
	}
	if len(info.Answers) == 0 {
		return nil, ""
	}
	return info, event.KindDNSResponse
}

func trimName(s string) string { return strings.TrimSuffix(s, ".") }

func joinTXT(txts [][]byte) []byte {
	out := make([]byte, 0, 32)
	for i, t := range txts {
		if i > 0 {
			out = append(out, ' ')
		}
		out = append(out, t...)
	}
	return out
}
