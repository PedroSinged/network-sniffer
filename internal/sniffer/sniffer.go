// Package sniffer wires libpcap capture to the parsing, enrichment and output
// pipeline.
package sniffer

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	"github.com/PedroSinged/network-sniffer/internal/config"
	"github.com/PedroSinged/network-sniffer/internal/event"
	"github.com/PedroSinged/network-sniffer/internal/export"
	"github.com/PedroSinged/network-sniffer/internal/filter"
	"github.com/PedroSinged/network-sniffer/internal/geoip"
	"github.com/PedroSinged/network-sniffer/internal/logger"
	"github.com/PedroSinged/network-sniffer/internal/parser"
	"github.com/PedroSinged/network-sniffer/internal/stats"
)

// readTimeout bounds how long a blocked read waits, so Run can notice context
// cancellation promptly.
const readTimeout = time.Second

// Deps are the collaborators the sniffer writes through. Logger, Exporter and
// Geo may be nil.
type Deps struct {
	Out      io.Writer
	ErrOut   io.Writer
	Logger   *logger.Logger
	Exporter *export.Writer
	Geo      *geoip.Resolver
	Stats    *stats.Stats
}

// Sniffer captures packets from one interface.
type Sniffer struct {
	handle   *pcap.Handle
	filter   *filter.Filter
	noColor  bool
	out      io.Writer
	errOut   io.Writer
	logger   *logger.Logger
	exporter *export.Writer
	geo      *geoip.Resolver
	stats    *stats.Stats
}

// New opens the capture handle and installs the kernel-side BPF filter.
func New(cfg config.Config, f *filter.Filter, d Deps) (*Sniffer, error) {
	handle, err := pcap.OpenLive(cfg.Interface, int32(cfg.SnapLen), cfg.Promiscuous, readTimeout)
	if err != nil {
		return nil, fmt.Errorf("open interface %q: %w", cfg.Interface, err)
	}
	if bpf := f.BPF(); bpf != "" {
		if err := handle.SetBPFFilter(bpf); err != nil {
			handle.Close()
			return nil, fmt.Errorf("apply bpf filter %q: %w", bpf, err)
		}
	}
	return &Sniffer{
		handle:   handle,
		filter:   f,
		noColor:  cfg.NoColor,
		out:      d.Out,
		errOut:   d.ErrOut,
		logger:   d.Logger,
		exporter: d.Exporter,
		geo:      d.Geo,
		stats:    d.Stats,
	}, nil
}

// BPF returns the kernel filter expression in effect ("" means capture all).
func (s *Sniffer) BPF() string { return s.filter.BPF() }

// Close releases the capture handle.
func (s *Sniffer) Close() {
	if s.handle != nil {
		s.handle.Close()
	}
}

// Run captures until ctx is cancelled or the handle returns a fatal error.
func (s *Sniffer) Run(ctx context.Context) error {
	src := gopacket.NewPacketSource(s.handle, s.handle.LinkType())
	src.NoCopy = true

	for {
		if ctx.Err() != nil {
			return nil
		}
		pkt, err := src.NextPacket()
		if err != nil {
			switch {
			case errors.Is(err, pcap.NextErrorTimeoutExpired):
				continue
			case errors.Is(err, io.EOF):
				return nil
			default:
				continue // skip undecodable packet
			}
		}
		s.process(pkt)
	}
}

func (s *Sniffer) process(pkt gopacket.Packet) {
	meta := pkt.Metadata()
	ts := meta.Timestamp
	if ts.IsZero() {
		ts = time.Now()
	}

	base := event.Event{Timestamp: ts, Length: meta.Length}

	switch {
	case pkt.Layer(layers.LayerTypeIPv4) != nil:
		ip := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		base.SrcIP, base.DstIP = ip.SrcIP.String(), ip.DstIP.String()
		base.Protocol = ip.Protocol.String()
	case pkt.Layer(layers.LayerTypeIPv6) != nil:
		ip := pkt.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
		base.SrcIP, base.DstIP = ip.SrcIP.String(), ip.DstIP.String()
		base.Protocol = ip.NextHeader.String()
	default:
		return
	}

	if tcp, ok := pkt.Layer(layers.LayerTypeTCP).(*layers.TCP); ok {
		s.handleTCP(pkt, base, tcp)
		return
	}
	if udp, ok := pkt.Layer(layers.LayerTypeUDP).(*layers.UDP); ok {
		s.handleUDP(pkt, base, udp)
		return
	}

	if s.filter.Protocol == "tcp" || s.filter.Protocol == "udp" {
		return
	}
	if !s.filter.MatchIP(base.SrcIP) && !s.filter.MatchIP(base.DstIP) {
		return
	}
	base.Kind = event.KindOther
	s.emit(base)
}

func (s *Sniffer) handleTCP(pkt gopacket.Packet, e event.Event, tcp *layers.TCP) {
	if !s.filter.MatchProtocol("tcp") {
		return
	}
	sp, dp := int(tcp.SrcPort), int(tcp.DstPort)
	if !s.filter.MatchEndpoints(e.SrcIP, e.DstIP, sp, dp) {
		return
	}
	e.SrcPort, e.DstPort, e.Protocol = sp, dp, "tcp"

	if app := pkt.ApplicationLayer(); app != nil {
		payload := app.Payload()
		if isHTTPPort(sp) || isHTTPPort(dp) {
			if info, kind := parser.HTTP(payload); info != nil {
				e.Kind, e.HTTP = kind, info
				s.emit(e)
				return
			}
		}
		if isTLSPort(sp) || isTLSPort(dp) {
			if info := parser.TLSClientHello(payload); info != nil {
				e.Kind, e.TLS = event.KindTLSClientHello, info
				s.emit(e)
				return
			}
		}
	}

	e.Kind = event.KindTCP
	s.emit(e)
}

func (s *Sniffer) handleUDP(pkt gopacket.Packet, e event.Event, udp *layers.UDP) {
	if !s.filter.MatchProtocol("udp") {
		return
	}
	sp, dp := int(udp.SrcPort), int(udp.DstPort)
	if !s.filter.MatchEndpoints(e.SrcIP, e.DstIP, sp, dp) {
		return
	}
	e.SrcPort, e.DstPort, e.Protocol = sp, dp, "udp"

	if sp == 53 || dp == 53 {
		if dns, ok := pkt.Layer(layers.LayerTypeDNS).(*layers.DNS); ok {
			if info, kind := parser.DNS(dns); info != nil {
				e.Kind, e.DNS = kind, info
				s.emit(e)
				return
			}
		}
	}

	e.Kind = event.KindUDP
	s.emit(e)
}

func (s *Sniffer) emit(e event.Event) {
	e.SrcGeo = s.geo.Lookup(e.SrcIP)
	e.DstGeo = s.geo.Lookup(e.DstIP)

	if s.stats != nil {
		s.stats.Record(e)
	}
	fmt.Fprintln(s.out, s.colorize(e))
	if s.logger != nil {
		s.logger.Log(e)
	}
	if s.exporter != nil {
		if err := s.exporter.Write(e); err != nil {
			fmt.Fprintf(s.errOut, "export error: %v\n", err)
		}
	}
}

func isHTTPPort(p int) bool {
	switch p {
	case 80, 8000, 8080, 8888:
		return true
	}
	return false
}

func isTLSPort(p int) bool {
	switch p {
	case 443, 8443:
		return true
	}
	return false
}
