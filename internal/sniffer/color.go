package sniffer

import "github.com/PedroSinged/network-sniffer/internal/event"

const (
	colReset  = "\x1b[0m"
	colGray   = "\x1b[90m"
	colBlue   = "\x1b[34m"
	colGreen  = "\x1b[32m"
	colYellow = "\x1b[33m"
	colCyan   = "\x1b[36m"
	colMag    = "\x1b[35m"
)

var kindColor = map[event.Kind]string{
	event.KindTCP:            colGray,
	event.KindUDP:            colGray,
	event.KindOther:          colGray,
	event.KindHTTPRequest:    colGreen,
	event.KindHTTPResponse:   colBlue,
	event.KindDNSQuery:       colYellow,
	event.KindDNSResponse:    colCyan,
	event.KindTLSClientHello: colMag,
}

// colorize renders an event line, wrapping it in an ANSI colour unless colour
// output is disabled.
func (s *Sniffer) colorize(e event.Event) string {
	line := e.String()
	if s.noColor {
		return line
	}
	c, ok := kindColor[e.Kind]
	if !ok {
		return line
	}
	return c + line + colReset
}
