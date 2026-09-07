// Package banner renders the startup banner.
package banner

import (
	"fmt"
	"io"
	"strings"

	"github.com/PedroSinged/network-sniffer/internal/config"
)

const art = `
  __   _ ____ ___ _  _ _  _ ____ ____    ____ _  _ _ ____ ____ ____ ____
 | \  | |___  |  |  | |  | |__/ |__/    [__  |\ | | |___ |___ |___ |__/
 |  \_| |___  |  |__| |_/  |  \ |  \    ___] | \| | |    |    |___ |  \
`

// Print writes the banner and the active configuration to w.
func Print(w io.Writer, version string, cfg config.Config) {
	fmt.Fprint(w, art)
	fmt.Fprintf(w, " network-sniffer v%s  -  github.com/PedroSinged/network-sniffer\n\n", version)

	fmt.Fprintf(w, " interface : %s\n", cfg.Interface)
	fmt.Fprintf(w, " snaplen   : %d\n", cfg.SnapLen)

	var filters []string
	if cfg.FilterIP != "" {
		filters = append(filters, "ip="+cfg.FilterIP)
	}
	if cfg.FilterProtocol != "" {
		filters = append(filters, "proto="+cfg.FilterProtocol)
	}
	if cfg.FilterPort != 0 {
		filters = append(filters, fmt.Sprintf("port=%d", cfg.FilterPort))
	}
	if len(filters) == 0 {
		filters = append(filters, "none")
	}
	fmt.Fprintf(w, " filters   : %s\n", strings.Join(filters, " "))

	if cfg.LogEnabled {
		fmt.Fprintf(w, " logging   : %s/\n", cfg.LogDir)
	}
	if cfg.ExportFormat != config.ExportNone {
		fmt.Fprintf(w, " export    : %s -> %s\n", cfg.ExportFormat, cfg.ExportFile)
	}
	if cfg.GeoIPPath != "" {
		fmt.Fprintf(w, " geoip     : %s\n", cfg.GeoIPPath)
	}

	fmt.Fprint(w, "\n Capturing... press Ctrl+C to stop\n")
	fmt.Fprintln(w, strings.Repeat("-", 72))
}
