// Package export streams captured events to a file as newline-delimited JSON
// or CSV.
package export

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/PedroSinged/network-sniffer/internal/config"
	"github.com/PedroSinged/network-sniffer/internal/event"
)

// Writer serialises events to an open file.
type Writer struct {
	mu     sync.Mutex
	f      *os.File
	format string
	json   *json.Encoder
	csv    *csv.Writer
}

var csvHeader = []string{
	"timestamp", "kind", "protocol", "src_ip", "src_port",
	"dst_ip", "dst_port", "length", "detail", "src_geo", "dst_geo",
}

// New opens path and prepares it for the given format. An empty format returns
// a nil Writer (export disabled).
func New(format, path string) (*Writer, error) {
	if format == config.ExportNone {
		return nil, nil
	}
	f, err := os.Create(path)
	if err != nil {
		return nil, fmt.Errorf("create export file: %w", err)
	}

	w := &Writer{f: f, format: format}
	switch format {
	case config.ExportJSON:
		w.json = json.NewEncoder(f)
	case config.ExportCSV:
		w.csv = csv.NewWriter(f)
		if err := w.csv.Write(csvHeader); err != nil {
			f.Close()
			return nil, err
		}
	default:
		f.Close()
		return nil, fmt.Errorf("unsupported export format %q", format)
	}
	return w, nil
}

// Write serialises one event.
func (w *Writer) Write(e event.Event) error {
	if w == nil {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()

	switch w.format {
	case config.ExportJSON:
		return w.json.Encode(e)
	case config.ExportCSV:
		return w.csv.Write([]string{
			e.Timestamp.Format(time.RFC3339),
			string(e.Kind),
			e.Protocol,
			e.SrcIP,
			itoa(e.SrcPort),
			e.DstIP,
			itoa(e.DstPort),
			itoa(e.Length),
			e.Detail(),
			geo(e.SrcGeo),
			geo(e.DstGeo),
		})
	}
	return nil
}

// Close flushes and closes the underlying file.
func (w *Writer) Close() error {
	if w == nil {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.csv != nil {
		w.csv.Flush()
	}
	return w.f.Close()
}

func itoa(n int) string {
	if n == 0 {
		return ""
	}
	return strconv.Itoa(n)
}

func geo(g *event.GeoInfo) string {
	if g == nil {
		return ""
	}
	if g.City != "" && g.CountryCode != "" {
		return g.City + "/" + g.CountryCode
	}
	if g.CountryCode != "" {
		return g.CountryCode
	}
	return g.Country
}
