// Package config holds the runtime configuration for the sniffer and validates
// it before any capture starts.
package config

import (
	"errors"
	"fmt"
	"strings"
)

// Export formats supported by the exporter.
const (
	ExportNone = ""
	ExportJSON = "json"
	ExportCSV  = "csv"
)

// Config is the fully resolved set of options the sniffer runs with.
type Config struct {
	// Capture
	Interface   string
	SnapLen     int
	Promiscuous bool

	// Filtering
	FilterIP       string
	FilterProtocol string
	FilterPort     int

	// Output
	NoColor    bool
	LogEnabled bool
	LogDir     string

	// Export
	ExportFormat string
	ExportFile   string

	// Enrichment
	GeoIPPath string

	// Reporting
	ShowStats bool
}

// Validate checks the configuration and returns the first problem found.
func (c *Config) Validate() error {
	if strings.TrimSpace(c.Interface) == "" {
		return errors.New("interface is required (use -i)")
	}
	if c.SnapLen <= 0 || c.SnapLen > 262144 {
		return fmt.Errorf("snaplen %d out of range (1-262144)", c.SnapLen)
	}
	switch c.ExportFormat {
	case ExportNone, ExportJSON, ExportCSV:
	default:
		return fmt.Errorf("invalid export format %q (want json or csv)", c.ExportFormat)
	}
	if c.ExportFormat != ExportNone && strings.TrimSpace(c.ExportFile) == "" {
		return errors.New("-export requires -out")
	}
	if c.LogEnabled && strings.TrimSpace(c.LogDir) == "" {
		return errors.New("log directory must not be empty when logging is enabled")
	}
	return nil
}
