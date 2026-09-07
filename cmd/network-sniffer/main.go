// Command network-sniffer captures and analyses live network traffic.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/PedroSinged/network-sniffer/internal/banner"
	"github.com/PedroSinged/network-sniffer/internal/config"
	"github.com/PedroSinged/network-sniffer/internal/export"
	"github.com/PedroSinged/network-sniffer/internal/filter"
	"github.com/PedroSinged/network-sniffer/internal/geoip"
	"github.com/PedroSinged/network-sniffer/internal/logger"
	"github.com/PedroSinged/network-sniffer/internal/netiface"
	"github.com/PedroSinged/network-sniffer/internal/sniffer"
	"github.com/PedroSinged/network-sniffer/internal/stats"
)

// version is set at build time via -ldflags "-X main.version=...".
// `make build` derives it from `git describe`; release binaries use the tag.
var version = "dev"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "network-sniffer:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("network-sniffer", flag.ContinueOnError)

	var (
		cfg         config.Config
		showVersion bool
		listIfaces  bool
	)
	fs.StringVar(&cfg.Interface, "i", "eth0", "capture interface: index, partial name, or full device name")
	fs.BoolVar(&listIfaces, "list-interfaces", false, "list capture interfaces and exit")
	fs.IntVar(&cfg.SnapLen, "snaplen", 65535, "capture length per packet in bytes")
	fs.BoolVar(&cfg.Promiscuous, "promisc", true, "put the interface in promiscuous mode")
	fs.StringVar(&cfg.FilterIP, "ip", "", "keep only traffic to/from this IP")
	fs.StringVar(&cfg.FilterProtocol, "protocol", "", "keep only this protocol (tcp, udp, icmp, icmp6)")
	fs.IntVar(&cfg.FilterPort, "port", 0, "keep only traffic to/from this port")
	fs.BoolVar(&cfg.NoColor, "no-color", false, "disable coloured console output")
	fs.BoolVar(&cfg.LogEnabled, "log", false, "write events to log files")
	fs.StringVar(&cfg.LogDir, "log-dir", "logs", "directory for log files")
	fs.StringVar(&cfg.ExportFormat, "export", "", "export events as `format` (json or csv)")
	fs.StringVar(&cfg.ExportFile, "out", "", "export output file path")
	fs.StringVar(&cfg.GeoIPPath, "geoip", "", "path to a MaxMind GeoLite2-City .mmdb for enrichment")
	fs.BoolVar(&cfg.ShowStats, "stats", true, "print a session summary on exit")
	fs.BoolVar(&showVersion, "version", false, "print version and exit")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if showVersion {
		fmt.Printf("network-sniffer %s\n", version)
		return nil
	}

	devices, err := netiface.List()
	if err != nil {
		return fmt.Errorf("list interfaces: %w", err)
	}
	if listIfaces {
		fmt.Print(netiface.Format(devices))
		return nil
	}

	if err := cfg.Validate(); err != nil {
		return err
	}

	resolved, err := netiface.Resolve(cfg.Interface, devices)
	if err != nil {
		return err
	}
	if resolved != cfg.Interface {
		fmt.Printf("interface  : %q -> %s\n", cfg.Interface, resolved)
	}
	cfg.Interface = resolved

	pf, err := filter.New(cfg.FilterIP, cfg.FilterProtocol, cfg.FilterPort)
	if err != nil {
		return err
	}

	deps := sniffer.Deps{Out: os.Stdout, ErrOut: os.Stderr, Stats: stats.New()}

	if cfg.LogEnabled {
		lg, err := logger.New(cfg.LogDir)
		if err != nil {
			return err
		}
		defer lg.Close()
		deps.Logger = lg
	}

	if cfg.GeoIPPath != "" {
		geo, err := geoip.Open(cfg.GeoIPPath)
		if err != nil {
			return err
		}
		defer geo.Close()
		deps.Geo = geo
	}

	if cfg.ExportFormat != config.ExportNone {
		ex, err := export.New(cfg.ExportFormat, cfg.ExportFile)
		if err != nil {
			return err
		}
		defer ex.Close()
		deps.Exporter = ex
	}

	snf, err := sniffer.New(cfg, pf, deps)
	if err != nil {
		return err
	}
	defer snf.Close()

	banner.Print(os.Stdout, version, cfg)
	if bpf := snf.BPF(); bpf != "" {
		fmt.Printf(" bpf       : %s\n", bpf)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	runErr := snf.Run(ctx)

	if cfg.ShowStats {
		fmt.Print(deps.Stats.Report().String())
	}
	return runErr
}
