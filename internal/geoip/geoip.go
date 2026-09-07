// Package geoip enriches IP addresses with country/city data from a MaxMind
// GeoLite2 database. When no database is configured the Resolver is nil and
// every lookup is a safe no-op, so callers never need to branch.
package geoip

import (
	"fmt"
	"net"

	"github.com/oschwald/geoip2-golang"

	"github.com/PedroSinged/network-sniffer/internal/event"
)

// Resolver looks up geographic data for IP addresses.
type Resolver struct {
	db *geoip2.Reader
}

// Open loads a GeoLite2-City (or GeoIP2-City) database. An empty path returns
// a nil Resolver with no error: enrichment is simply disabled.
func Open(path string) (*Resolver, error) {
	if path == "" {
		return nil, nil
	}
	db, err := geoip2.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open geoip database %q: %w", path, err)
	}
	return &Resolver{db: db}, nil
}

// Lookup returns geo data for ip, or nil when disabled, unparseable, private,
// or absent from the database.
func (r *Resolver) Lookup(ip string) *event.GeoInfo {
	if r == nil || r.db == nil {
		return nil
	}
	addr := net.ParseIP(ip)
	if addr == nil || !addr.IsGlobalUnicast() || addr.IsPrivate() {
		return nil
	}
	rec, err := r.db.City(addr)
	if err != nil || rec == nil {
		return nil
	}
	info := &event.GeoInfo{
		Country:     rec.Country.Names["en"],
		CountryCode: rec.Country.IsoCode,
		City:        rec.City.Names["en"],
	}
	if info.Country == "" && info.CountryCode == "" && info.City == "" {
		return nil
	}
	return info
}

// Close releases the database handle.
func (r *Resolver) Close() error {
	if r == nil || r.db == nil {
		return nil
	}
	return r.db.Close()
}
