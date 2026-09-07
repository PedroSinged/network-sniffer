// Package stats aggregates observed events into a session summary printed when
// the sniffer stops.
package stats

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/PedroSinged/network-sniffer/internal/event"
)

// Stats is a concurrency-safe event aggregator.
type Stats struct {
	mu      sync.Mutex
	start   time.Time
	packets int
	bytes   int64
	byKind  map[event.Kind]int
	talkers map[string]int
	domains map[string]int
}

// New returns an empty Stats with the clock started.
func New() *Stats {
	return &Stats{
		start:   time.Now(),
		byKind:  make(map[event.Kind]int),
		talkers: make(map[string]int),
		domains: make(map[string]int),
	}
}

// Record folds one event into the running totals.
func (s *Stats) Record(e event.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.packets++
	s.bytes += int64(e.Length)
	s.byKind[e.Kind]++
	s.talkers[e.SrcIP+" -> "+e.DstIP]++

	if e.DNS != nil {
		for _, q := range e.DNS.Questions {
			s.domains[q]++
		}
		for _, a := range e.DNS.Answers {
			s.domains[a.Name]++
		}
	}
	if e.TLS != nil && e.TLS.SNI != "" {
		s.domains[e.TLS.SNI]++
	}
	if e.HTTP != nil && e.HTTP.Host != "" {
		s.domains[e.HTTP.Host]++
	}
}

// Report is an immutable snapshot of the aggregated data.
type Report struct {
	Duration   time.Duration
	Packets    int
	Bytes      int64
	ByKind     map[event.Kind]int
	TopTalkers []Pair
	TopDomains []Pair
}

// Pair is a name/count tuple used in the top-N lists.
type Pair struct {
	Name  string
	Count int
}

// Report builds a snapshot with the top 5 talkers and domains.
func (s *Stats) Report() Report {
	s.mu.Lock()
	defer s.mu.Unlock()

	byKind := make(map[event.Kind]int, len(s.byKind))
	for k, v := range s.byKind {
		byKind[k] = v
	}
	return Report{
		Duration:   time.Since(s.start),
		Packets:    s.packets,
		Bytes:      s.bytes,
		ByKind:     byKind,
		TopTalkers: topN(s.talkers, 5),
		TopDomains: topN(s.domains, 5),
	}
}

func topN(m map[string]int, n int) []Pair {
	pairs := make([]Pair, 0, len(m))
	for k, v := range m {
		pairs = append(pairs, Pair{k, v})
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].Count != pairs[j].Count {
			return pairs[i].Count > pairs[j].Count
		}
		return pairs[i].Name < pairs[j].Name
	})
	if len(pairs) > n {
		pairs = pairs[:n]
	}
	return pairs
}

// String renders the human-readable session summary.
func (r Report) String() string {
	var b strings.Builder
	b.WriteString("\n------------ Session summary ------------\n")
	fmt.Fprintf(&b, "Duration : %s\n", r.Duration.Round(time.Second))
	fmt.Fprintf(&b, "Packets  : %d\n", r.Packets)
	fmt.Fprintf(&b, "Bytes    : %d\n", r.Bytes)

	if len(r.ByKind) > 0 {
		b.WriteString("\nBy kind:\n")
		kinds := make([]string, 0, len(r.ByKind))
		for k := range r.ByKind {
			kinds = append(kinds, string(k))
		}
		sort.Strings(kinds)
		for _, k := range kinds {
			fmt.Fprintf(&b, "  %-16s %d\n", k, r.ByKind[event.Kind(k)])
		}
	}

	if len(r.TopTalkers) > 0 {
		b.WriteString("\nTop talkers:\n")
		for _, p := range r.TopTalkers {
			fmt.Fprintf(&b, "  %-40s %d\n", p.Name, p.Count)
		}
	}
	if len(r.TopDomains) > 0 {
		b.WriteString("\nTop domains:\n")
		for _, p := range r.TopDomains {
			fmt.Fprintf(&b, "  %-40s %d\n", p.Name, p.Count)
		}
	}
	b.WriteString("----------------------------------------\n")
	return b.String()
}
