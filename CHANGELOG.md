# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.0.0] - 2026-09-07

First tagged release. Restructures the project and adds protocol analysis,
enrichment, export and a session summary on top of the earlier packet capture.

### Added
- IPv6 capture alongside IPv4.
- Kernel-side BPF filtering derived from the `-ip` / `-protocol` / `-port` flags.
- TLS ClientHello parsing with SNI extraction (`-port 443`).
- DNS response types beyond A: AAAA, CNAME, NS, PTR, TXT.
- HTTP user-agent capture and stricter request/response classification.
- GeoIP enrichment via MaxMind GeoLite2 (`-geoip`), plus
  `scripts/download-geoip.sh`.
- Event export to NDJSON and CSV (`-export` / `-out`).
- Session summary on exit: duration, packet/byte counts, per-kind counts,
  top talkers, top domains (`-stats`).
- Graceful shutdown on SIGINT/SIGTERM with log and export flushing.
- Coloured console output, disable with `-no-color`.
- `-list-interfaces` lists every libpcap capture device with its name and addresses.
- `-i` resolves an index (`-i 4`), a case-insensitive name substring (`-i realtek`),
  or a full device name; on Windows it also accepts the OS connection name
  (`-i Ethernet`, `-i "Wi-Fi"`) via a cached `Get-NetAdapter` lookup, falling back
  to substring matching where the cmdlet is unavailable. Unresolved values print
  the available interfaces.
- `Makefile`, multi-stage `Dockerfile`, and GitHub Actions CI.
- Unit tests for the parser, filter, stats, event, and netiface packages.

### Changed
- Reorganised from a flat `package main` into `cmd/` + `internal/` packages.
- All observations now flow through a single `event.Event` type.
- Buffered, mutex-guarded file logging.
- Capture interface flag renamed `-interface` → `-i`.
- Console output is ASCII-only (legible on legacy Windows consoles); IPv6
  endpoints are bracketed (`[fe80::1]:53`).

### Fixed
- `go.mod` / `go.sum` did not declare `gopacket`; the project would not build.
- Deferred cleanup (log flush) was skipped on Ctrl+C.
- Populated `.gitignore` (was committed empty).

## [0.6.0] - 2026-07-03
- HTTP request/response parsing.

## [0.5.0] - 2026-06-29
- DNS query/response parsing; file logging.

## [0.4.0]
- Enhanced UI banner.

## [0.3.0]
- Packet filtering by IP, protocol, and port.

## [0.2.0]
- TCP and UDP port parsing.
