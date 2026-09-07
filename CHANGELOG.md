# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- `-list-interfaces` prints every libpcap capture device with its name and addresses.
- `-i` now resolves an index (`-i 4`) or a case-insensitive name substring
  (`-i realtek`) in addition to a full device name; unresolved values print the
  available interfaces.

### Changed
- Banner and session summary use ASCII rules instead of box-drawing characters
  (legible on legacy Windows consoles).
- IPv6 endpoints are bracketed in output (`[fe80::1]:53`).

## [1.0.0] - 2026-09-07

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
- `Makefile`, multi-stage `Dockerfile`, and GitHub Actions CI.
- Unit tests for the parser, filter, stats, and event packages.

### Changed
- Reorganised from a flat `package main` into `cmd/` + `internal/` packages.
- All observations now flow through a single `event.Event` type.
- Buffered, mutex-guarded file logging.
- Capture interface flag renamed `-interface` → `-i`.

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
