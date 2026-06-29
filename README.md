# Network Sniffer

> A network packet sniffer built in Go with real-time analysis and filtering capabilities.

![Status](https://img.shields.io/badge/status-v0.5-blue)
![Language](https://img.shields.io/badge/language-Go-00ADD8)

## Features

- [x] Real-time packet capture
- [x] IPv4 layer parsing
- [x] TCP/UDP port extraction
- [x] Protocol detection (TCP, UDP, ICMPv4, IGMP, etc)
- [x] Filtering by IP, port, protocol
- [x] Enhanced UI with banner
- [x] DNS query and response parsing
- [x] File logging (main log + session-based logs)
- [ ] HTTP parsing and analysis
- [ ] GeoIP integration

## Build

```bash
go build -o sniffer main.go capture.go filter.go banner.go dns.go logger.go
```

## Usage

```bash
sudo ./sniffer -interface eth0 [options]
```

### Options

- `-interface string` - Network interface to sniff on (default: "eth0")
- `-ip string` - Filter by source or destination IP
- `-protocol string` - Filter by protocol (tcp, udp, icmp)
- `-port int` - Filter by port number
- `-log` - Enable logging to files (creates logs/ directory)

### Examples

Capture all TCP traffic on port 443:
```bash
sudo ./sniffer -interface eth0 -protocol tcp -port 443
```

Capture traffic to/from a specific IP with logging:
```bash
sudo ./sniffer -interface eth0 -ip 8.8.8.8 -log
```

Capture all DNS traffic:
```bash
sudo ./sniffer -interface eth0 -protocol udp -port 53
```

### Output Format

- TCP packets: `[TCP] src_ip:src_port -> dst_ip:dst_port`
- UDP packets: `[UDP] src_ip:src_port -> dst_ip:dst_port`
- DNS Query: `[DNS-Query] client: src_ip:port -> server: dst_ip:53 | Domain: example.com`
- DNS Response: `[DNS-Response] server: src_ip:53 -> client: dst_ip:port | Domain: example.com | IP: x.x.x.x`
- Other protocols: `[PROTOCOL] src_ip -> dst_ip`

### Logging

When `-log` flag is used:
- **Main log**: `logs/sniffer.log` (persistent across sessions)
- **Session log**: `logs/sniffer_YYYY-MM-DD_HH-MM-SS.log` (per-session logs)

Each entry includes timestamp in format: `[YYYY-MM-DD HH:MM:SS]`

## Author

**Pedro** — [@PedroSinged](https://github.com/PedroSinged)