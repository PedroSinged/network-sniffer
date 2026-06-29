# Network Sniffer

> A network packet sniffer built in Go with real-time analysis and filtering capabilities.

![Status](https://img.shields.io/badge/status-v0.4-blue)
![Language](https://img.shields.io/badge/language-Go-00ADD8)

## Features

- [x] Real-time packet capture
- [x] IPv4 layer parsing
- [x] TCP/UDP port extraction
- [x] Protocol detection (TCP, UDP, ICMPv4, IGMP, etc)
- [x] Filtering by IP, port, protocol
- [x] Enhanced UI with banner
- [ ] DNS parsing and analysis
- [ ] HTTP parsing and analysis

## Build

```bash
go build -o sniffer main.go capture.go filter.go banner.go
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

### Examples

Capture all TCP traffic on port 443:
```bash
sudo ./sniffer -interface eth0 -protocol tcp -port 443
```

Capture traffic to/from a specific IP:
```bash
sudo ./sniffer -interface eth0 -ip 8.8.8.8
```

Capture all UDP traffic:
```bash
sudo ./sniffer -interface eth0 -protocol udp
```

### Output Format

- TCP packets: `[TCP] src_ip:src_port -> dst_ip:dst_port`
- UDP packets: `[UDP] src_ip:src_port -> dst_ip:dst_port`
- Other protocols: `[PROTOCOL] src_ip -> dst_ip`

## Author

**Pedro** — [@PedroSinged](https://github.com/PedroSinged)