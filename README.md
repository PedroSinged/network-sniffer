# Network Sniffer

> A network packet sniffer built in Go with real-time analysis and filtering capabilities.

![Status](https://img.shields.io/badge/status-v0.2-blue)
![Language](https://img.shields.io/badge/language-Go-00ADD8)

## Features

- [x] Real-time packet capture
- [x] IPv4 layer parsing
- [x] TCP/UDP port extraction
- [x] Protocol detection (TCP, UDP, ICMPv4, IGMP, etc)
- [ ] Filtering by IP, port, protocol
- [ ] Deeper protocol analysis (DNS, HTTP)

## Build

```bash
go build -o sniffer main.go capture.go
```

## Usage

```bash
sudo ./sniffer -interface eth0
```

### Output Format

- TCP packets: `[TCP] src_ip:src_port -> dst_ip:dst_port`
- UDP packets: `[UDP] src_ip:src_port -> dst_ip:dst_port`
- Other protocols: `[PROTOCOL] src_ip -> dst_ip`

## Author

**Pedro** — [@PedroSinged](https://github.com/PedroSinged)