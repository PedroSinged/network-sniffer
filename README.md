# Network Sniffer

> A network packet sniffer built in Go with real-time analysis and filtering capabilities.

![Status](https://img.shields.io/badge/status-v0.1-blue)
![Language](https://img.shields.io/badge/language-Go-00ADD8)

## Features

- [x] Real-time packet capture
- [x] IPv4 layer parsing
- [x] Protocol detection (TCP, UDP, ICMPv4, etc)
- [ ] Filtering by IP, port, protocol
- [ ] Deeper protocol analysis (TCP, UDP, DNS, HTTP)

## Build

```bash
go build -o sniffer main.go capture.go
```

## Usage

```bash
sudo ./sniffer -interface eth0
```

## Author

**Pedro** — [@PedroSinged](https://github.com/PedroSinged)