# network-sniffer

> Real-time network packet capture and analysis, written in Go.

![status](https://img.shields.io/badge/version-1.0.0-blue)
![language](https://img.shields.io/badge/go-1.23%2B-00ADD8)
![license](https://img.shields.io/badge/license-MIT-green)

`network-sniffer` captures live traffic from a network interface, decodes it,
and prints a readable one-line summary per event. It recognises raw TCP/UDP,
plaintext HTTP, DNS, and the TLS ClientHello (SNI), optionally enriches
endpoints with GeoIP data, logs to disk, exports to JSON/CSV, and prints a
session summary on exit.

---

## Features

| Area | Status |
|---|---|
| Live capture (IPv4 **and** IPv6) | ✅ |
| Kernel-side BPF filtering by IP / protocol / port | ✅ |
| Raw TCP / UDP endpoints | ✅ |
| HTTP request & response parsing (method, path, host, user-agent, status) | ✅ |
| DNS queries and responses (A, AAAA, CNAME, NS, PTR, TXT) | ✅ |
| TLS ClientHello / SNI extraction | ✅ |
| GeoIP enrichment (MaxMind GeoLite2) | ✅ (optional) |
| File logging (persistent + per-session) | ✅ |
| Export to NDJSON / CSV | ✅ |
| Session summary (top talkers, top domains, counts) | ✅ |
| Graceful shutdown on Ctrl+C / SIGTERM | ✅ |
| Coloured console output | ✅ |

---

## Install

### Requirements

- Go 1.23+ (cgo enabled; a C compiler is required)
- libpcap (Linux/macOS) or [Npcap](https://npcap.com/) (Windows)
  - Debian/Ubuntu: `sudo apt-get install libpcap-dev`
  - macOS: ships with libpcap
- Capture privileges: run as root, or grant capabilities:
  `sudo setcap cap_net_raw,cap_net_admin=eip ./bin/network-sniffer`

### Build

```bash
make build           # -> bin/network-sniffer
# or
go build -o bin/network-sniffer ./cmd/network-sniffer
```

### Docker

```bash
docker build -f deployments/Dockerfile -t network-sniffer .
docker run --rm -it --net=host --cap-add=NET_RAW --cap-add=NET_ADMIN \
  network-sniffer -i eth0
```

---

## Usage

```bash
sudo ./bin/network-sniffer -i eth0 [flags]
```

| Flag | Default | Description |
|---|---|---|
| `-i` | `eth0` | Capture interface: index, partial name, or full device name (see below) |
| `-list-interfaces` | | List capture interfaces and exit |
| `-snaplen` | `65535` | Bytes captured per packet |
| `-promisc` | `true` | Promiscuous mode |
| `-ip` | – | Keep only traffic to/from this IP |
| `-protocol` | – | Keep only `tcp`, `udp`, `icmp`, or `icmp6` |
| `-port` | – | Keep only traffic to/from this port |
| `-no-color` | `false` | Disable ANSI colour |
| `-log` | `false` | Write events to log files |
| `-log-dir` | `logs` | Log directory |
| `-export` | – | `json` (NDJSON) or `csv` |
| `-out` | – | Export file path (required with `-export`) |
| `-geoip` | – | Path to a MaxMind GeoLite2-City `.mmdb` |
| `-stats` | `true` | Print session summary on exit |
| `-version` | | Print version and exit |

The filter flags are compiled into a BPF expression and pushed to the kernel,
so filtered-out packets never reach the process.

### Choosing an interface

`-list-interfaces` prints what libpcap sees:

```
$ network-sniffer -list-interfaces
[0] WAN Miniport (Network Monitor)
    name: \Device\NPF_{DAEA23F5-...}
[4] Realtek PCIe GbE Family Controller
    name: \Device\NPF_{CEC9BAA9-...}
    addr: 192.168.1.75, fe80::4385:...
```

`-i` accepts, in order of precedence:

1. an **index** — `-i 4`
2. an **exact device name** — `-i "\Device\NPF_{CEC9BAA9-...}"` / `-i eth0`
3. an **OS connection name** (Windows) — `-i Ethernet`, `-i "Wi-Fi"`
   (resolved via `Get-NetAdapter`, cached; falls back silently if unavailable)
4. a **case-insensitive substring** of the connection name, description, or
   device name — `-i realtek`, `-i ethernet`, `-i loopback`

On Linux/macOS options 1, 2 and 4 apply (`-i eth0`, `-i en0`, `-i wl`).

### Examples

```bash
# All DNS traffic
sudo ./bin/network-sniffer -i eth0 -protocol udp -port 53

# HTTPS to one host, with GeoIP and JSON export
sudo ./bin/network-sniffer -i eth0 -port 443 \
  -geoip GeoLite2-City.mmdb -export json -out capture.ndjson

# Everything to/from 8.8.8.8, logged to disk
sudo ./bin/network-sniffer -i eth0 -ip 8.8.8.8 -log
```

### Output

```
[DNS-Query]        10.0.0.5:51314 -> 8.8.8.8:53 | Query: example.com
[DNS-Response]     8.8.8.8:53 -> 10.0.0.5:51314 | Answer: example.com A 93.184.216.34
[TLS-ClientHello]  10.0.0.5:44120 -> 93.184.216.34:443 | SNI: example.com | geo: ? -> Norwalk/US
[HTTP-Request]     10.0.0.5:51500 -> 93.184.216.34:80 | GET / Host: example.com
```

### GeoIP database

GeoIP is disabled unless `-geoip` points at a database. Download one with a
free MaxMind license key:

```bash
MAXMIND_LICENSE_KEY=xxxx ./scripts/download-geoip.sh
```

---

## Project layout

```
cmd/network-sniffer/     entry point: flags, wiring, signal handling
internal/
  banner/                startup banner
  config/                option struct + validation
  event/                 the unified Event type every stage speaks
  filter/                IP/protocol/port matching + BPF generation
  netiface/              interface listing + -i resolution (index/name/GUID)
  parser/                HTTP, DNS, TLS payload decoders
  geoip/                 MaxMind lookup (no-op when disabled)
  logger/                buffered file logging
  export/                NDJSON / CSV writers
  stats/                 session aggregation
  sniffer/               capture loop tying it together
deployments/             Dockerfile
scripts/                 helper scripts
```

---

## Development

```bash
make test      # go test ./...
make cover     # tests + coverage total
make vet       # go vet
make lint      # vet + staticcheck (if installed)
```

Tested packages carry unit tests at 73–96% statement coverage
(`parser`, `filter`, `stats`, `event`, `netiface`); the capture loop is
exercised manually and in CI.

## Changelog

See [CHANGELOG.md](CHANGELOG.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT — see [LICENSE](LICENSE).

## Author

Pedro Trindade — [@PedroSinged](https://github.com/PedroSinged)
