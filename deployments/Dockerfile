# syntax=docker/dockerfile:1

# ---- build ----
FROM golang:1.26-bookworm AS build

RUN apt-get update && apt-get install -y --no-install-recommends libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .

ARG VERSION=docker
RUN CGO_ENABLED=1 go build -trimpath \
    -ldflags "-X main.version=${VERSION}" \
    -o /out/network-sniffer ./cmd/network-sniffer

# ---- runtime ----
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends libpcap0.8 ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /out/network-sniffer /usr/local/bin/network-sniffer

# Packet capture needs host networking and NET_RAW/NET_ADMIN:
#   docker run --rm -it --net=host --cap-add=NET_RAW --cap-add=NET_ADMIN \
#       network-sniffer:latest -i eth0
ENTRYPOINT ["network-sniffer"]
CMD ["-version"]
