package main

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func StartCapture(handle *pcap.Handle, filter *PacketFilter, logger *Logger) {
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {
		// Extrai camada IP
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer != nil {
			ip, _ := ipLayer.(*layers.IPv4)

			// Verifica filtro de IP
			srcIP := ip.SrcIP.String()
			dstIP := ip.DstIP.String()
			if !filter.MatchIP(srcIP) && !filter.MatchIP(dstIP) {
				continue
			}

			// Tenta extrair TCP
			tcpLayer := packet.Layer(layers.LayerTypeTCP)
			if tcpLayer != nil {
				tcp, _ := tcpLayer.(*layers.TCP)

				// Verifica filtro de protocolo e porta
				if !filter.MatchProtocol("tcp") {
					continue
				}
				if !filter.MatchPort(int(tcp.SrcPort)) && !filter.MatchPort(int(tcp.DstPort)) {
					continue
				}

				output := fmt.Sprintf("[TCP] %s:%d -> %s:%d",
					ip.SrcIP, tcp.SrcPort, ip.DstIP, tcp.DstPort)
				fmt.Println(output)
				if logger != nil {
					logger.Log(output)
				}
				continue
			}

			// Tenta extrair UDP
			udpLayer := packet.Layer(layers.LayerTypeUDP)
			if udpLayer != nil {
				udp, _ := udpLayer.(*layers.UDP)

				// Verifica filtro de protocolo e porta
				if !filter.MatchProtocol("udp") {
					continue
				}
				if !filter.MatchPort(int(udp.SrcPort)) && !filter.MatchPort(int(udp.DstPort)) {
					continue
				}

				// Tenta extrair DNS (UDP porta 53)
				if udp.DstPort == 53 || udp.SrcPort == 53 {
					dnsLayer := packet.Layer(layers.LayerTypeDNS)
					if dnsLayer != nil {
						dns, _ := dnsLayer.(*layers.DNS)

						if IsDNSQuery(dns) {
							domains := ParseDNSQuery(dns)
							for _, domain := range domains {
								output := fmt.Sprintf("[DNS-Query] client: %s:%d -> server: %s:53 | Domain: %s",
									srcIP, udp.SrcPort, dstIP, domain)
								fmt.Println(output)
								if logger != nil {
									logger.Log(output)
								}
							}
						} else if IsDNSResponse(dns) {
							responses := ParseDNSResponse(dns)
							for domain, ip := range responses {
								output := fmt.Sprintf("[DNS-Response] server: %s:53 -> client: %s:%d | Domain: %s | IP: %s",
									srcIP, dstIP, udp.DstPort, domain, ip)
								fmt.Println(output)
								if logger != nil {
									logger.Log(output)
								}
							}
						}
						continue
					}
				}

				output := fmt.Sprintf("[UDP] %s:%d -> %s:%d",
					ip.SrcIP, udp.SrcPort, ip.DstIP, udp.DstPort)
				fmt.Println(output)
				if logger != nil {
					logger.Log(output)
				}
				continue
			}

			// Se não for TCP/UDP, só mostra se passar no filtro de protocolo
			if !filter.MatchProtocol("") {
				output := fmt.Sprintf("[%s] %s -> %s", ip.Protocol, ip.SrcIP, ip.DstIP)
				fmt.Println(output)
				if logger != nil {
					logger.Log(output)
				}
			}
		}
	}
}