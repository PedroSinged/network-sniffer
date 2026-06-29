package main

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func StartCapture(handle *pcap.Handle, filter *PacketFilter) {
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

				fmt.Printf("[TCP] %s:%d -> %s:%d\n",
					ip.SrcIP, tcp.SrcPort, ip.DstIP, tcp.DstPort)
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

				fmt.Printf("[UDP] %s:%d -> %s:%d\n",
					ip.SrcIP, udp.SrcPort, ip.DstIP, udp.DstPort)
				continue
			}

			// Se não for TCP/UDP, só mostra se passar no filtro de protocolo
			if !filter.MatchProtocol("") {
				fmt.Printf("[%s] %s -> %s\n", ip.Protocol, ip.SrcIP, ip.DstIP)
			}
		}
	}
}