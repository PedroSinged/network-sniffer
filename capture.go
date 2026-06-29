package main

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func StartCapture(handle *pcap.Handle) {
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {
		// Extrai camada IP
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer != nil {
			ip, _ := ipLayer.(*layers.IPv4)

			// Tenta extrair TCP
			tcpLayer := packet.Layer(layers.LayerTypeTCP)
			if tcpLayer != nil {
				tcp, _ := tcpLayer.(*layers.TCP)
				fmt.Printf("[TCP] %s:%d -> %s:%d\n",
					ip.SrcIP, tcp.SrcPort, ip.DstIP, tcp.DstPort)
				continue
			}

			// Tenta extrair UDP
			udpLayer := packet.Layer(layers.LayerTypeUDP)
			if udpLayer != nil {
				udp, _ := udpLayer.(*layers.UDP)
				fmt.Printf("[UDP] %s:%d -> %s:%d\n",
					ip.SrcIP, udp.SrcPort, ip.DstIP, udp.DstPort)
				continue
			}

			// Se não for TCP/UDP, só mostra o protocolo
			fmt.Printf("[%s] %s -> %s\n", ip.Protocol, ip.SrcIP, ip.DstIP)
		}
	}
}