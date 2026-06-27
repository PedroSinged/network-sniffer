package main

import (
	"fmt"
	"log"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func StartCapture(handle *pcap.Handle) {
	packetSource := handle.PacketSource()

	for packet := range packetSource.Packets() {
		// Tenta extrair camada de rede
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer != nil {
			ip, _ := ipLayer.(*layers.IPv4)
			fmt.Printf("IP: %s -> %s | Protocol: %s\n", 
				ip.SrcIP, ip.DstIP, ip.Protocol)
		}
	}
}