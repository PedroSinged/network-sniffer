package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/google/gopacket/pcap"
)

func main() {
	// Define as flags
	iface := flag.String("interface", "eth0", "Network interface to sniff on")
	snaplen := flag.Int("snaplen", 65535, "Packet capture length")
	filterIP := flag.String("ip", "", "Filter by source or destination IP")
	filterProtocol := flag.String("protocol", "", "Filter by protocol (tcp, udp, icmp)")
	filterPort := flag.Int("port", 0, "Filter by port")
	flag.Parse()

	// Cria a struct de filtros
	filter := &PacketFilter{
		IP:       *filterIP,
		Protocol: *filterProtocol,
		Port:     *filterPort,
	}

	// Abre a interface
	handle, err := pcap.OpenLive(*iface, int32(*snaplen), true, pcap.BlockForever)
	if err != nil {
		log.Fatalf("Error opening interface %s: %v", *iface, err)
	}
	defer handle.Close()

	fmt.Printf("Sniffing on %s...\n", *iface)
	if *filterIP != "" {
		fmt.Printf("Filter IP: %s\n", *filterIP)
	}
	if *filterProtocol != "" {
		fmt.Printf("Filter Protocol: %s\n", *filterProtocol)
	}
	if *filterPort != 0 {
		fmt.Printf("Filter Port: %d\n", *filterPort)
	}
	fmt.Println("Press Ctrl+C to stop\n")

	// Começa a capturar
	StartCapture(handle, filter)
}