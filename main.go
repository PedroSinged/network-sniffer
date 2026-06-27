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
	flag.Parse()

	// Abre a interface
	handle, err := pcap.OpenLive(*iface, int32(*snaplen), true, pcap.BlockForever)
	if err != nil {
		log.Fatalf("Error opening interface %s: %v", *iface, err)
	}
	defer handle.Close()

	fmt.Printf("Sniffing on %s...\n", *iface)
	fmt.Println("Press Ctrl+C to stop\n")

	// Começa a capturar
	StartCapture(handle)
}