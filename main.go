package main

import (
	"flag"
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
	enableLog := flag.Bool("log", false, "Enable logging to files")
	flag.Parse()

	// Cria a struct de filtros
	filter := &PacketFilter{
		IP:       *filterIP,
		Protocol: *filterProtocol,
		Port:     *filterPort,
	}

	// Cria o logger se habilitado
	var logger *Logger
	if *enableLog {
		var err error
		logger, err = NewLogger()
		if err != nil {
			log.Fatalf("Error creating logger: %v", err)
		}
		defer logger.Close()
	}

	// Abre a interface
	handle, err := pcap.OpenLive(*iface, int32(*snaplen), true, pcap.BlockForever)
	if err != nil {
		log.Fatalf("Error opening interface %s: %v", *iface, err)
	}
	defer handle.Close()

	// Exibe o banner
	PrintBanner(*iface, filter)

	// Começa a capturar
	StartCapture(handle, filter, logger)
}