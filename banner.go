package main

import (
	"fmt"
)

func PrintBanner(iface string, filter *PacketFilter) {
	fmt.Println("╔════════════════════════════════════════════════════╗")
	fmt.Println("║        Network Sniffer v0.3                        ║")
	fmt.Println("║  Real-time packet capture and analysis             ║")
	fmt.Println("║                                                    ║")
	fmt.Println("║  Author: Pedro Trindade (@PedroSinged)             ║")
	fmt.Println("║  GitHub: github.com/PedroSinged/network-sniffer    ║")
	fmt.Println("╚════════════════════════════════════════════════════╝\n")

	fmt.Printf("[*] Interface: %s\n", iface)
	
	if filter.IP != "" {
		fmt.Printf("[*] Filter IP: %s\n", filter.IP)
	}
	if filter.Protocol != "" {
		fmt.Printf("[*] Filter Protocol: %s\n", filter.Protocol)
	}
	if filter.Port != 0 {
		fmt.Printf("[*] Filter Port: %d\n", filter.Port)
	}
	
	fmt.Println("[*] Starting capture...")
	fmt.Println("\nPress Ctrl+C to stop\n")
	fmt.Println("────────────────────────────────────────────────────")
}