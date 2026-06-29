package main

import (
	"fmt"
	"strings"

	"github.com/google/gopacket/layers"
)

// ParseDNSQuery extrai domínios de uma query DNS
func ParseDNSQuery(dnsLayer *layers.DNS) []string {
	var domains []string
	for _, question := range dnsLayer.Questions {
		domain := string(question.Name)
		// Remove o ponto final do domínio
		domain = strings.TrimSuffix(domain, ".")
		domains = append(domains, domain)
	}
	return domains
}

// ParseDNSResponse extrai IPs de uma resposta DNS
func ParseDNSResponse(dnsLayer *layers.DNS) map[string]string {
	results := make(map[string]string)
	for _, answer := range dnsLayer.Answers {
		domain := string(answer.Name)
		domain = strings.TrimSuffix(domain, ".")
		
		// Extrai IP se for um registro A (IPv4)
		if answer.Type == layers.DNSTypeA {
			ip := answer.IP.String()
			results[domain] = ip
		}
	}
	return results
}

// IsDNSQuery verifica se é uma query DNS
func IsDNSQuery(dnsLayer *layers.DNS) bool {
	return dnsLayer.QR == false
}

// IsDNSResponse verifica se é uma resposta DNS
func IsDNSResponse(dnsLayer *layers.DNS) bool {
	return dnsLayer.QR == true
}