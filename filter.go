package main

import (
	"net"
	"strconv"
)

type PacketFilter struct {
	IP       string
	Protocol string
	Port     int
}

// Verifica se um IP bate com o filtro
func (pf *PacketFilter) MatchIP(ip string) bool {
	if pf.IP == "" {
		return true // sem filtro = passa tudo
	}
	return ip == pf.IP
}

// Verifica se um protocolo bate com o filtro
func (pf *PacketFilter) MatchProtocol(protocol string) bool {
	if pf.Protocol == "" {
		return true
	}
	return protocol == pf.Protocol
}

// Verifica se uma porta bate com o filtro
func (pf *PacketFilter) MatchPort(port int) bool {
	if pf.Port == 0 {
		return true
	}
	return port == pf.Port
}