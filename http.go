package main

import (
	"bytes"
	"strings"
)

type HTTPInfo struct {
	Method string
	Path   string
	Host   string
	Status string // Para respostas
}

// ParseHTTPRequest extrai informações de uma requisição HTTP
func ParseHTTPRequest(payload []byte) *HTTPInfo {
	if len(payload) == 0 {
		return nil
	}

	// Procura por "HTTP/" pra identificar se é HTTP
	if !bytes.Contains(payload, []byte("HTTP/")) {
		return nil
	}

	lines := strings.Split(string(payload), "\r\n")
	if len(lines) == 0 {
		return nil
	}

	info := &HTTPInfo{}

	// Primeira linha: METHOD PATH HTTP/VERSION
	firstLine := strings.Fields(lines[0])
	if len(firstLine) >= 2 {
		info.Method = firstLine[0]
		info.Path = firstLine[1]
	}

	// Procura por Host
	for _, line := range lines {
		if strings.HasPrefix(strings.ToLower(line), "host:") {
			info.Host = strings.TrimSpace(strings.TrimPrefix(strings.ToLower(line), "host:"))
			break
		}
	}

	return info
}

// ParseHTTPResponse extrai status code de uma resposta HTTP
func ParseHTTPResponse(payload []byte) *HTTPInfo {
	if len(payload) == 0 {
		return nil
	}

	// Procura por "HTTP/" pra identificar se é resposta HTTP
	if !bytes.Contains(payload, []byte("HTTP/")) {
		return nil
	}

	lines := strings.Split(string(payload), "\r\n")
	if len(lines) == 0 {
		return nil
	}

	info := &HTTPInfo{}

	// Primeira linha: HTTP/VERSION STATUS MESSAGE
	firstLine := strings.Fields(lines[0])
	if len(firstLine) >= 2 {
		info.Status = firstLine[1]
	}

	return info
}

// IsHTTPPayload verifica se o payload contém HTTP
func IsHTTPPayload(payload []byte) bool {
	return bytes.Contains(payload, []byte("HTTP/"))
}