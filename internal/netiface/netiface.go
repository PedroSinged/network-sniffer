// Package netiface lists the host capture interfaces and resolves a
// user-supplied -i value (index, partial name, or exact device name) to a
// concrete libpcap device name.
package netiface

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/google/gopacket/pcap"
)

// Device is a capture interface as reported by libpcap.
type Device struct {
	Name        string
	Description string
	Addrs       []string
}

// Title is the human label for the device (description, falling back to name).
func (d Device) Title() string {
	if d.Description != "" {
		return d.Description
	}
	return d.Name
}

// List returns every capture device visible to libpcap, in libpcap order.
func List() ([]Device, error) {
	devs, err := pcap.FindAllDevs()
	if err != nil {
		return nil, err
	}
	out := make([]Device, 0, len(devs))
	for _, d := range devs {
		dev := Device{Name: d.Name, Description: d.Description}
		for _, a := range d.Addresses {
			if a.IP != nil {
				dev.Addrs = append(dev.Addrs, a.IP.String())
			}
		}
		out = append(out, dev)
	}
	return out, nil
}

// Resolve maps input to a device name, trying in order:
//
//  1. a numeric index into devices,
//  2. an exact device-name match (covers a full \Device\NPF_{GUID}),
//  3. a case-insensitive substring of the description or the name.
//
// devices is normally the result of List.
func Resolve(input string, devices []Device) (string, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return "", fmt.Errorf("no interface given\n\n%s", hint(devices))
	}

	if idx, err := strconv.Atoi(input); err == nil {
		if idx < 0 || idx >= len(devices) {
			return "", fmt.Errorf("interface index %d out of range (%d available)\n\n%s",
				idx, len(devices), hint(devices))
		}
		return devices[idx].Name, nil
	}

	for _, d := range devices {
		if d.Name == input {
			return d.Name, nil
		}
	}

	low := strings.ToLower(input)
	for _, d := range devices {
		if strings.Contains(strings.ToLower(d.Description), low) ||
			strings.Contains(strings.ToLower(d.Name), low) {
			return d.Name, nil
		}
	}

	return "", fmt.Errorf("interface not found: %q\n\n%s", input, hint(devices))
}

// Format is the full, multi-line listing printed by -list-interfaces.
func Format(devices []Device) string {
	if len(devices) == 0 {
		return "no capture interfaces found\n"
	}
	var b strings.Builder
	for i, d := range devices {
		fmt.Fprintf(&b, "[%d] %s\n", i, d.Title())
		fmt.Fprintf(&b, "    name: %s\n", d.Name)
		if len(d.Addrs) > 0 {
			fmt.Fprintf(&b, "    addr: %s\n", strings.Join(d.Addrs, ", "))
		}
	}
	return b.String()
}

// hint is the compact list shown inside resolution errors.
func hint(devices []Device) string {
	var b strings.Builder
	b.WriteString("available interfaces (use -list-interfaces for full details):\n")
	for i, d := range devices {
		fmt.Fprintf(&b, "  [%d] %s\n", i, d.Title())
	}
	b.WriteString("\nexamples:\n")
	b.WriteString("  -i 0           by index\n")
	b.WriteString("  -i ethernet    by name (partial, case-insensitive)\n")
	return b.String()
}
