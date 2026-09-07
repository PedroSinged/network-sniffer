//go:build windows

package netiface

import (
	"context"
	"os/exec"
	"time"
)

func init() { loadFriendlyNames = powershellAdapterNames }

// powershellAdapterNames maps interface GUID -> Windows connection name via
// Get-NetAdapter. Any failure (missing cmdlet, timeout, parse error) yields nil,
// and resolution falls back to description/substring matching.
func powershellAdapterNames() map[string]string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "powershell",
		"-NoProfile", "-NonInteractive", "-Command",
		"Get-NetAdapter | Select-Object Name,InterfaceGuid | ConvertTo-Json -Compress")

	out, err := cmd.Output()
	if err != nil {
		return nil
	}
	return parseNetAdapterJSON(out)
}
