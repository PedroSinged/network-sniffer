package netiface

import (
	"encoding/json"
	"strings"
	"sync"
)

// loadFriendlyNames returns a map of lower-case interface GUID -> OS connection
// name (e.g. "Ethernet", "Wi-Fi"). It is replaced on Windows (see
// adapternames_windows.go) with a Get-NetAdapter query; on every other platform
// it stays nil-returning and callers fall back to description matching.
var loadFriendlyNames = func() map[string]string { return nil }

var (
	friendlyOnce  sync.Once
	friendlyCache map[string]string
)

// friendlyNames runs loadFriendlyNames at most once per process.
func friendlyNames() map[string]string {
	friendlyOnce.Do(func() { friendlyCache = loadFriendlyNames() })
	return friendlyCache
}

// parseNetAdapterJSON parses the output of
// `Get-NetAdapter | Select-Object Name,InterfaceGuid | ConvertTo-Json`.
// PowerShell emits a bare object for a single adapter and an array for several.
// It returns nil on any problem or when nothing usable is found.
func parseNetAdapterJSON(out []byte) map[string]string {
	out = trimSpaceBytes(out)
	if len(out) == 0 {
		return nil
	}

	type row struct {
		Name          string `json:"Name"`
		InterfaceGuid string `json:"InterfaceGuid"`
	}
	var rows []row

	switch out[0] {
	case '[':
		if json.Unmarshal(out, &rows) != nil {
			return nil
		}
	case '{':
		var r row
		if json.Unmarshal(out, &r) != nil {
			return nil
		}
		rows = []row{r}
	default:
		return nil
	}

	m := make(map[string]string, len(rows))
	for _, r := range rows {
		if g := normalizeGUID(r.InterfaceGuid); g != "" && r.Name != "" {
			m[g] = r.Name
		}
	}
	if len(m) == 0 {
		return nil
	}
	return m
}

// deviceGUID extracts the lower-case GUID from a libpcap device name such as
// `\Device\NPF_{CEC9BAA9-...}`. Returns "" when there is no brace-wrapped GUID.
func deviceGUID(pcapName string) string {
	i := strings.IndexByte(pcapName, '{')
	j := strings.IndexByte(pcapName, '}')
	if i < 0 || j < 0 || j <= i {
		return ""
	}
	return strings.ToLower(pcapName[i+1 : j])
}

func normalizeGUID(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimPrefix(s, "{")
	s = strings.TrimSuffix(s, "}")
	return s
}

func trimSpaceBytes(b []byte) []byte {
	return []byte(strings.TrimSpace(string(b)))
}
