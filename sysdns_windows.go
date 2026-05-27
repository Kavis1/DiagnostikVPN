//go:build windows

package main

import (
	"os/exec"
	"strings"
)

// platformSystemDNS возвращает список системных DNS-серверов через ipconfig /all.
func platformSystemDNS() []string {
	out, err := exec.Command("ipconfig", "/all").CombinedOutput()
	if err == nil {
		if servers := extractDNSFromIPConfig(string(out)); len(servers) > 0 {
			return servers
		}
	}

	// Fallback: nslookup localhost
	out2, err2 := exec.Command("nslookup", "localhost").CombinedOutput()
	if err2 == nil {
		lines := strings.Split(string(out2), "\n")
		for i, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "Server:") || strings.HasPrefix(line, "Default Server:") {
				if i+1 < len(lines) {
					addrLine := strings.TrimSpace(lines[i+1])
					if strings.HasPrefix(addrLine, "Address:") {
						addr := strings.TrimSpace(strings.SplitN(addrLine, ":", 2)[1])
						if addr != "" {
							return []string{addr}
						}
					}
				}
			}
		}
	}
	return nil
}
