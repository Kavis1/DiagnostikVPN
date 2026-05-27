//go:build windows

package main

import (
	"os/exec"
	"strings"
)

// readSystemMachineID — стабильный device-ID Windows из реестра.
func readSystemMachineID() string {
	out, err := exec.Command("reg", "query",
		`HKLM\SOFTWARE\Microsoft\Cryptography`, "/v", "MachineGuid").CombinedOutput()
	if err != nil {
		return ""
	}
	text := decodeConsoleOutput(out)
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "MachineGuid") && strings.Contains(line, "REG_SZ") {
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				return parts[len(parts)-1]
			}
		}
	}
	return ""
}
