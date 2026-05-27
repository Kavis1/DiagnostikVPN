//go:build darwin

package main

import (
	"os/exec"
	"strings"
)

// getProcessList — список процессов в нижнем регистре через `ps`.
// Возвращает имена бинарей (basename) в lower-case — это формат, под который
// заточены детекторы AV/VPN-клиентов в коде.
func getProcessList() string {
	out, err := exec.Command("ps", "-A", "-o", "comm=").CombinedOutput()
	if err != nil {
		return ""
	}
	var sb strings.Builder
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// ps выдаёт полный путь — берём basename
		if idx := strings.LastIndex(line, "/"); idx >= 0 {
			line = line[idx+1:]
		}
		sb.WriteString(strings.ToLower(line))
		sb.WriteByte('\n')
	}
	return sb.String()
}
