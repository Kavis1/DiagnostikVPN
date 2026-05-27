//go:build windows

package main

import (
	"os/exec"
	"strings"
)

// getProcessList — список запущенных процессов в нижнем регистре через tasklist.
// Один вызов на программу обычно достаточно.
func getProcessList() string {
	out, err := exec.Command("tasklist", "/FO", "CSV", "/NH").CombinedOutput()
	if err != nil {
		return ""
	}
	return strings.ToLower(string(out))
}
