//go:build darwin

package main

import (
	"os"
	"os/exec"
)

// killProcessByName убивает все процессы с указанным именем через pkill.
func killProcessByName(name string) {
	exec.Command("pkill", "-f", name).Run()
}

// На macOS sing-box TUN требует root (sudo). os.Geteuid()==0 — стандартный
// UNIX-способ проверки.
func isRunningAsAdmin() bool {
	return os.Geteuid() == 0
}
