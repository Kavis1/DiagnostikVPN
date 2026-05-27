//go:build windows

package main

import (
	"os/exec"
	"strings"
)

// killProcessByName убивает все процессы с указанным именем (Win: taskkill /F /IM).
func killProcessByName(name string) {
	exec.Command("taskkill", "/F", "/IM", name).Run()
}

func isRunningAsAdmin() bool {
	out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command",
		`[bool]([Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)`).Output()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(out)) == "True"
}
