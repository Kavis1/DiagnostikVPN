//go:build darwin

package main

import (
	"os/exec"
	"strings"
)

// readSystemMachineID — IOPlatformUUID на macOS, аналог Windows MachineGuid.
// Возвращается командой `ioreg`. Это устойчивый ID, переживающий перезагрузки
// и не меняющийся пока пользователь не сделает чистую переустановку macOS.
func readSystemMachineID() string {
	out, err := exec.Command("ioreg", "-d2", "-c", "IOPlatformExpertDevice").CombinedOutput()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "IOPlatformUUID") {
			// Формат: "IOPlatformUUID" = "5C7C9F4F-XXXX-XXXX-XXXX-XXXXXXXXXXXX"
			parts := strings.Split(line, "\"")
			if len(parts) >= 4 {
				return parts[3]
			}
		}
	}
	return ""
}
