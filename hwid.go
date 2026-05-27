package main

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"os/exec"
	"strings"
	"sync"
)

// HWID для запросов к подпискам, которые ограничивают по устройствам.
//
// Формируется как SHA-256 от:
//   1) Системный device-ID (MachineGuid на Windows, IOPlatformUUID на macOS) —
//      стабилен пока ОС не переустановят.
//   2) MAC первого физического интерфейса — на случай если ID недоступен.
//
// Возвращаемая строка — hex 64 символа. Стабильна между запусками программы
// на одной и той же машине.

var (
	hwidOnce  sync.Once
	hwidValue string
)

func getStableHWID() string {
	hwidOnce.Do(func() {
		h := sha256.New()

		if id := readSystemMachineID(); id != "" {
			h.Write([]byte(id))
		}

		if mac := firstPhysicalMAC(); mac != "" {
			h.Write([]byte(mac))
		}

		// Фоллбэк — hostname
		hostname, _ := exec.Command("hostname").Output()
		h.Write(hostname)

		hwidValue = hex.EncodeToString(h.Sum(nil))
	})
	return hwidValue
}

// firstPhysicalMAC возвращает MAC первого "настоящего" сетевого интерфейса
// (не loopback, не виртуальный VPN-адаптер). Эта функция кросс-платформенна
// потому что net.Interfaces() работает одинаково на Win/macOS/Linux.
func firstPhysicalMAC() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		if len(ifc.HardwareAddr) == 0 {
			continue
		}
		nl := strings.ToLower(ifc.Name)
		// Виртуальные / VPN на любой платформе
		if strings.Contains(nl, "tun") || strings.Contains(nl, "tap") ||
			strings.Contains(nl, "wintun") || strings.Contains(nl, "wireguard") ||
			strings.Contains(nl, "virtual") || strings.Contains(nl, "hyper-v") ||
			strings.Contains(nl, "vmware") || strings.Contains(nl, "vbox") ||
			strings.HasPrefix(nl, "utun") || strings.HasPrefix(nl, "awdl") ||
			strings.HasPrefix(nl, "bridge") || strings.HasPrefix(nl, "llw") {
			continue
		}
		return ifc.HardwareAddr.String()
	}
	return ""
}

// shortHWID — первые 32 символа hash'а, удобно для логов / отображения пользователю.
func shortHWID() string {
	full := getStableHWID()
	if len(full) > 32 {
		return full[:32]
	}
	return full
}
