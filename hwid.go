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
//   1) MachineGuid (HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid) — стабилен
//      пока ОС не переустановят. Это тот же ID, который Windows использует
//      для своих device-привязок.
//   2) MAC первого физического интерфейса — на случай если MachineGuid недоступен.
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

		mguid := readMachineGUID()
		if mguid != "" {
			h.Write([]byte(mguid))
		}

		if mac := firstPhysicalMAC(); mac != "" {
			h.Write([]byte(mac))
		}

		// Фоллбэк — hostname (если ни MachineGuid ни MAC недоступны, всё равно
		// получим что-то детерминированное на этой машине).
		hostname, _ := exec.Command("hostname").Output()
		h.Write(hostname)

		hwidValue = hex.EncodeToString(h.Sum(nil))
	})
	return hwidValue
}

// readMachineGUID — стабильный device-ID Windows.
func readMachineGUID() string {
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

// firstPhysicalMAC возвращает MAC первого "настоящего" сетевого интерфейса
// (не loopback, не виртуальный VPN-адаптер).
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
		// Скипаем VPN/виртуальные адаптеры
		nl := strings.ToLower(ifc.Name)
		if strings.Contains(nl, "tun") || strings.Contains(nl, "tap") ||
			strings.Contains(nl, "wintun") || strings.Contains(nl, "wireguard") ||
			strings.Contains(nl, "virtual") || strings.Contains(nl, "hyper-v") ||
			strings.Contains(nl, "vmware") || strings.Contains(nl, "vbox") {
			continue
		}
		return ifc.HardwareAddr.String()
	}
	return ""
}

// shortHWID — первые 32 символа hash'а, удобно для логов / Subscription-Userinfo-like headers.
func shortHWID() string {
	full := getStableHWID()
	if len(full) > 32 {
		return full[:32]
	}
	return full
}
