package main

import (
	"fmt"
	"os/exec"
	"strings"
)

// WARPState — состояние Cloudflare WARP на машине пользователя.
type WARPState struct {
	Installed bool
	Running   bool
	Connected bool
	Mode      string // warp / warp+doh / proxy / dot
	Account   string // free / WARP+ / teams
	Raw       string
}

// detectWARP читает состояние Cloudflare WARP через warp-cli.
// Если warp-cli не в PATH — пробуем стандартные пути.
func detectWARP() WARPState {
	state := WARPState{}

	warpCLI := locateWarpCLI()
	if warpCLI == "" {
		return state
	}
	state.Installed = true

	// status
	if out, err := exec.Command(warpCLI, "status").CombinedOutput(); err == nil {
		s := decodeConsoleOutput(out)
		state.Raw = s
		if strings.Contains(strings.ToLower(s), "connected") &&
			!strings.Contains(strings.ToLower(s), "disconnect") {
			state.Connected = true
			state.Running = true
		} else if strings.Contains(strings.ToLower(s), "disconnect") {
			state.Running = true
		}
	}

	// mode
	if out, err := exec.Command(warpCLI, "settings").CombinedOutput(); err == nil {
		s := decodeConsoleOutput(out)
		state.Raw += "\n" + s
		for _, line := range strings.Split(s, "\n") {
			low := strings.ToLower(line)
			if strings.Contains(low, "mode") && strings.Contains(line, ":") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					state.Mode = strings.TrimSpace(parts[1])
				}
			}
			if strings.Contains(low, "account type") && strings.Contains(line, ":") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					state.Account = strings.TrimSpace(parts[1])
				}
			}
		}
	}

	return state
}

func locateWarpCLI() string {
	candidates := []string{
		"warp-cli.exe",
		`C:\Program Files\Cloudflare\Cloudflare WARP\warp-cli.exe`,
		`C:\Program Files (x86)\Cloudflare\Cloudflare WARP\warp-cli.exe`,
	}
	for _, c := range candidates {
		if p, err := exec.LookPath(c); err == nil {
			return p
		}
	}
	return ""
}

// runWARPCheck — генерирует TestResult про текущее состояние WARP.
func runWARPCheck() TestResult {
	w := detectWARP()
	if !w.Installed {
		return TestResult{
			Name:    "Cloudflare WARP",
			Status:  StatusInfo,
			Message: "не установлен (можно использовать для обхода блокировок если ключ упал)",
			Details: "Установка: winget install Cloudflare.Warp",
		}
	}
	if w.Connected {
		msg := "установлен и активен"
		if w.Mode != "" {
			msg += " (mode=" + w.Mode + ")"
		}
		if w.Account != "" {
			msg += ", account=" + w.Account
		}
		return TestResult{
			Name:    "Cloudflare WARP",
			Status:  StatusOK,
			Message: msg,
			Details: "WARP может маскировать VPN-трафик от провайдера. Если ключ упал — включён WARP может помочь.",
		}
	}
	return TestResult{
		Name:    "Cloudflare WARP",
		Status:  StatusInfo,
		Message: "установлен, но не подключен — запустите `warp-cli connect` чтобы попробовать комбинацию",
		Details: w.Raw,
	}
}

// recommendWARPForFailedKeys возвращает рекомендацию по WARP в зависимости
// от того, есть ли он на машине и в каком состоянии.
func recommendWARPForFailedKeys(failed []*VPNConfig) string {
	if len(failed) == 0 {
		return ""
	}
	w := detectWARP()
	if !w.Installed {
		return "WARP не установлен. Установите: `winget install Cloudflare.Warp`, " +
			"запустите `warp-cli connect` — это часто помогает когда провайдер " +
			"блокирует именно VPN-инфраструктуру."
	}
	if !w.Connected {
		return fmt.Sprintf("WARP установлен, но выключен. Запустите `warp-cli connect`, " +
			"затем повторите тест — некоторые ключи могут стать рабочими через WARP.")
	}
	return "WARP уже активен — все тесты прошли через него. Если ключи всё равно падают, проблема не в провайдере."
}
