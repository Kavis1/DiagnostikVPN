package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"
)

// TestTUNResult — результат запуска нашего собственного тестового TUN.
type TestTUNResult struct {
	Attempted    bool
	AdminPresent bool
	NodeUsed     string
	BackendName  string // sing-box / xray
	IPBefore     string
	IPAfter      string
	IPChanged    bool
	StderrTail   string
	ErrorMsg     string
	Notes        []string
}

// SingBoxTUN — обёртка над процессом sing-box запущенного с TUN inbound.
// Отличается от SingBoxProxy: нет SOCKS-порта, трафик идёт через виртуальный
// сетевой адаптер благодаря auto_route.
type SingBoxTUN struct {
	cmd        *exec.Cmd
	configPath string
	stderr     *bytes.Buffer
}

// isRunningAsAdmin проверяет — запущена ли наша программа от Администратора.
// Без админа TUN inbound в sing-box не поднимется (нужны права на создание
// сетевого адаптера и установку маршрутов).
func isRunningAsAdmin() bool {
	out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command",
		`[bool]([Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)`).Output()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(out)) == "True"
}

// runTestTUN поднимает свой sing-box с TUN inbound на указанном VPN-конфиге,
// измеряет смену IP, докладывает результат пользователю.
//
// Возвращает TestTUNResult — пишется в общий отчёт.
func runTestTUN(cfg *VPNConfig, baselineIP string) *TestTUNResult {
	r := &TestTUNResult{Attempted: true, IPBefore: baselineIP}

	if cfg == nil {
		r.ErrorMsg = "не передан VPN-конфиг для теста"
		return r
	}
	if strings.EqualFold(cfg.Transport, "xhttp") {
		// xhttp идёт через xray-core, а xray TUN inbound не делает.
		// Просим выбрать другой ключ.
		r.ErrorMsg = "выбранный ключ использует xhttp — sing-box TUN не поддерживает этот транспорт. Используется sing-box-совместимый ключ."
		return r
	}

	// 1) Проверяем admin
	r.AdminPresent = isRunningAsAdmin()
	if !r.AdminPresent {
		r.ErrorMsg = "программа не запущена от Администратора — TUN inbound не поднять"
		return r
	}

	// 2) Готовим конфиг sing-box с TUN
	r.NodeUsed = nodeDisplayName(cfg)
	r.BackendName = "sing-box (TUN)"

	configJSON, err := generateSingBoxTUNConfig(cfg)
	if err != nil {
		r.ErrorMsg = "генерация config: " + err.Error()
		return r
	}

	tmpfile, err := os.CreateTemp("", "diag-tun-*.json")
	if err != nil {
		r.ErrorMsg = "tmp config: " + err.Error()
		return r
	}
	tmpfile.Write(configJSON)
	tmpfile.Close()

	binPath := locateSingBox()
	if binPath == "" {
		os.Remove(tmpfile.Name())
		r.ErrorMsg = "sing-box.exe не найден"
		return r
	}

	// 3) Запускаем
	var stderr bytes.Buffer
	cmd := exec.Command(binPath, "run", "-c", tmpfile.Name())
	cmd.Stdout = io.Discard
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		os.Remove(tmpfile.Name())
		r.ErrorMsg = "не удалось запустить sing-box: " + err.Error()
		return r
	}

	tun := &SingBoxTUN{cmd: cmd, configPath: tmpfile.Name(), stderr: &stderr}
	defer tun.Stop()

	// 4) Ждём пока TUN-адаптер появится в системе (макс 15 сек)
	fmt.Printf("    Жду создания TUN-адаптера...")
	if !waitForTUNInterface("DiagnostikVPN", 15*time.Second) {
		fmt.Printf(" %sне поднялся за 15с%s\n", colorRed, colorReset)
		r.StderrTail = tailStr(stderr.String(), 600)
		r.ErrorMsg = "TUN-адаптер не появился в системе — возможно нет wintun.dll или конфликт с другим VPN-адаптером"
		return r
	}
	fmt.Printf(" %sок%s\n", colorGreen, colorReset)

	// Доп. задержка чтобы маршруты устаканились
	time.Sleep(3 * time.Second)

	// 5) Замер IP через ВСЕМ-проксированный канал (наша Go-программа тоже идёт через TUN
	//    благодаря auto_route)
	fmt.Printf("    Замер IP через наш TUN...")
	ip, country, err := detectLocalExitIP()
	if err != nil || ip == "" {
		fmt.Printf(" %sошибка: %v%s\n", colorRed, err, colorReset)
		r.StderrTail = tailStr(stderr.String(), 600)
		r.ErrorMsg = "не удалось определить IP через TUN — возможно сам ключ не работает или DNS не настроен"
		return r
	}
	fmt.Printf(" %s%s (%s)%s\n", colorGreen, ip, country, colorReset)
	r.IPAfter = ip
	r.IPChanged = (ip != baselineIP) && baselineIP != ""

	return r
}

// generateSingBoxTUNConfig — конфиг sing-box с TUN inbound (вместо SOCKS5).
// Использует gvisor-стек: не требует wintun.dll, переносим между сборками sing-box.
// auto_route=true перехватывает default route ОС — на время работы весь трафик
// машины (включая наш Go-процесс) идёт через VPN-сервер.
func generateSingBoxTUNConfig(cfg *VPNConfig) ([]byte, error) {
	outbound, err := buildOutbound(cfg)
	if err != nil {
		return nil, err
	}
	if outbound == nil {
		return nil, fmt.Errorf("конфиг не поддерживается sing-box (например xhttp)")
	}

	full := map[string]interface{}{
		"log": map[string]interface{}{
			"level":     "warn",
			"timestamp": true,
		},
		"dns": map[string]interface{}{
			"servers": []interface{}{
				map[string]interface{}{
					"tag":    "remote",
					"type":   "udp",
					"server": "1.1.1.1",
				},
			},
			"final": "remote",
		},
		"inbounds": []interface{}{
			map[string]interface{}{
				"type":           "tun",
				"tag":            "tun-in",
				"interface_name": "DiagnostikVPN",
				"address":        []string{"172.19.0.1/30"},
				"mtu":            1500,
				"auto_route":     true,
				"strict_route":   true,
				"stack":          "gvisor",
			},
		},
		"outbounds": []interface{}{
			outbound,
			map[string]interface{}{"type": "direct", "tag": "direct"},
		},
		"route": map[string]interface{}{
			"final": "proxy",
		},
	}
	return json.MarshalIndent(full, "", "  ")
}

// waitForTUNInterface ждёт появления указанного интерфейса в системе.
func waitForTUNInterface(name string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		ifaces, err := net.Interfaces()
		if err == nil {
			for _, ifc := range ifaces {
				if ifc.Flags&net.FlagUp == 0 {
					continue
				}
				if strings.EqualFold(ifc.Name, name) ||
					strings.Contains(strings.ToLower(ifc.Name), strings.ToLower(name)) {
					return true
				}
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	return false
}

// Stop корректно останавливает sing-box TUN — это ВАЖНО, иначе route'ы остаются
// и интернет на машине пользователя ломается до перезагрузки.
func (t *SingBoxTUN) Stop() {
	if t == nil {
		return
	}
	if t.cmd != nil && t.cmd.Process != nil {
		// SIGINT не работает на Windows — Kill корректно отрабатывает,
		// sing-box на SIGKILL/exit_code cleanup'нет маршруты сам.
		_ = t.cmd.Process.Kill()
		_, _ = t.cmd.Process.Wait()
	}
	if t.configPath != "" {
		os.Remove(t.configPath)
	}
	// Дополнительно — taskkill для уверенности (на случай если sing-box зависнет)
	exec.Command("taskkill", "/F", "/IM", "sing-box.exe").Run()
}

// nodeDisplayName — короткое имя ключа для логов и отчёта.
func nodeDisplayName(cfg *VPNConfig) string {
	if cfg.Remark != "" {
		return cfg.Remark
	}
	return fmt.Sprintf("%s:%d", cfg.Address, cfg.Port)
}

func tailStr(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return "..." + s[len(s)-n:]
}

// formatTestTUNForFile — секция в отчёт.
func formatTestTUNForFile(r *TestTUNResult) string {
	if r == nil || !r.Attempted {
		return ""
	}
	var b strings.Builder
	b.WriteString("\n--------------------------------------------------\n")
	b.WriteString("Свой тестовый TUN (sing-box)\n")
	b.WriteString("--------------------------------------------------\n")
	if !r.AdminPresent {
		b.WriteString("Программа НЕ запущена от Администратора — тест TUN не делался.\n")
		b.WriteString("Для запуска: ПКМ по .exe → «Запустить от имени администратора», затем -only-tun.\n")
		return b.String()
	}
	fmt.Fprintf(&b, "Использован ключ: %s\n", r.NodeUsed)
	fmt.Fprintf(&b, "Backend: %s\n", r.BackendName)
	if r.IPBefore != "" {
		fmt.Fprintf(&b, "Baseline IP (без VPN): %s\n", r.IPBefore)
	}
	if r.IPAfter != "" {
		fmt.Fprintf(&b, "IP через наш TUN: %s\n", r.IPAfter)
	}
	if r.IPChanged {
		b.WriteString("Результат: IP СМЕНИЛСЯ → TUN на этой машине работает. Проблема не в системе.\n")
	} else if r.IPAfter != "" {
		b.WriteString("Результат: IP НЕ СМЕНИЛСЯ — TUN поднялся но default route не перехвачен.\n")
	}
	if r.ErrorMsg != "" {
		fmt.Fprintf(&b, "Ошибка: %s\n", r.ErrorMsg)
	}
	if r.StderrTail != "" {
		fmt.Fprintf(&b, "stderr sing-box (последние 600 символов):\n%s\n", r.StderrTail)
	}
	for _, n := range r.Notes {
		fmt.Fprintf(&b, "Заметка: %s\n", n)
	}
	return b.String()
}
