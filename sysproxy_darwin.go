//go:build darwin

package main

import (
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
)

// SystemProxyState — снимок настроек прокси на macOS.
//
// На macOS прокси настраивается per-network-service (Wi-Fi, Ethernet, USB и т.д.),
// поэтому мы запоминаем имя сервиса который менялся и его предыдущее состояние.
type SystemProxyState struct {
	WasEnabled bool
	Server     string
	Override   string
	// Per-service состояние для отката
	Services []macServiceProxyState
}

type macServiceProxyState struct {
	Service     string
	HTTPEnabled bool
	HTTPServer  string
	HTTPPort    string
	HTTPSEnabled bool
	HTTPSServer string
	HTTPSPort   string
}

// setSystemProxy включает HTTP+HTTPS прокси на ВСЕХ активных сетевых сервисах.
func setSystemProxy(proxyServer string) (SystemProxyState, error) {
	prev := readSystemProxyState()

	host, port, err := splitHostPort(proxyServer)
	if err != nil {
		return prev, fmt.Errorf("неверный формат прокси (%s): %w", proxyServer, err)
	}

	services := listActiveNetworkServices()
	for _, svc := range services {
		// Setwebproxy и setsecurewebproxy требуют 3 аргумента: имя, host, port.
		exec.Command("networksetup", "-setwebproxy", svc, host, port).Run()
		exec.Command("networksetup", "-setsecurewebproxy", svc, host, port).Run()
		// Bypass — стандартный список
		exec.Command("networksetup", "-setproxybypassdomains", svc,
			"*.local", "169.254/16", "127.0.0.1", "localhost").Run()
	}

	prev.WasEnabled = true
	prev.Server = proxyServer
	return prev, nil
}

// restoreSystemProxy откатывает прокси на каждом сервисе который был в Services.
func restoreSystemProxy(prev SystemProxyState) {
	for _, s := range prev.Services {
		if s.HTTPEnabled && s.HTTPServer != "" {
			exec.Command("networksetup", "-setwebproxy", s.Service, s.HTTPServer, s.HTTPPort).Run()
		} else {
			exec.Command("networksetup", "-setwebproxystate", s.Service, "off").Run()
		}
		if s.HTTPSEnabled && s.HTTPSServer != "" {
			exec.Command("networksetup", "-setsecurewebproxy", s.Service, s.HTTPSServer, s.HTTPSPort).Run()
		} else {
			exec.Command("networksetup", "-setsecurewebproxystate", s.Service, "off").Run()
		}
	}
}

func readSystemProxyState() SystemProxyState {
	st := SystemProxyState{}
	services := listActiveNetworkServices()
	for _, svc := range services {
		ss := macServiceProxyState{Service: svc}
		if out, err := exec.Command("networksetup", "-getwebproxy", svc).Output(); err == nil {
			parseMacProxyOutput(string(out), &ss.HTTPEnabled, &ss.HTTPServer, &ss.HTTPPort)
		}
		if out, err := exec.Command("networksetup", "-getsecurewebproxy", svc).Output(); err == nil {
			parseMacProxyOutput(string(out), &ss.HTTPSEnabled, &ss.HTTPSServer, &ss.HTTPSPort)
		}
		st.Services = append(st.Services, ss)
		if ss.HTTPEnabled || ss.HTTPSEnabled {
			st.WasEnabled = true
		}
	}
	return st
}

// listActiveNetworkServices возвращает список активных сетевых сервисов
// (Wi-Fi, Ethernet и т.д.) — каждый из них имеет свои настройки прокси.
func listActiveNetworkServices() []string {
	out, err := exec.Command("networksetup", "-listallnetworkservices").Output()
	if err != nil {
		return nil
	}
	var services []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		// Первая строка — заголовок "An asterisk denotes that..." пропускаем.
		// Сервисы с `*` префиксом — отключённые, тоже пропускаем.
		if line == "" || strings.HasPrefix(line, "An asterisk") || strings.HasPrefix(line, "*") {
			continue
		}
		services = append(services, line)
	}
	return services
}

func parseMacProxyOutput(out string, enabled *bool, server, port *string) {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "Enabled:"):
			*enabled = strings.Contains(strings.ToLower(line), "yes")
		case strings.HasPrefix(line, "Server:"):
			*server = strings.TrimSpace(strings.TrimPrefix(line, "Server:"))
		case strings.HasPrefix(line, "Port:"):
			*port = strings.TrimSpace(strings.TrimPrefix(line, "Port:"))
		}
	}
}

func splitHostPort(addr string) (string, string, error) {
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		return "", "", err
	}
	if _, err := strconv.Atoi(p); err != nil {
		return "", "", fmt.Errorf("порт не число: %s", p)
	}
	return h, p, nil
}

// notifyProxyChange / regWrite / regRead — на macOS не нужны, но определены
// как no-op чтобы interactive.go (общий код) компилировался.
func notifyProxyChange()                              {}
func regWrite(name, typ, value string) error          { return nil }
func regRead(name string) (string, error)             { return "", fmt.Errorf("not applicable") }
