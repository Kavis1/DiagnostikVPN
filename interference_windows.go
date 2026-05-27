//go:build windows

package main

import (
	"fmt"
	"os/exec"
	"strings"
)

func checkFirewallStatus() TestResult {
	// Проверяем статус через реестр — не зависит от языка системы
	profiles := []struct {
		key  string
		name string
	}{
		{`HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile`, "Domain"},
		{`HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile`, "Private"},
		{`HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile`, "Public"},
	}

	var details []string
	enabledCount := 0

	for _, p := range profiles {
		out, err := exec.Command("reg", "query", p.key, "/v", "EnableFirewall").CombinedOutput()
		if err != nil {
			details = append(details, fmt.Sprintf("%s: не удалось определить", p.name))
			continue
		}
		output := string(out)
		if strings.Contains(output, "0x1") {
			details = append(details, fmt.Sprintf("%s: ВКЛ", p.name))
			enabledCount++
		} else if strings.Contains(output, "0x0") {
			details = append(details, fmt.Sprintf("%s: ВЫКЛ", p.name))
		}
	}

	status := StatusOK
	msg := "Windows Firewall активен"
	if enabledCount == 0 {
		status = StatusInfo
		msg = "Windows Firewall отключён (проверьте, если это не намеренно)"
	} else if enabledCount < 3 {
		status = StatusInfo
		msg = fmt.Sprintf("Windows Firewall: %d из 3 профилей активны", enabledCount)
	}

	return TestResult{
		Name:    "Брандмауэр",
		Status:  status,
		Message: msg,
		Details: strings.Join(details, "\n"),
	}
}

func checkSystemProxy() TestResult {
	// Проверяем системные прокси через реестр
	out, err := exec.Command("reg", "query",
		`HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`,
		"/v", "ProxyEnable").CombinedOutput()

	proxyEnabled := false
	if err == nil && strings.Contains(string(out), "0x1") {
		proxyEnabled = true
	}

	var proxyServer string
	if proxyEnabled {
		out2, err2 := exec.Command("reg", "query",
			`HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`,
			"/v", "ProxyServer").CombinedOutput()
		if err2 == nil {
			lines := strings.Split(string(out2), "\n")
			for _, line := range lines {
				if strings.Contains(line, "ProxyServer") {
					parts := strings.Fields(line)
					if len(parts) >= 3 {
						proxyServer = parts[len(parts)-1]
					}
				}
			}
		}
	}

	// Переменные окружения
	var envProxies []string
	for _, env := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy"} {
		if val := getEnvVar(env); val != "" {
			envProxies = append(envProxies, fmt.Sprintf("%s=%s", env, val))
		}
	}

	if proxyEnabled || len(envProxies) > 0 {
		var details []string
		msg := "обнаружены системные прокси — могут перехватывать трафик VPN"
		if proxyEnabled && proxyServer != "" {
			details = append(details, fmt.Sprintf("Системный прокси: %s", proxyServer))
		}
		if len(envProxies) > 0 {
			details = append(details, envProxies...)
		}
		return TestResult{
			Name:    "Системный прокси",
			Status:  StatusWarning,
			Message: msg,
			Details: strings.Join(details, "\n"),
		}
	}

	return TestResult{
		Name:    "Системный прокси",
		Status:  StatusOK,
		Message: "системные прокси не настроены",
	}
}
