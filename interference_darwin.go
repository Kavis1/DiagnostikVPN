//go:build darwin

package main

import (
	"fmt"
	"os/exec"
	"strings"
)

// checkFirewallStatus — macOS Application Firewall через `socketfilterfw`.
// Команда без sudo показывает только глобальный enable/disable.
func checkFirewallStatus() TestResult {
	out, err := exec.Command("/usr/libexec/ApplicationFirewall/socketfilterfw",
		"--getglobalstate").CombinedOutput()
	if err != nil {
		return TestResult{
			Name:    "Брандмауэр",
			Status:  StatusInfo,
			Message: "не удалось опросить macOS Application Firewall",
		}
	}
	output := strings.TrimSpace(string(out))
	status := StatusInfo
	msg := output
	if strings.Contains(strings.ToLower(output), "enabled") {
		status = StatusOK
		msg = "macOS Application Firewall: включён"
	} else if strings.Contains(strings.ToLower(output), "disabled") {
		status = StatusInfo
		msg = "macOS Application Firewall: выключен"
	}
	return TestResult{
		Name:    "Брандмауэр",
		Status:  status,
		Message: msg,
		Details: output,
	}
}

// checkSystemProxy — на macOS читаем через `scutil --proxy`. Поддерживает HTTP,
// HTTPS, SOCKS proxy конфигурации.
func checkSystemProxy() TestResult {
	out, err := exec.Command("scutil", "--proxy").CombinedOutput()
	if err != nil {
		return TestResult{
			Name:    "Системный прокси",
			Status:  StatusInfo,
			Message: "не удалось опросить scutil --proxy",
		}
	}
	text := string(out)

	httpEnabled := extractScutilFlag(text, "HTTPEnable") == "1"
	httpsEnabled := extractScutilFlag(text, "HTTPSEnable") == "1"
	socksEnabled := extractScutilFlag(text, "SOCKSEnable") == "1"

	var envProxies []string
	for _, env := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy"} {
		if val := getEnvVar(env); val != "" {
			envProxies = append(envProxies, fmt.Sprintf("%s=%s", env, val))
		}
	}

	if !httpEnabled && !httpsEnabled && !socksEnabled && len(envProxies) == 0 {
		return TestResult{
			Name:    "Системный прокси",
			Status:  StatusOK,
			Message: "системные прокси не настроены",
		}
	}

	var details []string
	if httpEnabled {
		details = append(details, fmt.Sprintf("HTTP: %s:%s",
			extractScutilFlag(text, "HTTPProxy"), extractScutilFlag(text, "HTTPPort")))
	}
	if httpsEnabled {
		details = append(details, fmt.Sprintf("HTTPS: %s:%s",
			extractScutilFlag(text, "HTTPSProxy"), extractScutilFlag(text, "HTTPSPort")))
	}
	if socksEnabled {
		details = append(details, fmt.Sprintf("SOCKS: %s:%s",
			extractScutilFlag(text, "SOCKSProxy"), extractScutilFlag(text, "SOCKSPort")))
	}
	if len(envProxies) > 0 {
		details = append(details, envProxies...)
	}

	return TestResult{
		Name:    "Системный прокси",
		Status:  StatusWarning,
		Message: "обнаружены системные прокси — могут перехватывать трафик VPN",
		Details: strings.Join(details, "\n"),
	}
}

func extractScutilFlag(text, key string) string {
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, key+" :") || strings.HasPrefix(line, key+":") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return ""
}
