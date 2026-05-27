//go:build windows

package main

import (
	"fmt"
	"os/exec"
	"strings"
)

// checkOutboundBlockRules ищет в Windows Firewall outbound-правила со статусом Block,
// которые могут блокировать VPN-приложения.
func checkOutboundBlockRules() TestResult {
	// Используем PowerShell — netsh не отдаёт чистый структурированный вывод.
	psCmd := `Get-NetFirewallRule -Direction Outbound -Action Block -Enabled True -ErrorAction SilentlyContinue | ` +
		`Where-Object { $_.Profile -ne 'Domain' -or $true } | ` +
		`Select-Object -First 200 DisplayName, Profile, Group | ` +
		`ForEach-Object { '{0}|{1}|{2}' -f $_.DisplayName, $_.Profile, $_.Group }`

	out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", psCmd).CombinedOutput()
	if err != nil {
		return TestResult{
			Name:    "Outbound-блокировки Firewall",
			Status:  StatusInfo,
			Message: "не удалось опросить Get-NetFirewallRule",
		}
	}

	text := strings.TrimSpace(string(out))
	if text == "" {
		return TestResult{
			Name:    "Outbound-блокировки Firewall",
			Status:  StatusOK,
			Message: "явных outbound-блокировок не обнаружено",
		}
	}

	lines := strings.Split(text, "\n")
	// Подозрительные ключевые слова — намекают что правило связано с VPN/proxy
	vpnKeywords := []string{
		"vpn", "proxy", "xray", "v2ray", "trojan", "hiddify", "wireguard", "openvpn",
		"shadowsocks", "clash", "sing-box", "nekoray", "hysteria", "tuic", "mihomo",
	}

	var suspicious []string
	totalRules := 0
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		totalRules++
		ll := strings.ToLower(line)
		for _, kw := range vpnKeywords {
			if strings.Contains(ll, kw) {
				suspicious = append(suspicious, line)
				break
			}
		}
	}

	status := StatusInfo
	msg := fmt.Sprintf("активных outbound-блок-правил: %d", totalRules)
	details := ""
	if len(suspicious) > 0 {
		status = StatusWarning
		msg = fmt.Sprintf("найдено %d правил блокирующих VPN-приложения (всего outbound-блокировок: %d)",
			len(suspicious), totalRules)
		details = "Подозрительные правила:\n" + strings.Join(suspicious, "\n")
	} else if totalRules > 0 && totalRules <= 30 {
		details = "Список правил:\n" + strings.Join(lines, "\n")
	} else if totalRules > 30 {
		details = fmt.Sprintf("Всего правил: %d (показаны не все, чтобы не раздувать отчёт)", totalRules)
	}

	return TestResult{
		Name:    "Outbound-блокировки Firewall",
		Status:  status,
		Message: msg,
		Details: details,
	}
}

// checkAppFirewallStatus возвращает короткий summary AppLocker/SmartScreen/AppContainer,
// если они включены — это часто причина блокировки нестандартных VPN-бинарников.
func checkAppRestrictions() TestResult {
	psCmd := `$smart = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' -Name 'SmartScreenEnabled' -ErrorAction SilentlyContinue).SmartScreenEnabled; ` +
		`$applocker = (Get-Service -Name AppIDSvc -ErrorAction SilentlyContinue).Status; ` +
		`$ws = (Get-MpComputerStatus -ErrorAction SilentlyContinue).IsTamperProtected; ` +
		`'SmartScreen={0}|AppLocker={1}|TamperProtect={2}' -f $smart, $applocker, $ws`

	out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", psCmd).CombinedOutput()
	if err != nil {
		return TestResult{
			Name:    "Ограничения запуска приложений",
			Status:  StatusInfo,
			Message: "не удалось опросить",
		}
	}
	line := strings.TrimSpace(string(out))
	status := StatusInfo
	if strings.Contains(line, "Block") {
		status = StatusWarning
	}
	return TestResult{
		Name:    "Ограничения запуска приложений",
		Status:  status,
		Message: line,
	}
}
