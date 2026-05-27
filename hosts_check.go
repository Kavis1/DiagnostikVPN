package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
)

// hostsFilePath — определена в platform_windows.go (`C:\Windows\System32\drivers\etc\hosts`)
// и platform_darwin.go (`/etc/hosts`).

// checkHostsFile анализирует hosts-файл на предмет:
//   - нестандартных записей кроме localhost
//   - блокировок (записи 0.0.0.0 / 127.0.0.1 для не-localhost доменов)
//   - подмен IP для адресов наших серверов
func checkHostsFile(serverAddresses []string) TestResult {
	f, err := os.Open(hostsFilePath)
	if err != nil {
		return TestResult{
			Name:    "Hosts-файл",
			Status:  StatusInfo,
			Message: "не удалось прочитать hosts (нужны права?)",
		}
	}
	defer f.Close()

	addrSet := make(map[string]bool)
	for _, a := range serverAddresses {
		addrSet[strings.ToLower(a)] = true
	}

	var blockedDomains []string
	var nonStandard []string
	var hijackedServers []string

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		raw := scanner.Text()
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Уберём inline-комментарий
		if idx := strings.Index(line, "#"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		ip := fields[0]
		hosts := fields[1:]

		// Стандартные строки localhost-маппинга — пропускаем
		isLocalhost := true
		for _, h := range hosts {
			lh := strings.ToLower(h)
			if lh != "localhost" && lh != "localhost.localdomain" &&
				lh != "broadcasthost" && !strings.HasPrefix(lh, "ip6-") {
				isLocalhost = false
				break
			}
		}
		if isLocalhost {
			continue
		}

		// Блокировка — IP в дырку
		if ip == "0.0.0.0" || ip == "127.0.0.1" || ip == "::" || ip == "::1" {
			blockedDomains = append(blockedDomains, fmt.Sprintf("%s -> %s", strings.Join(hosts, ","), ip))
		} else {
			nonStandard = append(nonStandard, fmt.Sprintf("%s -> %s", strings.Join(hosts, ","), ip))
		}

		// Hijack: один из доменов совпадает с адресом сервера VPN
		for _, h := range hosts {
			lh := strings.ToLower(h)
			if addrSet[lh] {
				resolvedIP := net.ParseIP(ip)
				if resolvedIP != nil {
					hijackedServers = append(hijackedServers, fmt.Sprintf("%s -> %s", lh, ip))
				}
			}
		}
	}

	if len(hijackedServers) > 0 {
		return TestResult{
			Name:    "Hosts-файл",
			Status:  StatusError,
			Message: fmt.Sprintf("ВНИМАНИЕ: домен VPN-сервера переопределён в hosts (%d записей)", len(hijackedServers)),
			Details: "Hijacked:\n" + strings.Join(hijackedServers, "\n"),
		}
	}

	if len(blockedDomains) > 0 || len(nonStandard) > 0 {
		var details []string
		if len(blockedDomains) > 0 {
			details = append(details, "Заблокировано через hosts:")
			details = append(details, blockedDomains...)
		}
		if len(nonStandard) > 0 {
			details = append(details, "Нестандартные записи:")
			details = append(details, nonStandard...)
		}
		return TestResult{
			Name:    "Hosts-файл",
			Status:  StatusInfo,
			Message: fmt.Sprintf("найдено %d нестандартных записей (%d блокировок)", len(blockedDomains)+len(nonStandard), len(blockedDomains)),
			Details: strings.Join(details, "\n"),
		}
	}

	return TestResult{
		Name:    "Hosts-файл",
		Status:  StatusOK,
		Message: "чистый — только стандартные записи",
	}
}
