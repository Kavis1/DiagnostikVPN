package main

import (
	"context"
	"fmt"
	"net"
	"time"
)

// checkIPv6Connectivity проверяет — доступен ли IPv6.
// Это важно: если IPv6 включен и достижим, но VPN-клиент не туннелирует IPv6,
// может произойти IPv6-leak (запросы пойдут вне VPN).
func checkIPv6Connectivity() TestResult {
	hasIPv6 := false
	ifaces, err := net.Interfaces()
	if err == nil {
		for _, iface := range ifaces {
			if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
				continue
			}
			addrs, _ := iface.Addrs()
			for _, a := range addrs {
				ipnet, ok := a.(*net.IPNet)
				if !ok {
					continue
				}
				if ipnet.IP.To4() != nil {
					continue
				}
				if ipnet.IP.IsLinkLocalUnicast() {
					continue
				}
				hasIPv6 = true
			}
		}
	}

	if !hasIPv6 {
		return TestResult{
			Name:    "IPv6",
			Status:  StatusOK,
			Message: "IPv6 не активен на интерфейсах — leak невозможен",
		}
	}

	// Проверяем достижимость v6 (Google DNS)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "tcp6", "[2001:4860:4860::8888]:53")
	if err != nil {
		return TestResult{
			Name:    "IPv6",
			Status:  StatusOK,
			Message: "IPv6 настроен на интерфейсе, но не имеет выхода в интернет — leak маловероятен",
		}
	}
	conn.Close()

	return TestResult{
		Name:    "IPv6",
		Status:  StatusWarning,
		Message: "IPv6 активен и доступен — возможен IPv6-leak в обход VPN",
		Details: "Рекомендация: убедитесь что ваш VPN-клиент туннелирует IPv6 или отключите IPv6 на интерфейсе (ncpa.cpl → свойства подключения → снять галку Internet Protocol Version 6).",
	}
}

// checkDNSLeakPotential сравнивает DNS-сервер системы с DNS, который вернёт публичный резолвер.
// Помогает понять, использует ли система свой "локальный" DNS, который может протекать в обход VPN.
func checkDNSLeakPotential() TestResult {
	myDNS := getSystemDNSServers()
	if len(myDNS) == 0 {
		return TestResult{
			Name:    "DNS leak (потенциал)",
			Status:  StatusInfo,
			Message: "не удалось определить системные DNS",
		}
	}

	// Эвристика: если все DNS — публичные (1.1.1.1, 8.8.8.8 и т.д.), то меньше шанс утечки в провайдер
	publicDNS := map[string]bool{
		"8.8.8.8": true, "8.8.4.4": true,
		"1.1.1.1": true, "1.0.0.1": true,
		"9.9.9.9": true, "149.112.112.112": true,
		"208.67.222.222": true, "208.67.220.220": true,
		"94.140.14.14": true, "94.140.15.15": true,
		"77.88.8.8": true, "77.88.8.1": true, // Yandex
	}

	privateCount := 0
	publicCount := 0
	for _, d := range myDNS {
		if publicDNS[d] {
			publicCount++
		} else {
			privateCount++
		}
	}

	if privateCount > 0 && publicCount == 0 {
		return TestResult{
			Name:    "DNS leak (потенциал)",
			Status:  StatusWarning,
			Message: fmt.Sprintf("используется только локальный/провайдерский DNS (%d серверов) — высокий риск DNS-утечки", privateCount),
			Details: "Системные DNS: " + joinStrs(myDNS) + "\nРекомендация: добавьте в свойствах подключения публичный DNS (1.1.1.1 / 8.8.8.8) или используйте DoH в браузере.",
		}
	}

	return TestResult{
		Name:    "DNS leak (потенциал)",
		Status:  StatusOK,
		Message: fmt.Sprintf("DNS-конфигурация: %d публичных, %d частных", publicCount, privateCount),
		Details: "Системные DNS: " + joinStrs(myDNS),
	}
}

func getSystemDNSServers() []string {
	// Дёшево — переиспользуем уже существующий extractDNSFromIPConfig.
	out, err := runWindowsCmd("ipconfig", "/all")
	if err != nil {
		return nil
	}
	return extractDNSFromIPConfig(out)
}

func joinStrs(s []string) string {
	if len(s) == 0 {
		return "(пусто)"
	}
	res := ""
	for i, v := range s {
		if i > 0 {
			res += ", "
		}
		res += v
	}
	return res
}
